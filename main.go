package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/ramin00542/GO_V2rayCollector/collector"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"gopkg.in/yaml.v3"
)

const (
	MaxConfigsPerProtocol = 50000
	MaxConfigsAll         = 50000
	MaxWorkers            = 5
	RequestTimeout        = 15 * time.Second
)

var (
	sortFlag    = flag.Bool("sort", false, "sort configs from latest to oldest")
	dedupFlag   = flag.Bool("dedup", false, "enable advanced deduplication (fingerprint-based)")
	testFlag    = flag.Bool("test", false, "test connectivity for a sample of configs")
	concurrent  = flag.Int("concurrent", 3, "number of concurrent workers for fetching sources")
	maxMessages = flag.Int("max-msgs", 100, "maximum messages to fetch per Telegram channel")
	clashFlag   = flag.Bool("clash", false, "generate Clash YAML file for all configs")

	regexCache = make(map[string]*regexp.Regexp)
	protoList  = []string{"ss", "vmess", "trojan", "vless", "http", "socks", "wireguard", "hysteria2", "mtproto", "tuic", "slipnet"}

	client = &http.Client{Timeout: RequestTimeout}

	cacheMutex     sync.RWMutex
	configCache    = make(map[string]CacheEntry)
	telegramByChannel = make(map[string]map[string][]string)
	subConfigs     = make(map[string][]string)

	stats = struct {
		sync.Mutex
		telegramCount, subCount, newCount, duplicateCount int
		protoCounts map[string]int
	}{protoCounts: make(map[string]int)}

	lastArchiveDate string
	shutdownChan    = make(chan os.Signal, 1)
)

type CacheEntry struct {
	Timestamp   int64  `json:"timestamp"`
	Source      string `json:"source"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Channel     string `json:"channel,omitempty"`
}

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

type CacheData struct {
	Configs   map[string]CacheEntry `json:"configs"`
	Timestamp int64                 `json:"timestamp"`
	LastDate  string                `json:"last_archive_date,omitempty"`
}

func main() {
	flag.Parse()
	initRegexps()
	setupLogging()
	createDirs()
	loadCache()
	registerSignalHandler()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fetchAllTelegramChannels()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		fetchAllSubscriptions()
	}()
	wg.Wait()

	updateCache()
	pruneCacheByProtocol()
	writeOutputFiles()      // telegram, mixed, subscription
	writeAllConfigs()       // all_configs
	generateLinksFile()     // links.txt

	today := time.Now().Format("2006-01-02")
	if lastArchiveDate != today {
		archiveDaily()
		lastArchiveDate = today
		saveCache()
	}

	if *clashFlag {
		generateClashYAML()
	}
	if *testFlag {
		testSampleConfigs()
	}
	printStats()
	saveCache()
	gologger.Info().Msg("All Done!")
}

// ==================== توابع اولیه ====================
func initRegexps() {
	for _, proto := range protoList {
		pattern := getPatternForProto(proto)
		if pattern != "" {
			regexCache[proto] = regexp.MustCompile(pattern)
		}
	}
}

func getPatternForProto(proto string) string {
	switch proto {
	case "ss":
		return `(?m)(...ss:|^ss:)\/\/.+?(%3A%40|#)`
	case "vmess":
		return `(?m)vmess:\/\/[^\s]+`
	case "trojan":
		return `(?m)trojan:\/\/.+?(%3A%40|#)`
	case "vless":
		return `(?m)vless:\/\/[^\s]+`
	case "http":
		return `(?m)https?:\/\/[^\s]+`
	case "socks":
		return `(?m)socks(?:5)?:\/\/[^\s]+`
	case "wireguard":
		return `(?m)wireguard:\/\/[^\s]+`
	case "hysteria2":
		return `(?m)hysteria2:\/\/[^\s]+`
	case "mtproto":
		return `(?m)tg:\/\/proxy\?[^\s]+`
	case "tuic":
		return `(?m)tuic:\/\/[^\s]+`
	case "slipnet":
		return `(?m)(?:slipnet|slip):\/\/[^\s]+`
	default:
		return ""
	}
}

func setupLogging() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
}

func createDirs() {
	dirs := []string{"telegram", "subscription", "mixed", "daily_archive", "all_configs"}
	for _, d := range dirs {
		os.MkdirAll(d, 0755)
	}
}

func registerSignalHandler() {
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdownChan
		saveCache()
		os.Exit(0)
	}()
}

// ==================== مدیریت Cache ====================
func loadCache() {
	data, err := os.ReadFile("config_cache.json")
	if err != nil {
		gologger.Info().Msg("No existing cache file, starting fresh.")
		return
	}
	var cd CacheData
	if err = json.Unmarshal(data, &cd); err != nil {
		gologger.Error().Msgf("Failed to parse cache: %v", err)
		return
	}
	cacheMutex.Lock()
	configCache = cd.Configs
	lastArchiveDate = cd.LastDate
	cacheMutex.Unlock()
	gologger.Info().Msgf("Loaded %d configs from cache", len(configCache))
}

func saveCache() {
	cacheMutex.RLock()
	cd := CacheData{
		Configs:   configCache,
		Timestamp: time.Now().Unix(),
		LastDate:  lastArchiveDate,
	}
	cacheMutex.RUnlock()
	data, _ := json.MarshalIndent(cd, "", "  ")
	os.WriteFile("config_cache.json", data, 0644)
}

func updateCache() {
	now := time.Now().Unix()
	newCount, dupCount := 0, 0

	addIfNew := func(cfg, source, channel string) {
		if cfg == "" {
			return
		}
		cacheMutex.Lock()
		defer cacheMutex.Unlock()

		if *dedupFlag && strings.HasPrefix(cfg, "vmess://") {
			fp := fingerprintVmess(cfg)
			for ec, e := range configCache {
				if e.Fingerprint == fp && fp != "" && ec != cfg {
					dupCount++
					return
				}
			}
		}
		if _, exists := configCache[cfg]; exists {
			dupCount++
			return
		}
		fp := ""
		if *dedupFlag && strings.HasPrefix(cfg, "vmess://") {
			fp = fingerprintVmess(cfg)
		}
		configCache[cfg] = CacheEntry{Timestamp: now, Source: source, Fingerprint: fp, Channel: channel}
		newCount++
		stats.Lock()
		stats.newCount++
		if source == "telegram" {
			stats.telegramCount++
		} else {
			stats.subCount++
		}
		proto := detectProtocol(cfg)
		stats.protoCounts[proto]++
		stats.Unlock()
	}

	for ch, pm := range telegramByChannel {
		for _, lst := range pm {
			for _, cfg := range lst {
				addIfNew(cfg, "telegram", ch)
			}
		}
	}
	for _, lst := range subConfigs {
		for _, cfg := range lst {
			addIfNew(cfg, "subscription", "")
		}
	}
	gologger.Info().Msgf("Cache update: %d new, %d dup", newCount, dupCount)
}

func pruneCacheByProtocol() {
	groups := make(map[string][]struct {
		key string
		ts  int64
	})
	cacheMutex.RLock()
	for cfg, e := range configCache {
		proto := detectProtocol(cfg)
		groups[proto] = append(groups[proto], struct {
			key string
			ts  int64
		}{cfg, e.Timestamp})
	}
	cacheMutex.RUnlock()

	newCache := make(map[string]CacheEntry)
	for proto, items := range groups {
		if len(items) <= MaxConfigsPerProtocol {
			for _, it := range items {
				newCache[it.key] = configCache[it.key]
			}
			continue
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		for i := 0; i < MaxConfigsPerProtocol; i++ {
			newCache[items[i].key] = configCache[items[i].key]
		}
		gologger.Info().Msgf("Pruned %s: kept %d", proto, MaxConfigsPerProtocol)
	}
	cacheMutex.Lock()
	configCache = newCache
	cacheMutex.Unlock()
}

func detectProtocol(cfg string) string {
	for proto, re := range regexCache {
		if re.MatchString(cfg) {
			return proto
		}
	}
	return "mixed"
}

func fingerprintVmess(vmessUrl string) string {
	parts := strings.SplitN(vmessUrl, "vmess://", 2)
	if len(parts) != 2 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err = json.Unmarshal(decoded, &data); err != nil {
		return ""
	}
	add := fmt.Sprintf("%v:%v:%v", data["add"], data["port"], data["id"])
	hash := md5.Sum([]byte(add))
	return fmt.Sprintf("%x", hash)
}

// ==================== دریافت از تلگرام ====================
func fetchAllTelegramChannels() {
	fileData, err := collector.ReadFileContent("channels.csv")
	if err != nil {
		gologger.Warning().Msg("channels.csv not found, skipping Telegram.")
		return
	}
	var channels []ChannelsType
	csvutil.Unmarshal([]byte(fileData), &channels)
	jobs := make(chan ChannelsType, len(channels))
	var wg sync.WaitGroup
	for i := 0; i < *concurrent; i++ {
		wg.Add(1)
		go telegramWorker(jobs, &wg)
	}
	for _, ch := range channels {
		jobs <- ch
	}
	close(jobs)
	wg.Wait()
}

func telegramWorker(jobs <-chan ChannelsType, wg *sync.WaitGroup) {
	defer wg.Done()
	for ch := range jobs {
		url := collector.ChangeUrlToTelegramWebUrl(ch.URL)
		channelName := extractChannelNameFromURL(url)
		if channelName == "" {
			continue
		}
		resp := HttpRequest(url)
		if resp == nil {
			continue
		}
		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		doc.Url = resp.Request.URL
		allTexts := getAllMessages(doc, *maxMessages)
		for _, text := range allTexts {
			processTelegramText(text, channelName)
		}
	}
}

func extractChannelNameFromURL(url string) string {
	re := regexp.MustCompile(`t\.me/(?:s/)?([^/?]+)`)
	m := re.FindStringSubmatch(url)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func getAllMessages(startDoc *goquery.Document, max int) []string {
	var allTexts []string
	seen := make(map[string]bool)
	currentURL := startDoc.Url.String()
	doc := startDoc
	for len(allTexts) < max {
		texts := extractMessagesFromDoc(doc)
		for _, t := range texts {
			if !seen[t] {
				seen[t] = true
				allTexts = append(allTexts, t)
			}
		}
		if len(allTexts) >= max {
			break
		}
		lastMsg := doc.Find(".tgme_widget_message_wrap").Last()
		postLink, _ := lastMsg.Attr("data-post")
		if postLink == "" {
			break
		}
		parts := strings.Split(postLink, "/")
		before := parts[len(parts)-1]
		nextURL := fmt.Sprintf("%s?before=%s", strings.TrimSuffix(currentURL, "/"), before)
		nextDoc := loadMore(nextURL)
		if nextDoc == nil {
			break
		}
		doc = nextDoc
		currentURL = nextURL
		time.Sleep(500 * time.Millisecond)
	}
	return allTexts
}

func extractMessagesFromDoc(doc *goquery.Document) []string {
	var texts []string
	doc.Find(".tgme_widget_message_text").Each(func(i int, s *goquery.Selection) {
		html, _ := s.Html()
		text := strings.ReplaceAll(html, "<br/>", "\n")
		plain := extractTextFromHTML(text)
		texts = append(texts, plain)
	})
	return texts
}

func loadMore(link string) *goquery.Document {
	req, _ := http.NewRequest("GET", link, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	doc, _ := goquery.NewDocumentFromReader(resp.Body)
	doc.Url = resp.Request.URL
	return doc
}

func processTelegramText(text, channelName string) {
	configs := extractAllConfigs(text)
	for _, cfg := range configs {
		cfg = strings.TrimSpace(cfg)
		if cfg == "" {
			continue
		}
		if strings.HasPrefix(cfg, "vmess://") {
			cfg = editVmessPs(cfg, "telegram")
		}
		proto := detectProtocol(cfg)
		if telegramByChannel[channelName] == nil {
			telegramByChannel[channelName] = make(map[string][]string)
		}
		telegramByChannel[channelName][proto] = append(telegramByChannel[channelName][proto], cfg)
	}
}

// ==================== دریافت از ساب‌لینک ====================
func fetchAllSubscriptions() {
	data, err := collector.ReadFileContent("Sources.json")
	if err != nil {
		gologger.Warning().Msg("Sources.json not found, skipping subscriptions.")
		return
	}
	var sources []string
	json.Unmarshal([]byte(data), &sources)
	jobs := make(chan string, len(sources))
	var wg sync.WaitGroup
	for i := 0; i < *concurrent; i++ {
		wg.Add(1)
		go subWorker(jobs, &wg)
	}
	for _, src := range sources {
		jobs <- src
	}
	close(jobs)
	wg.Wait()
}

func subWorker(jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for src := range jobs {
		fetchSubscription(src)
	}
}

func fetchSubscription(url string) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}
	processSubscriptionContent(content)
}

func processSubscriptionContent(raw string) {
	configs := extractAllConfigs(raw)
	for _, cfg := range configs {
		cfg = strings.TrimSpace(cfg)
		if cfg == "" {
			continue
		}
		if strings.HasPrefix(cfg, "vmess://") {
			cfg = editVmessPs(cfg, "subscription")
		}
		proto := detectProtocol(cfg)
		subConfigs[proto] = append(subConfigs[proto], cfg)
	}
}

func extractAllConfigs(text string) []string {
	var results []string
	for _, re := range regexCache {
		matches := re.FindAllString(text, -1)
		for _, m := range matches {
			if !contains(results, m) {
				results = append(results, m)
			}
		}
	}
	return results
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func editVmessPs(config, source string) string {
	parts := strings.SplitN(config, "vmess://", 2)
	if len(parts) != 2 {
		return config
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return config
	}
	var data map[string]interface{}
	json.Unmarshal(decoded, &data)
	data["ps"] = fmt.Sprintf("%s-%d", source, time.Now().Unix())
	jsonData, _ := json.Marshal(data)
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonData)
}

func extractTextFromHTML(html string) string {
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(html))
	return doc.Text()
}

// ==================== خروجی‌های اصلی ====================
func writeOutputFiles() {
	writeTelegramPerChannel()
	writeMixedFromTelegram()
	writeSubscriptionFolder()
}

func writeTelegramPerChannel() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	chMap := make(map[string]map[string][]string)
	for cfg, e := range configCache {
		if e.Source == "telegram" && e.Channel != "" {
			proto := detectProtocol(cfg)
			if chMap[e.Channel] == nil {
				chMap[e.Channel] = make(map[string][]string)
			}
			chMap[e.Channel][proto] = append(chMap[e.Channel][proto], cfg)
		}
	}
	for ch, pm := range chMap {
		dir := filepath.Join("telegram", ch)
		os.MkdirAll(dir, 0755)
		for proto, lst := range pm {
			content := strings.Join(lst, "\n")
			if content != "" {
				collector.WriteToFile(content, filepath.Join(dir, proto+"_iran.txt"))
			}
		}
	}
}

func writeMixedFromTelegram() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	mixed := make(map[string][]string)
	for cfg, e := range configCache {
		if e.Source == "telegram" {
			proto := detectProtocol(cfg)
			mixed[proto] = append(mixed[proto], cfg)
		}
	}
	for proto, lst := range mixed {
		content := strings.Join(lst, "\n")
		if content != "" {
			collector.WriteToFile(content, filepath.Join("mixed", proto+"_iran.txt"))
		}
	}
}

func writeSubscriptionFolder() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	sub := make(map[string][]string)
	for cfg, e := range configCache {
		if e.Source == "subscription" {
			proto := detectProtocol(cfg)
			sub[proto] = append(sub[proto], cfg)
		}
	}
	for proto, lst := range sub {
		content := strings.Join(lst, "\n")
		if content != "" {
			collector.WriteToFile(content, filepath.Join("subscription", proto+"_iran.txt"))
		}
	}
}

// ==================== all_configs (فقط 24 ساعت اخیر) ====================
func writeAllConfigs() {
	threshold := time.Now().Add(-24 * time.Hour).Unix()
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	type item struct {
		cfg string
		ts  int64
	}
	allowedProtos := map[string]bool{
		"socks": true, "ss": true, "trojan": true, "tuic": true,
		"vless": true, "vmess": true, "wireguard": true, "hysteria2": true,
	}
	var allItems []item
	httpItems := []item{}
	mtprotoItems := []item{}
	slipnetItems := []item{}

	for cfg, e := range configCache {
		if e.Timestamp < threshold {
			continue
		}
		proto := detectProtocol(cfg)
		if allowedProtos[proto] {
			allItems = append(allItems, item{cfg, e.Timestamp})
		} else if proto == "http" {
			httpItems = append(httpItems, item{cfg, e.Timestamp})
		} else if proto == "mtproto" {
			mtprotoItems = append(mtprotoItems, item{cfg, e.Timestamp})
		} else if proto == "slipnet" {
			slipnetItems = append(slipnetItems, item{cfg, e.Timestamp})
		}
	}

	sort.Slice(allItems, func(i, j int) bool { return allItems[i].ts > allItems[j].ts })
	sort.Slice(httpItems, func(i, j int) bool { return httpItems[i].ts > httpItems[j].ts })
	sort.Slice(mtprotoItems, func(i, j int) bool { return mtprotoItems[i].ts > mtprotoItems[j].ts })
	sort.Slice(slipnetItems, func(i, j int) bool { return slipnetItems[i].ts > slipnetItems[j].ts })

	writeLimited := func(filename string, items []item, maxLines int) {
		if len(items) > maxLines {
			items = items[:maxLines]
		}
		lines := make([]string, len(items))
		for i, it := range items {
			lines[i] = it.cfg
		}
		content := strings.Join(lines, "\n")
		if content != "" {
			collector.WriteToFile(content, filepath.Join("all_configs", filename))
		} else {
			os.WriteFile(filepath.Join("all_configs", filename), []byte{}, 0644)
		}
	}
	writeLimited("all_protocols.txt", allItems, MaxConfigsAll)
	writeLimited("http.txt", httpItems, MaxConfigsAll)
	writeLimited("mtproto.txt", mtprotoItems, MaxConfigsAll)
	writeLimited("slipnet.txt", slipnetItems, MaxConfigsAll)
}

// ==================== آرشیو روزانه ====================
func archiveDaily() {
	today := time.Now().Format("2006-01-02")
	archiveDir := filepath.Join("daily_archive", today)
	os.MkdirAll(archiveDir, 0755)

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	threshold := time.Now().Add(-24 * time.Hour).Unix()
	type item struct {
		cfg string
		ts  int64
	}
	byProto := make(map[string][]item)
	for cfg, e := range configCache {
		if e.Timestamp >= threshold {
			proto := detectProtocol(cfg)
			byProto[proto] = append(byProto[proto], item{cfg, e.Timestamp})
		}
	}
	for proto, items := range byProto {
		sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		if len(items) > MaxConfigsPerProtocol {
			items = items[:MaxConfigsPerProtocol]
		}
		lines := make([]string, len(items))
		for i, it := range items {
			lines[i] = it.cfg
		}
		content := strings.Join(lines, "\n")
		if content != "" {
			os.WriteFile(filepath.Join(archiveDir, proto+"_iran.txt"), []byte(content), 0644)
		}
	}
	gologger.Info().Msgf("Daily archive created in %s", archiveDir)
}

// ==================== تولید فایل links.txt ====================
func generateLinksFile() {
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		repo = "ramin00542/GO_V2rayCollector"
	}
	branch := "main"
	baseURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", repo, branch)

	var links []string
	links = append(links, "# Links to configuration files")
	links = append(links, "")

	// all_configs
	links = append(links, "## all_configs")
	files, _ := filepath.Glob("all_configs/*.txt")
	for _, f := range files {
		name := filepath.Base(f)
		url := fmt.Sprintf("%s/all_configs/%s", baseURL, name)
		links = append(links, fmt.Sprintf("- [%s](%s)", name, url))
	}
	links = append(links, "")

	// daily_archive
	links = append(links, "## daily_archive")
	archives, _ := filepath.Glob("daily_archive/*")
	sort.Strings(archives)
	for _, arch := range archives {
		stat, _ := os.Stat(arch)
		if stat != nil && stat.IsDir() {
			subDir := filepath.Base(arch)
			links = append(links, fmt.Sprintf("### %s", subDir))
			innerFiles, _ := filepath.Glob(filepath.Join(arch, "*.txt"))
			for _, f := range innerFiles {
				name := filepath.Base(f)
				url := fmt.Sprintf("%s/daily_archive/%s/%s", baseURL, subDir, name)
				links = append(links, fmt.Sprintf("  - [%s](%s)", name, url))
			}
		}
	}
	links = append(links, "")

	// mixed
	links = append(links, "## mixed")
	mixedFiles, _ := filepath.Glob("mixed/*.txt")
	for _, f := range mixedFiles {
		name := filepath.Base(f)
		url := fmt.Sprintf("%s/mixed/%s", baseURL, name)
		links = append(links, fmt.Sprintf("- [%s](%s)", name, url))
	}
	links = append(links, "")

	// subscription
	links = append(links, "## subscription")
	subFiles, _ := filepath.Glob("subscription/*.txt")
	for _, f := range subFiles {
		name := filepath.Base(f)
		url := fmt.Sprintf("%s/subscription/%s", baseURL, name)
		links = append(links, fmt.Sprintf("- [%s](%s)", name, url))
	}
	links = append(links, "")

	// telegram
	links = append(links, "## telegram")
	channels, _ := filepath.Glob("telegram/*")
	sort.Strings(channels)
	for _, ch := range channels {
		stat, _ := os.Stat(ch)
		if stat != nil && stat.IsDir() {
			chName := filepath.Base(ch)
			links = append(links, fmt.Sprintf("### %s", chName))
			chFiles, _ := filepath.Glob(filepath.Join(ch, "*.txt"))
			for _, f := range chFiles {
				name := filepath.Base(f)
				url := fmt.Sprintf("%s/telegram/%s/%s", baseURL, chName, name)
				links = append(links, fmt.Sprintf("  - [%s](%s)", name, url))
			}
		}
	}
	os.WriteFile("links.txt", []byte(strings.Join(links, "\n")), 0644)
	gologger.Info().Msg("links.txt generated")
}

// ==================== Clash YAML ====================
type ClashProxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	UUID     string `yaml:"uuid,omitempty"`
	Password string `yaml:"password,omitempty"`
	Cipher   string `yaml:"cipher,omitempty"`
	Network  string `yaml:"network,omitempty"`
	TLS      bool   `yaml:"tls,omitempty"`
	Sni      string `yaml:"sni,omitempty"`
}

func generateClashYAML() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	var proxies []ClashProxy
	count := 0
	for cfg, e := range configCache {
		proto := detectProtocol(cfg)
		var cp *ClashProxy
		switch proto {
		case "vmess":
			cp = vmessToClash(cfg, e.Source)
		case "ss":
			cp = ssToClash(cfg)
		case "trojan":
			cp = trojanToClash(cfg)
		case "vless":
			cp = vlessToClash(cfg)
		default:
			continue
		}
		if cp != nil {
			proxies = append(proxies, *cp)
			count++
		}
		if count >= 2000 {
			break
		}
	}
	if len(proxies) == 0 {
		return
	}
	proxyNames := make([]string, len(proxies))
	for i, p := range proxies {
		proxyNames[i] = p.Name
	}
	clashConfig := struct {
		Proxies     []ClashProxy `yaml:"proxies"`
		ProxyGroups []any        `yaml:"proxy-groups"`
		Rules       []string     `yaml:"rules"`
	}{
		Proxies: proxies,
		ProxyGroups: []any{
			map[string]any{"name": "PROXY", "type": "select", "proxies": append([]string{"IRAN", "DIRECT"}, proxyNames...)},
			map[string]any{"name": "IRAN", "type": "fallback", "proxies": proxyNames, "url": "http://www.gstatic.com/generate_204", "interval": 300},
		},
		Rules: []string{"GEOIP,IRAN,IRAN", "MATCH,PROXY"},
	}
	data, _ := yaml.Marshal(&clashConfig)
	os.WriteFile("clash-config.yaml", data, 0644)
}

func vmessToClash(vmessURL, source string) *ClashProxy {
	parts := strings.SplitN(vmessURL, "vmess://", 2)
	if len(parts) != 2 {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var data map[string]interface{}
	json.Unmarshal(decoded, &data)
	server, _ := data["add"].(string)
	portRaw, _ := data["port"].(string)
	port, _ := strconv.Atoi(portRaw)
	uuid, _ := data["id"].(string)
	cipher, _ := data["scy"].(string)
	if cipher == "" {
		cipher = "auto"
	}
	net, _ := data["net"].(string)
	tlsVal, _ := data["tls"].(string)
	tls := tlsVal == "tls"
	sni, _ := data["sni"].(string)
	name := fmt.Sprintf("%s_%s_%d", source, server, port)
	return &ClashProxy{Name: name, Type: "vmess", Server: server, Port: port, UUID: uuid, Cipher: cipher, Network: net, TLS: tls, Sni: sni}
}

func ssToClash(ssURL string) *ClashProxy {
	if !strings.HasPrefix(ssURL, "ss://") {
		return nil
	}
	withoutScheme := strings.TrimPrefix(ssURL, "ss://")
	atIdx := strings.Index(withoutScheme, "@")
	if atIdx == -1 {
		return nil
	}
	userinfoB64 := withoutScheme[:atIdx]
	rest := withoutScheme[atIdx+1:]
	colonIdx := strings.LastIndex(rest, ":")
	if colonIdx == -1 {
		return nil
	}
	server := rest[:colonIdx]
	portStr := rest[colonIdx+1:]
	port, _ := strconv.Atoi(portStr)
	userinfo, err := base64.StdEncoding.DecodeString(userinfoB64)
	if err != nil {
		return nil
	}
	parts := strings.SplitN(string(userinfo), ":", 2)
	if len(parts) != 2 {
		return nil
	}
	method, password := parts[0], parts[1]
	name := fmt.Sprintf("ss_%s_%d", server, port)
	return &ClashProxy{Name: name, Type: "ss", Server: server, Port: port, Cipher: method, Password: password}
}

func trojanToClash(trojanURL string) *ClashProxy {
	if !strings.HasPrefix(trojanURL, "trojan://") {
		return nil
	}
	withoutScheme := strings.TrimPrefix(trojanURL, "trojan://")
	atIdx := strings.Index(withoutScheme, "@")
	if atIdx == -1 {
		return nil
	}
	password := withoutScheme[:atIdx]
	rest := withoutScheme[atIdx+1:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx == -1 {
		return nil
	}
	server := rest[:colonIdx]
	restAfterPort := rest[colonIdx+1:]
	questionIdx := strings.Index(restAfterPort, "?")
	var portStr string
	if questionIdx != -1 {
		portStr = restAfterPort[:questionIdx]
	} else {
		portStr = restAfterPort
	}
	port, _ := strconv.Atoi(portStr)
	name := fmt.Sprintf("trojan_%s_%d", server, port)
	return &ClashProxy{Name: name, Type: "trojan", Server: server, Port: port, Password: password}
}

func vlessToClash(vlessURL string) *ClashProxy {
	if !strings.HasPrefix(vlessURL, "vless://") {
		return nil
	}
	withoutScheme := strings.TrimPrefix(vlessURL, "vless://")
	atIdx := strings.Index(withoutScheme, "@")
	if atIdx == -1 {
		return nil
	}
	uuid := withoutScheme[:atIdx]
	rest := withoutScheme[atIdx+1:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx == -1 {
		return nil
	}
	server := rest[:colonIdx]
	restAfterPort := rest[colonIdx+1:]
	questionIdx := strings.Index(restAfterPort, "?")
	var portStr string
	if questionIdx != -1 {
		portStr = restAfterPort[:questionIdx]
	} else {
		portStr = restAfterPort
	}
	port, _ := strconv.Atoi(portStr)
	params := make(map[string]string)
	if questionIdx != -1 {
		query := restAfterPort[questionIdx+1:]
		for _, pair := range strings.Split(query, "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = kv[1]
			}
		}
	}
	security := params["security"]
	tls := security == "tls" || security == "reality"
	sni := params["sni"]
	name := fmt.Sprintf("vless_%s_%d", server, port)
	return &ClashProxy{Name: name, Type: "vless", Server: server, Port: port, UUID: uuid, TLS: tls, Sni: sni}
}

// ==================== توابع کمکی ====================
func testSampleConfigs() {
	gologger.Info().Msg("Test feature not implemented")
}

func printStats() {
	stats.Lock()
	defer stats.Unlock()
	gologger.Info().Msg("========== STATISTICS ==========")
	gologger.Info().Msgf("Total configs: %d", len(configCache))
	gologger.Info().Msgf("New: %d", stats.newCount)
	gologger.Info().Msgf("Telegram: %d, Subscription: %d", stats.telegramCount, stats.subCount)
	gologger.Info().Msg("Protocols:")
	for p, c := range stats.protoCounts {
		gologger.Info().Msgf("  %s: %d", p, c)
	}
	statFile, _ := json.MarshalIndent(map[string]interface{}{
		"total": len(configCache), "new": stats.newCount,
		"telegram": stats.telegramCount, "subscription": stats.subCount,
		"protocols": stats.protoCounts,
	}, "", "  ")
	os.WriteFile("stats.json", statFile, 0644)
}

func HttpRequest(url string) *http.Response {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	return resp
}
