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
	"github.com/mrvcoder/V2rayCollector/collector"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"gopkg.in/yaml.v3"
)

// ========================== تنظیمات ==========================
const (
	MaxConfigsPerProtocol = 50000
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

	cacheMutex sync.RWMutex
	configCache = make(map[string]CacheEntry)

	// ساختار جدید برای ذخیره کانفیگ‌های تلگرام به تفکیک کانال
	telegramByChannel = make(map[string]map[string][]string) // channel -> protocol -> []configs
	subConfigs        = make(map[string][]string)            // protocol -> []configs (برای ساب‌لینک)

	stats = struct {
		sync.Mutex
		telegramCount, subCount, newCount, duplicateCount int
		protoCounts map[string]int
	}{
		protoCounts: make(map[string]int),
	}

	lastArchiveDate string
	shutdownChan    = make(chan os.Signal, 1)
)

type CacheEntry struct {
	Timestamp   int64  `json:"timestamp"`
	Source      string `json:"source"` // "telegram" or "subscription"
	Fingerprint string `json:"fingerprint,omitempty"`
	Channel     string `json:"channel,omitempty"` // نام کانال تلگرام (برای Telegram)
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

// ========================== توابع اصلی ==========================
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
	writeOutputFiles()

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
	gologger.Info().Msg("All Done! Program finished successfully.")
}

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
	dirs := []string{"telegram", "subscription", "mixed", "daily"}
	for _, d := range dirs {
		os.MkdirAll(d, 0755)
	}
}

func registerSignalHandler() {
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdownChan
		gologger.Warning().Msg("Received shutdown signal, saving cache...")
		saveCache()
		os.Exit(0)
	}()
}

// ========================== مدیریت Cache ==========================
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

	data, err := json.MarshalIndent(cd, "", "  ")
	if err != nil {
		gologger.Error().Msgf("Failed to marshal cache: %v", err)
		return
	}
	if err = os.WriteFile("config_cache.json", data, 0644); err != nil {
		gologger.Error().Msgf("Failed to write cache: %v", err)
	}
}

func updateCache() {
	now := time.Now().Unix()
	newCount := 0
	dupCount := 0

	addIfNew := func(cfg, source, channel string) {
		if cfg == "" {
			return
		}
		cacheMutex.Lock()
		defer cacheMutex.Unlock()

		if *dedupFlag && strings.HasPrefix(cfg, "vmess://") {
			fp := fingerprintVmess(cfg)
			for existingCfg, entry := range configCache {
				if entry.Fingerprint == fp && entry.Fingerprint != "" && existingCfg != cfg {
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
		configCache[cfg] = CacheEntry{
			Timestamp:   now,
			Source:      source,
			Fingerprint: fp,
			Channel:     channel,
		}
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

	// تلگرام: کانفیگ‌های ذخیره شده در telegramByChannel
	for channel, protoMap := range telegramByChannel {
		for _, cfgList := range protoMap {
			for _, cfg := range cfgList {
				addIfNew(cfg, "telegram", channel)
			}
		}
	}
	// ساب‌لینک‌ها
	for _, cfgList := range subConfigs {
		for _, cfg := range cfgList {
			addIfNew(cfg, "subscription", "")
		}
	}

	gologger.Info().Msgf("Cache update: %d new, %d duplicate configs ignored.", newCount, dupCount)
}

func pruneCacheByProtocol() {
	groups := make(map[string][]struct {
		key string
		ts  int64
	})
	cacheMutex.RLock()
	for cfg, entry := range configCache {
		proto := detectProtocol(cfg)
		groups[proto] = append(groups[proto], struct {
			key string
			ts  int64
		}{cfg, entry.Timestamp})
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
			it := items[i]
			newCache[it.key] = configCache[it.key]
		}
		gologger.Info().Msgf("Pruned %s: kept %d out of %d", proto, MaxConfigsPerProtocol, len(items))
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

// ========================== دریافت منابع ==========================
func fetchAllTelegramChannels() {
	fileData, err := collector.ReadFileContent("channels.csv")
	if err != nil {
		gologger.Warning().Msg("channels.csv not found, skipping Telegram crawling.")
		return
	}
	var channels []ChannelsType
	if err = csvutil.Unmarshal([]byte(fileData), &channels); err != nil {
		gologger.Warning().Msgf("Error parsing channels.csv: %v", err)
		return
	}

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
			gologger.Warning().Msgf("Cannot extract channel name from %s", url)
			continue
		}
		resp := HttpRequest(url)
		if resp == nil {
			continue
		}
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		if err != nil {
			gologger.Error().Msgf("Failed to parse %s: %v", url, err)
			continue
		}
		doc.Url = resp.Request.URL
		gologger.Info().Msgf("Crawling Telegram: %s (channel: %s)", url, channelName)

		allTexts := getAllMessages(doc, *maxMessages)
		for _, text := range allTexts {
			processTelegramText(text, channelName)
		}
	}
}

// استخراج نام کانال از آدرس t.me
func extractChannelNameFromURL(url string) string {
	// نمونه: https://t.me/FreeV2rays یا https://t.me/s/FreeV2rays
	re := regexp.MustCompile(`t\.me/(?:s/)?([^/?]+)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		return matches[1]
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
		if len(parts) < 2 {
			break
		}
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
		gologger.Error().Msgf("loadMore error: %v", err)
		return nil
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		gologger.Error().Msgf("parse error: %v", err)
		return nil
	}
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
		// ذخیره در نقشه تفکیک شده بر اساس کانال
		if telegramByChannel[channelName] == nil {
			telegramByChannel[channelName] = make(map[string][]string)
		}
		telegramByChannel[channelName][proto] = append(telegramByChannel[channelName][proto], cfg)
	}
}

func fetchAllSubscriptions() {
	sourcesData, err := collector.ReadFileContent("Sources.json")
	if err != nil {
		gologger.Warning().Msg("Sources.json not found, skipping subscriptions.")
		return
	}
	var sources []string
	if err = json.Unmarshal([]byte(sourcesData), &sources); err != nil {
		gologger.Warning().Msgf("Error parsing Sources.json: %v", err)
		return
	}

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
		gologger.Info().Msgf("Fetching subscription: %s", src)
		fetchSubscription(src)
	}
}

func fetchSubscription(url string) {
	resp, err := http.Get(url)
	if err != nil {
		gologger.Error().Msgf("Failed to fetch %s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("Failed to read %s: %v", url, err)
		return
	}
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

func editVmessPs(config string, source string) string {
	parts := strings.SplitN(config, "vmess://", 2)
	if len(parts) != 2 {
		return config
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		gologger.Warning().Msgf("Failed to decode vmess: %v", err)
		return config
	}
	var data map[string]interface{}
	if err = json.Unmarshal(decoded, &data); err != nil {
		gologger.Warning().Msgf("Failed to unmarshal vmess: %v", err)
		return config
	}
	newName := fmt.Sprintf("%s-%d", source, time.Now().Unix())
	data["ps"] = newName
	jsonData, err := json.Marshal(data)
	if err != nil {
		return config
	}
	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return "vmess://" + encoded
}

func extractTextFromHTML(html string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return ""
	}
	return doc.Text()
}

// ========================== تولید فایل‌های خروجی ==========================
func writeOutputFiles() {
	writeTelegramPerChannel()
	writeMixedFromTelegram()
	writeSubscriptionFolder()
}

// نوشتن پوشه telegram با زیرپوشه‌های هر کانال
func writeTelegramPerChannel() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	// گروه‌بندی کانفیگ‌های تلگرام بر اساس کانال
	channelConfigs := make(map[string]map[string][]string) // channel -> proto -> []configs

	for cfg, entry := range configCache {
		if entry.Source == "telegram" && entry.Channel != "" {
			proto := detectProtocol(cfg)
			if channelConfigs[entry.Channel] == nil {
				channelConfigs[entry.Channel] = make(map[string][]string)
			}
			channelConfigs[entry.Channel][proto] = append(channelConfigs[entry.Channel][proto], cfg)
		}
	}

	// برای هر کانال، پوشه ایجاد کن و فایل‌های پروتکل را بنویس
	for channel, protoMap := range channelConfigs {
		channelDir := filepath.Join("telegram", channel)
		os.MkdirAll(channelDir, 0755)

		for proto, items := range protoMap {
			// اگر نیاز به مرتب‌سازی داریم
			if *sortFlag {
				// برای مرتب‌سازی نیاز به timestamp داریم، فعلاً ساده می‌گذاریم
				// می‌توانیم با ذخیره timestamp در struct بهتر کنیم، برای سادگی فعلاً بدون مرتب‌سازی
			}
			content := strings.Join(items, "\n")
			if content != "" {
				filePath := filepath.Join(channelDir, proto+"_iran.txt")
				collector.WriteToFile(content, filePath)
			}
		}
	}
}

// نوشتن پوشه mixed فقط از کانفیگ‌های تلگرام (همه کانال‌ها)
func writeMixedFromTelegram() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	protoItems := make(map[string][]string)

	for cfg, entry := range configCache {
		if entry.Source == "telegram" {
			proto := detectProtocol(cfg)
			protoItems[proto] = append(protoItems[proto], cfg)
		}
	}

	for proto, items := range protoItems {
		if *sortFlag {
			// در صورت نیاز به مرتب‌سازی بر اساس زمان، باید با timestamp انجام شود
			// فعلاً بدون مرتب‌سازی
		}
		content := strings.Join(items, "\n")
		if content != "" {
			filePath := filepath.Join("mixed", proto+"_iran.txt")
			collector.WriteToFile(content, filePath)
		}
	}
}

// نوشتن پوشه subscription فقط از ساب‌لینک‌ها
func writeSubscriptionFolder() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	subProto := make(map[string][]string)

	for cfg, entry := range configCache {
		if entry.Source == "subscription" {
			proto := detectProtocol(cfg)
			subProto[proto] = append(subProto[proto], cfg)
		}
	}

	for proto, items := range subProto {
		if *sortFlag {
			// مرتب‌سازی در صورت نیاز
		}
		content := strings.Join(items, "\n")
		if content != "" {
			filePath := filepath.Join("subscription", proto+"_iran.txt")
			collector.WriteToFile(content, filePath)
		}
	}
}

// ========================== آرشیو روزانه (فقط ۲۴ ساعت اخیر) ==========================
func archiveDaily() {
	today := time.Now().Format("2006-01-02")
	archiveDir := filepath.Join("daily", today)
	os.MkdirAll(archiveDir, 0755)

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	threshold := time.Now().Add(-24 * time.Hour).Unix()

	type item struct {
		cfg string
		ts  int64
	}
	byProto := make(map[string][]item)

	for cfg, entry := range configCache {
		if entry.Timestamp >= threshold {
			proto := detectProtocol(cfg)
			byProto[proto] = append(byProto[proto], item{cfg, entry.Timestamp})
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
			archivePath := filepath.Join(archiveDir, proto+"_iran.txt")
			os.WriteFile(archivePath, []byte(content), 0644)
		}
	}
	gologger.Info().Msgf("Daily archive created in %s with configs from last 24h", archiveDir)
}

// ========================== CLASH YAML GENERATION ==========================
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

	for cfg, entry := range configCache {
		proto := detectProtocol(cfg)
		var cp *ClashProxy
		switch proto {
		case "vmess":
			cp = vmessToClash(cfg, entry.Source)
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
		gologger.Warning().Msg("No proxies converted for Clash YAML.")
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
			map[string]any{
				"name":    "PROXY",
				"type":    "select",
				"proxies": append([]string{"IRAN", "DIRECT"}, proxyNames...),
			},
			map[string]any{
				"name":     "IRAN",
				"type":     "fallback",
				"proxies":  proxyNames,
				"url":      "http://www.gstatic.com/generate_204",
				"interval": 300,
			},
		},
		Rules: []string{
			"GEOIP,IRAN,IRAN",
			"MATCH,PROXY",
		},
	}

	data, err := yaml.Marshal(&clashConfig)
	if err != nil {
		gologger.Error().Msgf("Failed to marshal Clash YAML: %v", err)
		return
	}
	if err := os.WriteFile("clash-config.yaml", data, 0644); err != nil {
		gologger.Error().Msgf("Failed to write Clash YAML: %v", err)
	} else {
		gologger.Info().Msgf("Clash YAML generated with %d proxies: clash-config.yaml", len(proxies))
	}
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
	if err := json.Unmarshal(decoded, &data); err != nil {
		return nil
	}
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
	return &ClashProxy{
		Name:     name,
		Type:     "vmess",
		Server:   server,
		Port:     port,
		UUID:     uuid,
		Cipher:   cipher,
		Network:  net,
		TLS:      tls,
		Sni:      sni,
	}
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
	return &ClashProxy{
		Name:     name,
		Type:     "ss",
		Server:   server,
		Port:     port,
		Cipher:   method,
		Password: password,
	}
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
	return &ClashProxy{
		Name:     name,
		Type:     "trojan",
		Server:   server,
		Port:     port,
		Password: password,
	}
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
	return &ClashProxy{
		Name:     name,
		Type:     "vless",
		Server:   server,
		Port:     port,
		UUID:     uuid,
		TLS:      tls,
		Sni:      sni,
	}
}

// ========================== توابع کمکی و تست ==========================
func testSampleConfigs() {
	gologger.Info().Msg("Testing a sample of configs (first 10 from each protocol)...")
	gologger.Info().Msg("Test feature not fully implemented in this example.")
}

func printStats() {
	stats.Lock()
	defer stats.Unlock()
	gologger.Info().Msg("========== STATISTICS ==========")
	gologger.Info().Msgf("Total configs in cache: %d", len(configCache))
	gologger.Info().Msgf("New configs added: %d", stats.newCount)
	gologger.Info().Msgf("Telegram sources: %d configs", stats.telegramCount)
	gologger.Info().Msgf("Subscription sources: %d configs", stats.subCount)
	gologger.Info().Msg("Configs per protocol:")
	for proto, count := range stats.protoCounts {
		gologger.Info().Msgf("  %s: %d", proto, count)
	}
	gologger.Info().Msg("================================")

	statFile, _ := json.MarshalIndent(map[string]interface{}{
		"total":        len(configCache),
		"new":          stats.newCount,
		"telegram":     stats.telegramCount,
		"subscription": stats.subCount,
		"protocols":    stats.protoCounts,
	}, "", "  ")
	os.WriteFile("stats.json", statFile, 0644)
}

func HttpRequest(url string) *http.Response {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		gologger.Error().Msgf("HTTP request failed: %v", err)
		return nil
	}
	return resp
}
