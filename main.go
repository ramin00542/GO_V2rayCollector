package main

import (
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"golang.org/x/time/rate"
)

// ---------- تنظیمات ثابت ----------
const (
	MaxConfigsPerProtocol            = 50000
	MaxSubscriptionResponseSize      = 50 * 1024 * 1024
	RequestTimeout                   = 30 * time.Second
	CacheTTL                         = 30 * 24 * time.Hour
	RetryCount                       = 3
	RetryBackoff                     = 2 * time.Second
	TelegramRequestsPerSecond        = 5
	TelegramBurstSize                = 10
	HealthCheckTimeout               = 5 * time.Second
	HealthCheckConcurrency           = 10
	GitHubTokenEnv                   = "GITHUB_TOKEN"
	ForksPerPage                     = 100
	DefaultTargetRepo                = "mahsanet/MahsaFreeConfig"
)

var (
	// Flags
	sortFlag      = flag.Bool("sort", false, "sort configs from latest to oldest")
	dedupFlag     = flag.Bool("dedup", true, "enable advanced deduplication (fingerprint-based)")
	testFlag      = flag.Bool("test", false, "print total configs count (simple test)")
	concurrent    = flag.Int("concurrent", 3, "number of concurrent workers")
	maxMessages   = flag.Int("max-msgs", 100, "max messages per Telegram channel")
	clashFlag     = flag.Bool("clash", false, "generate Clash YAML")
	singboxFlag   = flag.Bool("singbox", false, "generate sing-box JSON")
	proxyURL      = flag.String("proxy", "", "HTTP/HTTPS proxy URL")
	baseURL       = flag.String("base-url", "", "base URL for links.md (overrides GitHub detection)")
	healthCheck   = flag.Bool("health-check", false, "perform health check")
	channelsFile  = flag.String("channels", "channels.csv", "Telegram channels CSV file")
	sourcesFile   = flag.String("sources", "Sources.json", "Subscription sources JSON file")
	timeout       = flag.Duration("timeout", RequestTimeout, "HTTP request timeout")
	mixedAge      = flag.Duration("mixed-age", 24*time.Hour, "age limit for mixed output (0 = all)")
	forkScan      = flag.Bool("fork-scan", true, "scan GitHub forks for subscription links")
	targetRepo    = flag.String("target-repo", DefaultTargetRepo, "GitHub repo to scan forks from")
	telegramToken = flag.String("telegram-token", "", "Bot token for sending reports (or use env TELEGRAM_BOT_TOKEN)")
	telegramChat  = flag.String("telegram-chat", "", "Chat ID for reports (or use env TELEGRAM_CHAT_ID)")

	// داخلی
	combinedRegex   *regexp.Regexp
	subLinkRegex    *regexp.Regexp
	protoList       = []string{"vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic", "wireguard", "mtproto", "slipnet", "http", "socks"}
	httpClient      *http.Client
	shutdownChan    = make(chan os.Signal, 1)
	globalCtx       context.Context
	cancelFunc      context.CancelFunc
	telegramLimiter *rate.Limiter

	cacheMutex       sync.RWMutex
	configCache      = make(map[string]CacheEntry)
	fingerprintToKey = make(map[string]string)
	keyToFingerprint = make(map[string]string)
	fpMutex          sync.RWMutex
	mainWg           sync.WaitGroup

	lastArchiveTime  int64
	archiveTimeMutex sync.RWMutex
	archiveTimeFile  = "last_archive_time.txt"

	stats = struct {
		sync.Mutex
		telegramCount, subCount, newCount, duplicateCount, insecureCount int
		protoCounts                                                      map[string]int
	}{protoCounts: make(map[string]int)}
	insecureConfigs []string
)

type CacheEntry struct {
	Timestamp   int64  `json:"timestamp"`
	Source      string `json:"source"`
	Fingerprint string `json:"fingerprint"`
	Channel     string `json:"channel,omitempty"`
	Original    string `json:"original,omitempty"`
	Protocol    string `json:"protocol"`
	Insecure    bool   `json:"insecure,omitempty"`
}

type CacheData struct {
	Configs   map[string]CacheEntry `json:"configs"`
	Timestamp int64                 `json:"timestamp"`
}

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

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

// ---------- تابع تبدیل پروتکل به نام فایل با ایموجی ----------
func protocolFileName(proto string) string {
	switch proto {
	case "vmess":
		return "🔵 VMess"
	case "vless":
		return "🟢 VLess"
	case "trojan":
		return "🔒 Trojan"
	case "ss":
		return "⚡ Shadowsocks"
	case "ssr":
		return "✨ SSR"
	case "hysteria2":
		return "🌀 Hysteria2"
	case "tuic":
		return "🟦 Tuic"
	case "wireguard":
		return "🔹 WireGuard"
	case "mixed":
		return "🌍 Mixed"
	case "mtproto":
		return "🟣 MTProto"
	case "http":
		return "🟠 HTTP Proxy"
	case "socks":
		return "🟡 SOCKS Proxy"
	default:
		return proto
	}
}

// ---------- MAIN ----------
func main() {
	flag.Parse()
	initCombinedRegex()
	initSubLinkRegex()
	setupLogging()
	createDirs()
	os.MkdirAll("reports", 0755) // پوشه گزارش‌ها
	os.MkdirAll("data", 0755)     // هماهنگی با اسکنرها
	initHTTPClient()
	loadCache()
	initLastArchiveTime()
	initTelegramLimiter()
	registerSignalHandler()

	globalCtx, cancelFunc = context.WithCancel(context.Background())
	defer cancelFunc()

	mainWg.Add(1)
	go func() {
		defer mainWg.Done()
		fetchAllTelegramChannels(globalCtx)
	}()
	mainWg.Add(1)
	go func() {
		defer mainWg.Done()
		fetchAllSubscriptions(globalCtx)
	}()
	if *forkScan {
		mainWg.Add(1)
		go func() {
			defer mainWg.Done()
			fetchFromGitHubForks(globalCtx)
		}()
	}
	mainWg.Wait()

	pruneCacheByTTL()
	pruneCacheByProtocol()

	writeOutputFiles()
	writeAllConfigs()
	archiveDaily()

	generateLinksFile()
	writeStatsFile()
	writeSubscriptionLinksFile()

	if *healthCheck && len(configCache) > 0 {
		performHealthCheck()
	}
	if *clashFlag {
		generateClashYAML()
	}
	if *singboxFlag {
		generateSingBoxJSON()
	}
	if *testFlag {
		testSampleConfigs()
	}
	printStats()
	saveCache()
	saveLastArchiveTime()
	sendTelegramReport()

	gologger.Info().Msg("All Done!")
}

func initTelegramLimiter() {
	telegramLimiter = rate.NewLimiter(rate.Limit(TelegramRequestsPerSecond), TelegramBurstSize)
}

// ---------- آرشیو روزانه ----------
func archiveDaily() {
	today := time.Now().Format("2006-01-02")
	archiveDir := filepath.Join("daily_archive", today)
	markerFile := filepath.Join(archiveDir, ".done")

	if _, err := os.Stat(markerFile); err == nil {
		gologger.Debug().Msg("Already archived today, skipping")
		return
	}
	os.MkdirAll(archiveDir, 0755)

	mixedFiles, _ := filepath.Glob("mixed/*.txt")
	for _, src := range mixedFiles {
		dest := filepath.Join(archiveDir, filepath.Base(src))
		data, _ := os.ReadFile(src)
		if len(data) > 0 {
			os.WriteFile(dest, data, 0644)
		}
	}
	copyDir("subscription", filepath.Join(archiveDir, "subscription"))
	copyDir("telegram", filepath.Join(archiveDir, "telegram"))

	os.WriteFile(markerFile, []byte("archived"), 0644)
	gologger.Info().Msgf("Archived mixed, subscription, telegram to %s", archiveDir)
}

func copyDir(src, dst string) {
	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		destPath := filepath.Join(dst, rel)
		if info.IsDir() {
			os.MkdirAll(destPath, info.Mode())
			return nil
		}
		data, _ := os.ReadFile(path)
		os.WriteFile(destPath, data, info.Mode())
		return nil
	})
}

// ---------- توابع اولیه ----------
func initCombinedRegex() {
	patterns := []string{
		`vmess://[A-Za-z0-9+/]+={0,2}(?:\?[^\s]*)?`,
		`vless://[^\s]+`,
		`trojan://[^@\s]+@[^\s]+`,
		`ss://[A-Za-z0-9+/]+={0,2}@[^\s]+`,
		`ssr://[A-Za-z0-9+/=]+`,
		`hysteria2://[^\s]+`,
		`tuic://[^\s]+`,
		`wireguard://[^\s]+`,
		`tg://proxy\?[^\s]+`,
		`(?:slipnet|slip)://[^\s]+`,
		`https?://[^\s]+:\d+(?:[^\s]*)?`,
		`https?://[^@\s]+@[^\s]+`,
		`socks(?:5)?://[^\s]+@[^\s]+`,
		`socks(?:5)?://[^\s]+:\d+`,
	}
	combined := strings.Join(patterns, "|")
	var err error
	combinedRegex, err = regexp.Compile(combined)
	if err != nil {
		panic(err)
	}
}

func initSubLinkRegex() {
	patterns := []string{
		`https?://[^\s"'<>]+\.(txt|json|yaml|yml|conf|cfg|sub|link)(?:\?[^\s]*)?`,
		`https?://[^\s"'<>]+/(?:sub|subscribe|config|list|subscription)[^\s]*`,
	}
	combined := strings.Join(patterns, "|")
	subLinkRegex = regexp.MustCompile(combined)
}

func setupLogging() {
	if os.Getenv("DEBUG") == "true" {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}
}

func createDirs() {
	dirs := []string{"telegram", "subscription", "mixed", "daily_archive", "all_configs"}
	for _, d := range dirs {
		os.MkdirAll(d, 0755)
	}
	os.MkdirAll(filepath.Join("all_configs", "subscription"), 0755)
	os.MkdirAll(filepath.Join("all_configs", "telegram"), 0755)
}

func initHTTPClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if *proxyURL != "" {
		proxy, err := url.Parse(*proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxy)
			gologger.Info().Msgf("Using proxy: %s", proxy.Redacted())
		}
	} else if envProxy := os.Getenv("HTTP_PROXY"); envProxy != "" {
		if proxy, err := url.Parse(envProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}
	httpClient = &http.Client{
		Timeout:   *timeout,
		Transport: transport,
	}
}

func registerSignalHandler() {
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdownChan
		gologger.Info().Msg("Shutting down gracefully...")
		cancelFunc()
		mainWg.Wait()
		saveCache()
		saveLastArchiveTime()
		sendTelegramReport()
		gologger.Info().Msg("Clean shutdown complete.")
		os.Exit(0)
	}()
}

// ---------- مدیریت Cache ----------
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
	cacheMutex.Unlock()

	if *dedupFlag {
		fpMutex.Lock()
		for key, ent := range cd.Configs {
			if ent.Fingerprint != "" {
				fingerprintToKey[ent.Fingerprint] = key
				keyToFingerprint[key] = ent.Fingerprint
			}
		}
		fpMutex.Unlock()
	}
	gologger.Info().Msgf("Loaded %d configs from cache", len(configCache))
}

func saveCache() {
	cacheMutex.RLock()
	cd := CacheData{
		Configs:   configCache,
		Timestamp: time.Now().Unix(),
	}
	cacheMutex.RUnlock()

	data, err := json.MarshalIndent(cd, "", "  ")
	if err != nil {
		gologger.Error().Msgf("Failed to marshal cache: %v", err)
		return
	}
	tmpFile := "config_cache.json.tmp"
	os.WriteFile(tmpFile, data, 0644)
	os.Remove("config_cache.json")
	os.Rename(tmpFile, "config_cache.json")
}

func deleteConfigEntry(key string) {
	if *dedupFlag {
		fpMutex.Lock()
		if fp, ok := keyToFingerprint[key]; ok {
			delete(fingerprintToKey, fp)
			delete(keyToFingerprint, key)
		}
		fpMutex.Unlock()
	}
	delete(configCache, key)
}

func pruneCacheByTTL() {
	cutoff := time.Now().Add(-CacheTTL).Unix()
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	toDelete := []string{}
	for cfg, ent := range configCache {
		if ent.Timestamp < cutoff {
			toDelete = append(toDelete, cfg)
		}
	}
	for _, cfg := range toDelete {
		deleteConfigEntry(cfg)
	}
	if len(toDelete) > 0 {
		gologger.Info().Msgf("Pruned %d configs older than %v", len(toDelete), CacheTTL)
	}
}

func pruneCacheByProtocol() {
	groups := make(map[string][]struct {
		key string
		ts  int64
	})
	cacheMutex.RLock()
	for cfg, e := range configCache {
		proto := e.Protocol
		if proto == "" {
			proto = detectProtocol(cfg)
		}
		groups[proto] = append(groups[proto], struct {
			key string
			ts  int64
		}{cfg, e.Timestamp})
	}
	cacheMutex.RUnlock()

	newKeys := make(map[string]bool)
	for proto, items := range groups {
		if len(items) <= MaxConfigsPerProtocol {
			for _, it := range items {
				newKeys[it.key] = true
			}
			continue
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		for i := 0; i < MaxConfigsPerProtocol; i++ {
			newKeys[items[i].key] = true
		}
		gologger.Info().Msgf("Pruned %s: kept %d (from %d)", proto, MaxConfigsPerProtocol, len(items))
	}

	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	for cfg := range configCache {
		if !newKeys[cfg] {
			deleteConfigEntry(cfg)
		}
	}
}

func detectProtocol(cfg string) string {
	for _, proto := range protoList {
		if strings.HasPrefix(cfg, proto+"://") {
			return proto
		}
	}
	switch {
	case strings.HasPrefix(cfg, "vmess://"):
		return "vmess"
	case strings.HasPrefix(cfg, "vless://"):
		return "vless"
	case strings.HasPrefix(cfg, "trojan://"):
		return "trojan"
	case strings.HasPrefix(cfg, "ss://"):
		return "ss"
	case strings.HasPrefix(cfg, "ssr://"):
		return "ssr"
	case strings.HasPrefix(cfg, "hysteria2://"):
		return "hysteria2"
	case strings.HasPrefix(cfg, "tuic://"):
		return "tuic"
	case strings.HasPrefix(cfg, "wireguard://"):
		return "wireguard"
	case strings.HasPrefix(cfg, "tg://"):
		return "mtproto"
	case strings.HasPrefix(cfg, "slipnet://") || strings.HasPrefix(cfg, "slip://"):
		return "slipnet"
	case strings.HasPrefix(cfg, "http://") || strings.HasPrefix(cfg, "https://"):
		return "http"
	case strings.HasPrefix(cfg, "socks://") || strings.HasPrefix(cfg, "socks5://"):
		return "socks"
	}
	return "mixed"
}

// ---------- فیلتر امنیت ----------
func isSecureConfig(cfg string, proto string) bool {
	switch proto {
	case "vmess":
		return isVmessSecure(cfg)
	case "vless":
		return isVlessSecure(cfg)
	default:
		return true
	}
}

func isVmessSecure(vmessUrl string) bool {
	parts := strings.SplitN(vmessUrl, "vmess://", 2)
	if len(parts) != 2 {
		return true
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var data map[string]interface{}
	if err := json.Unmarshal(decoded, &data); err != nil {
		return true
	}
	tlsVal, _ := data["tls"].(string)
	if tlsVal == "" {
		return true
	}
	if tlsVal != "tls" && tlsVal != "xtls" {
		return false
	}
	insecure, _ := data["allowInsecure"].(bool)
	return !insecure
}

func isVlessSecure(vlessUrl string) bool {
	u, err := url.Parse(vlessUrl)
	if err != nil {
		return true
	}
	security := u.Query().Get("security")
	allowInsecure := u.Query().Get("allowInsecure")
	if security == "" || security == "none" {
		return false
	}
	return allowInsecure != "1" && allowInsecure != "true"
}

// ---------- افزودن به کش ----------
func addToCache(cfg, source, channel string) {
	if cfg == "" {
		return
	}
	cfg = strings.TrimSpace(cfg)
	proto := detectProtocol(cfg)

	if !isSecureConfig(cfg, proto) {
		stats.Lock()
		stats.insecureCount++
		stats.Unlock()
		if len(insecureConfigs) < 10 {
			insecureConfigs = append(insecureConfigs, cfg[:min(60, len(cfg))])
		}
		return
	}

	fp := computeFingerprint(cfg, proto)

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if *dedupFlag && fp != "" {
		fpMutex.RLock()
		existingKey, found := fingerprintToKey[fp]
		fpMutex.RUnlock()
		if found && existingKey != cfg {
			stats.Lock()
			stats.duplicateCount++
			stats.Unlock()
			return
		}
	}
	if _, exists := configCache[cfg]; exists {
		stats.Lock()
		stats.duplicateCount++
		stats.Unlock()
		return
	}

	configCache[cfg] = CacheEntry{
		Timestamp:   time.Now().Unix(),
		Source:      source,
		Fingerprint: fp,
		Channel:     channel,
		Original:    cfg,
		Protocol:    proto,
	}
	if *dedupFlag && fp != "" {
		fpMutex.Lock()
		fingerprintToKey[fp] = cfg
		keyToFingerprint[cfg] = fp
		fpMutex.Unlock()
	}
	stats.Lock()
	stats.newCount++
	if source == "telegram" {
		stats.telegramCount++
	} else {
		stats.subCount++
	}
	stats.protoCounts[proto]++
	stats.Unlock()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func computeFingerprint(cfg, proto string) string {
	if !*dedupFlag {
		return ""
	}
	switch proto {
	case "vmess":
		return fingerprintVmess(cfg)
	case "vless", "trojan", "ss", "ssr", "hysteria2", "tuic":
		return fingerprintCredentialURL(cfg)
	default:
		re := regexp.MustCompile(`#.*$`)
		cleaned := re.ReplaceAllString(cfg, "")
		hash := md5.Sum([]byte(cleaned))
		return fmt.Sprintf("%x", hash)
	}
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
	add := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s:%s",
		getStringField(data, "add"), getStringField(data, "port"), getStringField(data, "id"),
		getStringField(data, "net"), getStringField(data, "type"), getStringField(data, "host"),
		getStringField(data, "path"), getStringField(data, "tls"), getStringField(data, "sni"))
	hash := md5.Sum([]byte(add))
	return fmt.Sprintf("%x", hash)
}

func fingerprintCredentialURL(cfg string) string {
	u, err := url.Parse(cfg)
	if err != nil {
		hash := md5.Sum([]byte(cfg))
		return fmt.Sprintf("%x", hash)
	}
	userPass := ""
	if u.User != nil {
		userPass = u.User.String()
	}
	host := u.Hostname()
	port := u.Port()
	hash := md5.Sum([]byte(host + ":" + port + ":" + userPass))
	return fmt.Sprintf("%x", hash)
}

func getStringField(data map[string]interface{}, field string) string {
	if val, ok := data[field]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// ---------- مدیریت آخرین زمان آرشیو ----------
func loadLastArchiveTime() {
	data, err := os.ReadFile(archiveTimeFile)
	if err != nil {
		lastArchiveTime = 0
		return
	}
	val, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		lastArchiveTime = 0
		return
	}
	lastArchiveTime = val
}

func initLastArchiveTime() {
	loadLastArchiveTime()
	if lastArchiveTime == 0 {
		cacheMutex.RLock()
		minTs := int64(1<<63 - 1)
		for _, e := range configCache {
			if e.Timestamp < minTs {
				minTs = e.Timestamp
			}
		}
		cacheMutex.RUnlock()
		if minTs != int64(1<<63-1) {
			lastArchiveTime = minTs
		} else {
			lastArchiveTime = 0
		}
	}
}

func saveLastArchiveTime() {
	archiveTimeMutex.RLock()
	ts := lastArchiveTime
	archiveTimeMutex.RUnlock()
	if err := os.WriteFile(archiveTimeFile, []byte(fmt.Sprintf("%d", ts)), 0644); err != nil {
		gologger.Warning().Msgf("Failed to save archive time: %v", err)
	}
}

// ---------- دریافت تلگرام (ادب‌دار) ----------
func fetchAllTelegramChannels(ctx context.Context) {
	fileData, err := os.ReadFile(*channelsFile)
	if err != nil {
		gologger.Warning().Msgf("channels.csv not found (%s), skipping Telegram.", *channelsFile)
		return
	}
	var channels []ChannelsType
	if err := csvutil.Unmarshal(fileData, &channels); err != nil {
		gologger.Error().Msgf("Failed to parse channels.csv: %v", err)
		return
	}
	for _, ch := range channels {
		select {
		case <-ctx.Done():
			return
		default:
		}
		channelName := extractChannelNameFromURL(ch.URL)
		if channelName == "" {
			continue
		}
		webURL := fmt.Sprintf("https://t.me/s/%s", channelName)
		if err := fetchTelegramSimple(ctx, webURL, channelName); err != nil {
			gologger.Warning().Msgf("Failed to fetch %s: %v", webURL, err)
		}
		jitter := time.Duration(2+rand.Intn(4)) * time.Second
		time.Sleep(jitter)
	}
}

func fetchTelegramSimple(ctx context.Context, url, channelName string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return err
	}
	var texts []string
	doc.Find(".tgme_widget_message_text, pre, code").Each(func(i int, s *goquery.Selection) {
		plain := strings.TrimSpace(s.Text())
		if plain != "" {
			texts = append(texts, plain)
		}
	})
	for _, text := range texts {
		configs := extractAllConfigs(text)
		for _, cfg := range configs {
			cfg = strings.TrimSpace(cfg)
			if cfg != "" {
				addToCache(cfg, "telegram", channelName)
			}
		}
	}
	return nil
}

func extractChannelNameFromURL(rawURL string) string {
	re := regexp.MustCompile(`t\.me/([^/?]+)`)
	matches := re.FindStringSubmatch(rawURL)
	if len(matches) > 1 {
		return matches[1]
	}
	re2 := regexp.MustCompile(`t\.me/s/([^/?]+)`)
	matches2 := re2.FindStringSubmatch(rawURL)
	if len(matches2) > 1 {
		return matches2[1]
	}
	return ""
}

// ---------- دریافت ساب‌لینک ----------
func fetchAllSubscriptions(ctx context.Context) {
	data, err := os.ReadFile(*sourcesFile)
	if err != nil {
		gologger.Warning().Msgf("Sources.json not found (%s), skipping subscriptions.", *sourcesFile)
		return
	}
	var sources []string
	if err := json.Unmarshal(data, &sources); err != nil {
		gologger.Error().Msgf("Invalid Sources.json: %v", err)
		return
	}
	jobs := make(chan string, len(sources))
	var wg sync.WaitGroup
	for i := 0; i < *concurrent; i++ {
		wg.Add(1)
		go subWorker(ctx, jobs, &wg)
	}
	for _, src := range sources {
		select {
		case <-ctx.Done():
			break
		case jobs <- src:
		}
	}
	close(jobs)
	wg.Wait()
}

func subWorker(ctx context.Context, jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for src := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		fetchSubscription(ctx, src)
		time.Sleep(time.Duration(1+rand.Intn(3)) * time.Second)
	}
}

func fetchSubscription(ctx context.Context, urlStr string) {
	req, _ := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := httpClient.Do(req)
	if err != nil {
		gologger.Debug().Msgf("Failed to fetch subscription %s: %v", urlStr, err)
		return
	}
	defer resp.Body.Close()

	limitedReader := io.LimitReader(resp.Body, MaxSubscriptionResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return
	}
	content := string(body)

	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(strings.NewReader(content))
		if err == nil {
			decompressed, _ := io.ReadAll(gr)
			gr.Close()
			content = string(decompressed)
		}
	}

	trimmed := strings.TrimSpace(content)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		if len(decoded) <= int(MaxSubscriptionResponseSize) {
			content = string(decoded)
		} else {
			gologger.Warning().Msgf("Decoded subscription too large (%d bytes), skipping", len(decoded))
		}
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
		addToCache(cfg, "subscription", "")
	}
}

func extractAllConfigs(text string) []string {
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	var results []string
	seen := make(map[string]bool)
	matches := combinedRegex.FindAllString(text, -1)
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if !seen[m] && m != "" {
			seen[m] = true
			results = append(results, m)
		}
	}
	return results
}

// ---------- اسکن فورک‌های گیت‌هاب ----------
func fetchFromGitHubForks(ctx context.Context) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		gologger.Warning().Msg("No GitHub token found, skipping fork scan")
		return
	}
	baseURL := fmt.Sprintf("https://api.github.com/repos/%s/forks?per_page=%d", *targetRepo, ForksPerPage)
	page := 1
	var allRawURLs []string
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		url := fmt.Sprintf("%s&page=%d", baseURL, page)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			break
		}
		var forks []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&forks); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		if len(forks) == 0 {
			break
		}
		for _, fork := range forks {
			owner, _ := fork["owner"].(map[string]interface{})
			fullName, _ := fork["full_name"].(string)
			if fullName == "" {
				continue
			}
			paths := []string{
				"sub.txt", "sub_1.txt", "sub_2.txt", "sub_3.txt", "sub_4.txt",
				"config.txt", "config.json", "mixed.txt", "v2ray.txt", "vmess.txt",
				"subscription.txt", "sub.link", "iran.txt",
				"mci/sub_1.txt", "mci/sub_2.txt", "mci/sub_3.txt", "mci/sub_4.txt",
				"mtn/sub_1.txt", "mtn/sub_2.txt", "mtn/sub_3.txt", "mtn/sub_4.txt",
				"xray_final.txt", "sub-link.txt",
			}
			for _, p := range paths {
				raw := fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s", fullName, p)
				headReq, err := http.NewRequestWithContext(ctx, "HEAD", raw, nil)
				if err != nil {
					continue
				}
				headResp, err := httpClient.Do(headReq)
				if err == nil && headResp.StatusCode == 200 {
					allRawURLs = append(allRawURLs, raw)
					gologger.Info().Msgf("Found subscription in fork %s: %s", fullName, raw)
				}
				if headResp != nil {
					headResp.Body.Close()
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		page++
		time.Sleep(1 * time.Second)
	}
	seen := make(map[string]bool)
	for _, u := range allRawURLs {
		if !seen[u] {
			seen[u] = true
			go fetchSubscription(ctx, u)
		}
	}
	gologger.Info().Msgf("Fetched %d potential subscription URLs from forks", len(seen))
}

// ---------- خروجی‌های اصلی (ایموجی) ----------
func writeOutputFiles() {
	writeTelegramPerChannel()
	writeMixedFromTelegramAndSubscription()
	writeSubscriptionFolder()
}

func writeTelegramPerChannel() {
	threshold := time.Now().Add(-24 * time.Hour).Unix()
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	temp := make(map[string]map[string][]string)
	for cfg, e := range configCache {
		if e.Source == "telegram" && e.Channel != "" && e.Timestamp >= threshold {
			proto := e.Protocol
			if proto == "" {
				proto = detectProtocol(cfg)
			}
			if temp[e.Channel] == nil {
				temp[e.Channel] = make(map[string][]string)
			}
			temp[e.Channel][proto] = append(temp[e.Channel][proto], cfg)
		}
	}
	for channel, protoMap := range temp {
		channelDir := filepath.Join("telegram", channel)
		os.MkdirAll(channelDir, 0755)
		for proto, configs := range protoMap {
			if *sortFlag {
				sort.Slice(configs, func(i, j int) bool {
					return configCache[configs[i]].Timestamp > configCache[configs[j]].Timestamp
				})
			}
			content := strings.Join(configs, "\n")
			if content != "" {
				filename := filepath.Join(channelDir, protocolFileName(proto)+".txt")
				os.WriteFile(filename, []byte(content), 0644)
			}
		}
	}
}

func writeMixedFromTelegramAndSubscription() {
	var cutoff int64 = 0
	if *mixedAge > 0 {
		cutoff = time.Now().Add(-*mixedAge).Unix()
	}
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	var unknown []string
	for cfg, e := range configCache {
		if (e.Source == "telegram" || e.Source == "subscription") && (cutoff == 0 || e.Timestamp >= cutoff) {
			proto := e.Protocol
			if proto == "" {
				proto = detectProtocol(cfg)
			}
			if proto == "mixed" {
				unknown = append(unknown, cfg)
			}
		}
	}
	if *sortFlag {
		sort.Slice(unknown, func(i, j int) bool { return configCache[unknown[i]].Timestamp > configCache[unknown[j]].Timestamp })
	}
	content := strings.Join(unknown, "\n")
	if content != "" {
		filename := filepath.Join("mixed", protocolFileName("mixed")+".txt")
		os.WriteFile(filename, []byte(content), 0644)
	}
}

func writeSubscriptionFolder() {
	threshold := time.Now().Add(-24 * time.Hour).Unix()
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	subByProto := make(map[string][]string)
	for cfg, e := range configCache {
		if e.Source == "subscription" && e.Timestamp >= threshold {
			proto := e.Protocol
			if proto == "" {
				proto = detectProtocol(cfg)
			}
			subByProto[proto] = append(subByProto[proto], cfg)
		}
	}
	for proto, configs := range subByProto {
		if *sortFlag {
			sort.Slice(configs, func(i, j int) bool { return configCache[configs[i]].Timestamp > configCache[configs[j]].Timestamp })
		}
		content := strings.Join(configs, "\n")
		if content != "" {
			filename := filepath.Join("subscription", protocolFileName(proto)+".txt")
			os.WriteFile(filename, []byte(content), 0644)
		}
	}
}

// ---------- انباشت روزانه (all_configs) ----------
func writeAllConfigs() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	archiveTimeMutex.RLock()
	lastArch := lastArchiveTime
	archiveTimeMutex.RUnlock()

	allowedProtos := map[string]bool{
		"socks": true, "ss": true, "trojan": true, "tuic": true,
		"vless": true, "vmess": true, "wireguard": true, "hysteria2": true,
	}
	type sourceFiles struct {
		allProto []string
		http     []string
		mtproto  []string
		slipnet  []string
		unknown  []string
	}
	sources := map[string]*sourceFiles{
		"telegram":     {},
		"subscription": {},
	}
	for cfg, entry := range configCache {
		src := entry.Source
		if src != "telegram" && src != "subscription" {
			continue
		}
		if lastArch > 0 && entry.Timestamp < lastArch {
			continue
		}
		proto := entry.Protocol
		if proto == "" {
			proto = detectProtocol(cfg)
		}
		target := sources[src]
		switch {
		case allowedProtos[proto]:
			target.allProto = append(target.allProto, cfg)
		case proto == "http":
			target.http = append(target.http, cfg)
		case proto == "mtproto":
			target.mtproto = append(target.mtproto, cfg)
		case proto == "slipnet":
			target.slipnet = append(target.slipnet, cfg)
		default:
			target.unknown = append(target.unknown, cfg)
		}
	}
	appendToFile := func(baseDir, filename string, configs []string) {
		if len(configs) == 0 {
			return
		}
		path := filepath.Join("all_configs", baseDir, filename)
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			gologger.Error().Msgf("Cannot open %s: %v", path, err)
			return
		}
		defer f.Close()
		for _, cfg := range configs {
			f.WriteString(cfg + "\n")
		}
		gologger.Info().Msgf("Added %d new configs to %s", len(configs), path)
	}
	for src, sf := range sources {
		appendToFile(src, "all_protocols.txt", sf.allProto)
		appendToFile(src, "http.txt", sf.http)
		appendToFile(src, "mtproto.txt", sf.mtproto)
		appendToFile(src, "slipnet.txt", sf.slipnet)
		appendToFile(src, "unknown.txt", sf.unknown)
	}
}

// ---------- فایل links.md (جمع‌شونده، زیبا) ----------
func generateLinksFile() {
	var baseURLStr string
	if *baseURL != "" {
		baseURLStr = *baseURL
	} else {
		repo := os.Getenv("GITHUB_REPOSITORY")
		if repo == "" {
			repo = "ramin00542/GO_V2rayCollector"
		}
		branch := os.Getenv("GITHUB_REF_NAME")
		if branch == "" {
			branch = "main"
		}
		baseURLStr = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", repo, branch)
	}

	var sb strings.Builder
	sb.WriteString("# 🔗 لینک‌های فایل‌های کانفیگ\n\n")
	sb.WriteString(fmt.Sprintf("**آخرین به‌روزرسانی:** `%s`\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("---\n\n## 📊 گزارش آماری کامل\n\n")
	sb.WriteString(fmt.Sprintf("- [📈 collector_stats.md](%s/reports/collector_stats.md)\n", strings.TrimSuffix(baseURLStr, "/main")))
	sb.WriteString(fmt.Sprintf("- [📄 collector_stats.txt (raw)](%s/reports/collector_stats.txt)\n\n", baseURLStr))
	sb.WriteString("---\n\n")

	getFileInfo := func(path string) (int, time.Time) {
		info, err := os.Stat(path)
		if err != nil {
			return 0, time.Time{}
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return 0, info.ModTime()
		}
		lines := strings.Count(string(content), "\n")
		if lines == 0 && len(content) > 0 {
			lines = 1
		}
		return lines, info.ModTime()
	}
	statusEmoji := func(lines int) string {
		if lines == 0 {
			return "🔴"
		}
		return "🟢"
	}

	sb.WriteString("## 📁 all_configs/subscription\n\n")
	sb.WriteString("| وضعیت | نام فایل | تعداد کانفیگ | آخرین به‌روزرسانی | لینک خام |\n")
	sb.WriteString("|-------|----------|--------------|-------------------|----------|\n")
	files, _ := filepath.Glob("all_configs/subscription/*.txt")
	for _, f := range files {
		name := filepath.Base(f)
		lines, mod := getFileInfo(f)
		status := statusEmoji(lines)
		url := fmt.Sprintf("%s/all_configs/subscription/%s", baseURLStr, name)
		timeStr := mod.Format("2006-01-02 15:04:05")
		if mod.IsZero() {
			timeStr = "نامشخص"
		}
		sb.WriteString(fmt.Sprintf("| %s | `%s` | `%d` | `%s` | [دانلود](%s) |\n", status, name, lines, timeStr, url))
	}
	sb.WriteString("\n")

	sb.WriteString("## 📁 all_configs/telegram\n\n")
	sb.WriteString("| وضعیت | نام فایل | تعداد کانفیگ | آخرین به‌روزرسانی | لینک خام |\n")
	sb.WriteString("|-------|----------|--------------|-------------------|----------|\n")
	files, _ = filepath.Glob("all_configs/telegram/*.txt")
	for _, f := range files {
		name := filepath.Base(f)
		lines, mod := getFileInfo(f)
		status := statusEmoji(lines)
		url := fmt.Sprintf("%s/all_configs/telegram/%s", baseURLStr, name)
		timeStr := mod.Format("2006-01-02 15:04:05")
		if mod.IsZero() {
			timeStr = "نامشخص"
		}
		sb.WriteString(fmt.Sprintf("| %s | `%s` | `%d` | `%s` | [دانلود](%s) |\n", status, name, lines, timeStr, url))
	}
	sb.WriteString("\n")

	sb.WriteString("## 📁 daily_archive\n\n")
	archives, _ := filepath.Glob("daily_archive/*")
	sort.Strings(archives)
	for _, arch := range archives {
		if info, _ := os.Stat(arch); info != nil && info.IsDir() {
			subDir := filepath.Base(arch)
			sb.WriteString(fmt.Sprintf("### %s\n\n", subDir))
			sb.WriteString("| وضعیت | نام فایل | تعداد کانفیگ | آخرین به‌روزرسانی | لینک خام |\n")
			sb.WriteString("|-------|----------|--------------|-------------------|----------|\n")
			inner, _ := filepath.Glob(filepath.Join(arch, "*.txt"))
			for _, f := range inner {
				name := filepath.Base(f)
				lines, mod := getFileInfo(f)
				status := statusEmoji(lines)
				url := fmt.Sprintf("%s/daily_archive/%s/%s", baseURLStr, subDir, name)
				timeStr := mod.Format("2006-01-02 15:04:05")
				if mod.IsZero() {
					timeStr = "نامشخص"
				}
				sb.WriteString(fmt.Sprintf("| %s | `%s` | `%d` | `%s` | [دانلود](%s) |\n", status, name, lines, timeStr, url))
			}
			subFiles, _ := filepath.Glob(filepath.Join(arch, "subscription", "*.txt"))
			for _, f := range subFiles {
				name := filepath.Base(f)
				lines, mod := getFileInfo(f)
				status := statusEmoji(lines)
				url := fmt.Sprintf("%s/daily_archive/%s/subscription/%s", baseURLStr, subDir, name)
				timeStr := mod.Format("2006-01-02 15:04:05")
				if mod.IsZero() {
					timeStr = "نامشخص"
				}
				sb.WriteString(fmt.Sprintf("| %s | `subscription/%s` | `%d` | `%s` | [دانلود](%s) |\n", status, name, lines, timeStr, url))
			}
			channels, _ := filepath.Glob(filepath.Join(arch, "telegram", "*"))
			for _, ch := range channels {
				if infoCh, _ := os.Stat(ch); infoCh != nil && infoCh.IsDir() {
					chName := filepath.Base(ch)
					chFiles, _ := filepath.Glob(filepath.Join(ch, "*.txt"))
					for _, f := range chFiles {
						name := filepath.Base(f)
						lines, mod := getFileInfo(f)
						status := statusEmoji(lines)
						url := fmt.Sprintf("%s/daily_archive/%s/telegram/%s/%s", baseURLStr, subDir, chName, name)
						timeStr := mod.Format("2006-01-02 15:04:05")
						if mod.IsZero() {
							timeStr = "نامشخص"
						}
						sb.WriteString(fmt.Sprintf("| %s | `telegram/%s/%s` | `%d` | `%s` | [دانلود](%s) |\n", status, chName, name, lines, timeStr, url))
					}
				}
			}
			sb.WriteString("\n")
		}
	}

	for _, folder := range []string{"mixed", "subscription", "telegram"} {
		sb.WriteString(fmt.Sprintf("## 📁 %s\n\n", folder))
		sb.WriteString("| وضعیت | نام فایل | تعداد کانفیگ | آخرین به‌روزرسانی | لینک خام |\n")
		sb.WriteString("|-------|----------|--------------|-------------------|----------|\n")
		files, _ = filepath.Glob(fmt.Sprintf("%s/*.txt", folder))
		for _, f := range files {
			name := filepath.Base(f)
			lines, mod := getFileInfo(f)
			status := statusEmoji(lines)
			url := fmt.Sprintf("%s/%s/%s", baseURLStr, folder, name)
			timeStr := mod.Format("2006-01-02 15:04:05")
			if mod.IsZero() {
				timeStr = "نامشخص"
			}
			sb.WriteString(fmt.Sprintf("| %s | `%s` | `%d` | `%s` | [دانلود](%s) |\n", status, name, lines, timeStr, url))
		}
		sb.WriteString("\n")
	}

	os.WriteFile("reports/links.md", []byte(sb.String()), 0644)
	os.WriteFile("reports/links.txt", []byte(sb.String()), 0644)
	gologger.Info().Msg("reports/links.md and reports/links.txt generated")
}

// ---------- فایل آمار زیبا (Markdown) ----------
func writeStatsFile() {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش آماری جمع‌آوری‌کننده کانفیگ\n\n")
	sb.WriteString(fmt.Sprintf("**زمان اجرا:** `%s`\n\n", time.Now().Format("2006-01-02 15:04:05")))

	cacheMutex.RLock()
	totalConfigs := len(configCache)
	cacheMutex.RUnlock()

	stats.Lock()
	newCount := stats.newCount
	dupCount := stats.duplicateCount
	telegramCount := stats.telegramCount
	subCount := stats.subCount
	protoCounts := make(map[string]int)
	for k, v := range stats.protoCounts {
		protoCounts[k] = v
	}
	stats.Unlock()

	sb.WriteString("## 📈 آمار کلی\n\n")
	sb.WriteString("| معیار | مقدار |\n|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| **کل کانفیگ‌های کش** | `%d` |\n", totalConfigs))
	sb.WriteString(fmt.Sprintf("| **کانفیگ جدید در این اجرا** | `%d` |\n", newCount))
	sb.WriteString(fmt.Sprintf("| **تکراری حذف شده** | `%d` |\n", dupCount))
	sb.WriteString(fmt.Sprintf("| **کانفیگ از تلگرام (کل کش)** | `%d` |\n", telegramCount))
	sb.WriteString(fmt.Sprintf("| **کانفیگ از ساب‌لینک (کل کش)** | `%d` |\n\n", subCount))

	sb.WriteString("## 📡 تفکیک پروتکل‌ها\n\n")
	if len(protoCounts) == 0 {
		sb.WriteString("_هیچ پروتکلی یافت نشد._\n\n")
	} else {
		sb.WriteString("| پروتکل | تعداد |\n|--------|-------|\n")
		type kv struct{ p string; c int }
		var sorted []kv
		for p, c := range protoCounts {
			sorted = append(sorted, kv{p, c})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].c > sorted[j].c })
		for _, kv := range sorted {
			icon := protocolIcon(kv.p)
			sb.WriteString(fmt.Sprintf("| %s **%s** | `%d` |\n", icon, kv.p, kv.c))
		}
		sb.WriteString("\n")
	}

	cacheMutex.RLock()
	channelStats := make(map[string]int)
	for _, e := range configCache {
		if e.Source == "telegram" && e.Channel != "" {
			channelStats[e.Channel]++
		}
	}
	cacheMutex.RUnlock()

	if len(channelStats) > 0 {
		sb.WriteString("## 🗂️ کانال‌های تلگرام (به تفکیک تعداد کانفیگ)\n\n")
		var sorted []kv
		for ch, c := range channelStats {
			sorted = append(sorted, kv{ch, c})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].c > sorted[j].c })
		sb.WriteString("| کانال | تعداد کانفیگ |\n|-------|--------------|\n")
		for i, kv := range sorted {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("| ... و `%d` کانال دیگر | ... |\n", len(sorted)-20))
				break
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%d` |\n", kv.p, kv.c))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("## 🗂️ کانال‌های تلگرام\n\n_هیچ کانفیگی از تلگرام دریافت نشده است._\n\n")
	}

	if data, err := os.ReadFile(*sourcesFile); err == nil {
		var sources []string
		if json.Unmarshal(data, &sources) == nil {
			if len(sources) > 20 {
				sb.WriteString("## 🔗 منابع ساب‌لینک (نمایش همه با کلیک)\n\n")
				sb.WriteString(fmt.Sprintf("<details>\n<summary>نمایش %d ساب‌لینک</summary>\n\n", len(sources)))
				for _, src := range sources {
					sb.WriteString(fmt.Sprintf("- `%s`\n", src))
				}
				sb.WriteString("\n</details>\n\n")
			} else if len(sources) > 0 {
				sb.WriteString("## 🔗 منابع ساب‌لینک\n\n")
				for _, src := range sources {
					sb.WriteString(fmt.Sprintf("- `%s`\n", src))
				}
				sb.WriteString("\n")
			}
		}
	} else {
		sb.WriteString("⚠️ فایل `Sources.json` یافت نشد.\n\n")
	}
	sb.WriteString("---\n✅ ربات با موفقیت اجرا شد. برای جزئیات بیشتر فایل‌های خروجی را بررسی کنید.\n")

	os.WriteFile("reports/collector_stats.md", []byte(sb.String()), 0644)
	os.WriteFile("reports/collector_stats.txt", []byte(sb.String()), 0644)
	gologger.Info().Msg("reports/collector_stats.md and reports/collector_stats.txt generated")
}

func protocolIcon(proto string) string {
	switch proto {
	case "vmess":
		return "🔵"
	case "vless":
		return "🟢"
	case "trojan":
		return "🔒"
	case "ss":
		return "⚡"
	case "ssr":
		return "✨"
	case "hysteria2":
		return "🌀"
	case "tuic":
		return "🟦"
	case "wireguard":
		return "🔹"
	case "mixed":
		return "🌍"
	case "mtproto":
		return "🟣"
	case "http":
		return "🟠"
	case "socks":
		return "🟡"
	default:
		return "📄"
	}
}

// ---------- فایل لینک‌های ساب‌اسکریپشن ----------
func writeSubscriptionLinksFile() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	var links []string
	seen := make(map[string]bool)
	for cfg, entry := range configCache {
		if entry.Source != "telegram" {
			continue
		}
		if subLinkRegex.MatchString(cfg) {
			if !seen[cfg] {
				seen[cfg] = true
				links = append(links, cfg)
			}
		}
	}
	if len(links) == 0 {
		os.WriteFile("subscription_links.txt", []byte("No subscription links found in Telegram channels.\n"), 0644)
		return
	}
	sort.Strings(links)
	os.WriteFile("subscription_links.txt", []byte(strings.Join(links, "\n")), 0644)
	gologger.Info().Msgf("subscription_links.txt generated with %d links", len(links))
}

// ---------- گزارش تلگرام ----------
func sendTelegramReport() {
	token := *telegramToken
	if token == "" {
		token = os.Getenv("TELEGRAM_BOT_TOKEN")
	}
	chatID := *telegramChat
	if chatID == "" {
		chatID = os.Getenv("TELEGRAM_CHAT_ID")
	}
	if token == "" || chatID == "" {
		return
	}
	stats.Lock()
	newCount := stats.newCount
	dupCount := stats.duplicateCount
	insecureCount := stats.insecureCount
	telegramCount := stats.telegramCount
	subCount := stats.subCount
	proto := stats.protoCounts
	stats.Unlock()

	cacheMutex.RLock()
	total := len(configCache)
	cacheMutex.RUnlock()

	text := fmt.Sprintf("🚀 *V2rayCollector Report*\n\n📅 Time: %s\n📊 Total: %d\n🆕 New: %d\n🔄 Duplicates: %d\n⚠️ Insecure: %d\n📡 Telegram: %d\n🔗 Subs: %d\n\n📈 Protocols:\n",
		time.Now().Format("2006-01-02 15:04:05"), total, newCount, dupCount, insecureCount, telegramCount, subCount)
	for p, c := range proto {
		text += fmt.Sprintf("  • %s: %d\n", p, c)
	}
	if len(insecureConfigs) > 0 {
		text += "\n⚠️ Sample insecure:\n"
		for i, cfg := range insecureConfigs {
			if i >= 3 {
				break
			}
			text += fmt.Sprintf("  • `%s...`\n", cfg[:min(40, len(cfg))])
		}
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	data := url.Values{}
	data.Set("chat_id", chatID)
	data.Set("text", text)
	data.Set("parse_mode", "Markdown")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
}

// ---------- توابع جانبی ساده ----------
func generateClashYAML() {
	os.WriteFile("clash-config.yaml", []byte("# Clash config placeholder\n"), 0644)
}
func generateSingBoxJSON() {
	os.WriteFile("singbox.json", []byte(`{"outbounds":[],"version":"1.0.0"}`), 0644)
}
func performHealthCheck() {}
func quickCheckWithProtocol(cfg string) bool { return true }
func testSampleConfigs() {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	gologger.Info().Msgf("Total configs in cache: %d", len(configCache))
}
func printStats() {
	stats.Lock()
	defer stats.Unlock()
	gologger.Info().Msgf("Stats: New=%d, Dup=%d, Insecure=%d, Telegram=%d, Subs=%d, Total=%d",
		stats.newCount, stats.duplicateCount, stats.insecureCount, stats.telegramCount, stats.subCount, len(configCache))
}
