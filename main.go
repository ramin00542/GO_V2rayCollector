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
	"gopkg.in/yaml.v3"
)

// ========================== تنظیمات ثابت ==========================
const (
	MaxConfigsPerProtocol            = 50000
	MaxSubscriptionResponseSize      = 50 * 1024 * 1024
	RequestTimeout                   = 30 * time.Second
	CacheTTL                         = 30 * 24 * time.Hour
	RetryCount                       = 3
	RetryBackoff                     = 2 * time.Second
	TelegramPageDelayBase            = 1 * time.Second
	TelegramPageJitter               = 1 * time.Second
	HealthCheckTimeout               = 5 * time.Second
	HealthCheckConcurrency           = 10
	TelegramRequestsPerSecond        = 5
	TelegramBurstSize                = 10
)

var (
	sortFlag      = flag.Bool("sort", false, "sort configs from latest to oldest (already sorted by default)")
	dedupFlag     = flag.Bool("dedup", true, "enable advanced deduplication (fingerprint-based)")
	testFlag      = flag.Bool("test", false, "print total configs count (simple test)")
	concurrent    = flag.Int("concurrent", 3, "number of concurrent workers")
	maxMessages   = flag.Int("max-msgs", 100, "max messages per Telegram channel")
	clashFlag     = flag.Bool("clash", false, "generate Clash YAML")
	singboxFlag   = flag.Bool("singbox", false, "generate sing-box JSON")
	proxyURL      = flag.String("proxy", "", "HTTP/HTTPS proxy URL")
	baseURL       = flag.String("base-url", "", "base URL for links.txt (overrides GitHub detection)")
	healthCheck   = flag.Bool("health-check", false, "perform health check")
	channelsFile  = flag.String("channels", "channels.csv", "Telegram channels CSV file")
	sourcesFile   = flag.String("sources", "Sources.json", "Subscription sources JSON file")
	timeout       = flag.Duration("timeout", RequestTimeout, "HTTP request timeout")
	mixedAge      = flag.Duration("mixed-age", 24*time.Hour, "age limit for mixed output (0 = all)")

	combinedRegex   *regexp.Regexp
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
	telegramOffsets  = make(map[string]string)
	offsetsMutex     sync.RWMutex
	mainWg           sync.WaitGroup

	lastArchiveTime  int64
	archiveTimeMutex sync.RWMutex
	archiveTimeFile  = "last_archive_time.txt"

	stats = struct {
		sync.Mutex
		telegramCount, subCount, newCount, duplicateCount int
		protoCounts                                        map[string]int
	}{protoCounts: make(map[string]int)}
)

type CacheEntry struct {
	Timestamp   int64  `json:"timestamp"`
	Source      string `json:"source"`
	Fingerprint string `json:"fingerprint"`
	Channel     string `json:"channel,omitempty"`
	Offset      string `json:"offset,omitempty"`
	Original    string `json:"original,omitempty"`
	Protocol    string `json:"protocol"`
}

type CacheData struct {
	Configs   map[string]CacheEntry `json:"configs"`
	Timestamp int64                 `json:"timestamp"`
	Offsets   map[string]string     `json:"offsets"`
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

// ========================== تابع تبدیل پروتکل به نام فایل با ایموجی ==========================
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

// ========================== MAIN ==========================
func main() {
	flag.Parse()
	initCombinedRegex()
	setupLogging()
	createDirs()
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
	mainWg.Wait()

	pruneCacheByTTL()
	pruneCacheByProtocol()

	writeOutputFiles()
	writeAllConfigs()
	archiveDaily()

	generateLinksFile()

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
	gologger.Info().Msg("All Done!")
}

func initTelegramLimiter() {
	telegramLimiter = rate.NewLimiter(rate.Limit(TelegramRequestsPerSecond), TelegramBurstSize)
}

// ==================== آرشیو روزانه (بکاپ کامل all_configs و سپس پاک کردن) ====================
func archiveDaily() {
	today := time.Now().Format("2006-01-02")
	archiveDir := filepath.Join("daily_archive", today)
	markerFile := filepath.Join(archiveDir, ".done")

	if _, err := os.Stat(markerFile); err == nil {
		gologger.Debug().Msg("Already archived today, skipping")
		return
	}

	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		gologger.Warning().Msgf("Failed to create archive dir: %v", err)
		return
	}

	// 1. کپی کل all_configs به داخل daily_archive (با حفظ زیرپوشه‌ها)
	if err := copyDir("all_configs", archiveDir); err != nil {
		gologger.Error().Msgf("Failed to copy all_configs: %v", err)
		return
	}

	// 2. خالی کردن تمام فایل‌های متنی داخل all_configs
	files, _ := filepath.Glob("all_configs/*/*.txt")
	for _, f := range files {
		if err := os.Truncate(f, 0); err != nil {
			gologger.Warning().Msgf("Error truncating %s: %v", f, err)
		}
	}

	// 3. (اختیاری) کپی فایل‌های mixed برای دسترسی سریع در ریشه آرشیو
	mixedFiles, _ := filepath.Glob("mixed/*.txt")
	for _, src := range mixedFiles {
		dest := filepath.Join(archiveDir, filepath.Base(src))
		data, err := os.ReadFile(src)
		if err != nil {
			gologger.Warning().Msgf("Read error %s: %v", src, err)
			continue
		}
		if len(data) > 0 {
			if err := os.WriteFile(dest, data, 0644); err != nil {
				gologger.Warning().Msgf("Write error %s: %v", dest, err)
			}
		}
	}

	// 4. به‌روزرسانی زمان آخرین آرشیو
	archiveTimeMutex.Lock()
	lastArchiveTime = time.Now().Unix()
	archiveTimeMutex.Unlock()
	saveLastArchiveTime()

	os.WriteFile(markerFile, []byte("archived"), 0644)
	gologger.Info().Msgf("Archived all_configs to %s and cleared", archiveDir)
}

// تابع کمکی برای کپی بازگشتی پوشه
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destPath, data, info.Mode())
	})
}

// ==================== توابع اولیه ====================
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
		if err := os.MkdirAll(d, 0755); err != nil {
			gologger.Warning().Msgf("Failed to create directory %s: %v", d, err)
		}
	}
	if err := os.MkdirAll(filepath.Join("all_configs", "subscription"), 0755); err != nil {
		gologger.Warning().Msgf("Failed to create all_configs/subscription: %v", err)
	}
	if err := os.MkdirAll(filepath.Join("all_configs", "telegram"), 0755); err != nil {
		gologger.Warning().Msgf("Failed to create all_configs/telegram: %v", err)
	}
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
		gologger.Info().Msg("Clean shutdown complete.")
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
	cacheMutex.Unlock()

	offsetsMutex.Lock()
	if cd.Offsets != nil {
		telegramOffsets = cd.Offsets
	}
	offsetsMutex.Unlock()

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
	offsetsMutex.RLock()
	cd.Offsets = telegramOffsets
	offsetsMutex.RUnlock()

	data, err := json.MarshalIndent(cd, "", "  ")
	if err != nil {
		gologger.Error().Msgf("Failed to marshal cache: %v", err)
		return
	}
	tmpFile := "config_cache.json.tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		gologger.Error().Msgf("Failed to write temp cache: %v", err)
		return
	}
	os.Remove("config_cache.json")
	if err := os.Rename(tmpFile, "config_cache.json"); err != nil {
		gologger.Error().Msgf("Failed to rename cache file: %v", err)
	}
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

func getStringField(data map[string]interface{}, field string) string {
	if val, ok := data[field]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	return ""
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
		getStringField(data, "add"),
		getStringField(data, "port"),
		getStringField(data, "id"),
		getStringField(data, "net"),
		getStringField(data, "type"),
		getStringField(data, "host"),
		getStringField(data, "path"),
		getStringField(data, "tls"),
		getStringField(data, "sni"))
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

func addToCache(cfg, source, channel string, offset ...string) {
	if cfg == "" {
		return
	}
	cfg = strings.TrimSpace(cfg)
	proto := detectProtocol(cfg)
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

	off := ""
	if len(offset) > 0 {
		off = offset[0]
	}
	configCache[cfg] = CacheEntry{
		Timestamp:   time.Now().Unix(),
		Source:      source,
		Fingerprint: fp,
		Channel:     channel,
		Offset:      off,
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

// ==================== مدیریت آخرین زمان آرشیو ====================
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

// ==================== دریافت ====================
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
	validChannels := []ChannelsType{}
	for _, ch := range channels {
		if !strings.Contains(ch.URL, "t.me") && !strings.Contains(ch.URL, "telegram.me") {
			gologger.Warning().Msgf("Invalid telegram URL: %s", ch.URL)
			continue
		}
		validChannels = append(validChannels, ch)
	}
	jobs := make(chan ChannelsType, len(validChannels))
	var wg sync.WaitGroup
	for i := 0; i < *concurrent; i++ {
		wg.Add(1)
		go telegramWorker(ctx, jobs, &wg)
	}
	for _, ch := range validChannels {
		select {
		case <-ctx.Done():
			break
		case jobs <- ch:
		}
	}
	close(jobs)
	wg.Wait()
}

func telegramWorker(ctx context.Context, jobs <-chan ChannelsType, wg *sync.WaitGroup) {
	defer wg.Done()
	for ch := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		webURL := changeUrlToTelegramWebUrl(ch.URL)
		channelName := extractChannelNameFromURL(webURL)
		if channelName == "" {
			continue
		}
		offsetsMutex.Lock()
		lastOffset := telegramOffsets[channelName]
		offsetsMutex.Unlock()

		maxMsg := *maxMessages
		if ch.AllMessagesFlag {
			maxMsg = 10000
		}
		allMessages, lastMsgOffset := fetchTelegramMessagesWithResume(ctx, webURL, lastOffset, maxMsg)

		if lastMsgOffset != "" {
			offsetsMutex.Lock()
			telegramOffsets[channelName] = lastMsgOffset
			offsetsMutex.Unlock()
			saveOffsetsCheckpoint()
		}
		for _, text := range allMessages {
			processTelegramText(text, channelName)
		}
		jitter := time.Duration(rand.Int63n(int64(TelegramPageJitter)))
		time.Sleep(TelegramPageDelayBase + jitter)
	}
}

func saveOffsetsCheckpoint() {
	offsetsMutex.RLock()
	data, err := json.Marshal(telegramOffsets)
	offsetsMutex.RUnlock()
	if err != nil {
		gologger.Warning().Msgf("Failed to marshal offsets checkpoint: %v", err)
		return
	}
	if err := os.WriteFile("telegram_offsets_checkpoint.json", data, 0644); err != nil {
		gologger.Warning().Msgf("Failed to write offsets checkpoint: %v", err)
	}
}

func changeUrlToTelegramWebUrl(tgURL string) string {
	re := regexp.MustCompile(`(?:https?://)?(?:t\.me|telegram\.me|web\.telegram\.org)/([^/?]+)`)
	match := re.FindStringSubmatch(tgURL)
	if len(match) == 2 {
		return fmt.Sprintf("https://t.me/%s", match[1])
	}
	return tgURL
}

func extractChannelNameFromURL(rawURL string) string {
	re := regexp.MustCompile(`t\.me/([^/?]+)`)
	matches := re.FindStringSubmatch(rawURL)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func fetchTelegramMessagesWithResume(ctx context.Context, startURL, offset string, max int) ([]string, string) {
	var allTexts []string
	seenTexts := make(map[string]bool)
	var lastUsedOffset string
	currentURL := startURL
	if offset != "" {
		currentURL = fmt.Sprintf("%s?before=%s", strings.TrimSuffix(startURL, "/"), offset)
	}
	maxIterations := 100
	iter := 0
	for len(allTexts) < max && iter < maxIterations {
		iter++
		select {
		case <-ctx.Done():
			return allTexts, lastUsedOffset
		default:
		}
		doc, err := fetchDocWithRetry(ctx, currentURL)
		if err != nil {
			gologger.Debug().Msgf("Failed to fetch %s: %v", currentURL, err)
			break
		}
		if doc == nil {
			break
		}
		texts := extractMessagesFromDoc(doc)
		for _, t := range texts {
			if !seenTexts[t] {
				seenTexts[t] = true
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
		newOffset := parts[len(parts)-1]
		if newOffset == offset {
			break
		}
		offset = newOffset
		lastUsedOffset = offset
		currentURL = fmt.Sprintf("%s?before=%s", strings.TrimSuffix(startURL, "/"), offset)
		jitter := time.Duration(rand.Int63n(int64(TelegramPageJitter)))
		time.Sleep(TelegramPageDelayBase + jitter)
	}
	return allTexts, lastUsedOffset
}

func fetchDocWithRetry(ctx context.Context, urlStr string) (*goquery.Document, error) {
	if err := telegramLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	var resp *http.Response
	var err error
	for i := 0; i < RetryCount; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err = httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					secs, _ := strconv.Atoi(retryAfter)
					time.Sleep(time.Duration(secs) * time.Second)
				}
			}
		}
		time.Sleep(RetryBackoff * time.Duration(i+1))
	}
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func extractMessagesFromDoc(doc *goquery.Document) []string {
	var texts []string
	doc.Find(".tgme_widget_message_text, .tgme_widget_message, pre, code").Each(func(i int, s *goquery.Selection) {
		plain := strings.TrimSpace(s.Text())
		if plain != "" {
			texts = append(texts, plain)
		}
	})
	return texts
}

func processTelegramText(text, channelName string) {
	configs := extractAllConfigs(text)
	for _, cfg := range configs {
		cfg = strings.TrimSpace(cfg)
		if cfg == "" {
			continue
		}
		addToCache(cfg, "telegram", channelName)
	}
}

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
		if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
			continue
		}
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

// ==================== خروجی‌های اصلی با نام فایل‌های ایموجی ====================
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
		if err := os.MkdirAll(channelDir, 0755); err != nil {
			gologger.Warning().Msgf("Cannot create dir %s: %v", channelDir, err)
			continue
		}
		for proto, configs := range protoMap {
			if *sortFlag {
				sort.Slice(configs, func(i, j int) bool {
					return configCache[configs[i]].Timestamp > configCache[configs[j]].Timestamp
				})
			}
			content := strings.Join(configs, "\n")
			if content != "" {
				displayName := protocolFileName(proto)
				filename := filepath.Join(channelDir, displayName+".txt")
				if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
					gologger.Warning().Msgf("Failed to write %s: %v", filename, err)
				}
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

	var unknownConfigs []string
	for cfg, e := range configCache {
		if (e.Source == "telegram" || e.Source == "subscription") && (cutoff == 0 || e.Timestamp >= cutoff) {
			proto := e.Protocol
			if proto == "" {
				proto = detectProtocol(cfg)
			}
			if proto == "mixed" {
				unknownConfigs = append(unknownConfigs, cfg)
			}
		}
	}

	if *sortFlag {
		sort.Slice(unknownConfigs, func(i, j int) bool {
			return configCache[unknownConfigs[i]].Timestamp > configCache[unknownConfigs[j]].Timestamp
		})
	}

	content := strings.Join(unknownConfigs, "\n")
	if content != "" {
		displayName := protocolFileName("mixed")
		filename := filepath.Join("mixed", displayName+".txt")
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			gologger.Warning().Msgf("Failed to write %s: %v", filename, err)
		}
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
			sort.Slice(configs, func(i, j int) bool {
				return configCache[configs[i]].Timestamp > configCache[configs[j]].Timestamp
			})
		}
		content := strings.Join(configs, "\n")
		if content != "" {
			displayName := protocolFileName(proto)
			filename := filepath.Join("subscription", displayName+".txt")
			if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
				gologger.Warning().Msgf("Failed to write %s: %v", filename, err)
			}
		}
	}
}

// ==================== انباشت روزانه ====================
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
			if _, err := f.WriteString(cfg + "\n"); err != nil {
				gologger.Warning().Msgf("Error writing to %s: %v", path, err)
			}
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

// ==================== links.txt با توضیحات پروتکل و اموجی وضعیت ====================
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

	var links []string
	links = append(links, "# Links to configuration files")
	links = append(links, "")
	links = append(links, "## 📖 Protocol Descriptions")
	links = append(links, "")
	links = append(links, "- 🔵 **VMess** – پروتکل اختصاصی V2Ray، امن و پرسرعت")
	links = append(links, "- 🟢 **VLess** – نسخه سبک‌تر VMess بدون شناسه ثابت")
	links = append(links, "- 🔒 **Trojan** – شبیه‌سازی ترافیک HTTPS برای عبور از فیلتر")
	links = append(links, "- ⚡ **Shadowsocks** – پروتکل سبک و سریع برای دور زدن محدودیت")
	links = append(links, "- 🌍 **Mixed** – کانفیگ‌های ناشناخته یا ترکیبی")
	links = append(links, "- 🟣 **MTProto** – پروتکل پروکسی اختصاصی تلگرام")
	links = append(links, "- 🟠 **HTTP Proxy** – پروکسی معمولی HTTP/HTTPS")
	links = append(links, "- 🟡 **SOCKS Proxy** – پروکسی SOCKS4/SOCKS5")
	links = append(links, "")
	links = append(links, "---")
	links = append(links, "")

	fileStatus := func(path string) string {
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			return "🔴"
		}
		return "🟢"
	}

	links = append(links, "## 📁 all_configs/subscription")
	files, _ := filepath.Glob("all_configs/subscription/*.txt")
	for _, f := range files {
		name := filepath.Base(f)
		url := fmt.Sprintf("%s/all_configs/subscription/%s", baseURLStr, name)
		links = append(links, fmt.Sprintf("- %s [%s](%s)", fileStatus(f), name, url))
	}
	links = append(links, "")

	links = append(links, "## 📁 all_configs/telegram")
	files, _ = filepath.Glob("all_configs/telegram/*.txt")
	for _, f := range files {
		name := filepath.Base(f)
		url := fmt.Sprintf("%s/all_configs/telegram/%s", baseURLStr, name)
		links = append(links, fmt.Sprintf("- %s [%s](%s)", fileStatus(f), name, url))
	}
	links = append(links, "")

	links = append(links, "## 📁 daily_archive")
	archives, _ := filepath.Glob("daily_archive/*")
	sort.Strings(archives)
	for _, arch := range archives {
		if info, _ := os.Stat(arch); info != nil && info.IsDir() {
			subDir := filepath.Base(arch)
			links = append(links, fmt.Sprintf("### %s", subDir))
			innerFiles, _ := filepath.Glob(filepath.Join(arch, "*.txt"))
			for _, f := range innerFiles {
				name := filepath.Base(f)
				url := fmt.Sprintf("%s/daily_archive/%s/%s", baseURLStr, subDir, name)
				links = append(links, fmt.Sprintf("  - %s [%s](%s)", fileStatus(f), name, url))
			}
		}
	}
	links = append(links, "")

	for _, folder := range []string{"mixed", "subscription", "telegram"} {
		links = append(links, fmt.Sprintf("## 📁 %s", folder))
		files, _ = filepath.Glob(fmt.Sprintf("%s/*.txt", folder))
		for _, f := range files {
			name := filepath.Base(f)
			url := fmt.Sprintf("%s/%s/%s", baseURLStr, folder, name)
			links = append(links, fmt.Sprintf("- %s [%s](%s)", fileStatus(f), name, url))
		}
		links = append(links, "")
	}

	if err := os.WriteFile("links.txt", []byte(strings.Join(links, "\n")), 0644); err != nil {
		gologger.Warning().Msgf("Failed to write links.txt: %v", err)
	} else {
		gologger.Info().Msg("links.txt generated with protocol descriptions and status emojis")
	}
}

// ==================== Clash YAML ====================
func generateClashYAML() {
	gologger.Info().Msg("Generating Clash YAML...")
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	type proxyWithTime struct {
		proxy ClashProxy
		ts    int64
	}
	var list []proxyWithTime

	for cfg, e := range configCache {
		proto := e.Protocol
		if proto == "" {
			proto = detectProtocol(cfg)
		}
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
		case "hysteria2":
			cp = hysteria2ToClash(cfg)
		case "tuic":
			cp = tuicToClash(cfg)
		default:
			continue
		}
		if cp != nil {
			list = append(list, proxyWithTime{*cp, e.Timestamp})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ts > list[j].ts })
	if len(list) > 2000 {
		list = list[:2000]
	}
	proxies := make([]ClashProxy, len(list))
	for i, item := range list {
		proxies[i] = item.proxy
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
	if err := os.WriteFile("clash-config.yaml", data, 0644); err != nil {
		gologger.Warning().Msgf("Failed to write clash-config.yaml: %v", err)
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
	cipher, _ := data["cipher"].(string)
	if cipher == "" {
		cipher, _ = data["scy"].(string)
	}
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

func hysteria2ToClash(h2URL string) *ClashProxy {
	if !strings.HasPrefix(h2URL, "hysteria2://") {
		return nil
	}
	u, err := url.Parse(h2URL)
	if err != nil {
		return nil
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	password := u.Query().Get("auth")
	if password == "" {
		password = u.Query().Get("password")
	}
	name := fmt.Sprintf("hysteria2_%s_%d", server, port)
	return &ClashProxy{
		Name:     name,
		Type:     "hysteria2",
		Server:   server,
		Port:     port,
		Password: password,
	}
}

func tuicToClash(tuicURL string) *ClashProxy {
	if !strings.HasPrefix(tuicURL, "tuic://") {
		return nil
	}
	u, err := url.Parse(tuicURL)
	if err != nil {
		return nil
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	uuid := ""
	password := ""
	if u.User != nil {
		uuid = u.User.Username()
		password, _ = u.User.Password()
	}
	name := fmt.Sprintf("tuic_%s_%d", server, port)
	return &ClashProxy{
		Name:     name,
		Type:     "tuic",
		Server:   server,
		Port:     port,
		UUID:     uuid,
		Password: password,
	}
}

// ==================== sing-box JSON ====================
func generateSingBoxJSON() {
	gologger.Info().Msg("Generating sing-box JSON...")
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	outbounds := make([]map[string]interface{}, 0)

	for cfg, e := range configCache {
		proto := e.Protocol
		if proto == "" {
			proto = detectProtocol(cfg)
		}
		tag := fmt.Sprintf("%s_%d", proto, e.Timestamp)
		if len(tag) > 40 {
			tag = tag[:40]
		}
		var outbound map[string]interface{}
		switch proto {
		case "vmess":
			outbound = vmessToSingbox(cfg, tag)
		case "ss":
			outbound = ssToSingbox(cfg, tag)
		case "trojan":
			outbound = trojanToSingbox(cfg, tag)
		case "vless":
			outbound = vlessToSingbox(cfg, tag)
		case "hysteria2":
			outbound = hysteria2ToSingbox(cfg, tag)
		case "tuic":
			outbound = tuicToSingbox(cfg, tag)
		default:
			continue
		}
		if outbound != nil {
			outbounds = append(outbounds, outbound)
		}
	}

	result := map[string]interface{}{
		"outbounds": outbounds,
		"version":   "1.0.0",
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile("singbox.json", data, 0644); err != nil {
		gologger.Warning().Msgf("Failed to write singbox.json: %v", err)
	}
}

func vmessToSingbox(vmessURL, tag string) map[string]interface{} {
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
	security, _ := data["scy"].(string)
	if security == "" {
		security, _ = data["cipher"].(string)
	}
	if security == "" {
		security = "auto"
	}
	net, _ := data["net"].(string)
	tlsVal, _ := data["tls"].(string)
	tls := tlsVal == "tls"
	sni, _ := data["sni"].(string)
	host, _ := data["host"].(string)
	path, _ := data["path"].(string)

	out := map[string]interface{}{
		"type":        "vmess",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
		"security":    security,
	}
	if tls {
		out["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    false,
		}
	}
	if net == "ws" {
		out["transport"] = map[string]interface{}{
			"type":    "ws",
			"path":    path,
			"headers": map[string]string{"Host": host},
		}
	} else if net == "grpc" {
		out["transport"] = map[string]interface{}{
			"type":         "grpc",
			"service_name": path,
		}
	}
	return out
}

func ssToSingbox(ssURL, tag string) map[string]interface{} {
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
	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
}

func trojanToSingbox(trojanURL, tag string) map[string]interface{} {
	if !strings.HasPrefix(trojanURL, "trojan://") {
		return nil
	}
	u, err := url.Parse(trojanURL)
	if err != nil {
		return nil
	}
	password := u.User.Username()
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	sni := u.Query().Get("sni")
	return map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"password":    password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    false,
		},
	}
}

func vlessToSingbox(vlessURL, tag string) map[string]interface{} {
	if !strings.HasPrefix(vlessURL, "vless://") {
		return nil
	}
	u, err := url.Parse(vlessURL)
	if err != nil {
		return nil
	}
	uuid := u.User.Username()
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	flow := u.Query().Get("flow")
	sni := u.Query().Get("sni")
	security := u.Query().Get("security")
	encryption := u.Query().Get("encryption")
	if encryption == "" {
		encryption = "none"
	}
	out := map[string]interface{}{
		"type":        "vless",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
		"encryption":  encryption,
	}
	if flow != "" {
		out["flow"] = flow
	}
	if security == "reality" {
		pbk := u.Query().Get("pbk")
		serverName := u.Query().Get("sni")
		fp := u.Query().Get("fp")
		shortId := u.Query().Get("sid")
		publicKey := pbk
		out["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": serverName,
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": publicKey,
				"short_id":   shortId,
			},
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": fp,
			},
		}
	} else if security == "tls" {
		out["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    false,
		}
	}
	return out
}

func hysteria2ToSingbox(h2URL, tag string) map[string]interface{} {
	u, err := url.Parse(h2URL)
	if err != nil {
		return nil
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	password := u.Query().Get("auth")
	if password == "" {
		password = u.Query().Get("password")
	}
	sni := u.Query().Get("sni")
	insecureStr := u.Query().Get("insecure")
	insecure := insecureStr == "1" || insecureStr == "true"
	out := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"password":    password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    insecure,
		},
	}
	return out
}

func tuicToSingbox(tuicURL, tag string) map[string]interface{} {
	u, err := url.Parse(tuicURL)
	if err != nil {
		return nil
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	uuid := ""
	password := ""
	if u.User != nil {
		uuid = u.User.Username()
		password, _ = u.User.Password()
	}
	sni := u.Query().Get("sni")
	return map[string]interface{}{
		"type":        "tuic",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
		"password":    password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    false,
		},
	}
}

// ==================== Health Check ====================
func performHealthCheck() {
	gologger.Info().Msg("Starting health check...")
	cacheMutex.RLock()
	configs := make([]string, 0, len(configCache))
	for cfg := range configCache {
		configs = append(configs, cfg)
	}
	cacheMutex.RUnlock()
	if len(configs) == 0 {
		return
	}
	sampleSize := 500
	if len(configs) < sampleSize {
		sampleSize = len(configs)
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	shuffled := make([]string, len(configs))
	copy(shuffled, configs)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	sample := shuffled[:sampleSize]

	var wg sync.WaitGroup
	sem := make(chan struct{}, HealthCheckConcurrency)
	alive := make(map[string]bool)
	var mu sync.Mutex
	for _, cfg := range sample {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if quickCheckWithProtocol(c) {
				mu.Lock()
				alive[c] = true
				mu.Unlock()
			}
		}(cfg)
	}
	wg.Wait()
	gologger.Info().Msgf("Health check: %d/%d configs alive", len(alive), sampleSize)
}

func quickCheckWithProtocol(cfg string) bool {
	re := regexp.MustCompile(`([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\]):(\d+)`)
	matches := re.FindStringSubmatch(cfg)
	if len(matches) < 3 {
		return false
	}
	host := matches[1]
	port := matches[2]
	ctx, cancel := context.WithTimeout(context.Background(), HealthCheckTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ==================== تست نمونه ====================
func testSampleConfigs() {
	cacheMutex.RLock()
	total := len(configCache)
	cacheMutex.RUnlock()
	gologger.Info().Msgf("Total configs in cache: %d", total)
}

// ==================== آمار ====================
func printStats() {
	stats.Lock()
	defer stats.Unlock()
	gologger.Info().Msgf("Statistics: New=%d, Duplicates=%d, Telegram=%d, Subscriptions=%d",
		stats.newCount, stats.duplicateCount, stats.telegramCount, stats.subCount)
	gologger.Info().Msgf("Protocol counts: %v", stats.protoCounts)
	cacheMutex.RLock()
	gologger.Info().Msgf("Total configs in cache: %d", len(configCache))
	cacheMutex.RUnlock()
}
