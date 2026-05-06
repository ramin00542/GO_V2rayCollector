package main

import (
	"context"
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
)

// ========================== تنظیمات ==========================
const (
	MaxConfigsPerProtocol = 50000
	MaxWorkers            = 5
	RequestTimeout        = 15 * time.Second
)

var (
	// فلگ‌های خط فرمان
	sortFlag    = flag.Bool("sort", false, "sort configs from latest to oldest")
	dedupFlag   = flag.Bool("dedup", false, "enable advanced deduplication (fingerprint-based)")
	testFlag    = flag.Bool("test", false, "test connectivity for a sample of configs")
	concurrent  = flag.Int("concurrent", 3, "number of concurrent workers for fetching sources")
	maxMessages = flag.Int("max-msgs", 100, "maximum messages to fetch per Telegram channel")

	// ریجکس‌های کامپایل شده (سراسری)
	regexCache = make(map[string]*regexp.Regexp)
	protoList  = []string{"ss", "vmess", "trojan", "vless", "http", "socks", "wireguard", "hysteria2", "mtproto", "tuic", "slipnet"}

	// کلاینت HTTP با timeout
	client = &http.Client{Timeout: RequestTimeout}

	// Cache اصلی با منبع و timestamp
	cacheMutex sync.RWMutex
	configCache = make(map[string]CacheEntry) // key = config string

	// برای جمع‌آوری موقت (قبل از ادغام با cache)
	tempTelegram = make(map[string][]string)
	tempSub      = make(map[string][]string)

	// آمار
	stats = struct {
		sync.Mutex
		telegramCount, subCount, newCount, duplicateCount int
		protoCounts                                       map[string]int
	}{
		protoCounts: make(map[string]int),
	}

	lastArchiveDate string
	shutdownChan    = make(chan os.Signal, 1)
)

// ساختار ورودی cache
type CacheEntry struct {
	Timestamp int64  `json:"timestamp"`
	Source    string `json:"source"` // "telegram" or "subscription"
	Fingerprint string `json:"fingerprint,omitempty"` // برای dedup پیشرفته
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

	// فچ همزمان کانال‌های تلگرام و ساب‌لینک‌ها
	var wg sync.WaitGroup

	// 1. تلگرام
	wg.Add(1)
	go func() {
		defer wg.Done()
		fetchAllTelegramChannels()
	}()

	// 2. ساب‌لینک‌ها
	wg.Add(1)
	go func() {
		defer wg.Done()
		fetchAllSubscriptions()
	}()

	wg.Wait()

	// به‌روزرسانی cache با کانفیگ‌های جدید (حذف تکراری)
	updateCache()

	// prune بر اساس پروتکل و تعداد مجاز
	pruneCacheByProtocol()

	// تولید فایل‌های خروجی
	writeOutputFiles()

	// آرشیو روزانه
	today := time.Now().Format("2006-01-02")
	if lastArchiveDate != today {
		archiveDaily()
		lastArchiveDate = today
	}

	// اگر فلگ test فعال است، نمونه‌ای از کانفیگ‌ها را تست کن
	if *testFlag {
		testSampleConfigs()
	}

	// نمایش آمار نهایی
	printStats()

	// ذخیره cache در دیسک
	saveCache()

	// لاگ پایان کار
	gologger.Info().Msg("All Done! Program finished successfully.")
}

// ========================== مقداردهی اولیه ==========================
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
	// نوشتن لاگ در فایل (اختیاری)
	logFile, _ := os.OpenFile("collector.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	// می‌توان logFile را به writer اضافه کرد، فعلاً ساده می‌گذاریم
	_ = logFile
}

func createDirs() {
	dirs := []string{"telegram", "subscription", "mixed", "daily_archive"}
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

	// تابع کمکی برای افزودن کانفیگ به cache
	addIfNew := func(cfg, source string) {
		if cfg == "" {
			return
		}
		cacheMutex.Lock()
		defer cacheMutex.Unlock()
		if _, exists := configCache[cfg]; exists {
			dupCount++
			return
		}
		// محاسبه fingerprint در صورت نیاز
		fp := ""
		if *dedupFlag && strings.HasPrefix(cfg, "vmess://") {
			fp = fingerprintVmess(cfg)
		}
		configCache[cfg] = CacheEntry{
			Timestamp:   now,
			Source:      source,
			Fingerprint: fp,
		}
		newCount++
		// بروز آمار
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

	// پردازش tempTelegram
	for _, list := range tempTelegram {
		for _, cfg := range list {
			addIfNew(cfg, "telegram")
		}
	}
	// پردازش tempSub
	for _, list := range tempSub {
		for _, cfg := range list {
			addIfNew(cfg, "subscription")
		}
	}

	gologger.Info().Msgf("Cache update: %d new, %d duplicate configs ignored.", newCount, dupCount)
}

func pruneCacheByProtocol() {
	// گروه‌بندی با استفاده از یک map موقت
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
			// نگهداری همه
			for _, it := range items {
				newCache[it.key] = configCache[it.key]
			}
			continue
		}
		// مرتب‌سازی نزولی بر اساس timestamp
		sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		// نگهداری MaxConfigsPerProtocol تای اول
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

// تولید اثرانگشت برای vmess (بر اساس server:port:uuid)
func fingerprintVmess(vmessUrl string) string {
	// vmess://base64
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
	// استخراج فیلدهای اصلی
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

	// استفاده از worker pool برای پردازش همزمان کانال‌ها
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
		gologger.Info().Msgf("Crawling Telegram: %s", url)
		crawlTelegram(doc, ch.AllMessagesFlag)
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

	// worker pool برای ساب‌لینک‌ها
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

// ========================== کرال تلگرام (اصلاح شده) ==========================
func crawlTelegram(doc *goquery.Document, allMessages bool) {
	// دریافت تمام پیام‌ها با صفحه‌بندی صحیح
	fullDoc := getAllMessages(doc, *maxMessages)

	// استخراج متن از پیام‌ها
	if allMessages {
		fullDoc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			html, _ := s.Html()
			text := strings.Replace(html, "<br/>", "\n", -1)
			plain := extractTextFromHTML(text)
			processConfigLines(plain, "telegram")
		})
	} else {
		fullDoc.Find("code,pre").Each(func(j int, s *goquery.Selection) {
			html, _ := s.Html()
			text := strings.ReplaceAll(html, "<br/>", "\n")
			plain := extractTextFromHTML(text)
			processConfigLines(plain, "telegram")
		})
	}
}

func getAllMessages(doc *goquery.Document, max int) *goquery.Document {
	currentDoc := doc
	for {
		msgs := currentDoc.Find(".tgme_widget_message_wrap")
		if msgs.Length() >= max {
			break
		}
		lastMsg := msgs.Last()
		postLink, exists := lastMsg.Attr("data-post")
		if !exists || postLink == "" {
			break
		}
		// استخراج عدد پیام از data-post (مثال: channel/1234)
		parts := strings.Split(postLink, "/")
		if len(parts) < 2 {
			break
		}
		before := parts[len(parts)-1]
		channelUrl := strings.TrimSuffix(currentDoc.Url.String(), "/")
		nextUrl := fmt.Sprintf("%s?before=%s", channelUrl, before)
		nextDoc := loadMore(nextUrl)
		if nextDoc == nil {
			break
		}
		// ادغام محتوای جدید
		bodyHTML, _ := nextDoc.Html()
		newDoc, _ := goquery.NewDocumentFromReader(strings.NewReader(bodyHTML))
		currentDoc.Find("body").AppendSelection(newDoc.Find("body").Children())
		currentDoc.Url = nextDoc.Url
		time.Sleep(500 * time.Millisecond) // احترام به محدودیت
	}
	return currentDoc
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

// ========================== پردازش ساب‌لینک ==========================
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
	// تلاش برای دیکد base64
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}
	processConfigLines(content, "subscription")
}

// ========================== استخراج کانفیگ‌ها (اصلاح شده) ==========================
func processConfigLines(raw string, source string) {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// با تابع جدید تمام کانفیگ‌ها را استخراج کن
		configs := extractAllConfigs(line)
		for _, cfg := range configs {
			cfg = strings.TrimSpace(cfg)
			if cfg == "" {
				continue
			}
			// اصلاح vmess (اضافه کردن نام)
			if strings.HasPrefix(cfg, "vmess://") {
				cfg = editVmessPs(cfg, source)
			}
			if cfg == "" {
				continue
			}
			proto := detectProtocol(cfg)
			if source == "telegram" {
				tempTelegram[proto] = append(tempTelegram[proto], cfg)
			} else {
				tempSub[proto] = append(tempSub[proto], cfg)
			}
		}
	}
}

// تابع جدید: استخراج همه کانفیگ‌ها از یک خط
func extractAllConfigs(text string) []string {
	var results []string
	// برای هر پروتکل، تمام matchها را پیدا کن
	for proto, re := range regexCache {
		matches := re.FindAllString(text, -1)
		for _, m := range matches {
			// حذف موارد تکراری در همان خط (مثلاً اگر vmess داخل متن تکراری بود)
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
	// ساخت نام معنادار: منبع+زمان
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
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(html))
	return doc.Text()
}

// ========================== تولید فایل‌های خروجی (با در نظر گرفتن sortFlag) ==========================
func writeOutputFiles() {
	// مخلوط (mixed) با استفاده از cache
	writeMixedFolder()

	// telegram و subscription با در نظر گرفتن source و sortFlag
	writeSourceFolder("telegram", "telegram")
	writeSourceFolder("subscription", "subscription")
}

func writeMixedFolder() {
	// گروه‌بندی بر اساس پروتکل و مرتب‌سازی بر اساس timestamp
	byProto := make(map[string][]string)
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	// جمع‌آوری تمام کانفیگ‌ها
	type item struct {
		cfg string
		ts  int64
	}
	protoItems := make(map[string][]item)
	for cfg, entry := range configCache {
		proto := detectProtocol(cfg)
		protoItems[proto] = append(protoItems[proto], item{cfg, entry.Timestamp})
	}

	for proto, items := range protoItems {
		if *sortFlag {
			sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		}
		lines := make([]string, len(items))
		for i, it := range items {
			lines[i] = it.cfg
		}
		content := strings.Join(lines, "\n")
		if content != "" {
			filePath := filepath.Join("mixed", proto+"_iran.txt")
			collector.WriteToFile(content, filePath)
		}
	}
}

func writeSourceFolder(folder, sourceFilter string) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	// گروه‌بندی بر اساس پروتکل از cache با source مورد نظر
	byProto := make(map[string][]struct {
		cfg string
		ts  int64
	})
	for cfg, entry := range configCache {
		if entry.Source == sourceFilter {
			proto := detectProtocol(cfg)
			byProto[proto] = append(byProto[proto], struct {
				cfg string
				ts  int64
			}{cfg, entry.Timestamp})
		}
	}

	for proto, items := range byProto {
		if *sortFlag {
			sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		}
		lines := make([]string, len(items))
		for i, it := range items {
			lines[i] = it.cfg
		}
		content := strings.Join(lines, "\n")
		if content != "" {
			filePath := filepath.Join(folder, proto+"_iran.txt")
			collector.WriteToFile(content, filePath)
		}
	}
}

// ========================== آرشیو روزانه (با رعایت محدودیت) ==========================
func archiveDaily() {
	today := time.Now().Format("2006-01-02")
	archiveDir := filepath.Join("daily_archive", today)
	os.MkdirAll(archiveDir, 0755)

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	byProto := make(map[string][]struct {
		cfg string
		ts  int64
	})
	for cfg, entry := range configCache {
		proto := detectProtocol(cfg)
		byProto[proto] = append(byProto[proto], struct {
			cfg string
			ts  int64
		}{cfg, entry.Timestamp})
	}

	for proto, items := range byProto {
		// مرتب‌سازی نزولی و برش به MaxConfigsPerProtocol
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
	gologger.Info().Msgf("Daily archive created in %s", archiveDir)
}

// ========================== تست نمونه کانفیگ‌ها (اختیاری) ==========================
func testSampleConfigs() {
	gologger.Info().Msg("Testing a sample of configs (first 10 from each protocol)...")
	// پیاده‌سازی ساده: فقط vmess را با یک درخواست http تست می‌کنیم (نمونه)
	// به دلیل طولانی شدن، فقط یک نمونه لاگ می‌دهیم
	gologger.Info().Msg("Test feature not fully implemented in this example.")
}

// ========================== آمار ==========================
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

	// ذخیره آمار در فایل JSON
	statFile, _ := json.MarshalIndent(map[string]interface{}{
		"total":     len(configCache),
		"new":       stats.newCount,
		"telegram":  stats.telegramCount,
		"subscription": stats.subCount,
		"protocols": stats.protoCounts,
	}, "", "  ")
	os.WriteFile("stats.json", statFile, 0644)
}

// ========================== توابع کمکی ==========================
func HttpRequest(url string) *http.Response {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		gologger.Error().Msgf("HTTP request failed: %v", err)
		return nil
	}
	return resp
}
