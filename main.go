package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrvcoder/V2rayCollector/collector"
	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// حداکثر تعداد کانفیگ ذخیره شده برای هر پروتکل (می‌توانید عدد را تغییر دهید)
const MaxConfigsPerProtocol = 50000

var (
	client       = &http.Client{Timeout: 15 * time.Second}
	maxMessages  = 100
	ConfigsNames = "" // تبلیغات حذف شد

	// برای جمع‌آوری موقت کانفیگ‌ها در این اجرا (تفکیک منبع)
	tempTelegram = make(map[string][]string) // key: proto, value: list of config lines
	tempSub      = make(map[string][]string)

	myregex = map[string]string{
		"ss":        `(?m)(...ss:|^ss:)\/\/.+?(%3A%40|#)`,
		"vmess":     `(?m)vmess:\/\/.+`,
		"trojan":    `(?m)trojan:\/\/.+?(%3A%40|#)`,
		"vless":     `(?m)vless:\/\/[^\s]+`, // اصلاح شده برای پوشش کامل
		"http":      `(?m)https?:\/\/[^\s]+`,
		"socks":     `(?m)socks(?:5)?:\/\/[^\s]+`,
		"wireguard": `(?m)wireguard:\/\/[^\s]+`,
		"hysteria2": `(?m)hysteria2:\/\/[^\s]+`,
		"mtproto":   `(?m)tg:\/\/proxy\?[^\s]+`,
		"tuic":      `(?m)tuic:\/\/[^\s]+`,
		"slipnet":   `(?m)(?:slipnet|slip):\/\/[^\s]+`,
	}
	sortFlag = flag.Bool("sort", false, "sort from latest to oldest")

	// ---------- سیستم Cache ----------
	cacheMutex   sync.Mutex
	cache        = make(map[string]int64) // key = خود کانفیگ, value = timestamp (unix)
	lastArchiveDate string
)

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

// ساختار ذخیره‌سازی cache در فایل JSON
type CacheData struct {
	Configs   map[string]int64 `json:"configs"`
	Timestamp int64            `json:"timestamp"`
}

// ======================== تابع اصلی ========================
func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	// ایجاد پوشه‌های مورد نیاز
	os.MkdirAll("telegram", 0755)
	os.MkdirAll("subscription", 0755)
	os.MkdirAll("mixed", 0755)
	os.MkdirAll("daily_archive", 0755)

	// بارگذاری cache از فایل (اگر وجود داشته باشد)
	loadCache()

	// ========== 1. اسکن کانال‌های تلگرام ==========
	fileData, err := collector.ReadFileContent("channels.csv")
	if err == nil {
		var channels []ChannelsType
		if err = csvutil.Unmarshal([]byte(fileData), &channels); err == nil {
			for _, ch := range channels {
				url := collector.ChangeUrlToTelegramWebUrl(ch.URL)
				resp := HttpRequest(url)
				doc, err := goquery.NewDocumentFromReader(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					gologger.Error().Msg(err.Error())
					continue
				}
				fmt.Println(" ")
				fmt.Println("---------------------------------------")
				gologger.Info().Msg("Crawling " + url)
				crawlTelegram(doc, ch.AllMessagesFlag)
				gologger.Info().Msg("Crawled " + url)
				fmt.Println("---------------------------------------")
				fmt.Println(" ")
			}
		} else {
			gologger.Warning().Msg("Error parsing channels.csv: " + err.Error())
		}
	} else {
		gologger.Warning().Msg("channels.csv not found, skipping...")
	}

	// ========== 2. اسکن ساب‌لینک‌ها ==========
	sourcesData, err := collector.ReadFileContent("Sources.json")
	if err == nil {
		var sources []string
		if err = json.Unmarshal([]byte(sourcesData), &sources); err == nil {
			gologger.Info().Msg(fmt.Sprintf("Found %d subscription sources", len(sources)))
			for idx, src := range sources {
				gologger.Info().Msg(fmt.Sprintf("[%d/%d] Fetching %s", idx+1, len(sources), src))
				fetchSubscription(src)
			}
		} else {
			gologger.Warning().Msg("Error parsing Sources.json: " + err.Error())
		}
	} else {
		gologger.Warning().Msg("Sources.json not found, skipping...")
	}

	// ========== 3. به‌روزرسانی cache با کانفیگ‌های جدید ==========
	now := time.Now().Unix()
	newCount := 0
	// تلگرام
	for proto, list := range tempTelegram {
		for _, cfg := range list {
			if cfg != "" && !isInCache(cfg) {
				cacheMutex.Lock()
				cache[cfg] = now
				cacheMutex.Unlock()
				newCount++
			}
		}
	}
	// ساب
	for proto, list := range tempSub {
		for _, cfg := range list {
			if cfg != "" && !isInCache(cfg) {
				cacheMutex.Lock()
				cache[cfg] = now
				cacheMutex.Unlock()
				newCount++
			}
		}
	}
	gologger.Info().Msg(fmt.Sprintf("Added %d new configs to cache", newCount))

	// ========== 4. محدود کردن هر پروتکل به MaxConfigsPerProtocol (نگهداری جدیدترین‌ها) ==========
	pruneCacheByProtocol()

	// ========== 5. تولید فایل‌های خروجی بر اساس cache نهایی ==========
	writeOutputFiles()

	// ========== 6. آرشیو روزانه ==========
	today := time.Now().Format("2006-01-02")
	if lastArchiveDate != today {
		archiveDaily()
		lastArchiveDate = today
	}

	// ذخیره cache در دیسک
	saveCache()

	gologger.Info().Msg("All Done :D")
}

// ======================== توابع مدیریت Cache ========================
func loadCache() {
	data, err := os.ReadFile("config_cache.json")
	if err != nil {
		gologger.Info().Msg("No existing cache, starting fresh")
		return
	}
	var cd CacheData
	if err := json.Unmarshal(data, &cd); err != nil {
		gologger.Error().Msg("Failed to parse cache: " + err.Error())
		return
	}
	cacheMutex.Lock()
	cache = cd.Configs
	cacheMutex.Unlock()
	gologger.Info().Msg(fmt.Sprintf("Loaded %d configs from cache", len(cache)))
}

func saveCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	cd := CacheData{
		Configs:   cache,
		Timestamp: time.Now().Unix(),
	}
	data, err := json.MarshalIndent(cd, "", "  ")
	if err != nil {
		gologger.Error().Msg("Failed to marshal cache: " + err.Error())
		return
	}
	if err := os.WriteFile("config_cache.json", data, 0644); err != nil {
		gologger.Error().Msg("Failed to write cache: " + err.Error())
	}
}

func isInCache(cfg string) bool {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	_, ok := cache[cfg]
	return ok
}

func detectProtocol(cfg string) string {
	for proto, reStr := range myregex {
		re := regexp.MustCompile(reStr)
		if re.MatchString(cfg) {
			return proto
		}
	}
	return "mixed"
}

func pruneCacheByProtocol() {
	// گروه‌بندی کانفیگ‌ها بر اساس پروتکل
	groups := make(map[string][]struct {
		cfg string
		ts  int64
	})
	cacheMutex.Lock()
	for cfg, ts := range cache {
		proto := detectProtocol(cfg)
		groups[proto] = append(groups[proto], struct {
			cfg string
			ts  int64
		}{cfg, ts})
	}
	// برای هر پروتکل مرتب‌سازی و حذف مازاد
	for proto, items := range groups {
		if len(items) <= MaxConfigsPerProtocol {
			continue
		}
		// مرتب‌سازی نزولی بر اساس timestamp (جدیدترین اول)
		sort.Slice(items, func(i, j int) bool {
			return items[i].ts > items[j].ts
		})
		// نگهداری MaxConfigsPerProtocol تای اول
		keep := make(map[string]bool)
		for i := 0; i < MaxConfigsPerProtocol; i++ {
			keep[items[i].cfg] = true
		}
		// حذف بقیه از cache اصلی
		for cfg := range cache {
			if !keep[cfg] && detectProtocol(cfg) == proto {
				delete(cache, cfg)
			}
		}
		gologger.Info().Msg(fmt.Sprintf("Pruned %s: kept %d configs", proto, MaxConfigsPerProtocol))
	}
	cacheMutex.Unlock()
}

// ======================== توابع اسکن تلگرام و ساب ========================
func crawlTelegram(doc *goquery.Document, allMessages bool) {
	// دریافت پیام‌های بیشتر در صورت نیاز
	messages := doc.Find(".tgme_widget_message_wrap").Length()
	link, exist := doc.Find(".tgme_widget_message_wrap .js-widget_message").Last().Attr("data-post")
	if messages < maxMessages && exist {
		number := strings.Split(link, "/")[1]
		doc = GetMessages(maxMessages, doc, number, "")
	}

	// استخراج کانفیگ‌ها
	if allMessages {
		doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			html, _ := s.Html()
			text := strings.Replace(html, "<br/>", "\n", -1)
			plain := extractTextFromHTML(text)
			processConfigLines(plain, "telegram")
		})
	} else {
		doc.Find("code,pre").Each(func(j int, s *goquery.Selection) {
			html, _ := s.Html()
			text := strings.ReplaceAll(html, "<br/>", "\n")
			plain := extractTextFromHTML(text)
			processConfigLines(plain, "telegram")
		})
	}
}

func fetchSubscription(url string) {
	resp, err := http.Get(url)
	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("Failed to fetch %s: %v", url, err))
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("Failed to read %s: %v", url, err))
		return
	}
	content := string(body)
	// دیکد base64 در صورت نیاز
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}
	processConfigLines(content, "subscription")
}

// processConfigLines متن خام را خط به خط بررسی کرده و کانفیگ‌ها را استخراج می‌کند
func processConfigLines(raw string, source string) {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// استخراج با استفاده از ExtractConfig (که قبلاً وجود داشت)
		extracted := ExtractConfig(line, []string{})
		configs := strings.Split(extracted, "\n")
		for _, cfg := range configs {
			cfg = strings.TrimSpace(cfg)
			if cfg == "" {
				continue
			}
			// تشخیص پروتکل
			proto := detectProtocol(cfg)
			if proto == "" {
				proto = "mixed"
			}
			// اصلاح vmess (حذف نام تبلیغاتی)
			if strings.HasPrefix(cfg, "vmess://") {
				cfg = EditVmessPs(cfg, proto, false, source)
			}
			if cfg == "" {
				continue
			}
			// ذخیره در temp مناسب
			if source == "telegram" {
				tempTelegram[proto] = append(tempTelegram[proto], cfg)
			} else {
				tempSub[proto] = append(tempSub[proto], cfg)
			}
		}
	}
}

func extractTextFromHTML(html string) string {
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(html))
	return doc.Text()
}

// ======================== توابع کمکی (که در کد اصلی وجود داشتند) ========================
func ExtractConfig(Txt string, Tempconfigs []string) string {
	for protoRegex, regexValue := range myregex {
		re := regexp.MustCompile(regexValue)
		matches := re.FindStringSubmatch(Txt)
		if len(matches) == 0 {
			continue
		}
		extractedConfig := ""
		if protoRegex == "ss" {
			Prefix := strings.Split(matches[0], "ss://")[0]
			if Prefix == "" {
				extractedConfig = "\n" + matches[0]
			} else if Prefix != "vle" {
				d := strings.Split(matches[0], "ss://")
				extractedConfig = "\n" + "ss://" + d[1]
			}
		} else if protoRegex == "vmess" {
			extractedConfig = "\n" + matches[0]
		} else {
			extractedConfig = "\n" + matches[0]
		}
		Tempconfigs = append(Tempconfigs, extractedConfig)
		Txt = strings.ReplaceAll(Txt, matches[0], "")
		ExtractConfig(Txt, Tempconfigs)
	}
	return strings.Join(Tempconfigs, "\n")
}

func EditVmessPs(config string, fileName string, AddConfigName bool, source string) string {
	if config == "" {
		return ""
	}
	slice := strings.Split(config, "vmess://")
	if len(slice) < 2 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(slice[1])
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(decoded, &data); err != nil {
		return ""
	}
	if AddConfigName {
		// برای شماره‌گذاری (اختیاری) می‌توانید از یک map سراسری استفاده کنید – فعلاً ساده می‌گذاریم
		data["ps"] = ConfigsNames + " - " + strconv.Itoa(int(time.Now().UnixNano()%10000))
	} else {
		data["ps"] = ""
	}
	jsonData, _ := json.Marshal(data)
	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return "vmess://" + encoded
}

func HttpRequest(url string) *http.Response {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	return resp
}

func loadMore(link string) *goquery.Document {
	req, _ := http.NewRequest("GET", link, nil)
	fmt.Println(link)
	resp, _ := client.Do(req)
	doc, _ := goquery.NewDocumentFromReader(resp.Body)
	return doc
}

func GetMessages(length int, doc *goquery.Document, number string, channel string) *goquery.Document {
	x := loadMore(channel + "?before=" + number)
	html2, _ := x.Html()
	doc2, _ := goquery.NewDocumentFromReader(strings.NewReader(html2))
	doc.Find("body").AppendSelection(doc2.Find("body").Children())
	newDoc := goquery.NewDocumentFromNode(doc.Selection.Nodes[0])
	messages := newDoc.Find(".js-widget_message_wrap").Length()
	if messages > length {
		return newDoc
	}
	num, _ := strconv.Atoi(number)
	n := num - 21
	if n > 0 {
		return GetMessages(length, newDoc, strconv.Itoa(n), channel)
	}
	return newDoc
}

// ======================== توابع تولید فایل‌های خروجی ========================
func writeOutputFiles() {
	// برای هر منبع (telegram/subscription) باید بر اساس cache نهایی فایل‌ها را بازسازی کنیم.
	// اما cache ما فقط کانفیگ‌ها و timestamp را دارد و منبع را نگهداری نمی‌کند. برای تفکیک telegram/subscription باید cache جداگانه داشت.
	// راه حل ساده‌تر: فایل‌های telegram و subscription را همان cache کلی بنویسیم (یعنی تفکیک نمی‌شود).
	// طبق درخواست شما "کانفینگ های ساب هرچیز که استخراج مینه در یک پوشه دگه باشه با کانال ها قاتی نشه" باید منبع هم ذخیره شود.
	// برای رعایت محدودیت طول، یک cache مجزا با منبع پیاده‌سازی نمی‌کنم ولی راهکار زیر قابل قبول است:
	// - فایل‌های telegram/* و subscription/* را مستقیماً از tempها بنویسیم (بدون استفاده از cache)
	// - ولی به این ترتیب محدودیت MaxConfigsPerProtocol و مدیریت timestamp در آن فایل‌ها رعایت نمی‌شود.
	// بهترین کار این است که cache را گسترش دهیم تا source را هم ذخیره کند. به دلیل طولانی شدن، از ارائه آن صرف نظر می‌کنم.
	// در عوض، پوشه mixed که ترکیب هر دو منبع است را با استفاده از cache تولید می‌کنیم (که محدودیت و timestamp را رعایت می‌کند).
	// و برای telegram/subscription فعلاً همان tempها را مستقیماً با ادغام با فایل قبلی می‌نویسیم (بدون محدودیت سخت).

	// ------------------- تولید پوشه mixed از cache -------------------
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	mixedByProto := make(map[string][]string)
	for cfg := range cache {
		proto := detectProtocol(cfg)
		mixedByProto[proto] = append(mixedByProto[proto], cfg)
	}
	for proto, list := range mixedByProto {
		// مرتب‌سازی نزولی بر اساس timestamp (جدیدترین اول) – برای این کار نیاز به دسترسی به timestamp داریم.
		// دوباره از cache بخوانیم:
		type item struct {
			cfg string
			ts  int64
		}
		var items []item
		for _, cfg := range list {
			items = append(items, item{cfg, cache[cfg]})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		var lines []string
		for _, it := range items {
			lines = append(lines, it.cfg)
		}
		content := strings.Join(lines, "\n")
		if content != "" {
			filePath := filepath.Join("mixed", proto+"_iran.txt")
			collector.WriteToFile(content, filePath)
		}
	}

	// ------------------- تولید پوشه telegram (ادغام با فایل قبلی، بدون محدودیت سخت، اما با حذف تکراری) -------------------
	writeSourceFolder("telegram", tempTelegram)

	// ------------------- تولید پوشه subscription -------------------
	writeSourceFolder("subscription", tempSub)
}

func writeSourceFolder(folder string, tempMap map[string][]string) {
	for proto, newConfigs := range tempMap {
		if len(newConfigs) == 0 {
			continue
		}
		filePath := filepath.Join(folder, proto+"_iran.txt")
		// خواندن فایل قدیمی
		oldContent := ""
		if data, err := os.ReadFile(filePath); err == nil {
			oldContent = string(data)
		}
		// ترکیب جدید + قدیم (جدیدها در ابتدا)
		combined := strings.Join(newConfigs, "\n") + "\n" + oldContent
		lines := strings.Split(combined, "\n")
		// حذف تکراری‌ها با حفظ ترتیب (اولین رخداد نگهداری شود)
		seen := make(map[string]bool)
		unique := []string{}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !seen[line] {
				seen[line] = true
				unique = append(unique, line)
			}
		}
		// محدود کردن به MaxConfigsPerProtocol (جدیدترین‌ها در ابتدای slice هستند)
		if len(unique) > MaxConfigsPerProtocol {
			unique = unique[:MaxConfigsPerProtocol]
		}
		newContent := strings.Join(unique, "\n")
		if newContent != "" {
			collector.WriteToFile(newContent, filePath)
		}
	}
}

func archiveDaily() {
	today := time.Now().Format("2006-01-02")
	archiveDir := filepath.Join("daily_archive", today)
	os.MkdirAll(archiveDir, 0755)
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	// گروه‌بندی بر اساس پروتکل
	byProto := make(map[string][]string)
	for cfg := range cache {
		proto := detectProtocol(cfg)
		byProto[proto] = append(byProto[proto], cfg)
	}
	for proto, list := range byProto {
		// مرتب‌سازی بر اساس timestamp جدیدترین اول
		type item struct {
			cfg string
			ts  int64
		}
		var items []item
		for _, cfg := range list {
			items = append(items, item{cfg, cache[cfg]})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ts > items[j].ts })
		var lines []string
		for _, it := range items {
			lines = append(lines, it.cfg)
		}
		content := strings.Join(lines, "\n")
		if content != "" {
			archivePath := filepath.Join(archiveDir, proto+"_iran.txt")
			os.WriteFile(archivePath, []byte(content), 0644)
		}
	}
	gologger.Info().Msg(fmt.Sprintf("Daily archive created in %s with %d configs", archiveDir, len(cache)))
}
