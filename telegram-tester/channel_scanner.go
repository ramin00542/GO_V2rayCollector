// telegram-tester/channel_scanner.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	defaultActiveDays     = 30
	defaultConcurrency    = 5
	defaultRetryCount     = 3
	defaultBaseDelay      = 1 * time.Second
	defaultJitter         = 500 * time.Millisecond
	dataDir               = "../data"
	deadChannelsRecent    = dataDir + "/dead_channels_recent.json"
	deadChannelsOld       = dataDir + "/dead_channels_old.json"
	activeChannelsFile    = "../channels.csv"
	channelsReportFile    = "../reports/channels_report.md"
)

var (
	inputCSV      = flag.String("input", "channels.csv", "Input CSV file")
	outputCSV     = flag.String("output", "channels.csv", "Output CSV file")
	activeDays    = flag.Int("active-days", defaultActiveDays, "Max inactive days")
	concurrency   = flag.Int("concurrency", defaultConcurrency, "Number of concurrent workers")
	noRSS         = flag.Bool("no-rss", false, "Use HTML instead of RSS")
	oldScan       = flag.Bool("old-scan", false, "Scan only channels older than 365 days (yearly)")
)

var (
	client = &http.Client{Timeout: 15 * time.Second}
	regexPatterns = []*regexp.Regexp{
		regexp.MustCompile(`vmess://[A-Za-z0-9+/]+={0,2}(?:\?[^\s]*)?`),
		regexp.MustCompile(`vless://[^\s]+`),
		regexp.MustCompile(`trojan://[^@\s]+@[^\s]+`),
		regexp.MustCompile(`ss://[A-Za-z0-9+/]+={0,2}@[^\s]+`),
		regexp.MustCompile(`ssr://[A-Za-z0-9+/=]+`),
		regexp.MustCompile(`hysteria2://[^\s]+`),
		regexp.MustCompile(`tuic://[^\s]+`),
		regexp.MustCompile(`wireguard://[^\s]+`),
		regexp.MustCompile(`tg://proxy\?[^\s]+`),
		regexp.MustCompile(`(?:slipnet|slip)://[^\s]+`),
		regexp.MustCompile(`https?://[^\s]+:\d+(?:[^\s]*)?`),
		regexp.MustCompile(`https?://[^@\s]+@[^\s]+`),
		regexp.MustCompile(`socks(?:5)?://[^\s]+@[^\s]+`),
		regexp.MustCompile(`socks(?:5)?://[^\s]+:\d+`),
	}
)

type DeadChannelInfo struct {
	URL       string `json:"url"`
	LastPost  int64  `json:"last_post"`
	CheckedAt int64  `json:"checked_at"`
}

type ScanResult struct {
	URL          string    `json:"url"`
	LastPost     time.Time `json:"last_post"`
	HasConfig    bool      `json:"has_config"`
	Status       string    `json:"status"`
	MessageCount int       `json:"msg_count"`
	Error        string    `json:"error,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

var printMutex sync.Mutex

func safePrintf(format string, args ...interface{}) {
	printMutex.Lock()
	defer printMutex.Unlock()
	fmt.Printf(format, args...)
}

func main() {
	flag.Parse()
	os.MkdirAll("../reports", 0755)
	os.MkdirAll(dataDir, 0755)

	// بارگذاری آرشیوهای موجود
	recentDead := loadDeadArchive(deadChannelsRecent)
	oldDead := loadDeadArchive(deadChannelsOld)

	// خواندن کانال‌های فعال فعلی از CSV (فقط برای اسکن)
	records, headers, err := readCSV(*inputCSV)
	if err != nil {
		fmt.Printf("Error reading CSV: %v\n", err)
		os.Exit(1)
	}
	if len(records) == 0 {
		fmt.Println("No channels found.")
		generateEmptyChannelsReport()
		return
	}

	// ساخت لیست URLهایی که باید اسکن شوند
	urlSet := make(map[string]bool)
	for _, row := range records {
		if len(row) > 0 {
			urlSet[row[0]] = true
		}
	}
	if *oldScan {
		for url := range oldDead {
			urlSet[url] = true
		}
	} else {
		for url := range recentDead {
			urlSet[url] = true
		}
	}
	urlList := make([]string, 0, len(urlSet))
	for u := range urlSet {
		urlList = append(urlList, u)
	}

	if len(urlList) == 0 {
		fmt.Println("No channels to scan.")
		return
	}

	// اسکن همزمان
	jobs := make(chan string, len(urlList))
	results := make(chan ScanResult, len(urlList))
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}
	for _, url := range urlList {
		jobs <- url
	}
	close(jobs)
	wg.Wait()
	close(results)

	// پردازش نتایج
	var activeList []ScanResult
	updatedRecent := make(map[string]DeadChannelInfo)
	updatedOld := make(map[string]DeadChannelInfo)

	for res := range results {
		if res.Status == "active" {
			activeList = append(activeList, res)
			// حذف از هر دو آرشیو
			delete(recentDead, res.URL)
			delete(oldDead, res.URL)
		} else {
			daysSince := 0
			if !res.LastPost.IsZero() {
				daysSince = int(time.Since(res.LastPost).Hours() / 24)
			}
			info := DeadChannelInfo{
				URL:       res.URL,
				LastPost:  res.LastPost.Unix(),
				CheckedAt: time.Now().Unix(),
			}
			if daysSince > 365 {
				updatedOld[res.URL] = info
				delete(recentDead, res.URL)
			} else {
				updatedRecent[res.URL] = info
				delete(oldDead, res.URL)
			}
		}
	}
	// حفظ موارد اسکن نشده از آرشیوهای قبلی
	for k, v := range recentDead {
		updatedRecent[k] = v
	}
	for k, v := range oldDead {
		updatedOld[k] = v
	}

	// بازنویسی channels.csv فقط با کانال‌های فعال
	if err := writeActiveCSV(*outputCSV, headers, activeList); err != nil {
		fmt.Printf("Error writing CSV: %v\n", err)
	} else {
		fmt.Printf("✅ Updated %s with %d active channels.\n", *outputCSV, len(activeList))
	}

	// ذخیره آرشیوها
	saveDeadArchive(deadChannelsRecent, updatedRecent)
	saveDeadArchive(deadChannelsOld, updatedOld)
	generateChannelsReport(activeList, len(urlList))
	fmt.Printf("\n✅ Active: %d, Recent dead: %d, Old dead: %d\n", len(activeList), len(updatedRecent), len(updatedOld))
}

func worker(jobs <-chan string, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for url := range jobs {
		res := analyzeWithRetry(url)
		results <- res
	}
}

func analyzeWithRetry(url string) ScanResult {
	var lastErr error
	for attempt := 1; attempt <= defaultRetryCount; attempt++ {
		res, err := analyzeFull(url)
		if err == nil {
			return res
		}
		lastErr = err
		delay := defaultBaseDelay * time.Duration(1<<uint(attempt-1))
		jitter := time.Duration(rand.Int63n(int64(defaultJitter)))
		time.Sleep(delay + jitter)
	}
	return ScanResult{URL: url, Status: "error", Error: lastErr.Error(), Timestamp: time.Now()}
}

func analyzeFull(channelURL string) (ScanResult, error) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return ScanResult{}, fmt.Errorf("invalid URL")
	}
	if !*noRSS {
		rssURL := fmt.Sprintf("https://t.me/s/%s.rss", channelName)
		res, err := fetchFromRSS(rssURL, channelURL)
		if err == nil {
			return res, nil
		}
	}
	htmlURL := fmt.Sprintf("https://t.me/s/%s", channelName)
	return fetchFromHTML(htmlURL, channelURL)
}

func fetchFromRSS(rssURL, origURL string) (ScanResult, error) {
	resp, err := client.Get(rssURL)
	if err != nil {
		return ScanResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ScanResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ScanResult{}, err
	}
	var latestTime time.Time
	var anyConfig bool
	msgCount := doc.Find("item").Length()
	doc.Find("item").Each(func(i int, s *goquery.Selection) {
		pubDate := s.Find("pubDate").Text()
		if pubDate != "" {
			t, err := time.Parse(time.RFC1123Z, pubDate)
			if err == nil && (latestTime.IsZero() || t.After(latestTime)) {
				latestTime = t
			}
		}
		desc := s.Find("description").Text()
		if anyConfigInText(desc) {
			anyConfig = true
		}
	})
	if latestTime.IsZero() {
		return ScanResult{}, fmt.Errorf("no valid pubDate")
	}
	daysSince := int(time.Since(latestTime).Hours() / 24)
	status := "inactive"
	if anyConfig && daysSince <= *activeDays {
		status = "active"
	}
	safePrintf("[INFO] %s -> last: %s (%d days), config: %v, status: %s\n",
		origURL, latestTime.Format("2006-01-02"), daysSince, anyConfig, status)
	return ScanResult{
		URL:          origURL,
		LastPost:     latestTime,
		HasConfig:    anyConfig,
		Status:       status,
		MessageCount: msgCount,
		Timestamp:    time.Now(),
	}, nil
}

func fetchFromHTML(htmlURL, origURL string) (ScanResult, error) {
	resp, err := client.Get(htmlURL)
	if err != nil {
		return ScanResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return ScanResult{URL: origURL, Status: "banned", Error: "channel not found", Timestamp: time.Now()}, nil
	}
	if resp.StatusCode != 200 {
		return ScanResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ScanResult{}, err
	}
	var lastTime time.Time
	doc.Find("time").Each(func(i int, s *goquery.Selection) {
		if i == 0 {
			if dt, ok := s.Attr("datetime"); ok {
				if t, err := time.Parse(time.RFC3339, dt); err == nil {
					lastTime = t
				}
			}
		}
	})
	if lastTime.IsZero() {
		doc.Find(".datetime").Each(func(i int, s *goquery.Selection) {
			if i == 0 {
				if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s.Text())); err == nil {
					lastTime = t
				}
			}
		})
	}
	msgCount := doc.Find(".tgme_widget_message_wrap").Length()
	var texts []string
	doc.Find(".tgme_widget_message_text, pre, code").Each(func(i int, s *goquery.Selection) {
		texts = append(texts, s.Text())
	})
	has := anyConfigInText(strings.Join(texts, "\n"))
	if lastTime.IsZero() {
		return ScanResult{}, fmt.Errorf("no timestamp found")
	}
	daysSince := int(time.Since(lastTime).Hours() / 24)
	status := "inactive"
	if has && daysSince <= *activeDays {
		status = "active"
	}
	safePrintf("[INFO] %s -> last: %s (%d days), config: %v, status: %s\n",
		origURL, lastTime.Format("2006-01-02"), daysSince, has, status)
	return ScanResult{
		URL:          origURL,
		LastPost:     lastTime,
		HasConfig:    has,
		Status:       status,
		MessageCount: msgCount,
		Timestamp:    time.Now(),
	}, nil
}

func anyConfigInText(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func extractChannelName(rawURL string) string {
	re := regexp.MustCompile(`t\.me/(?:s/)?([^/?]+)`)
	m := re.FindStringSubmatch(rawURL)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// ---------- توابع کمکی ----------

// readCSV خواندن فایل CSV و بازگرداندن رکوردها و هدر
func readCSV(path string) ([][]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	rd := csv.NewReader(f)           // ← تغییر این خط
	rd.FieldsPerRecord = -1
	all, err := rd.ReadAll()         // ← اینجا هم از rd استفاده کنید
	if err != nil {
		return nil, nil, err
	}
	if len(all) == 0 {
		return nil, nil, nil
	}
	return all[1:], all[0], nil
}

// writeActiveCSV بازنویسی کامل CSV با فقط کانال‌های فعال
func writeActiveCSV(path string, oldHeaders []string, active []ScanResult) error {
	// تعیین هدر نهایی: اطمینان از وجود ستون‌های Status و AllMessagesFlag
	headers := make([]string, len(oldHeaders))
	copy(headers, oldHeaders)
	statusIdx := -1
	flagIdx := -1
	for i, h := range headers {
		if strings.EqualFold(h, "Status") {
			statusIdx = i
		}
		if strings.EqualFold(h, "AllMessagesFlag") {
			flagIdx = i
		}
	}
	if statusIdx == -1 {
		headers = append(headers, "Status")
		statusIdx = len(headers) - 1
	}
	if flagIdx == -1 {
		headers = append(headers, "AllMessagesFlag")
		flagIdx = len(headers) - 1
	}

	rows := make([][]string, 0, len(active))
	for _, res := range active {
		row := make([]string, len(headers))
		row[0] = res.URL // فرض اولی URL است
		row[statusIdx] = "active"
		row[flagIdx] = "true"
		rows = append(rows, row)
	}

	outFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer outFile.Close()
	w := csv.NewWriter(outFile)
	defer w.Flush()
	if err := w.Write(headers); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func loadDeadArchive(file string) map[string]DeadChannelInfo {
	m := make(map[string]DeadChannelInfo)
	data, err := os.ReadFile(file)
	if err != nil {
		return m
	}
	var list []DeadChannelInfo
	if err := json.Unmarshal(data, &list); err != nil {
		return m
	}
	for _, item := range list {
		m[item.URL] = item
	}
	return m
}

func saveDeadArchive(file string, m map[string]DeadChannelInfo) {
	list := make([]DeadChannelInfo, 0, len(m))
	for _, v := range m {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].URL < list[j].URL })
	data, _ := json.MarshalIndent(list, "", "  ")
	os.WriteFile(file, data, 0644)
	fmt.Printf("✅ Saved %s with %d entries.\n", file, len(list))
}

func generateEmptyChannelsReport() {
	report := fmt.Sprintf(`# 📊 گزارش اسکنر کانال‌های تلگرام

**تاریخ اجرا:** %s

## خلاصه آماری
| معیار | مقدار |
|-------|-------|
| کل کانال‌ها | 0 |
| ✅ فعال | 0 |
| 💀 غیرفعال | 0 |

هیچ کانالی برای بررسی وجود نداشت.

---
✅ گزارش توسط GitHub Actions تولید شده است.
`, time.Now().Format("2006-01-02 15:04:05"))
	os.WriteFile(channelsReportFile, []byte(report), 0644)
}

func generateChannelsReport(activeList []ScanResult, totalChecked int) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر کانال‌های تلگرام\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n| معیار | مقدار |\n|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل کانال‌های بررسی شده | %d |\n", totalChecked))
	sb.WriteString(fmt.Sprintf("| ✅ فعال | %d |\n\n", len(activeList)))

	sb.WriteString("## ✅ کانال‌های فعال\n\n")
	if len(activeList) > 0 {
		for _, res := range activeList {
			sb.WriteString(fmt.Sprintf("- %s\n", res.URL))
		}
	} else {
		sb.WriteString("(هیچ کانال فعالی یافت نشد)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط GitHub Actions تولید شده است.\n")
	os.WriteFile(channelsReportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", channelsReportFile)
}
