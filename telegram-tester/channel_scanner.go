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
	deadChannelsFile      = dataDir + "/dead_channels.txt"
	deadChannelsArchive   = dataDir + "/dead_channels_archive.txt"
	scanCacheFile         = dataDir + "/scan_cache.json"
	channelsReportFile    = "../reports/channels_report.md"
)

var (
	inputCSV      = flag.String("input", "channels.csv", "Input CSV file")
	outputCSV     = flag.String("output", "channels.csv", "Output CSV file")
	activeDays    = flag.Int("active-days", defaultActiveDays, "Max inactive days")
	concurrency   = flag.Int("concurrency", defaultConcurrency, "Number of concurrent workers")
	noRSS         = flag.Bool("no-rss", false, "Use HTML instead of RSS")
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

type ScanResult struct {
	URL          string    `json:"url"`
	LastPost     time.Time `json:"last_post"`
	HasConfig    bool      `json:"has_config"`
	Status       string    `json:"status"`
	MessageCount int       `json:"msg_count"`
	Error        string    `json:"error,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

type ScanCache struct {
	Results   map[string]ScanResult `json:"results"`
	LastRun   time.Time             `json:"last_run"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// برای قفل کردن چاپ کنسول در زمان همزمانی (اختیاری)
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
	cache := loadCache()
	if cache.Results == nil {
		cache.Results = make(map[string]ScanResult)
	}
	deadMap := loadMap(deadChannelsFile)
	archiveMap := loadMap(deadChannelsArchive)

	jobs := make(chan struct {
		idx int
		url string
	}, len(records))
	results := make(chan ScanResult, len(records))
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}
	for idx, row := range records {
		url := row[0]
		jobs <- struct {
			idx int
			url string
		}{idx, url}
	}
	close(jobs)
	wg.Wait()
	close(results)

	var activeList []ScanResult
	var deadList []ScanResult
	for res := range results {
		cache.Results[res.URL] = res
		if res.Status == "active" {
			activeList = append(activeList, res)
			delete(deadMap, res.URL)
			delete(archiveMap, res.URL)
		} else {
			deadList = append(deadList, res)
			deadMap[res.URL] = true
			if !archiveMap[res.URL] {
				archiveMap[res.URL] = true
			}
		}
	}
	cache.UpdatedAt = time.Now()
	saveCache(cache)
	updateCSV(*outputCSV, records, headers, activeList)
	saveMap(deadChannelsFile, deadMap)
	saveMap(deadChannelsArchive, archiveMap)

	generateChannelsReport(activeList, deadList, len(records))
	fmt.Printf("\n✅ Active: %d, Dead: %d\n", len(activeList), len(deadList))
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

func generateChannelsReport(activeList, deadList []ScanResult, totalChecked int) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر کانال‌های تلگرام\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n| معیار | مقدار |\n|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل کانال‌های بررسی شده | %d |\n", totalChecked))
	sb.WriteString(fmt.Sprintf("| ✅ فعال | %d |\n", len(activeList)))
	sb.WriteString(fmt.Sprintf("| 💀 غیرفعال/مرده | %d |\n\n", len(deadList)))

	sb.WriteString("## ✅ کانال‌های فعال\n\n")
	if len(activeList) > 0 {
		for _, res := range activeList {
			sb.WriteString(fmt.Sprintf("- %s\n", res.URL))
		}
	} else {
		sb.WriteString("(هیچ کانال فعالی یافت نشد)\n")
	}
	sb.WriteString("\n## 💀 کانال‌های غیرفعال/مرده\n\n")
	if len(deadList) > 0 {
		sb.WriteString(fmt.Sprintf("<details>\n<summary>نمایش همه %d کانال (کلیک کنید)</summary>\n\n", len(deadList)))
		for _, res := range deadList {
			lastPostStr := ""
			if !res.LastPost.IsZero() {
				lastPostStr = res.LastPost.Format("2006-01-02 15:04:05")
			}
			sb.WriteString(fmt.Sprintf("- **%s**  \n  - وضعیت: `%s`  \n  - آخرین پست: %s  \n  - دارای کانفیگ: %v\n\n", res.URL, res.Status, lastPostStr, res.HasConfig))
		}
		sb.WriteString("</details>\n")
	} else {
		sb.WriteString("(هیچ کانال غیرفعالی وجود ندارد)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط GitHub Actions تولید شده است.\n")
	os.WriteFile(channelsReportFile, []byte(sb.String()), 0644)
}

func worker(jobs <-chan struct{ idx int; url string }, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		res := analyzeWithRetry(job.url)
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
	// نمایش لاگ خوانا (با قفل برای همزمانی)
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

// I/O helpers (بدون تغییر)
func readCSV(path string) ([][]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	all, err := r.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(all) == 0 {
		return nil, nil, nil
	}
	return all[1:], all[0], nil
}

func updateCSV(path string, records [][]string, headers []string, active []ScanResult) error {
	activeMap := make(map[string]bool)
	for _, res := range active {
		activeMap[res.URL] = true
	}
	statusIdx := -1
	for i, h := range headers {
		if strings.EqualFold(h, "Status") {
			statusIdx = i
			break
		}
	}
	if statusIdx == -1 {
		headers = append(headers, "Status")
		statusIdx = len(headers) - 1
		for i := range records {
			for len(records[i]) < len(headers) {
				records[i] = append(records[i], "")
			}
		}
	}
	for i, row := range records {
		if len(row) == 0 {
			continue
		}
		url := row[0]
		if activeMap[url] {
			row[statusIdx] = "active"
		} else {
			row[statusIdx] = "inactive"
		}
		records[i] = row
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
	for _, row := range records {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func loadMap(file string) map[string]bool {
	m := make(map[string]bool)
	data, err := os.ReadFile(file)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			m[line] = true
		}
	}
	return m
}

func saveMap(file string, m map[string]bool) {
	var lines []string
	for k := range m {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0644)
}

func loadCache() ScanCache {
	data, err := os.ReadFile(scanCacheFile)
	if err != nil {
		return ScanCache{Results: make(map[string]ScanResult), LastRun: time.Now()}
	}
	var cache ScanCache
	json.Unmarshal(data, &cache)
	if cache.Results == nil {
		cache.Results = make(map[string]ScanResult)
	}
	return cache
}

func saveCache(cache ScanCache) {
	cache.LastRun = time.Now()
	data, _ := json.MarshalIndent(cache, "", "  ")
	os.WriteFile(scanCacheFile, data, 0644)
}
