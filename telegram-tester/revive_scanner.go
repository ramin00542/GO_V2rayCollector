// telegram-tester/revive_scanner.go
package main

import (
	"encoding/csv"
	"encoding/json"
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
	dataDir               = "../data"
	deadChannelsArchive   = dataDir + "/dead_channels_archive.txt"
	activeChannelsFile    = "../channels.csv"
	reviveCacheFile       = dataDir + "/revive_cache.json"
	reviveReportFile      = "../reports/revive_report.md"
	defaultRetryCount     = 3
	defaultBaseDelay      = 1 * time.Second
	defaultJitter         = 500 * time.Millisecond
	activeDays            = 30
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

type ReviveResult struct {
	URL       string    `json:"url"`
	LastPost  time.Time `json:"last_post"`
	HasConfig bool      `json:"has_config"`
	Status    string    `json:"status"`
	Revived   bool      `json:"revived"`
	Error     string    `json:"error,omitempty"`
}

func main() {
	os.MkdirAll("../reports", 0755)
	os.MkdirAll(dataDir, 0755)

	archive := loadArchive()
	if len(archive) == 0 {
		fmt.Println("Archive is empty. Nothing to revive.")
		generateEmptyReviveReport()
		return
	}
	fmt.Printf("Loaded %d archived channels.\n", len(archive))
	activeMap := loadActiveChannels()
	var revivedList []string
	var stillDead []string
	var results []ReviveResult

	jobs := make(chan string, len(archive))
	resultsCh := make(chan ReviveResult, len(archive))
	var wg sync.WaitGroup
	workers := 5
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				res := checkChannelWithRetry(url)
				resultsCh <- res
				time.Sleep(time.Duration(rand.Intn(500)+500) * time.Millisecond)
			}
		}()
	}
	for url := range archive {
		jobs <- url
	}
	close(jobs)
	wg.Wait()
	close(resultsCh)

	for res := range resultsCh {
		results = append(results, res)
		if res.Revived {
			if !activeMap[res.URL] {
				revivedList = append(revivedList, res.URL)
			}
		} else {
			stillDead = append(stillDead, res.URL)
		}
	}

	if len(revivedList) > 0 {
		addToActiveChannels(revivedList)
		fmt.Printf("✅ Added %d revived channels to %s\n", len(revivedList), activeChannelsFile)
	} else {
		fmt.Println("No revived channels found.")
	}
	newArchive := make(map[string]bool)
	for _, url := range stillDead {
		newArchive[url] = true
	}
	saveArchive(newArchive)
	saveReviveCache(results)
	generateReviveReport(revivedList, stillDead, results)
	fmt.Printf("✅ Revive scan finished. Revived: %d, Still dead: %d\n", len(revivedList), len(stillDead))
}

func generateEmptyReviveReport() {
	report := fmt.Sprintf(`# 📊 گزارش احیای کانال‌ها

**تاریخ اجرا:** %s

## خلاصه آماری
| معیار | مقدار |
|-------|-------|
| کل کانال‌های بایگانی | 0 |
| ✅ احیا شده | 0 |
| 💀 همچنان مرده | 0 |

هیچ کانالی در بایگانی وجود نداشت.
`, time.Now().Format("2006-01-02 15:04:05"))
	os.WriteFile(reviveReportFile, []byte(report), 0644)
}

func generateReviveReport(revived, stillDead []string, results []ReviveResult) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش احیای کانال‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n| معیار | مقدار |\n|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل کانال‌های بایگانی | %d |\n", len(results)))
	sb.WriteString(fmt.Sprintf("| ✅ احیا شده | %d |\n", len(revived)))
	sb.WriteString(fmt.Sprintf("| 💀 همچنان مرده | %d |\n\n", len(stillDead)))

	sb.WriteString("## ✅ کانال‌های احیا شده\n\n")
	if len(revived) > 0 {
		for _, url := range revived {
			sb.WriteString(fmt.Sprintf("- %s\n", url))
		}
	} else {
		sb.WriteString("(هیچ کانالی احیا نشد)\n")
	}
	sb.WriteString("\n## 💀 کانال‌های باقی‌مانده در بایگانی\n\n")
	if len(stillDead) > 0 {
		sb.WriteString(fmt.Sprintf("<details>\n<summary>نمایش همه %d کانال (کلیک کنید)</summary>\n\n", len(stillDead)))
		details := make(map[string]ReviveResult)
		for _, r := range results {
			details[r.URL] = r
		}
		for _, url := range stillDead {
			if d, ok := details[url]; ok {
				lastPostStr := ""
				if !d.LastPost.IsZero() {
					lastPostStr = d.LastPost.Format("2006-01-02 15:04:05")
				}
				sb.WriteString(fmt.Sprintf("- **%s**  \n  - آخرین پست: %s  \n  - دارای کانفیگ: %v  \n  - خطا: %s\n\n", url, lastPostStr, d.HasConfig, d.Error))
			} else {
				sb.WriteString(fmt.Sprintf("- %s\n", url))
			}
		}
		sb.WriteString("</details>\n")
	} else {
		sb.WriteString("(هیچ کانال مرده‌ای باقی نمانده)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط GitHub Actions تولید شده است.\n")
	os.WriteFile(reviveReportFile, []byte(sb.String()), 0644)
}

// ------------------------------------------------------------
// توابع اصلی (بدون تغییر)
// ------------------------------------------------------------
func checkChannelWithRetry(url string) ReviveResult {
	var lastErr error
	for attempt := 1; attempt <= defaultRetryCount; attempt++ {
		res, err := analyzeChannelForRevive(url)
		if err == nil {
			return res
		}
		lastErr = err
		delay := defaultBaseDelay * time.Duration(1<<uint(attempt-1))
		jitter := time.Duration(rand.Int63n(int64(defaultJitter)))
		time.Sleep(delay + jitter)
	}
	return ReviveResult{URL: url, Status: "error", Error: lastErr.Error(), Revived: false}
}

func analyzeChannelForRevive(channelURL string) (ReviveResult, error) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return ReviveResult{}, fmt.Errorf("invalid URL")
	}
	rssURL := fmt.Sprintf("https://t.me/s/%s.rss", channelName)
	res, err := fetchFromRSSRevive(rssURL, channelURL)
	if err == nil {
		return res, nil
	}
	htmlURL := fmt.Sprintf("https://t.me/s/%s", channelName)
	return fetchFromHTMLRevive(htmlURL, channelURL)
}

func fetchFromRSSRevive(rssURL, origURL string) (ReviveResult, error) {
	resp, err := client.Get(rssURL)
	if err != nil {
		return ReviveResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ReviveResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ReviveResult{}, err
	}
	var latestTime time.Time
	var anyConfig bool
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
		return ReviveResult{}, fmt.Errorf("no pubDate")
	}
	revived := anyConfig && time.Since(latestTime).Hours()/24 <= float64(activeDays)
	status := "inactive"
	if revived {
		status = "active"
	}
	return ReviveResult{
		URL:       origURL,
		LastPost:  latestTime,
		HasConfig: anyConfig,
		Status:    status,
		Revived:   revived,
	}, nil
}

func fetchFromHTMLRevive(htmlURL, origURL string) (ReviveResult, error) {
	resp, err := client.Get(htmlURL)
	if err != nil {
		return ReviveResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return ReviveResult{URL: origURL, Status: "banned", Revived: false, Error: "not found"}, nil
	}
	if resp.StatusCode != 200 {
		return ReviveResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ReviveResult{}, err
	}
	var lastTime time.Time
	doc.Find("time").Each(func(i int, s *goquery.Selection) {
		if i == 0 && lastTime.IsZero() {
			if dt, ok := s.Attr("datetime"); ok {
				t, _ := time.Parse(time.RFC3339, dt)
				lastTime = t
			}
		}
	})
	if lastTime.IsZero() {
		doc.Find(".datetime").Each(func(i int, s *goquery.Selection) {
			if i == 0 && lastTime.IsZero() {
				t, _ := time.Parse(time.RFC3339, strings.TrimSpace(s.Text()))
				lastTime = t
			}
		})
	}
	var texts []string
	doc.Find(".tgme_widget_message_text, pre, code").Each(func(i int, s *goquery.Selection) {
		texts = append(texts, s.Text())
	})
	has := anyConfigInText(strings.Join(texts, "\n"))
	revived := has && time.Since(lastTime).Hours()/24 <= float64(activeDays) && !lastTime.IsZero()
	status := "inactive"
	if revived {
		status = "active"
	}
	return ReviveResult{
		URL:       origURL,
		LastPost:  lastTime,
		HasConfig: has,
		Status:    status,
		Revived:   revived,
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

// I/O helpers
func loadArchive() map[string]bool {
	m := make(map[string]bool)
	data, err := os.ReadFile(deadChannelsArchive)
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

func saveArchive(m map[string]bool) {
	var lines []string
	for k := range m {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	os.WriteFile(deadChannelsArchive, []byte(strings.Join(lines, "\n")), 0644)
}

func loadActiveChannels() map[string]bool {
	m := make(map[string]bool)
	f, err := os.Open(activeChannelsFile)
	if err != nil {
		return m
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return m
	}
	if len(records) < 2 {
		return m
	}
	for _, row := range records[1:] {
		if len(row) > 0 {
			m[row[0]] = true
		}
	}
	return m
}

func addToActiveChannels(urls []string) {
	records, headers, err := readCSV(activeChannelsFile)
	if err != nil {
		fmt.Printf("Error reading CSV: %v\n", err)
		return
	}
	activeSet := make(map[string]bool)
	for _, row := range records {
		if len(row) > 0 {
			activeSet[row[0]] = true
		}
	}
	for _, url := range urls {
		if !activeSet[url] {
			records = append(records, []string{url, "false"})
			fmt.Printf("Adding revived channel: %s\n", url)
		}
	}
	if err := writeCSV(activeChannelsFile, headers, records); err != nil {
		fmt.Printf("Error writing CSV: %v\n", err)
	}
}

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

func writeCSV(path string, headers []string, records [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
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

func saveReviveCache(results []ReviveResult) {
	data, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(reviveCacheFile, data, 0644)
}
