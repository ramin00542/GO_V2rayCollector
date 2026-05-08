package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	deadChannelsArchive = "../dead_channels_archive.txt"
	activeChannelsFile  = "../channels.csv"
	reviveCacheFile     = "revive_cache.json"
	retryCount          = 3
	baseDelay           = 1 * time.Second
	jitter              = 500 * time.Millisecond
	activeDays          = 30
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
		if res.Revived && !activeMap[res.URL] {
			revivedList = append(revivedList, res.URL)
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

func checkChannelWithRetry(url string) ReviveResult {
	var lastErr error
	for attempt := 1; attempt <= retryCount; attempt++ {
		if res, err := analyzeChannel(url); err == nil {
			return res
		} else {
			lastErr = err
		}
		delay := baseDelay * time.Duration(1<<uint(attempt-1))
		jit := time.Duration(rand.Int63n(int64(jitter)))
		time.Sleep(delay + jit)
	}
	return ReviveResult{URL: url, Status: "error", Error: lastErr.Error(), Revived: false}
}

func analyzeChannel(channelURL string) (ReviveResult, error) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return ReviveResult{}, fmt.Errorf("invalid URL")
	}
	rssURL := fmt.Sprintf("https://t.me/s/%s.rss", channelName)
	lastPost, hasConfig, err := fetchFromRSS(rssURL)
	if err == nil {
		revived := hasConfig && time.Since(lastPost).Hours()/24 <= float64(activeDays)
		status := "inactive"
		if revived {
			status = "active"
		}
		return ReviveResult{
			URL:       channelURL,
			LastPost:  lastPost,
			HasConfig: hasConfig,
			Status:    status,
			Revived:   revived,
		}, nil
	}
	htmlURL := fmt.Sprintf("https://t.me/s/%s", channelName)
	lastPost, hasConfig, err = fetchFromHTML(htmlURL)
	if err != nil {
		return ReviveResult{}, err
	}
	revived := hasConfig && time.Since(lastPost).Hours()/24 <= float64(activeDays)
	status := "inactive"
	if revived {
		status = "active"
	}
	return ReviveResult{
		URL:       channelURL,
		LastPost:  lastPost,
		HasConfig: hasConfig,
		Status:    status,
		Revived:   revived,
	}, nil
}

func fetchFromRSS(rssURL string) (lastPost time.Time, hasConfig bool, err error) {
	resp, err := client.Get(rssURL)
	if err != nil {
		return time.Time{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return time.Time{}, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return time.Time{}, false, err
	}
	var latestTime time.Time
	doc.Find("item").Each(func(i int, s *goquery.Selection) {
		pubDate := s.Find("pubDate").Text()
		if pubDate != "" {
			if t, err := time.Parse(time.RFC1123Z, pubDate); err == nil && (latestTime.IsZero() || t.After(latestTime)) {
				latestTime = t
			}
		}
		desc := s.Find("description").Text()
		for _, re := range regexPatterns {
			if re.MatchString(desc) {
				hasConfig = true
			}
		}
	})
	if latestTime.IsZero() {
		return time.Time{}, false, fmt.Errorf("no pubDate")
	}
	return latestTime, hasConfig, nil
}

func fetchFromHTML(htmlURL string) (lastPost time.Time, hasConfig bool, err error) {
	resp, err := client.Get(htmlURL)
	if err != nil {
		return time.Time{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return time.Time{}, false, fmt.Errorf("channel not found")
	}
	if resp.StatusCode != 200 {
		return time.Time{}, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return time.Time{}, false, err
	}
	var lastTime time.Time
	doc.Find("time").Each(func(i int, s *goquery.Selection) {
		if i == 0 && lastTime.IsZero() {
			if dt, ok := s.Attr("datetime"); ok {
				if t, err := time.Parse(time.RFC3339, dt); err == nil {
					lastTime = t
				}
			}
		}
	})
	if lastTime.IsZero() {
		doc.Find(".datetime").Each(func(i int, s *goquery.Selection) {
			if i == 0 && lastTime.IsZero() {
				if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s.Text())); err == nil {
					lastTime = t
				}
			}
		})
	}
	var texts []string
	doc.Find(".tgme_widget_message_text, pre, code").Each(func(i int, s *goquery.Selection) {
		texts = append(texts, s.Text())
	})
	combined := strings.Join(texts, "\n")
	for _, re := range regexPatterns {
		if re.MatchString(combined) {
			hasConfig = true
			break
		}
	}
	if lastTime.IsZero() {
		return time.Time{}, hasConfig, fmt.Errorf("no timestamp")
	}
	return lastTime, hasConfig, nil
}

func extractChannelName(rawURL string) string {
	re := regexp.MustCompile(`t\.me/(?:s/)?([^/?]+)`)
	m := re.FindStringSubmatch(rawURL)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

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
	records, _ := r.ReadAll()
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
	writeCSV(activeChannelsFile, headers, records)
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

func generateEmptyReviveReport() {
	os.MkdirAll("../stats", 0755)
	reportPath := "../stats/revive_report.md"
	report := fmt.Sprintf(`# 📊 گزارش اسکنر احیای کانال‌ها

**تاریخ اجرا:** %s

## خلاصه آماری

| معیار | مقدار |
|-------|-------|
| کل کانال‌های بایگانی | 0 |
| کانال‌های احیا شده | 0 |
| کانال‌های همچنان مرده | 0 |

هیچ کانالی در بایگانی وجود نداشت. اسکنر کاری انجام نداد.

--- 
✅ گزارش توسط GitHub Actions تولید شده است.`, time.Now().Format("2006-01-02 15:04:05"))
	os.WriteFile(reportPath, []byte(report), 0644)
	fmt.Printf("✅ Empty report written to %s\n", reportPath)
}

func generateReviveReport(revived, stillDead []string, results []ReviveResult) {
	os.MkdirAll("../stats", 0755)
	reportPath := "../stats/revive_report.md"

	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر احیای کانال‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n")
	sb.WriteString("| معیار | مقدار |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل کانال‌های بایگانی | %d |\n", len(results)))
	sb.WriteString(fmt.Sprintf("| ✅ کانال‌های احیا شده | %d |\n", len(revived)))
	sb.WriteString(fmt.Sprintf("| 💀 کانال‌های همچنان مرده | %d |\n\n", len(stillDead)))

	if len(revived) > 0 {
		sb.WriteString("## ✅ کانال‌های احیا شده\n\n")
		for _, url := range revived {
			sb.WriteString(fmt.Sprintf("- %s\n", url))
		}
	} else {
		sb.WriteString("(هیچ کانالی احیا نشد)\n")
	}
	sb.WriteString("\n## 💀 کانال‌های باقی‌مانده در بایگانی (۱۰ مورد اول)\n\n")
	for i, url := range stillDead {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d کانال دیگر\n", len(stillDead)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s\n", url))
	}
	sb.WriteString("\n---\n✅ گزارش توسط GitHub Actions تولید شده است.\n")
	os.WriteFile(reportPath, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", reportPath)
}
