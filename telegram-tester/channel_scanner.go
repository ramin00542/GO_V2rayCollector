package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	requestTimeout     = 15 * time.Second
	deadChannelsFile   = "dead_channels.txt"
	deadChannelsArchive = "dead_channels_archive.txt"
	scanReportFile     = "scan_report.md"
	activeDays         = 30
)

var (
	client = &http.Client{Timeout: requestTimeout}
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

type ChannelInfo struct {
	URL       string
	LastPost  time.Time
	HasConfig bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run channel_scanner.go <channels.csv>")
		os.Exit(1)
	}
	inputFile := os.Args[1]

	records := readCSV(inputFile)
	if len(records) < 2 {
		fmt.Println("No channels found in CSV.")
		return
	}
	header := records[0]
	urlIdx := -1
	for i, col := range header {
		if strings.EqualFold(col, "URL") {
			urlIdx = i
			break
		}
	}
	if urlIdx == -1 {
		fmt.Println("CSV missing 'URL' column")
		os.Exit(1)
	}

	deadMap := loadMap(deadChannelsFile)
	archiveMap := loadMap(deadChannelsArchive)

	var active []ChannelInfo
	var dead []ChannelInfo

	for i, row := range records[1:] {
		url := row[urlIdx]
		fmt.Printf("[%d/%d] Scanning: %s ... ", i+1, len(records)-1, url)
		hasConfig, lastPost, err := analyzeChannel(url)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		daysSince := int(time.Since(lastPost).Hours() / 24)
		if daysSince < 0 {
			daysSince = 0
		}
		fmt.Printf("Last post: %s (%d days ago), Config: %v\n", lastPost.Format("2006-01-02"), daysSince, hasConfig)

		if hasConfig && daysSince <= activeDays {
			active = append(active, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: true})
			delete(deadMap, url)
			delete(archiveMap, url)
		} else {
			dead = append(dead, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: hasConfig})
			deadMap[url] = true
			if !archiveMap[url] {
				archiveMap[url] = true
			}
		}
		time.Sleep(1 * time.Second)
	}

	writeActiveChannels(inputFile, active)
	saveMap(deadChannelsFile, deadMap)
	saveMap(deadChannelsArchive, archiveMap)
	generateScanReport(active, dead)

	fmt.Printf("\n✅ Active: %d, Dead: %d\n", len(active), len(dead))
}

func analyzeChannel(channelURL string) (hasConfig bool, lastPost time.Time, err error) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return false, time.Time{}, fmt.Errorf("invalid URL")
	}
	// اول RSS
	rssURL := fmt.Sprintf("https://t.me/s/%s.rss", channelName)
	if lastPost, hasConfig, err = fetchFromRSS(rssURL); err == nil {
		return
	}
	// fallback به HTML
	htmlURL := fmt.Sprintf("https://t.me/s/%s", channelName)
	return fetchFromHTML(htmlURL)
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
		if anyConfig(desc) {
			hasConfig = true
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
	hasConfig = anyConfig(strings.Join(texts, "\n"))
	if lastTime.IsZero() {
		return time.Time{}, hasConfig, fmt.Errorf("no timestamp")
	}
	return lastTime, hasConfig, nil
}

func anyConfig(text string) bool {
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
func readCSV(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, _ := r.ReadAll()
	return records
}

func writeActiveChannels(path string, channels []ChannelInfo) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("Error writing %s: %v\n", path, err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"URL", "AllMessagesFlag"})
	for _, ch := range channels {
		w.Write([]string{ch.URL, "false"})
	}
	fmt.Printf("✅ Updated %s with %d active channels.\n", path, len(channels))
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
	fmt.Printf("✅ Saved %s with %d entries.\n", file, len(lines))
}

func generateScanReport(active, dead []ChannelInfo) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر کانال‌های تلگرام\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n")
	sb.WriteString("| معیار | مقدار |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| **کانال‌های فعال** (≤%d روز + کانفیگ) | %d |\n", activeDays, len(active)))
	sb.WriteString(fmt.Sprintf("| **کانال‌های غیرفعال/مرده** | %d |\n\n", len(dead)))

	if len(active) > 0 {
		sb.WriteString("## ✅ کانال‌های فعال (۱۰ مورد اول)\n\n")
		for i, ch := range active {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("... و %d کانال دیگر\n", len(active)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("- %s (آخرین پست: %s)\n", ch.URL, ch.LastPost.Format("2006-01-02")))
		}
	} else {
		sb.WriteString("(هیچ کانال فعالی وجود ندارد)\n")
	}
	sb.WriteString("\n## 💀 کانال‌های غیرفعال/مرده (۱۰ مورد اول)\n\n")
	for i, ch := range dead {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d کانال دیگر\n", len(dead)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s (آخرین پست: %s)\n", ch.URL, ch.LastPost.Format("2006-01-02")))
	}
	sb.WriteString("\n---\n✅ گزارش توسط ابزار اسکنر کانال‌ها تولید شده است.\n")
	os.WriteFile(scanReportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", scanReportFile)
}
