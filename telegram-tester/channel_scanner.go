// telegram-tester/channel_scanner.go
package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	requestTimeout      = 15 * time.Second
	deadChannelsFile    = "dead_channels.txt"
	deadChannelsArchive = "dead_channels_archive.txt"
	reportFile          = "scan_report.txt"
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

	// بارگذاری لیست سیاه و بایگانی فعلی
	deadMap := loadMap(deadChannelsFile)
	archiveMap := loadMap(deadChannelsArchive)

	var active []ChannelInfo
	var dead []ChannelInfo
	stats := &ScanStats{Total: len(records) - 1}

	for i, row := range records[1:] {
		if len(row) <= urlIdx {
			continue
		}
		url := row[urlIdx]
		fmt.Printf("[%d/%d] Scanning: %s ... ", i+1, stats.Total, url)
		hasConfig, lastPost, err := analyzeChannel(url)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			stats.Errors++
			continue
		}
		daysSince := int(time.Since(lastPost).Hours() / 24)
		if daysSince < 0 {
			daysSince = 0
		}
		fmt.Printf("Last post: %s (%d days ago), Config: %v\n", lastPost.Format("2006-01-02"), daysSince, hasConfig)

		if hasConfig && daysSince <= 30 {
			active = append(active, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: true})
			stats.Active++
			// اگر کانال قبلاً در لیست سیاه یا بایگانی بود، اکنون زنده شده است
			if deadMap[url] {
				delete(deadMap, url)
				stats.RevivedFromDead++
			}
			if archiveMap[url] {
				delete(archiveMap, url)
				stats.RevivedFromArchive++
			}
		} else {
			dead = append(dead, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: hasConfig})
			stats.Dead++
		}
		time.Sleep(1 * time.Second)
	}

	// به‌روزرسانی deadMap با کانال‌های جدید مرده
	for _, ch := range dead {
		deadMap[ch.URL] = true
		if !archiveMap[ch.URL] {
			archiveMap[ch.URL] = true
			stats.NewArchived++
		}
	}

	// نوشتن خروجی‌ها
	writeActiveChannels(inputFile, active)
	saveMap(deadChannelsFile, deadMap)
	saveMap(deadChannelsArchive, archiveMap)
	generateReport(stats, active, dead)

	fmt.Printf("\n✅ Active: %d, Dead: %d, Archived: %d, Errors: %d\n", stats.Active, stats.Dead, len(archiveMap), stats.Errors)
}

// ------------------------------------------------------------
// انواع و ساختارهای کمکی
// ------------------------------------------------------------
type ScanStats struct {
	Total             int
	Active            int
	Dead              int
	Errors            int
	RevivedFromDead   int
	RevivedFromArchive int
	NewArchived       int
}

// ------------------------------------------------------------
// توابع تحلیلی
// ------------------------------------------------------------
func analyzeChannel(channelURL string) (hasConfig bool, lastPost time.Time, err error) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return false, time.Time{}, fmt.Errorf("invalid URL")
	}
	fullURL := fmt.Sprintf("https://t.me/s/%s", channelName)
	resp, err := client.Get(fullURL)
	if err != nil {
		return false, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, time.Time{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return false, time.Time{}, err
	}
	// تاریخ آخرین پیام
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
	// بررسی وجود کانفیگ
	var texts []string
	doc.Find(".tgme_widget_message_text, pre, code").Each(func(i int, s *goquery.Selection) {
		texts = append(texts, s.Text())
	})
	has := anyConfig(strings.Join(texts, "\n"))
	return has, lastTime, nil
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

// ------------------------------------------------------------
// توابع فایل
// ------------------------------------------------------------
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
		// مقدار AllMessagesFlag می‌تواند بر اساس تشخیص true/false باشد، اینجا false پیش‌فرض
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

// ------------------------------------------------------------
// گزارش زیبا
// ------------------------------------------------------------
func generateReport(stats *ScanStats, active, dead []ChannelInfo) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر کانال‌های تلگرام\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n")
	sb.WriteString("| معیار | مقدار |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل کانال‌های بررسی شده | %d |\n", stats.Total))
	sb.WriteString(fmt.Sprintf("| ✅ کانال‌های فعال (≤۳۰ روز + کانفیگ) | %d |\n", stats.Active))
	sb.WriteString(fmt.Sprintf("| 💀 کانال‌های غیرفعال/مرده | %d |\n", stats.Dead))
	sb.WriteString(fmt.Sprintf("| 🔄 احیا شده از لیست سیاه موقت | %d |\n", stats.RevivedFromDead))
	sb.WriteString(fmt.Sprintf("| 📦 احیا شده از بایگانی دائمی | %d |\n", stats.RevivedFromArchive))
	sb.WriteString(fmt.Sprintf("| 🆕 اضافه شده به بایگانی (برای اولین بار) | %d |\n", stats.NewArchived))
	sb.WriteString(fmt.Sprintf("| ❌ خطا در بررسی | %d |\n\n", stats.Errors))

	sb.WriteString("## 📋 کانال‌های فعال (۱۰ مورد اول)\n\n")
	for i, ch := range active {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d کانال دیگر\n", len(active)-10))
			break
		}
		lastDate := ch.LastPost.Format("2006-01-02")
		sb.WriteString(fmt.Sprintf("- %s (آخرین پست: %s)\n", ch.URL, lastDate))
	}
	if len(active) == 0 {
		sb.WriteString("(هیچ کانال فعالی وجود ندارد)\n")
	}
	sb.WriteString("\n## 🗑️ کانال‌های مرده/غیرفعال (۱۰ مورد اول)\n\n")
	for i, ch := range dead {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d کانال دیگر\n", len(dead)-10))
			break
		}
		lastDate := ch.LastPost.Format("2006-01-02")
		sb.WriteString(fmt.Sprintf("- %s (آخرین پست: %s)\n", ch.URL, lastDate))
	}
	if len(dead) == 0 {
		sb.WriteString("(هیچ کانال مرده‌ای وجود ندارد)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط اسکنر خودکار کانال‌های تلگرام تولید شده است.\n")
	os.WriteFile(reportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", reportFile)
}
