// telegram-tester/revive_scanner.go
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
	requestTimeout      = 15 * time.Second
	deadChannelsArchive = "dead_channels_archive.txt"
	activeChannelsFile  = "channels.csv"
	reviveReport        = "revive_report.txt"
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

type ReviveStats struct {
	TotalChecked int
	Revived      int
	StillDead    int
	Errors       int
}

func main() {
	archive := loadArchive()
	if len(archive) == 0 {
		fmt.Println("Archive is empty. Nothing to revive.")
		return
	}
	fmt.Printf("Loaded %d archived channels. Checking for revival...\n", len(archive))

	activeMap := loadActiveChannels()
	stats := &ReviveStats{TotalChecked: len(archive)}
	var revivedList []string
	var stillDeadList []string

	for url := range archive {
		fmt.Printf("Checking: %s ... ", url)
		hasConfig, lastPost, err := analyzeChannel(url)
		if err != nil {
			fmt.Printf("ERROR: %v (still dead)\n", err)
			stats.Errors++
			stillDeadList = append(stillDeadList, url)
			continue
		}
		daysSince := int(time.Since(lastPost).Hours() / 24)
		fmt.Printf("Last post: %s (%d days ago), Config: %v\n", lastPost.Format("2006-01-02"), daysSince, hasConfig)

		if hasConfig && daysSince <= 30 {
			if !activeMap[url] {
				revivedList = append(revivedList, url)
				fmt.Printf("   → REVIVED!\n")
			} else {
				fmt.Printf("   → Already active, will be removed from archive.\n")
				revivedList = append(revivedList, url)
			}
		} else {
			stillDeadList = append(stillDeadList, url)
			fmt.Printf("   → Still dead/inactive.\n")
		}
		time.Sleep(1 * time.Second)
	}

	stats.Revived = len(revivedList)
	stats.StillDead = len(stillDeadList)

	// به‌روزرسانی فایل‌ها
	if stats.Revived > 0 {
		addToActiveChannels(revivedList)
		fmt.Printf("✅ Added %d revived channels to %s\n", stats.Revived, activeChannelsFile)
	} else {
		fmt.Println("No revived channels found.")
	}

	// به‌روزرسانی بایگانی (حذف کانال‌های احیا شده)
	newArchive := make(map[string]bool)
	for _, url := range stillDeadList {
		newArchive[url] = true
	}
	saveArchive(newArchive)

	// تولید گزارش
	generateReviveReport(stats, revivedList, stillDeadList)
	fmt.Printf("✅ Revive scan finished. Revived: %d, Still dead: %d, Errors: %d\n", stats.Revived, stats.StillDead, stats.Errors)
}

// ------------------------------------------------------------
// توابع تحلیلی (مشابه اسکنر اصلی)
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

func saveArchive(archive map[string]bool) {
	var lines []string
	for url := range archive {
		lines = append(lines, url)
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
	urlIdx := -1
	for i, col := range records[0] {
		if strings.EqualFold(col, "URL") {
			urlIdx = i
			break
		}
	}
	if urlIdx == -1 {
		return m
	}
	for _, row := range records[1:] {
		if len(row) > urlIdx {
			m[row[urlIdx]] = true
		}
	}
	return m
}

func addToActiveChannels(urls []string) {
	records := readCSV(activeChannelsFile)
	if len(records) == 0 {
		records = [][]string{{"URL", "AllMessagesFlag"}}
	}
	urlIdx := -1
	for i, col := range records[0] {
		if strings.EqualFold(col, "URL") {
			urlIdx = i
			break
		}
	}
	if urlIdx == -1 {
		urlIdx = 0
		records[0] = []string{"URL", "AllMessagesFlag"}
	}
	existing := make(map[string]bool)
	for _, row := range records[1:] {
		if len(row) > urlIdx {
			existing[row[urlIdx]] = true
		}
	}
	for _, url := range urls {
		if !existing[url] {
			records = append(records, []string{url, "false"})
		}
	}
	f, err := os.Create(activeChannelsFile)
	if err != nil {
		fmt.Printf("Error writing %s: %v\n", activeChannelsFile, err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	for _, row := range records {
		w.Write(row)
	}
}

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

// ------------------------------------------------------------
// گزارش
// ------------------------------------------------------------
func generateReviveReport(stats *ReviveStats, revived, stillDead []string) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر احیای کانال‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n")
	sb.WriteString("| معیار | مقدار |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل کانال‌های بررسی شده (بایگانی) | %d |\n", stats.TotalChecked))
	sb.WriteString(fmt.Sprintf("| ✅ کانال‌های احیا شده | %d |\n", stats.Revived))
	sb.WriteString(fmt.Sprintf("| 💀 کانال‌های همچنان مرده | %d |\n", stats.StillDead))
	sb.WriteString(fmt.Sprintf("| ❌ خطا در بررسی | %d |\n\n", stats.Errors))

	sb.WriteString("## ✅ کانال‌های احیا شده\n\n")
	if len(revived) > 0 {
		for _, url := range revived {
			sb.WriteString(fmt.Sprintf("- %s\n", url))
		}
	} else {
		sb.WriteString("(هیچ کانالی احیا نشد)\n")
	}
	sb.WriteString("\n## 💀 کانال‌های همچنان مرده (۱۰ مورد اول)\n\n")
	for i, url := range stillDead {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d کانال دیگر\n", len(stillDead)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s\n", url))
	}
	if len(stillDead) == 0 {
		sb.WriteString("(هیچ کانال مرده‌ای باقی نمانده)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط اسکنر خودکار احیای کانال‌ها تولید شده است.\n")
	os.WriteFile(reviveReport, []byte(sb.String()), 0644)
	fmt.Printf("✅ Revive report written to %s\n", reviveReport)
}
