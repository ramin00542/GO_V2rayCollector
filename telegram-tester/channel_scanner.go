// telegram-tester/channel_scanner.go
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
	requestTimeout       = 15 * time.Second
	blockedChannelsFile  = "blocked_channels.txt"
	reportFile           = "scan_report.txt"
	maxInactiveDays      = 30    // برای غیرفعال کلی (به لیست سیاه)
	activeThreshold      = 24    // ساعت – اگر کمتر از این باشد، فعال
	semiActiveThreshold  = 48    // ساعت – اگر بین 24 تا 48 باشد، نیمه‌فعال
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

type ChannelResult struct {
	URL           string
	Current       bool
	Suggested     bool
	Reason        string
	LastMessage   time.Time
	IsActive      bool
	ActivityLevel string // "active", "semi-active", "sleeping"
	NextCheck     string // پیشنهاد برای دفعه بعد (بر حسب ساعت)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run channel_scanner.go <channels.csv> [output.csv]")
		os.Exit(1)
	}
	inputFile := os.Args[1]
	outputFile := inputFile
	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Printf("Error reading CSV: %v\n", err)
		os.Exit(1)
	}
	if len(records) < 2 {
		fmt.Println("CSV has no data rows.")
		return
	}
	header := records[0]
	var urlIdx, flagIdx int = -1, -1
	for i, col := range header {
		if strings.EqualFold(col, "URL") {
			urlIdx = i
		}
		if strings.EqualFold(col, "AllMessagesFlag") {
			flagIdx = i
		}
	}
	if urlIdx == -1 || flagIdx == -1 {
		fmt.Println("CSV must have 'URL' and 'AllMessagesFlag' columns")
		os.Exit(1)
	}

	blocked := loadBlockedChannels()
	deadOrSleeping := make(map[string]bool)
	results := make([]ChannelResult, 0, len(records)-1)

	for i, row := range records[1:] {
		url := row[urlIdx]
		currentFlag := strings.EqualFold(row[flagIdx], "true")
		fmt.Printf("[%d/%d] Scanning: %s ... ", i+1, len(records)-1, url)

		suggested, reason, lastMsg, isActive, level, next := analyzeChannelAdvanced(url)
		results = append(results, ChannelResult{
			URL:           url,
			Current:       currentFlag,
			Suggested:     suggested,
			Reason:        reason,
			LastMessage:   lastMsg,
			IsActive:      isActive,
			ActivityLevel: level,
			NextCheck:     next,
		})
		fmt.Printf("Suggested: %v | LastMsg: %s | Level: %s | Next: %s\n",
			suggested, lastMsg.Format("2006-01-02"), level, next)

		// کانال‌های کاملاً مرده یا خواب (بدون کانفیگ یا آخرین پیام > 48h) به لیست سیاه اضافه شوند
		if strings.Contains(reason, "No config found") || level == "sleeping" {
			deadOrSleeping[url] = true
		}
		if blocked[url] && (isActive && level != "sleeping" && !strings.Contains(reason, "No config found")) {
			delete(blocked, url)
			fmt.Printf("   → Removed from blocklist (revived)\n")
		}
		time.Sleep(1 * time.Second)
	}

	for url := range deadOrSleeping {
		blocked[url] = true
	}
	saveBlockedChannels(blocked)

	// نوشتن CSV خروجی
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()
	writer := csv.NewWriter(outFile)
	defer writer.Flush()
	writer.Write([]string{"URL", "AllMessagesFlag", "SuggestedFlag", "Reason", "LastMessageDate", "ActivityLevel", "NextCheckHours"})
	for _, res := range results {
		lastDate := ""
		if !res.LastMessage.IsZero() {
			lastDate = res.LastMessage.Format("2006-01-02")
		}
		writer.Write([]string{
			res.URL,
			boolToString(res.Current),
			boolToString(res.Suggested),
			res.Reason,
			lastDate,
			res.ActivityLevel,
			res.NextCheck,
		})
	}
	fmt.Printf("\n✅ Output CSV written to %s\n", outputFile)

	generateReport(results, deadOrSleeping, blocked)
}

func analyzeChannelAdvanced(channelURL string) (suggested bool, reason string, lastMsgTime time.Time, isActive bool, level, nextCheck string) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return false, "Invalid channel URL", time.Time{}, false, "inactive", "never"
	}
	fullURL := fmt.Sprintf("https://t.me/s/%s", channelName)
	resp, err := client.Get(fullURL)
	if err != nil {
		return false, fmt.Sprintf("HTTP error: %v", err), time.Time{}, false, "dead", "never"
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode), time.Time{}, false, "dead", "never"
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return false, fmt.Sprintf("Parse error: %v", err), time.Time{}, false, "dead", "never"
	}

	// استخراج آخرین تاریخ پیام
	var lastTime time.Time
	doc.Find("time").Each(func(i int, s *goquery.Selection) {
		if i == 0 {
			if datetime, exists := s.Attr("datetime"); exists {
				if t, err := time.Parse(time.RFC3339, datetime); err == nil {
					lastTime = t
				}
			}
		}
	})
	if lastTime.IsZero() {
		doc.Find(".datetime").Each(func(i int, s *goquery.Selection) {
			if i == 0 {
				txt := strings.TrimSpace(s.Text())
				if t, err := time.Parse(time.RFC3339, txt); err == nil {
					lastTime = t
				}
			}
		})
	}
	hoursAgo := int(time.Since(lastTime).Hours())
	if hoursAgo < 0 {
		hoursAgo = 0
	}
	switch {
	case hoursAgo < activeThreshold:
		level = "active"
		nextCheck = "24"
	case hoursAgo < semiActiveThreshold:
		level = "semi-active"
		nextCheck = "48"
	default:
		level = "sleeping"
		nextCheck = "168" // 7 روز
	}
	isActive = (hoursAgo < maxInactiveDays*24)

	// تشخیص کانفیگ
	var codeTexts []string
	doc.Find("pre, code").Each(func(i int, s *goquery.Selection) {
		codeTexts = append(codeTexts, s.Text())
	})
	var plainTexts []string
	doc.Find(".tgme_widget_message_text").Each(func(i int, s *goquery.Selection) {
		clone := s.Clone()
		clone.Find("pre, code").Remove()
		plain := strings.TrimSpace(clone.Text())
		if plain != "" {
			plainTexts = append(plainTexts, plain)
		}
	})
	hasCode := anyConfig(strings.Join(codeTexts, "\n"))
	hasPlain := anyConfig(strings.Join(plainTexts, "\n"))

	if hasPlain && !hasCode {
		return true, "Config found in plain text (outside pre/code)", lastTime, isActive, level, nextCheck
	}
	if hasPlain && hasCode {
		return true, "Config found both in plain text and code tags", lastTime, isActive, level, nextCheck
	}
	if !hasPlain && hasCode {
		return false, "Config only in pre/code tags, false is sufficient", lastTime, isActive, level, nextCheck
	}
	return false, "No config found in this channel (maybe dead channel)", lastTime, false, "dead", "never"
}

func loadBlockedChannels() map[string]bool {
	blocked := make(map[string]bool)
	data, err := os.ReadFile(blockedChannelsFile)
	if err != nil {
		return blocked
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			blocked[line] = true
		}
	}
	return blocked
}

func saveBlockedChannels(blocked map[string]bool) {
	var lines []string
	for url := range blocked {
		lines = append(lines, url)
	}
	sort.Strings(lines)
	os.WriteFile(blockedChannelsFile, []byte(strings.Join(lines, "\n")), 0644)
}

func generateReport(results []ChannelResult, deadOrSleeping map[string]bool, blocked map[string]bool) {
	var sb strings.Builder
	sb.WriteString("# 📡 Telegram Channels Scanner Report\n\n")
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Total channels processed:** %d\n", len(results)))

	var trueSuggested, falseSuggested, deadCount, sleepingCount, activeCount, semiCount int
	for _, r := range results {
		if r.Suggested {
			trueSuggested++
		} else {
			falseSuggested++
		}
		if strings.Contains(r.Reason, "No config found") {
			deadCount++
		}
		switch r.ActivityLevel {
		case "active":
			activeCount++
		case "semi-active":
			semiCount++
		case "sleeping":
			sleepingCount++
		}
	}
	sb.WriteString("\n## 📊 Summary\n\n")
	sb.WriteString("| Metric | Value |\n|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| ✅ Suggested `true` | %d |\n", trueSuggested))
	sb.WriteString(fmt.Sprintf("| ❌ Suggested `false` | %d |\n", falseSuggested))
	sb.WriteString(fmt.Sprintf("| 💀 Dead (no config) | %d |\n", deadCount))
	sb.WriteString(fmt.Sprintf("| 🔥 Active (<24h) | %d |\n", activeCount))
	sb.WriteString(fmt.Sprintf("| 🌙 Semi-active (24-48h) | %d |\n", semiCount))
	sb.WriteString(fmt.Sprintf("| 💤 Sleeping (>48h) | %d |\n", sleepingCount))
	sb.WriteString(fmt.Sprintf("| 🚫 Currently blocked | %d |\n\n", len(blocked)))

	sb.WriteString("## 🗑️ Top 10 Dead/Sleeping Channels\n\n")
	var list []string
	for url := range deadOrSleeping {
		list = append(list, url)
	}
	sort.Strings(list)
	for i, url := range list {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... and %d more\n", len(list)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s\n", url))
	}
	sb.WriteString("\n## ✅ Channels that need `true`\n\n")
	var trueList []string
	for _, r := range results {
		if r.Suggested && len(trueList) < 10 {
			trueList = append(trueList, r.URL)
		}
	}
	for _, url := range trueList {
		sb.WriteString(fmt.Sprintf("- %s\n", url))
	}
	sb.WriteString("\n---\n✅ Report generated by V2rayCollector Channel Scanner (activity-aware)\n")
	os.WriteFile(reportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", reportFile)
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func extractChannelName(rawURL string) string {
	re := regexp.MustCompile(`t\.me/(?:s/)?([^/?]+)`)
	matches := re.FindStringSubmatch(rawURL)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func anyConfig(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}
