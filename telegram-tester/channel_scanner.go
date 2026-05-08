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
	requestTimeout   = 15 * time.Second
	deadChannelsFile = "dead_channels.txt"
	reportFile       = "scan_report.txt"
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
	URL           string
	HasConfig     bool
	LastPost      time.Time
	NextCheckDays int // 1, 7, 30
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run channel_scanner.go <channels.csv>")
		os.Exit(1)
	}
	inputFile := os.Args[1]

	// 1. خواندن channels.csv فعلی
	records := readCSV(inputFile)
	if len(records) == 0 {
		fmt.Println("No channels found.")
		return
	}

	// 2. بارگذاری لیست کانال‌های مرده (برای بررسی مجدد)
	deadMap := loadDeadChannels()

	// 3. بررسی هر کانال
	var aliveChannels []ChannelInfo
	var deadList []ChannelInfo

	for i, row := range records {
		if i == 0 {
			continue // header
		}
		url := row[0]
		fmt.Printf("[%d/%d] Scanning: %s ... ", i, len(records)-1, url)

		hasConfig, lastPost, err := analyzeChannel(url)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		daysSince := int(time.Since(lastPost).Hours() / 24)
		nextDays := 1
		if !hasConfig || daysSince > 60 {
			nextDays = 30 // ماهانه
		} else if daysSince > 30 {
			nextDays = 7 // هفتگی
		} else {
			nextDays = 1 // روزانه
		}
		info := ChannelInfo{URL: url, HasConfig: hasConfig, LastPost: lastPost, NextCheckDays: nextDays}
		if hasConfig && daysSince <= 30 { // فعال و دارای کانفیگ
			aliveChannels = append(aliveChannels, info)
			fmt.Printf("ALIVE (config found, last post %d days ago) -> daily check\n", daysSince)
		} else {
			deadList = append(deadList, info)
			fmt.Printf("DEAD/SLEEPING (config:%v, last post %d days ago) -> next check in %d days\n", hasConfig, daysSince, nextDays)
		}
		time.Sleep(1 * time.Second)
	}

	// 4. نوشتن channels.csv (فقط کانال‌های زنده)
	writeChannelsCSV("channels.csv", aliveChannels)

	// 5. به‌روزرسانی dead_channels.txt (با زمان بعدی بررسی)
	updateDeadChannels(deadMap, deadList)
	saveDeadChannels(deadMap)

	// 6. تولید گزارش
	generateReport(aliveChannels, deadList, deadMap)
}

func analyzeChannel(channelURL string) (hasConfig bool, lastPost time.Time, err error) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return false, time.Time{}, fmt.Errorf("invalid channel URL")
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
	// استخراج آخرین تاریخ
	var lastTime time.Time
	doc.Find("time").Each(func(i int, s *goquery.Selection) {
		if i == 0 {
			if datetime, ok := s.Attr("datetime"); ok {
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

// توابع کمکی برای خواندن/نوشتن CSV و dead list (به دلیل طولانی نشدن، فقط امضای آن‌ها را می‌نویسم – در کد واقعی باید کامل باشند)
func readCSV(path string) [][]string { /* ... */ }
func writeChannelsCSV(path string, channels []ChannelInfo) { /* ... */ }
func loadDeadChannels() map[string]int64 { /* ... */ }
func updateDeadChannels(deadMap map[string]int64, newDead []ChannelInfo) { /* ... */ }
func saveDeadChannels(deadMap map[string]int64) { /* ... */ }
func generateReport(alive, dead []ChannelInfo, deadMap map[string]int64) { /* ... */ }
