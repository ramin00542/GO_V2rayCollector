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

	// خواندن channels.csv
	records := readCSV(inputFile)
	if len(records) < 2 {
		fmt.Println("No channels found.")
		return
	}
	// ستون URL در index 0 فرض می‌شود
	var activeChannels []ChannelInfo
	var deadList []ChannelInfo

	for i, row := range records[1:] {
		url := row[0]
		fmt.Printf("[%d/%d] Scanning: %s ... ", i+1, len(records)-1, url)
		hasConfig, lastPost, err := analyzeChannel(url)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		daysSince := int(time.Since(lastPost).Hours() / 24)
		fmt.Printf("Last post: %s (%d days ago), Config: %v\n", lastPost.Format("2006-01-02"), daysSince, hasConfig)
		if hasConfig && daysSince <= 30 {
			activeChannels = append(activeChannels, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: true})
		} else {
			deadList = append(deadList, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: hasConfig})
		}
		time.Sleep(1 * time.Second)
	}

	// نوشتن channels.csv جدید (فقط کانال‌های فعال)
	writeActiveChannels("channels.csv", activeChannels)

	// به‌روزرسانی dead_channels.txt با زمان بررسی بعدی
	updateDeadChannels(deadList)

	fmt.Printf("\n✅ Active channels: %d, Dead/Inactive: %d\n", len(activeChannels), len(deadList))
}

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
	// آخرین تاریخ
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
	// بررسی کانفیگ
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

// توابع کمکی
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
	w.Write([]string{"URL", "AllMessagesFlag"}) // ستون دوم را false می‌گذاریم (پیش‌فرض)
	for _, ch := range channels {
		w.Write([]string{ch.URL, "false"})
	}
	fmt.Printf("✅ Updated %s with %d active channels.\n", path, len(channels))
}

func updateDeadChannels(dead []ChannelInfo) {
	// خواندن dead_channels.txt موجود
	existing := make(map[string]int64) // URL -> nextCheckTimestamp
	data, _ := os.ReadFile(deadChannelsFile)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if ts, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				existing[parts[0]] = ts
			}
		}
	}
	// به‌روزرسانی: برای هر کانال مرده، زمان بررسی بعدی را محاسبه کن
	now := time.Now().Unix()
	for _, ch := range dead {
		daysSince := int(time.Since(ch.LastPost).Hours() / 24)
		var next int64
		if daysSince > 60 || !ch.HasConfig {
			next = now + 30*24*3600 // یک ماه بعد
		} else if daysSince > 30 {
			next = now + 7*24*3600 // یک هفته بعد
		} else {
			next = now + 24*3600 // یک روز بعد (برای کانال‌هایی که کانفیگ ندارند اما اخیراً فعال بوده‌اند)
		}
		existing[ch.URL] = next
	}
	// ذخیره
	var lines []string
	for url, ts := range existing {
		lines = append(lines, fmt.Sprintf("%s %d", url, ts))
	}
	sort.Strings(lines)
	os.WriteFile(deadChannelsFile, []byte(strings.Join(lines, "\n")), 0644)
	fmt.Printf("✅ Updated dead_channels.txt with %d entries.\n", len(existing))
}
