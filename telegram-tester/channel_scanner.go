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

	var active []ChannelInfo
	var dead []ChannelInfo

	for i, row := range records[1:] {
		if len(row) <= urlIdx {
			continue
		}
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
		if hasConfig && daysSince <= 30 {
			active = append(active, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: true})
		} else {
			dead = append(dead, ChannelInfo{URL: url, LastPost: lastPost, HasConfig: hasConfig})
		}
		time.Sleep(1 * time.Second)
	}

	writeActiveChannels(inputFile, active)
	updateDeadChannels(dead)

	fmt.Printf("\n✅ Active channels: %d, Dead/Inactive: %d\n", len(active), len(dead))
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

func updateDeadChannels(dead []ChannelInfo) {
	existing := make(map[string]int64)
	data, _ := os.ReadFile(deadChannelsFile)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if ts, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				existing[parts[0]] = ts
			}
		}
	}
	now := time.Now().Unix()
	for _, ch := range dead {
		daysSince := int(time.Since(ch.LastPost).Hours() / 24)
		var next int64
		switch {
		case daysSince > 60 || !ch.HasConfig:
			next = now + 30*24*3600
		case daysSince > 30:
			next = now + 7*24*3600
		default:
			next = now + 24*3600
		}
		existing[ch.URL] = next
	}
	var lines []string
	for url, ts := range existing {
		lines = append(lines, fmt.Sprintf("%s %d", url, ts))
	}
	sort.Strings(lines)
	os.WriteFile(deadChannelsFile, []byte(strings.Join(lines, "\n")), 0644)
	fmt.Printf("✅ Updated dead_channels.txt with %d entries.\n", len(existing))
}
