package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	requestTimeout = 30 * time.Second
)

var (
	client = &http.Client{Timeout: requestTimeout}
	regexPatterns = map[string]string{
		"vmess":  `vmess://[A-Za-z0-9+/]+={0,2}(?:\?[^\s]*)?`,
		"vless":  `vless://[^\s]+`,
		"trojan": `trojan://[^@\s]+@[^\s]+`,
		"ss":     `ss://[A-Za-z0-9+/]+={0,2}@[^\s]+`,
		"ssr":    `ssr://[A-Za-z0-9+/=]+`,
	}
)

func main() {
	channels := []string{
		"FreeV2rays",
		"V2rayCollectorDonate",
		"ConfigV2rayNG",
	}

	fmt.Println("🔍 Starting telegram connection test...")
	successCount := 0
	for _, ch := range channels {
		fmt.Printf("\n📡 Testing channel: t.me/%s\n", ch)
		if testChannel(ch) {
			successCount++
		}
	}
	fmt.Printf("\n✅ Test finished. Successful channels: %d/%d\n", successCount, len(channels))
}

func testChannel(channel string) bool {
	url := fmt.Sprintf("https://t.me/s/%s", channel)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("   ❌ Connection failed: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("   ⚠️ HTTP Error: %d\n", resp.StatusCode)
		return false
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		fmt.Printf("   ❌ Parse error: %v\n", err)
		return false
	}

	var configs []string
	doc.Find(".tgme_widget_message_text, pre, code").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text == "" {
			return
		}
		for proto, pattern := range regexPatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllString(text, -1)
			for _, match := range matches {
				configs = append(configs, fmt.Sprintf("%s -> %s", proto, match))
			}
		}
	})

	if len(configs) > 0 {
		fmt.Printf("   🟢 Success! Found %d config(s):\n", len(configs))
		for i, cfg := range configs {
			if i < 3 {
				fmt.Printf("      - %s\n", cfg)
			}
		}
		if len(configs) > 3 {
			fmt.Printf("      ... and %d more\n", len(configs)-3)
		}
		return true
	} else {
		fmt.Printf("   ⚠️ Connected but no configs found\n")
		return true
	}
}
