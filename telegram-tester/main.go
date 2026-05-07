// channel_scanner.go – در پوشه telegram-tester قرار دهید
package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const requestTimeout = 15 * time.Second

var client = &http.Client{Timeout: requestTimeout}
var regexPatterns = []*regexp.Regexp{
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
	urlIdx, flagIdx := -1, -1
	for i, col := range header {
		switch strings.ToLower(col) {
		case "url":
			urlIdx = i
		case "allmessagesflag":
			flagIdx = i
		}
	}
	if urlIdx == -1 || flagIdx == -1 {
		fmt.Println("CSV must have 'URL' and 'AllMessagesFlag' columns")
		os.Exit(1)
	}
	var results []struct {
		URL       string
		Current   bool
		Suggested bool
		Reason    string
	}
	for i, row := range records[1:] {
		url := row[urlIdx]
		current := strings.EqualFold(row[flagIdx], "true")
		fmt.Printf("[%d/%d] %s ... ", i+1, len(records)-1, url)
		suggested, reason := analyzeChannel(url)
		results = append(results, struct {
			URL       string
			Current   bool
			Suggested bool
			Reason    string
		}{url, current, suggested, reason})
		fmt.Printf("Suggested: %v (%s)\n", suggested, reason)
		time.Sleep(1 * time.Second)
	}
	out, _ := os.Create(outputFile)
	defer out.Close()
	w := csv.NewWriter(out)
	defer w.Flush()
	w.Write([]string{"URL", "AllMessagesFlag", "SuggestedFlag", "Reason"})
	for _, r := range results {
		w.Write([]string{r.URL, boolToString(r.Current), boolToString(r.Suggested), r.Reason})
	}
	fmt.Printf("\n✅ Output written to %s\n", outputFile)
}

func analyzeChannel(channelURL string) (bool, string) {
	name := extractChannelName(channelURL)
	if name == "" {
		return false, "Invalid URL"
	}
	fullURL := fmt.Sprintf("https://t.me/s/%s", name)
	resp, err := client.Get(fullURL)
	if err != nil {
		return false, fmt.Sprintf("HTTP error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return false, fmt.Sprintf("Parse error: %v", err)
	}
	var codeTexts, plainTexts []string
	doc.Find("pre, code").Each(func(i int, s *goquery.Selection) {
		codeTexts = append(codeTexts, s.Text())
	})
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
		return true, "Config in plain text (needs true)"
	}
	if hasPlain && hasCode {
		return true, "Config in both (true recommended)"
	}
	if !hasPlain && hasCode {
		return false, "Config only in code (false ok)"
	}
	return false, "No config found (dead channel)"
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

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
