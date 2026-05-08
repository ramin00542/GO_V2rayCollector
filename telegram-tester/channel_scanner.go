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

const (
	requestTimeout = 15 * time.Second
)

var (
	client = &http.Client{Timeout: requestTimeout}
	// الگوهای تشخیص کانفیگ (همان الگوهای main.go)
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run channel_scanner.go <channels.csv> [output.csv]")
		fmt.Println("Example: go run channel_scanner.go ../channels.csv ../channels_new.csv")
		os.Exit(1)
	}
	inputFile := os.Args[1]
	outputFile := inputFile
	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}

	// خواندن فایل CSV
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
		fmt.Println("CSV file has no data rows.")
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

	results := make([]struct {
		URL       string
		Current   bool
		Suggested bool
		Reason    string
	}, 0, len(records)-1)

	for i, row := range records[1:] {
		url := row[urlIdx]
		currentFlag := strings.EqualFold(row[flagIdx], "true")
		fmt.Printf("[%d/%d] Scanning: %s ... ", i+1, len(records)-1, url)

		suggested, reason := analyzeChannel(url)
		results = append(results, struct {
			URL       string
			Current   bool
			Suggested bool
			Reason    string
		}{url, currentFlag, suggested, reason})
		fmt.Printf("Suggested: %v (%s)\n", suggested, reason)
		time.Sleep(1 * time.Second)
	}

	// نوشتن فایل CSV خروجی
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()
	writer := csv.NewWriter(outFile)
	defer writer.Flush()
	writer.Write([]string{"URL", "AllMessagesFlag", "SuggestedFlag", "Reason"})
	for _, res := range results {
		writer.Write([]string{
			res.URL,
			boolToString(res.Current),
			boolToString(res.Suggested),
			res.Reason,
		})
	}
	fmt.Printf("\n✅ Output CSV written to %s\n", outputFile)
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func analyzeChannel(channelURL string) (bool, string) {
	channelName := extractChannelName(channelURL)
	if channelName == "" {
		return false, "Invalid channel URL"
	}
	fullURL := fmt.Sprintf("https://t.me/s/%s", channelName)

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

	// متن داخل pre/code
	var codeTexts []string
	doc.Find("pre, code").Each(func(i int, s *goquery.Selection) {
		codeTexts = append(codeTexts, s.Text())
	})

	// متن کل پیام‌ها خارج از pre/code
	var plainTexts []string
	doc.Find(".tgme_widget_message_text").Each(func(i int, s *goquery.Selection) {
		clone := s.Clone()
		clone.Find("pre, code").Remove()
		plain := strings.TrimSpace(clone.Text())
		if plain != "" {
			plainTexts = append(plainTexts, plain)
		}
	})

	hasConfigInCode := hasAnyConfig(strings.Join(codeTexts, "\n"))
	hasConfigInPlain := hasAnyConfig(strings.Join(plainTexts, "\n"))

	if hasConfigInPlain && !hasConfigInCode {
		return true, "Config found in plain text (outside pre/code)"
	}
	if hasConfigInPlain && hasConfigInCode {
		return true, "Config found both in plain text and in code tags"
	}
	if !hasConfigInPlain && hasConfigInCode {
		return false, "Config only in pre/code tags, false is sufficient"
	}
	return false, "No config found in this channel (maybe dead channel)"
}

func extractChannelName(rawURL string) string {
	re := regexp.MustCompile(`t\.me/(?:s/)?([^/?]+)`)
	matches := re.FindStringSubmatch(rawURL)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func hasAnyConfig(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}
