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

type ChannelSuggestion struct {
	URL       string
	Current   bool
	Suggested bool
	Reason    string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run channel_scanner.go <channels.csv> [output.csv]")
		fmt.Println("Example: go run channel_scanner.go ../channels.csv ../channels_suggested.csv")
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

	results := make([]ChannelSuggestion, 0, len(records)-1)

	for i, row := range records[1:] {
		url := row[urlIdx]
		currentFlag := strings.EqualFold(row[flagIdx], "true")
		fmt.Printf("[%d/%d] Scanning: %s ... ", i+1, len(records)-1, url)

		suggested, reason := analyzeChannel(url)
		results = append(results, ChannelSuggestion{
			URL:       url,
			Current:   currentFlag,
			Suggested: suggested,
			Reason:    reason,
		})
		fmt.Printf("Suggested: %v (%s)\n", suggested, reason)
		time.Sleep(1 * time.Second)
	}

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

	// آمار
	var trueCurrent, falseCurrent, trueSuggested, falseSuggested int
	reasonCounts := make(map[string]int)
	var deadChannels []string
	for _, res := range results {
		if res.Current {
			trueCurrent++
		} else {
			falseCurrent++
		}
		if res.Suggested {
			trueSuggested++
		} else {
			falseSuggested++
		}
		reasonCounts[res.Reason]++
		if strings.Contains(res.Reason, "No config found") {
			deadChannels = append(deadChannels, res.URL)
		}
	}

	summaryContent := strings.Builder{}
	summaryContent.WriteString("=== Channel Scanner Summary ===\n")
	summaryContent.WriteString(fmt.Sprintf("Scan date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	summaryContent.WriteString(fmt.Sprintf("Total channels processed: %d\n\n", len(results)))
	summaryContent.WriteString("--- Current Flags ---\n")
	summaryContent.WriteString(fmt.Sprintf("true: %d\n", trueCurrent))
	summaryContent.WriteString(fmt.Sprintf("false: %d\n\n", falseCurrent))
	summaryContent.WriteString("--- Suggested Flags ---\n")
	summaryContent.WriteString(fmt.Sprintf("Suggested true: %d\n", trueSuggested))
	summaryContent.WriteString(fmt.Sprintf("Suggested false: %d\n\n", falseSuggested))
	summaryContent.WriteString("--- Reasons breakdown ---\n")
	for reason, cnt := range reasonCounts {
		summaryContent.WriteString(fmt.Sprintf("%s: %d\n", reason, cnt))
	}
	summaryContent.WriteString("\n--- Dead channels (no config found) ---\n")
	if len(deadChannels) > 0 {
		for i, ch := range deadChannels {
			if i >= 20 {
				summaryContent.WriteString(fmt.Sprintf("... and %d more\n", len(deadChannels)-20))
				break
			}
			summaryContent.WriteString(ch + "\n")
		}
	} else {
		summaryContent.WriteString("None\n")
	}
	summaryContent.WriteString("\n--- Action Items ---\n")
	summaryContent.WriteString(fmt.Sprintf("* %d channels should be set to true (currently %d are true).\n", trueSuggested, trueCurrent))
	if trueSuggested > trueCurrent {
		summaryContent.WriteString("* You need to increase the number of true flags.\n")
	} else if trueSuggested < trueCurrent {
		summaryContent.WriteString("* You have too many true flags; you can safely set many to false.\n")
	} else {
		summaryContent.WriteString("* The number of true flags is already optimal.\n")
	}
	summaryContent.WriteString(fmt.Sprintf("* Consider removing %d dead channels to speed up the collector.\n", len(deadChannels)))

	err = os.WriteFile("channel_scan_summary.txt", []byte(summaryContent.String()), 0644)
	if err != nil {
		fmt.Printf("Error writing summary file: %v\n", err)
	} else {
		fmt.Printf("✅ Summary written to channel_scan_summary.txt\n")
	}
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
