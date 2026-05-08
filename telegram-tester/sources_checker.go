// telegram-tester/sources_checker.go
package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	checkTimeout = 10 * time.Second
	sampleSize   = 50 * 1024 // 50 KB
)

var (
	httpClient = &http.Client{Timeout: checkTimeout}
	// همان الگوهای تشخیص کانفیگ
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

type SourceResult struct {
	URL     string
	Status  string // "OK", "NO_CONFIG", "DEAD"
	Details string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sources_checker.go <Sources.json> [output.csv]")
		fmt.Println("Example: go run sources_checker.go ../Sources.json ../sources_report.csv")
		os.Exit(1)
	}
	inputFile := os.Args[1]
	outputFile := "sources_report.csv"
	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}

	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", inputFile, err)
		os.Exit(1)
	}
	var sources []string
	if err := json.Unmarshal(data, &sources); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d sources. Checking...\n\n", len(sources))

	results := make([]SourceResult, 0, len(sources))
	for i, url := range sources {
		fmt.Printf("[%d/%d] Checking: %s ... ", i+1, len(sources), url)
		status, details := checkSource(url)
		results = append(results, SourceResult{URL: url, Status: status, Details: details})
		fmt.Printf("%s (%s)\n", status, details)
		time.Sleep(500 * time.Millisecond)
	}

	// نوشتن گزارش CSV
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()
	writer := csv.NewWriter(outFile)
	defer writer.Flush()
	writer.Write([]string{"URL", "Status", "Details"})
	for _, r := range results {
		writer.Write([]string{r.URL, r.Status, r.Details})
	}
	fmt.Printf("\n✅ Report written to %s\n", outputFile)

	// ایجاد فایل Sources_valid.json فقط با لینک‌های OK
	validSources := make([]string, 0)
	for _, r := range results {
		if r.Status == "OK" {
			validSources = append(validSources, r.URL)
		}
	}
	validData, _ := json.MarshalIndent(validSources, "", "  ")
	os.WriteFile("Sources_valid.json", validData, 0644)
	fmt.Printf("✅ Sources_valid.json created with %d valid links\n", len(validSources))
}

func checkSource(url string) (status, details string) {
	// HEAD request برای بررسی سریع
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "DEAD", fmt.Sprintf("HEAD request failed: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return "DEAD", fmt.Sprintf("HTTP error: %v", err)
	}
	resp.Body.Close()

	// GET sample برای بررسی محتوا
	req2, _ := http.NewRequest("GET", url, nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	resp2, err := httpClient.Do(req2)
	if err != nil {
		return "DEAD", fmt.Sprintf("GET failed: %v", err)
	}
	defer resp2.Body.Close()
	limited := io.LimitReader(resp2.Body, sampleSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return "DEAD", fmt.Sprintf("Read error: %v", err)
	}
	content := string(body)

	// دیکد base64 اگر بود
	trimmed := strings.TrimSpace(content)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
		content = string(decoded)
	}

	if hasAnyConfig(content) {
		return "OK", "Configs found"
	}
	return "NO_CONFIG", "No config pattern found in sample"
}

func hasAnyConfig(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}
