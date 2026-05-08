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
	"sort"
	"strings"
	"time"
)

const (
	checkTimeout        = 10 * time.Second
	sampleSize          = 50 * 1024
	blockedSourcesFile  = "blocked_sources.txt"
	staleDays           = 7
	reportFile          = "sources_report.txt"
	freshHours          = 24    // آخرین تغییر کمتر از 24 ساعت پیش
	semiFreshHours      = 48
)

var (
	httpClient = &http.Client{Timeout: checkTimeout}
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
	URL          string
	Status       string // "OK", "NO_CONFIG", "DEAD", "STALE"
	Details      string
	LastModified time.Time
	Freshness    string // "fresh", "semi-fresh", "stale"
	NextCheck    string // پیشنهاد (ساعت)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sources_checker.go <Sources.json> [output.csv]")
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
	fmt.Printf("Loaded %d sources.\n", len(sources))

	blocked := loadBlockedSources()
	results := make([]SourceResult, 0, len(sources))
	deadOrStale := make(map[string]bool)

	for i, url := range sources {
		fmt.Printf("[%d/%d] Checking: %s ... ", i+1, len(sources), url)
		status, details, lastMod, freshness, next := checkSourceAdvanced(url)
		results = append(results, SourceResult{
			URL:          url,
			Status:       status,
			Details:      details,
			LastModified: lastMod,
			Freshness:    freshness,
			NextCheck:    next,
		})
		fmt.Printf("%s (%s) | Freshness: %s | Next: %sh\n", status, details, freshness, next)

		if status == "DEAD" || status == "NO_CONFIG" || status == "STALE" {
			deadOrStale[url] = true
		} else if status == "OK" && freshness != "stale" {
			if blocked[url] {
				delete(blocked, url)
				fmt.Printf("   → Removed from blocklist (valid again)\n")
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	for url := range deadOrStale {
		blocked[url] = true
	}
	saveBlockedSources(blocked)

	// CSV خروجی
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()
	csvWriter := csv.NewWriter(outFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{"URL", "Status", "Details", "LastModified", "Freshness", "NextCheckHours"})
	for _, r := range results {
		lm := ""
		if !r.LastModified.IsZero() {
			lm = r.LastModified.Format(time.RFC1123)
		}
		csvWriter.Write([]string{r.URL, r.Status, r.Details, lm, r.Freshness, r.NextCheck})
	}
	fmt.Printf("✅ CSV report written to %s\n", outputFile)

	// فایل JSON فقط برای لینک‌های OK و تازه (Fresh + Semi-fresh)
	validSources := make([]string, 0)
	for _, r := range results {
		if r.Status == "OK" && r.Freshness != "stale" {
			validSources = append(validSources, r.URL)
		}
	}
	validData, _ := json.MarshalIndent(validSources, "", "  ")
	os.WriteFile("Sources_valid.json", validData, 0644)
	fmt.Printf("✅ Sources_valid.json created with %d valid (fresh) links\n", len(validSources))

	generateSourceReport(results, blocked)
}

func loadBlockedSources() map[string]bool {
	blocked := make(map[string]bool)
	data, err := os.ReadFile(blockedSourcesFile)
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

func saveBlockedSources(blocked map[string]bool) {
	var lines []string
	for url := range blocked {
		lines = append(lines, url)
	}
	sort.Strings(lines)
	os.WriteFile(blockedSourcesFile, []byte(strings.Join(lines, "\n")), 0644)
}

func checkSourceAdvanced(url string) (status, details string, lastMod time.Time, freshness, nextCheck string) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "DEAD", fmt.Sprintf("HEAD request failed: %v", err), time.Time{}, "unknown", "never"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return "DEAD", fmt.Sprintf("HTTP error: %v", err), time.Time{}, "dead", "never"
	}
	lmStr := resp.Header.Get("Last-Modified")
	if lmStr != "" {
		lastMod, _ = time.Parse(time.RFC1123, lmStr)
	}
	resp.Body.Close()

	// GET sample
	req2, _ := http.NewRequest("GET", url, nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	resp2, err := httpClient.Do(req2)
	if err != nil {
		return "DEAD", fmt.Sprintf("GET failed: %v", err), lastMod, "dead", "never"
	}
	defer resp2.Body.Close()
	limited := io.LimitReader(resp2.Body, sampleSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return "DEAD", fmt.Sprintf("Read error: %v", err), lastMod, "dead", "never"
	}
	content := string(body)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil && len(decoded) > 0 {
		content = string(decoded)
	}
	if !hasAnyConfig(content) {
		return "NO_CONFIG", "No config pattern found in sample", lastMod, "stale", "never"
	}
	hoursAgo := int(time.Since(lastMod).Hours())
	if hoursAgo < 0 {
		hoursAgo = 0
	}
	switch {
	case hoursAgo < freshHours:
		freshness = "fresh"
		nextCheck = "24"
	case hoursAgo < semiFreshHours:
		freshness = "semi-fresh"
		nextCheck = "48"
	default:
		freshness = "stale"
		nextCheck = "168" // 7 روز
	}
	return "OK", "Configs found and recent", lastMod, freshness, nextCheck
}

func hasAnyConfig(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func generateSourceReport(results []SourceResult, blocked map[string]bool) {
	var sb strings.Builder
	sb.WriteString("# 🔗 Subscription Sources Scanner Report\n\n")
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Total sources processed:** %d\n", len(results)))

	var okCount, deadCount, noConfigCount, staleCount, freshCount, semiCount int
	for _, r := range results {
		switch r.Status {
		case "OK":
			okCount++
		case "DEAD":
			deadCount++
		case "NO_CONFIG":
			noConfigCount++
		case "STALE":
			staleCount++
		}
		switch r.Freshness {
		case "fresh":
			freshCount++
		case "semi-fresh":
			semiCount++
		}
	}
	sb.WriteString("\n## 📊 Summary\n\n")
	sb.WriteString("| Status | Count |\n|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| ✅ OK (valid & has config) | %d |\n", okCount))
	sb.WriteString(fmt.Sprintf("| 💀 DEAD | %d |\n", deadCount))
	sb.WriteString(fmt.Sprintf("| ⚠️ NO_CONFIG | %d |\n", noConfigCount))
	sb.WriteString(fmt.Sprintf("| 🕰️ STALE (old content) | %d |\n", staleCount))
	sb.WriteString(fmt.Sprintf("| 🔥 Fresh (<%dh) | %d |\n", freshHours, freshCount))
	sb.WriteString(fmt.Sprintf("| 🌙 Semi-fresh (<%dh) | %d |\n", semiFreshHours, semiCount))
	sb.WriteString(fmt.Sprintf("| 🚫 Blocked sources | %d |\n\n", len(blocked)))

	sb.WriteString("## 🗑️ Top 10 Dead/Stale Sources\n\n")
	var deadList []string
	for _, r := range results {
		if r.Status == "DEAD" || r.Status == "STALE" {
			deadList = append(deadList, r.URL)
		}
	}
	sort.Strings(deadList)
	for i, u := range deadList {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... and %d more\n", len(deadList)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s\n", u))
	}
	sb.WriteString("\n---\n✅ Report generated by V2rayCollector Source Checker (freshness-aware)\n")
	os.WriteFile(reportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Source report written to %s\n", reportFile)
}
