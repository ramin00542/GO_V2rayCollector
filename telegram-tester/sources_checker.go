// telegram-tester/sources_checker.go
package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	deadSourcesFile     = "dead_sources.txt"
	deadSourcesArchive  = "dead_sources_archive.txt"
	sourcesReportFile   = "sources_report.txt"
	activeSourcesFile   = "Sources.json"
	checkTimeout        = 10 * time.Second
	sampleSize          = 50 * 1024
	defaultRetryCount   = 3
	defaultBaseDelay    = 1 * time.Second
	defaultJitter       = 500 * time.Millisecond
	activeDays          = 30
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

type SourceStatus struct {
	URL       string    `json:"url"`
	LastMod   time.Time `json:"last_mod"`
	HasConfig bool      `json:"has_config"`
	Status    string    `json:"status"` // "OK", "DEAD", "NO_CONFIG"
	Error     string    `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sources_checker.go <Sources.json>")
		os.Exit(1)
	}
	inputFile := os.Args[1]
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
	if len(sources) == 0 {
		fmt.Println("No sources found.")
		return
	}
	deadMap := loadMap(deadSourcesFile)
	archiveMap := loadMap(deadSourcesArchive)

	var activeURLs []string
	var deadInfos []SourceStatus
	var mu sync.Mutex
	jobs := make(chan string, len(sources))
	results := make(chan SourceStatus, len(sources))
	var wg sync.WaitGroup
	workers := 5
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				res := checkSourceWithRetry(url)
				results <- res
				time.Sleep(time.Duration(rand.Intn(500)+500) * time.Millisecond)
			}
		}()
	}
	for _, url := range sources {
		jobs <- url
	}
	close(jobs)
	wg.Wait()
	close(results)

	for res := range results {
		if res.Status == "OK" && res.HasConfig && time.Since(res.LastMod).Hours()/24 <= float64(activeDays) {
			activeURLs = append(activeURLs, res.URL)
			delete(deadMap, res.URL)
			delete(archiveMap, res.URL)
		} else {
			deadInfos = append(deadInfos, res)
			deadMap[res.URL] = true
			if !archiveMap[res.URL] {
				archiveMap[res.URL] = true
			}
		}
	}
	saveActiveSources(activeURLs)
	saveMap(deadSourcesFile, deadMap)
	saveMap(deadSourcesArchive, archiveMap)
	generateSourcesReport(activeURLs, deadInfos)
	fmt.Printf("✅ Active sources: %d, Dead: %d\n", len(activeURLs), len(deadInfos))
}

func checkSourceWithRetry(url string) SourceStatus {
	var lastErr error
	for attempt := 1; attempt <= defaultRetryCount; attempt++ {
		res, err := checkSource(url)
		if err == nil {
			return res
		}
		lastErr = err
		delay := defaultBaseDelay * time.Duration(1<<uint(attempt-1))
		jitter := time.Duration(rand.Int63n(int64(defaultJitter)))
		time.Sleep(delay + jitter)
	}
	return SourceStatus{URL: url, Status: "DEAD", Error: lastErr.Error()}
}

func checkSource(url string) (SourceStatus, error) {
	// HEAD request
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return SourceStatus{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return SourceStatus{URL: url, Status: "DEAD"}, nil
	}
	lastModStr := resp.Header.Get("Last-Modified")
	var lastMod time.Time
	if lastModStr != "" {
		lastMod, _ = time.Parse(time.RFC1123, lastModStr)
	}
	resp.Body.Close()

	// GET sample
	req2, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return SourceStatus{}, err
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	resp2, err := httpClient.Do(req2)
	if err != nil || resp2.StatusCode != 200 {
		if resp2 != nil {
			resp2.Body.Close()
		}
		return SourceStatus{URL: url, Status: "DEAD"}, nil
	}
	defer resp2.Body.Close()
	limited := io.LimitReader(resp2.Body, sampleSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return SourceStatus{}, err
	}
	content := string(body)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil && len(decoded) > 0 {
		content = string(decoded)
	}
	hasConfig := anyConfigInText(content)
	if !hasConfig {
		return SourceStatus{URL: url, LastMod: lastMod, HasConfig: false, Status: "NO_CONFIG"}, nil
	}
	if lastMod.IsZero() {
		lastMod = time.Now()
	}
	return SourceStatus{URL: url, LastMod: lastMod, HasConfig: true, Status: "OK"}, nil
}

func anyConfigInText(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// ------------------------------ I/O helpers ------------------------------
func loadMap(file string) map[string]bool {
	m := make(map[string]bool)
	data, err := os.ReadFile(file)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			m[line] = true
		}
	}
	return m
}

func saveMap(file string, m map[string]bool) {
	var lines []string
	for k := range m {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0644)
}

func saveActiveSources(urls []string) {
	data, err := json.MarshalIndent(urls, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		return
	}
	os.WriteFile(activeSourcesFile, data, 0644)
}

func generateSourcesReport(active []string, dead []SourceStatus) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر ساب‌لینک‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n")
	sb.WriteString(fmt.Sprintf("| معیار | مقدار |\n"))
	sb.WriteString(fmt.Sprintf("|-------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| کل ساب‌لینک‌های بررسی شده | %d |\n", len(active)+len(dead)))
	sb.WriteString(fmt.Sprintf("| ✅ فعال | %d |\n", len(active)))
	sb.WriteString(fmt.Sprintf("| 💀 مرده/غیرفعال | %d |\n\n", len(dead)))
	sb.WriteString("## ✅ ساب‌لینک‌های فعال\n\n")
	for _, u := range active {
		sb.WriteString(fmt.Sprintf("- %s\n", u))
	}
	if len(active) == 0 {
		sb.WriteString("(هیچ ساب‌لینک فعالی وجود ندارد)\n")
	}
	sb.WriteString("\n## 💀 ساب‌لینک‌های مرده (۱۰ مورد اول)\n\n")
	for i, d := range dead {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d ساب‌لینک دیگر\n", len(dead)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s (%s)\n", d.URL, d.Status))
	}
	os.WriteFile(sourcesReportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", sourcesReportFile)
}
