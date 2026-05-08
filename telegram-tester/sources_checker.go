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
	deadSourcesFile     = "../dead_sources.txt"
	deadSourcesArchive  = "../dead_sources_archive.txt"
	sourcesReportMD     = "../reports/sources_report.md"
	sourcesReportCSV    = "../reports/sources_data.csv"
	activeSourcesFile   = "../active_sources.json"
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
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
}

func main() {
	os.MkdirAll("../reports", 0755)
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
		generateEmptySourcesReport()
		return
	}
	deadMap := loadMap(deadSourcesFile)
	archiveMap := loadMap(deadSourcesArchive)

	var activeURLs []string
	var deadInfos []SourceStatus
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

	generateSourcesReportMD(activeURLs, deadInfos)
	generateSourcesReportCSV(activeURLs, deadInfos)
	fmt.Printf("✅ Active sources: %d, Dead: %d\n", len(activeURLs), len(deadInfos))
}

func generateEmptySourcesReport() {
	md := fmt.Sprintf(`# 📊 گزارش اسکنر ساب‌لینک‌ها

**تاریخ اجرا:** %s

## خلاصه آماری
| معیار | مقدار |
|-------|-------|
| کل ساب‌لینک‌ها | 0 |
| ✅ فعال | 0 |
| 💀 مرده | 0 |

هیچ ساب‌لینکی یافت نشد.
`, time.Now().Format("2006-01-02 15:04:05"))
	os.WriteFile(sourcesReportMD, []byte(md), 0644)

	csvFile, _ := os.Create(sourcesReportCSV)
	defer csvFile.Close()
	w := csv.NewWriter(csvFile)
	w.Write([]string{"ExecutionTime", "Total", "Active", "Dead", "Message"})
	w.Write([]string{time.Now().Format("2006-01-02 15:04:05"), "0", "0", "0", "empty"})
	w.Flush()
}

func generateSourcesReportMD(active []string, dead []SourceStatus) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر ساب‌لینک‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n| معیار | مقدار |\n|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل ساب‌لینک‌ها | %d |\n", len(active)+len(dead)))
	sb.WriteString(fmt.Sprintf("| ✅ فعال | %d |\n", len(active)))
	sb.WriteString(fmt.Sprintf("| 💀 مرده | %d |\n\n", len(dead)))

	sb.WriteString("## ✅ ساب‌لینک‌های فعال\n\n")
	for _, u := range active {
		sb.WriteString(fmt.Sprintf("- %s\n", u))
	}
	if len(active) == 0 {
		sb.WriteString("(هیچ ساب‌لینک فعالی وجود ندارد)\n")
	}
	sb.WriteString("\n## 💀 ساب‌لینک‌های مرده\n\n")
	if len(dead) > 0 {
		sb.WriteString(fmt.Sprintf("<details>\n<summary>نمایش همه %d ساب‌لینک (کلیک کنید)</summary>\n\n", len(dead)))
		for _, d := range dead {
			sb.WriteString(fmt.Sprintf("- `%s` (%s)\n", d.URL, d.Status))
		}
		sb.WriteString("\n</details>\n")
	} else {
		sb.WriteString("(هیچ ساب‌لینک مرده‌ای وجود ندارد)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط GitHub Actions تولید شده است.\n")
	os.WriteFile(sourcesReportMD, []byte(sb.String()), 0644)
}

func generateSourcesReportCSV(active []string, dead []SourceStatus) {
	csvFile, err := os.Create(sourcesReportCSV)
	if err != nil {
		fmt.Printf("Error creating CSV: %v\n", err)
		return
	}
	defer csvFile.Close()
	w := csv.NewWriter(csvFile)
	defer w.Flush()
	w.Write([]string{"ExecutionTime", "URL", "Status", "LastModified", "HasConfig", "Error"})
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	for _, u := range active {
		w.Write([]string{nowStr, u, "active", "", "true", ""})
	}
	for _, d := range dead {
		lastModStr := ""
		if !d.LastMod.IsZero() {
			lastModStr = d.LastMod.Format("2006-01-02 15:04:05")
		}
		w.Write([]string{nowStr, d.URL, d.Status, lastModStr, fmt.Sprintf("%v", d.HasConfig), d.Error})
	}
	fmt.Printf("✅ CSV report: %s\n", sourcesReportCSV)
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
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return SourceStatus{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Range", "bytes=0-50000")
	resp, err := httpClient.Do(req)
	if err != nil {
		return SourceStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return SourceStatus{URL: url, Status: "DEAD"}, nil
	}
	lastModStr := resp.Header.Get("Last-Modified")
	var lastMod time.Time
	if lastModStr != "" {
		lastMod, _ = time.Parse(time.RFC1123, lastModStr)
	}
	limited := io.LimitReader(resp.Body, sampleSize)
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
	fmt.Printf("✅ Active sources written to %s\n", activeSourcesFile)
}
