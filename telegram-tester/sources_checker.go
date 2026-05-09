// telegram-tester/sources_checker.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
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
	checkTimeout        = 10 * time.Second
	sampleSize          = 50 * 1024
	defaultRetryCount   = 3
	defaultBaseDelay    = 1 * time.Second
	defaultJitter       = 500 * time.Millisecond
	defaultActiveDays   = 30
	defaultConcurrency  = 5

	dataDir            = "../data"
	deadSourcesRecent  = dataDir + "/dead_sources_recent.json"
	deadSourcesOld     = dataDir + "/dead_sources_old.json"
	activeSourcesFile  = "../Sources.json"
	sourcesReportFile  = "../reports/sources_report.md"
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
		regexp.MustCompile(`hy2://[^\s]+`),
		regexp.MustCompile(`tuic://[^\s]+`),
		regexp.MustCompile(`wireguard://[^\s]+`),
		regexp.MustCompile(`warp://[^\s]+`),
		regexp.MustCompile(`tg://proxy\?[^\s]+`),
		regexp.MustCompile(`tg://socks\?[^\s]+`),
		regexp.MustCompile(`slipnet://[^\s]+`),
		regexp.MustCompile(`https?://[^\s]+:\d+(?:[^\s]*)?`),
		regexp.MustCompile(`https?://[^@\s]+@[^\s]+`),
		regexp.MustCompile(`socks(?:5)?://[^\s]+@[^\s]+`),
		regexp.MustCompile(`socks(?:5)?://[^\s]+:\d+`),
		regexp.MustCompile(`-----BEGIN ARGO VPN BRIDGE BLOCK-----[\s\S]+?-----END ARGO VPN BRIDGE BLOCK-----`),
	}
)

var (
	oldScan = flag.Bool("old-scan", false, "Scan only sources older than 365 days (yearly)")
)

type DeadSourceInfo struct {
	URL       string `json:"url"`
	LastMod   int64  `json:"last_mod"`
	CheckedAt int64  `json:"checked_at"`
}

type SourceStatus struct {
	URL       string    `json:"url"`
	LastMod   time.Time `json:"last_mod"`
	HasConfig bool      `json:"has_config"`
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
}

var printMutex sync.Mutex

func safePrintf(format string, args ...interface{}) {
	printMutex.Lock()
	defer printMutex.Unlock()
	fmt.Printf(format, args...)
}

func main() {
	flag.Parse()
	os.MkdirAll("../reports", 0755)
	os.MkdirAll(dataDir, 0755)

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sources_checker.go <Sources.json> [-old-scan]")
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

	recentDead := loadDeadSourceArchive(deadSourcesRecent)
	oldDead := loadDeadSourceArchive(deadSourcesOld)

	urlSet := make(map[string]bool)
	for _, src := range sources {
		urlSet[src] = true
	}
	if *oldScan {
		for url := range oldDead {
			urlSet[url] = true
		}
	} else {
		for url := range recentDead {
			urlSet[url] = true
		}
	}
	urlList := make([]string, 0, len(urlSet))
	for u := range urlSet {
		urlList = append(urlList, u)
	}

	jobs := make(chan string, len(urlList))
	results := make(chan SourceStatus, len(urlList))
	var wg sync.WaitGroup
	for i := 0; i < defaultConcurrency; i++ {
		wg.Add(1)
		go sourceWorker(jobs, results, &wg)
	}
	for _, url := range urlList {
		jobs <- url
	}
	close(jobs)
	wg.Wait()
	close(results)

	var activeURLs []string
	updatedRecent := make(map[string]DeadSourceInfo)
	updatedOld := make(map[string]DeadSourceInfo)

	for res := range results {
		daysSince := 0
		if !res.LastMod.IsZero() {
			daysSince = int(time.Since(res.LastMod).Hours() / 24)
		}
		if res.Status == "OK" && res.HasConfig && daysSince <= defaultActiveDays {
			activeURLs = append(activeURLs, res.URL)
			delete(recentDead, res.URL)
			delete(oldDead, res.URL)
		} else {
			info := DeadSourceInfo{
				URL:       res.URL,
				LastMod:   res.LastMod.Unix(),
				CheckedAt: time.Now().Unix(),
			}
			if daysSince > 365 {
				updatedOld[res.URL] = info
				delete(recentDead, res.URL)
			} else {
				updatedRecent[res.URL] = info
				delete(oldDead, res.URL)
			}
		}
	}
	for k, v := range recentDead {
		updatedRecent[k] = v
	}
	for k, v := range oldDead {
		updatedOld[k] = v
	}

	// ذخیره منابع فعال در Sources.json
	saveActiveSources(activeURLs, inputFile)
	saveDeadSourceArchive(deadSourcesRecent, updatedRecent)
	saveDeadSourceArchive(deadSourcesOld, updatedOld)
	generateSourcesReport(activeURLs)
	fmt.Printf("\n✅ Active sources: %d, Recent dead: %d, Old dead: %d\n", len(activeURLs), len(updatedRecent), len(updatedOld))
}

func sourceWorker(jobs <-chan string, results chan<- SourceStatus, wg *sync.WaitGroup) {
	defer wg.Done()
	for url := range jobs {
		res := checkSourceWithRetry(url)
		results <- res
	}
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
	daysSince := 0
	if !lastMod.IsZero() {
		daysSince = int(time.Since(lastMod).Hours() / 24)
	}
	status := "DEAD"
	if resp.StatusCode == 200 || resp.StatusCode == 206 {
		if hasConfig && daysSince <= defaultActiveDays {
			status = "OK"
		} else if !hasConfig {
			status = "NO_CONFIG"
		} else {
			status = "INACTIVE"
		}
	}
	safePrintf("[INFO] %s -> lastMod: %s (%d days), hasConfig: %v, status: %s\n",
		url, lastMod.Format("2006-01-02"), daysSince, hasConfig, status)
	return SourceStatus{
		URL:       url,
		LastMod:   lastMod,
		HasConfig: hasConfig,
		Status:    status,
	}, nil
}

func anyConfigInText(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func loadDeadSourceArchive(file string) map[string]DeadSourceInfo {
	m := make(map[string]DeadSourceInfo)
	data, err := os.ReadFile(file)
	if err != nil {
		return m
	}
	var list []DeadSourceInfo
	if err := json.Unmarshal(data, &list); err != nil {
		return m
	}
	for _, item := range list {
		m[item.URL] = item
	}
	return m
}

func saveDeadSourceArchive(file string, m map[string]DeadSourceInfo) {
	list := make([]DeadSourceInfo, 0, len(m))
	for _, v := range m {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].URL < list[j].URL })
	data, _ := json.MarshalIndent(list, "", "  ")
	os.WriteFile(file, data, 0644)
	fmt.Printf("✅ Saved %s with %d entries.\n", file, len(list))
}

func saveActiveSources(active []string, inputFile string) {
	data, err := json.MarshalIndent(active, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		return
	}
	os.WriteFile(inputFile, data, 0644)
	fmt.Printf("✅ Active sources written to %s\n", inputFile)
}

func generateEmptySourcesReport() {
	report := fmt.Sprintf(`# 📊 گزارش اسکنر ساب‌لینک‌ها

**تاریخ اجرا:** %s

## خلاصه آماری
| معیار | مقدار |
|-------|-------|
| کل ساب‌لینک‌ها | 0 |
| ✅ فعال | 0 |
| 💀 مرده | 0 |

هیچ ساب‌لینکی یافت نشد.
`, time.Now().Format("2006-01-02 15:04:05"))
	os.WriteFile(sourcesReportFile, []byte(report), 0644)
}

func generateSourcesReport(active []string) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر ساب‌لینک‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n| معیار | مقدار |\n|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| ساب‌لینک‌های فعال | %d |\n", len(active)))
	sb.WriteString("\n## ✅ ساب‌لینک‌های فعال\n\n")
	if len(active) > 0 {
		for _, u := range active {
			sb.WriteString(fmt.Sprintf("- %s\n", u))
		}
	} else {
		sb.WriteString("(هیچ ساب‌لینک فعالی وجود ندارد)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط GitHub Actions تولید شده است.\n")
	os.WriteFile(sourcesReportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", sourcesReportFile)
}
