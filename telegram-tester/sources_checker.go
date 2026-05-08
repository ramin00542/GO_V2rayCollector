package main

import (
	"encoding/base64"
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
	checkTimeout       = 10 * time.Second
	sampleSize         = 50 * 1024
	deadSourcesFile    = "dead_sources.txt"
	deadSourcesArchive = "dead_sources_archive.txt"
	sourcesReportFile  = "sources_report.md"
	activeDays         = 30
)

var (
	httpClient = &http.Client{Timeout: checkTimeout}
	regexPatterns = []*regexp.Regexp{
		// همان الگوهای قبلی
	}
)

type SourceInfo struct {
	URL       string
	LastMod   time.Time
	HasConfig bool
	Status    string
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

	var active []SourceInfo
	var dead []SourceInfo

	for i, url := range sources {
		fmt.Printf("[%d/%d] Checking: %s ... ", i+1, len(sources), url)
		hasConfig, lastMod, status, err := checkSource(url)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		daysSince := int(time.Since(lastMod).Hours() / 24)
		if daysSince < 0 {
			daysSince = 0
		}
		fmt.Printf("Last mod: %s (%d days ago), Config: %v\n", lastMod.Format("2006-01-02"), daysSince, hasConfig)

		if status == "OK" && hasConfig && daysSince <= activeDays {
			active = append(active, SourceInfo{URL: url, LastMod: lastMod, HasConfig: true, Status: status})
			delete(deadMap, url)
			delete(archiveMap, url)
		} else {
			dead = append(dead, SourceInfo{URL: url, LastMod: lastMod, HasConfig: hasConfig, Status: status})
			deadMap[url] = true
			if !archiveMap[url] {
				archiveMap[url] = true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	saveActiveSources(active)
	saveMap(deadSourcesFile, deadMap)
	saveMap(deadSourcesArchive, archiveMap)
	generateSourcesReport(active, dead)

	fmt.Printf("\n✅ Active: %d, Dead: %d\n", len(active), len(dead))
}

func checkSource(url string) (hasConfig bool, lastMod time.Time, status string, err error) {
	// HEAD
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, time.Time{}, "ERROR", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return false, time.Time{}, "DEAD", nil
	}
	lm := resp.Header.Get("Last-Modified")
	if lm != "" {
		lastMod, _ = time.Parse(time.RFC1123, lm)
	}
	resp.Body.Close()

	// GET sample
	req2, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, lastMod, "DEAD", err
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	resp2, err := httpClient.Do(req2)
	if err != nil || resp2.StatusCode != 200 {
		if resp2 != nil {
			resp2.Body.Close()
		}
		return false, lastMod, "DEAD", nil
	}
	defer resp2.Body.Close()
	limited := io.LimitReader(resp2.Body, sampleSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return false, lastMod, "DEAD", err
	}
	content := string(body)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil && len(decoded) > 0 {
		content = string(decoded)
	}
	has := anyConfig(content)
	if !has {
		return false, lastMod, "NO_CONFIG", nil
	}
	if lastMod.IsZero() {
		lastMod = time.Now()
	}
	return true, lastMod, "OK", nil
}

func anyConfig(text string) bool {
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
	fmt.Printf("✅ Saved %s with %d entries.\n", file, len(lines))
}

func saveActiveSources(sources []SourceInfo) {
	list := make([]string, len(sources))
	for i, s := range sources {
		list[i] = s.URL
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		return
	}
	os.WriteFile("../Sources.json", data, 0644) // overwrite original
	fmt.Printf("✅ Updated Sources.json with %d active sources.\n", len(sources))
}

func generateSourcesReport(active, dead []SourceInfo) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر ساب‌لینک‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n")
	sb.WriteString("| معیار | مقدار |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| **ساب‌لینک‌های فعال** (≤%d روز + کانفیگ) | %d |\n", activeDays, len(active)))
	sb.WriteString(fmt.Sprintf("| **ساب‌لینک‌های مرده/غیرفعال** | %d |\n\n", len(dead)))

	if len(active) > 0 {
		sb.WriteString("## ✅ ساب‌لینک‌های فعال (۱۰ مورد اول)\n\n")
		for i, s := range active {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("... و %d ساب‌لینک دیگر\n", len(active)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("- %s (آخرین تغییر: %s)\n", s.URL, s.LastMod.Format("2006-01-02")))
		}
	} else {
		sb.WriteString("(هیچ ساب‌لینک فعالی وجود ندارد)\n")
	}
	sb.WriteString("\n## 💀 ساب‌لینک‌های غیرفعال (۱۰ مورد اول)\n\n")
	for i, s := range dead {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d ساب‌لینک دیگر\n", len(dead)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s (وضعیت: %s)\n", s.URL, s.Status))
	}
	sb.WriteString("\n---\n✅ گزارش توسط ابزار اسکنر ساب‌لینک‌ها تولید شده است.\n")
	os.WriteFile(sourcesReportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", sourcesReportFile)
}
