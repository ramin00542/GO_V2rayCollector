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
	checkTimeout          = 10 * time.Second
	sampleSize            = 50 * 1024 // 50 KB
	deadSourcesFile       = "dead_sources.txt"
	deadSourcesArchive    = "dead_sources_archive.txt"
	sourcesReportFile     = "sources_report.txt"
	activeSourcesFile     = "Sources.json" // بازنویسی می‌شود
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

type SourceInfo struct {
	URL       string
	LastMod   time.Time
	HasConfig bool
	Status    string // "OK", "DEAD", "NO_CONFIG"
}

type SourceStats struct {
	Total           int
	Active          int
	Dead            int
	NoConfig        int
	Errors          int
	RevivedFromDead int
	RevivedFromArc  int
	NewArchived     int
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sources_checker.go <Sources.json>")
		os.Exit(1)
	}
	inputFile := os.Args[1]

	// خواندن فایل JSON
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
		fmt.Println("No sources found in JSON.")
		return
	}

	// بارگذاری لیست سیاه و بایگانی
	deadMap := loadMap(deadSourcesFile)
	archiveMap := loadMap(deadSourcesArchive)

	stats := &SourceStats{Total: len(sources)}
	var active []SourceInfo
	var deadInfos []SourceInfo

	for i, url := range sources {
		fmt.Printf("[%d/%d] Checking: %s ... ", i+1, stats.Total, url)
		hasConfig, lastMod, status, err := analyzeSource(url)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			stats.Errors++
			deadInfos = append(deadInfos, SourceInfo{URL: url, HasConfig: false, Status: "ERROR"})
			continue
		}
		daysSince := int(time.Since(lastMod).Hours() / 24)
		if daysSince < 0 {
			daysSince = 0
		}
		fmt.Printf("Last mod: %s (%d days ago), Config: %v, Status: %s\n",
			lastMod.Format("2006-01-02"), daysSince, hasConfig, status)

		if status == "OK" && hasConfig && daysSince <= 30 {
			active = append(active, SourceInfo{URL: url, LastMod: lastMod, HasConfig: true, Status: status})
			stats.Active++
			if deadMap[url] {
				delete(deadMap, url)
				stats.RevivedFromDead++
			}
			if archiveMap[url] {
				delete(archiveMap, url)
				stats.RevivedFromArc++
			}
		} else {
			deadInfos = append(deadInfos, SourceInfo{URL: url, LastMod: lastMod, HasConfig: hasConfig, Status: status})
			stats.Dead++
			if status == "NO_CONFIG" {
				stats.NoConfig++
			}
			// به روز رسانی deadMap و archiveMap
			deadMap[url] = true
			if !archiveMap[url] {
				archiveMap[url] = true
				stats.NewArchived++
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	// ذخیره فایل‌ها
	writeActiveSources(active)               // بازنویسی Sources.json با منابع فعال
	saveMap(deadSourcesFile, deadMap)        // لیست سیاه موقت
	saveMap(deadSourcesArchive, archiveMap)  // بایگانی دائمی
	generateSourceReport(stats, active, deadInfos)

	fmt.Printf("\n✅ Active: %d, Dead: %d, Archived total: %d, Errors: %d\n",
		stats.Active, stats.Dead, len(archiveMap), stats.Errors)
}

// ------------------------------------------------------------
// توابع تحلیلی
// ------------------------------------------------------------
func analyzeSource(url string) (hasConfig bool, lastMod time.Time, status string, err error) {
	// HEAD request برای Last-Modified و بررسی زنده بودن
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, time.Time{}, "DEAD", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return false, time.Time{}, "DEAD", fmt.Errorf("HTTP error: %v", err)
	}
	lmStr := resp.Header.Get("Last-Modified")
	if lmStr != "" {
		lastMod, _ = time.Parse(time.RFC1123, lmStr)
	}
	resp.Body.Close()

	// GET نمونه برای بررسی محتوا
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
		return false, lastMod, "DEAD", fmt.Errorf("GET failed: %v", err)
	}
	defer resp2.Body.Close()
	limited := io.LimitReader(resp2.Body, sampleSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return false, lastMod, "DEAD", err
	}
	content := string(body)
	// تلاش برای دیکد base64
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil && len(decoded) > 0 {
		content = string(decoded)
	}
	has := anyConfig(content)
	if !has {
		return false, lastMod, "NO_CONFIG", nil
	}
	// اگر Last-Modified وجود نداشت، زمان حال را در نظر بگیر (منبع تازه فرض شود)
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

// ------------------------------------------------------------
// توابع فایل
// ------------------------------------------------------------
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

func writeActiveSources(sources []SourceInfo) {
	list := make([]string, len(sources))
	for i, s := range sources {
		list[i] = s.URL
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		return
	}
	if err := os.WriteFile(activeSourcesFile, data, 0644); err != nil {
		fmt.Printf("Error writing %s: %v\n", activeSourcesFile, err)
	} else {
		fmt.Printf("✅ Updated %s with %d active sources.\n", activeSourcesFile, len(sources))
	}
}

// ------------------------------------------------------------
// گزارش زیبا
// ------------------------------------------------------------
func generateSourceReport(stats *SourceStats, active, dead []SourceInfo) {
	var sb strings.Builder
	sb.WriteString("# 📊 گزارش اسکنر ساب‌لینک‌ها\n\n")
	sb.WriteString(fmt.Sprintf("**تاریخ اجرا:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("## خلاصه آماری\n\n")
	sb.WriteString("| معیار | مقدار |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| کل ساب‌لینک‌های بررسی شده | %d |\n", stats.Total))
	sb.WriteString(fmt.Sprintf("| ✅ فعال (OK + کانفیگ + ≤۳۰ روز) | %d |\n", stats.Active))
	sb.WriteString(fmt.Sprintf("| 💀 مرده (HTTP error) | %d |\n", stats.Dead-stats.NoConfig))
	sb.WriteString(fmt.Sprintf("| ⚠️ زنده اما بدون کانفیگ (NO_CONFIG) | %d |\n", stats.NoConfig))
	sb.WriteString(fmt.Sprintf("| 🔄 احیا شده از لیست سیاه موقت | %d |\n", stats.RevivedFromDead))
	sb.WriteString(fmt.Sprintf("| 📦 احیا شده از بایگانی دائمی | %d |\n", stats.RevivedFromArc))
	sb.WriteString(fmt.Sprintf("| 🆕 اضافه شده به بایگانی (برای اولین بار) | %d |\n", stats.NewArchived))
	sb.WriteString(fmt.Sprintf("| ❌ خطا در بررسی | %d |\n\n", stats.Errors))

	sb.WriteString("## ✅ ساب‌لینک‌های فعال (۱۰ مورد اول)\n\n")
	for i, s := range active {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d ساب‌لینک دیگر\n", len(active)-10))
			break
		}
		lastDate := s.LastMod.Format("2006-01-02")
		sb.WriteString(fmt.Sprintf("- %s (آخرین تغییر: %s)\n", s.URL, lastDate))
	}
	if len(active) == 0 {
		sb.WriteString("(هیچ ساب‌لینک فعالی وجود ندارد)\n")
	}
	sb.WriteString("\n## 💀 ساب‌لینک‌های مرده/غیرفعال (۱۰ مورد اول)\n\n")
	for i, s := range dead {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... و %d ساب‌لینک دیگر\n", len(dead)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s (وضعیت: %s)\n", s.URL, s.Status))
	}
	if len(dead) == 0 {
		sb.WriteString("(هیچ ساب‌لینک مرده‌ای وجود ندارد)\n")
	}
	sb.WriteString("\n---\n✅ گزارش توسط اسکنر خودکار ساب‌لینک‌ها تولید شده است.\n")
	os.WriteFile(sourcesReportFile, []byte(sb.String()), 0644)
	fmt.Printf("✅ Report written to %s\n", sourcesReportFile)
}
