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
	"strconv"
	"strings"
	"time"
)

const (
	deadSourcesFile = "dead_sources.txt"
)

var (
	httpClient = &http.Client{Timeout: 10 * time.Second}
	regexPatterns = []*regexp.Regexp{
		// همان الگوهای قبلی
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
	json.Unmarshal(data, &sources)

	var active []SourceInfo
	var dead []SourceInfo

	for i, url := range sources {
		fmt.Printf("[%d/%d] Checking: %s ... ", i+1, len(sources), url)
		hasConfig, lastMod, err := checkSource(url)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		daysSince := int(time.Since(lastMod).Hours() / 24)
		fmt.Printf("Last modified: %s (%d days ago), Config: %v\n", lastMod.Format("2006-01-02"), daysSince, hasConfig)
		if hasConfig && daysSince <= 30 {
			active = append(active, SourceInfo{URL: url, LastMod: lastMod, HasConfig: true})
		} else {
			dead = append(dead, SourceInfo{URL: url, LastMod: lastMod, HasConfig: hasConfig})
		}
		time.Sleep(500 * time.Millisecond)
	}

	// نوشتن Sources.json جدید (فقط لینک‌های فعال)
	writeActiveSources("Sources.json", active)
	// به‌روزرسانی dead_sources.txt
	updateDeadSources(dead)

	fmt.Printf("\n✅ Active sources: %d, Dead/Inactive: %d\n", len(active), len(dead))
}

func checkSource(url string) (hasConfig bool, lastMod time.Time, err error) {
	// HEAD برای Last-Modified
	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, time.Time{}, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return false, time.Time{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	lm := resp.Header.Get("Last-Modified")
	if lm != "" {
		lastMod, _ = time.Parse(time.RFC1123, lm)
	}
	resp.Body.Close()

	// GET نمونه برای بررسی کانفیگ
	req2, _ := http.NewRequest("GET", url, nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	resp2, err := httpClient.Do(req2)
	if err != nil {
		return false, lastMod, err
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp2.Body, 50*1024))
	content := string(body)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}
	has := anyConfig(content)
	return has, lastMod, nil
}

func anyConfig(text string) bool {
	for _, re := range regexPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func writeActiveSources(path string, sources []SourceInfo) {
	list := make([]string, len(sources))
	for i, s := range sources {
		list[i] = s.URL
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	os.WriteFile(path, data, 0644)
	fmt.Printf("✅ Updated %s with %d active sources.\n", path, len(sources))
}

func updateDeadSources(dead []SourceInfo) {
	existing := make(map[string]int64)
	data, _ := os.ReadFile(deadSourcesFile)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if ts, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				existing[parts[0]] = ts
			}
		}
	}
	now := time.Now().Unix()
	for _, src := range dead {
		daysSince := int(time.Since(src.LastMod).Hours() / 24)
		var next int64
		if daysSince > 60 || !src.HasConfig {
			next = now + 30*24*3600
		} else if daysSince > 30 {
			next = now + 7*24*3600
		} else {
			next = now + 24*3600
		}
		existing[src.URL] = next
	}
	var lines []string
	for url, ts := range existing {
		lines = append(lines, fmt.Sprintf("%s %d", url, ts))
	}
	sort.Strings(lines)
	os.WriteFile(deadSourcesFile, []byte(strings.Join(lines, "\n")), 0644)
	fmt.Printf("✅ Updated dead_sources.txt with %d entries.\n", len(existing))
}
