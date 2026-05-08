package main

import (
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
	deadSourcesFile = "dead_sources.txt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sources_checker.go <Sources.json>")
		os.Exit(1)
	}
	inputFile := os.Args[1]
	data, _ := os.ReadFile(inputFile)
	var sources []string
	json.Unmarshal(data, &sources)

	// بارگذاری dead sources
	deadMap := loadDeadSources()
	var alive []string
	var deadList []SourceInfo

	for _, url := range sources {
		status, lastMod, err := checkSource(url)
		daysSince := int(time.Since(lastMod).Hours() / 24)
		nextDays := 1
		if err != nil || status != "OK" || daysSince > 60 {
			nextDays = 30
		} else if daysSince > 30 {
			nextDays = 7
		}
		if status == "OK" && daysSince <= 30 {
			alive = append(alive, url)
		} else {
			deadList = append(deadList, SourceInfo{URL: url, NextCheckDays: nextDays})
		}
	}
	// نوشتن Sources.json (فقط لینک‌های زنده)
	writeSourcesJSON("Sources.json", alive)
	// به‌روزرسانی dead_sources.txt
	updateDeadSources(deadMap, deadList)
	saveDeadSources(deadMap)
}
