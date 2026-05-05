func main() {
    gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
    flag.Parse()

    // 📥 مرحله 1: دریافت کانفیگ‌ها از کانال‌های تلگرام (channels.csv)
    fileData, err := collector.ReadFileContent("channels.csv")
    if err == nil {
        var channels []ChannelsType
        if err = csvutil.Unmarshal([]byte(fileData), &channels); err == nil {
            for _, channel := range channels {
                channel.URL = collector.ChangeUrlToTelegramWebUrl(channel.URL)
                resp := HttpRequest(channel.URL)
                doc, err := goquery.NewDocumentFromReader(resp.Body)
                _ = resp.Body.Close()
                if err != nil {
                    gologger.Error().Msg(err.Error())
                }
                fmt.Println(" ")
                fmt.Println("---------------------------------------")
                gologger.Info().Msg("Crawling " + channel.URL)
                CrawlForV2ray(doc, channel.URL, channel.AllMessagesFlag)
                gologger.Info().Msg("Crawled " + channel.URL + " ! ")
                fmt.Println("---------------------------------------")
                fmt.Println(" ")
            }
        } else {
            gologger.Warning().Msg("Error reading channels.csv: " + err.Error())
        }
    } else {
        gologger.Warning().Msg("channels.csv not found, skipping...")
    }

    // 🌐 مرحله 2: دریافت کانفیگ‌ها از لینک‌های ساب (Sources.json)
    sourcesData, err := collector.ReadFileContent("Sources.json")
    if err == nil {
        var sources []string
        if err = json.Unmarshal([]byte(sourcesData), &sources); err == nil {
            gologger.Info().Msg(fmt.Sprintf("Found %d subscription sources", len(sources)))
            for idx, sourceURL := range sources {
                gologger.Info().Msg(fmt.Sprintf("[%d/%d] Fetching from subscription link: %s", idx+1, len(sources), sourceURL))
                fetchAndProcessSubscription(sourceURL)
            }
        } else {
            gologger.Warning().Msg("Error parsing Sources.json: " + err.Error())
        }
    } else {
        gologger.Warning().Msg("Sources.json not found, skipping...")
    }

    // 📁 مرحله 3: ذخیره نهایی فایل‌ها (ادامه کد قبلی شما)
    gologger.Info().Msg("Creating output files !")
    for proto, configcontent := range configs {
        // ... (بقیه کد شما برای ذخیره فایل‌ها همان‌طور که هست)
        lines := collector.RemoveDuplicate(configcontent)
        lines = AddConfigNames(lines, proto)
        // ... (بقیه کد شما)
    }
    gologger.Info().Msg("All Done :D")
}

// این تابع جدید، لینک ساب را گرفته و کانفیگ‌های آن را پردازش می‌کند
func fetchAndProcessSubscription(subURL string) {
    resp, err := http.Get(subURL)
    if err != nil {
        gologger.Error().Msg(fmt.Sprintf("Failed to fetch subscription %s: %v", subURL, err))
        return
    }
    defer resp.Body.Close()

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        gologger.Error().Msg(fmt.Sprintf("Failed to read response body from %s: %v", subURL, err))
        return
    }

    content := string(bodyBytes)
    // اگر محتوا base64 بود، آن را دیکد کن
    if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
        content = string(decoded)
    }

    lines := strings.Split(content, "\n")
    gologger.Info().Msg(fmt.Sprintf("Processing %d lines from %s", len(lines), subURL))

    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        // از رجکس‌های شما برای شناسایی پروتکل استفاده می‌شود
        for protoRegex, regexValue := range myregex {
            re := regexp.MustCompile(regexValue)
            if re.MatchString(line) {
                if protoRegex == "vmess" {
                    line = EditVmessPs(line, protoRegex, false)
                }
                if line != "" {
                    configs[protoRegex] += line + "\n"
                }
                break
            }
        }
    }
}
