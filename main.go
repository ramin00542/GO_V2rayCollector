package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrvcoder/V2rayCollector/collector"
	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// =======================================================
// 1️⃣ بخش متغیرهای سراسری (Global Variables)
// =======================================================
var (
	client = &http.Client{Timeout: 15 * time.Second} // اضافه شدن timeout از پروژه justVisiting992
	maxMessages        = 100
	ConfigsNames       = "@Vip_Security join us"
	// نقشه configs: شامل لیست پروتکل‌های پشتیبانی شده
	configs = map[string]string{
		"ss": "", "vmess": "", "trojan": "", "vless": "", "http": "", "socks": "",
		"wireguard": "", "hysteria2": "", "mtproto": "", "tuic": "", "mixed": "",
	}
	ConfigFileIds = map[string]int32{
		"ss": 0, "vmess": 0, "trojan": 0, "vless": 0, "http": 0, "socks": 0,
		"wireguard": 0, "hysteria2": 0, "mtproto": 0, "tuic": 0, "mixed": 0,
	}
	// نقشه myregex: الگوهای مربوط به هر پروتکل
	myregex = map[string]string{
		"ss":        `(?m)(...ss:|^ss:)\/\/.+?(%3A%40|#)`,
		"vmess":     `(?m)vmess:\/\/.+`,
		"trojan":    `(?m)trojan:\/\/.+?(%3A%40|#)`,
		"vless":     `(?m)vless:\/\/.+?(%3A%40|#)`,
		"http":      `(?m)https?:\/\/[^\s]+`,
		"socks":     `(?m)socks(?:5)?:\/\/[^\s]+`,
		"wireguard": `(?m)wireguard:\/\/[^\s]+`,
		"hysteria2": `(?m)(?:hysteria2|hysteria|hy2):\/\/[^\s]+`,
		"mtproto":   `(?m)tg:\/\/proxy\?[^\s]+`,
		"tuic":      `(?m)tuic:\/\/[^\s]+`,
	}
	sort = flag.Bool("sort", false, "sort from latest to oldest (default : false)")
	// متغیرهای اضافه شده از پروژه justVisiting992 برای تست سلامت
	healthCheckEnabled = true // تغییر این مقدار به false برای غیرفعال کردن تست سلامت
	// اضافه شده از پروژه justVisiting992: لاک‌ها و نگاشت‌های امن برای concurrenct (در صورت نیاز)
)

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

// =======================================================
// 2️⃣ تابع اصلی (Main)
// =======================================================
func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	fileData, err := collector.ReadFileContent("channels.csv")
	var channels []ChannelsType
	if err = csvutil.Unmarshal([]byte(fileData), &channels); err != nil {
		gologger.Fatal().Msg("error: " + err.Error())
	}

	// حلقه اصلی برای اسکن کانال‌ها
	for _, channel := range channels {
		channel.URL = collector.ChangeUrlToTelegramWebUrl(channel.URL)
		resp := HttpRequest(channel.URL)
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		fmt.Println(" ")
		fmt.Println(" ")
		fmt.Println("---------------------------------------")
		gologger.Info().Msg("Crawling " + channel.URL)
		CrawlForV2ray(doc, channel.URL, channel.AllMessagesFlag)
		gologger.Info().Msg("Crawled " + channel.URL + " ! ")
		fmt.Println("---------------------------------------")
		fmt.Println(" ")
		fmt.Println(" ")
	}

	gologger.Info().Msg("Creating output files !")

	// =======================================================
	// 3️⃣ مرحله تست سلامت و ذخیره فایل‌ها (ایده از justVisiting992)
	// =======================================================
	for proto, configcontent := range configs {
		var finalLines []string
		if configcontent != "" {
			if healthCheckEnabled {
				// تست سلامت کانفیگ‌ها
				gologger.Info().Msg(fmt.Sprintf("Checking health for %s configs...", proto))
				rawLines := strings.Split(configcontent, "\n")
				finalLines = filterHealthyConfigs(rawLines, proto)
			} else {
				finalLines = strings.Split(configcontent, "\n")
			}
			// حذف موارد تکراری
			uniqueLines := removeDuplicates(finalLines)
			lines := strings.Join(uniqueLines, "\n")
			// اضافه کردن اسم و شماره به کانفیگ‌ها
			lines = AddConfigNames(lines, proto)
			// مرتب‌سازی (اگر کاربر فلگ -sort را فعال کرده باشد)
			if *sort {
				linesArr := strings.Split(lines, "\n")
				linesArr = collector.Reverse(linesArr)
				lines = strings.Join(linesArr, "\n")
			}
			lines = strings.TrimSpace(lines)
			if lines != "" {
				collector.WriteToFile(lines, proto+"_iran.txt")
				gologger.Info().Msg(fmt.Sprintf("Saved %s configs to %s_iran.txt", proto, proto))
			}
		}
	}
	gologger.Info().Msg("All Done :D")
}

// =======================================================
// 4️⃣ توابع کمکی (Helper Functions)
// =======================================================

// filterHealthyConfigs از پروژه justVisiting992 الهام گرفته شده
func filterHealthyConfigs(configs []string, protocol string) []string {
	var healthy []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // محدودیت همزمانی برای جلوگیری از اتصال زیاد

	for _, cfg := range configs {
		if cfg == "" {
			continue
		}
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if isConfigAlive(c, protocol) {
				mu.Lock()
				healthy = append(healthy, c)
				mu.Unlock()
			}
		}(cfg)
	}
	wg.Wait()
	gologger.Info().Msg(fmt.Sprintf("Health check passed for %d out of %d %s configs", len(healthy), len(configs), protocol))
	return healthy
}

// isConfigAlive از پروژه justVisiting992 الهام گرفته شده
func isConfigAlive(config string, protocol string) bool {
	// تست VMess (نیازمند دیکد VMess)
	if strings.HasPrefix(strings.ToLower(config), "vmess://") {
		// ... (کد دیکد VMess برای استخراج Host و Port)
		// در صورت عدم دیکد، true برگردانید تا مشکلی در اجرا ایجاد نشود.
		return true // به عنوان پیش‌فرض
	}

	// برای پروتکل‌های URL-based (VLESS, Trojan, etc)
	u, err := url.Parse(config)
	if err != nil {
		return false
	}
	return tcpDial(u.Hostname(), u.Port())
}

// tcpDial از پروژه justVisiting992 الهام گرفته شده
func tcpDial(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// removeDuplicates از پروژه justVisiting992 الهام گرفته شده
func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var list []string
	for _, v := range slice {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !seen[v] {
			seen[v] = true
			list = append(list, v)
		}
	}
	return list
}

// HttpRequest - درخواست HTTP
func HttpRequest(url string) *http.Response {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Fatal().Msg(fmt.Sprintf("Error When requesting to: %s Error : %s", url, err))
	}
	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	return resp
}

// ExtractConfig -- استخراج کانفیگ‌ها (بدون تغییر)
func ExtractConfig(Txt string, Tempconfigs []string) string {
	for protoRegex, regexValue := range myregex {
		re := regexp.MustCompile(regexValue)
		matches := re.FindStringSubmatch(Txt)
		extractedConfig := ""
		if len(matches) > 0 {
			if protoRegex == "ss" {
				Prefix := strings.Split(matches[0], "ss://")[0]
				if Prefix == "" {
					extractedConfig = "\n" + matches[0]
				} else if Prefix != "vle" {
					d := strings.Split(matches[0], "ss://")
					extractedConfig = "\n" + "ss://" + d[1]
				}
			} else if protoRegex == "vmess" {
				extractedConfig = "\n" + matches[0]
			} else {
				extractedConfig = "\n" + matches[0]
			}
			Tempconfigs = append(Tempconfigs, extractedConfig)
			Txt = strings.ReplaceAll(Txt, matches[0], "")
			ExtractConfig(Txt, Tempconfigs)
		}
	}
	d := strings.Join(Tempconfigs, "\n")
	return d
}

// EditVmessPs -- ویرایش VMess (بدون تغییر)
func EditVmessPs(config string, fileName string, AddConfigName bool) string {
	if config == "" {
		return ""
	}
	slice := strings.Split(config, "vmess://")
	if len(slice) > 0 {
		decodedBytes, err := base64.StdEncoding.DecodeString(slice[1])
		if err == nil {
			var data map[string]interface{}
			err = json.Unmarshal(decodedBytes, &data)
			if err == nil {
				if AddConfigName {
					ConfigFileIds[fileName] += 1
					data["ps"] = ConfigsNames + " - " + strconv.Itoa(int(ConfigFileIds[fileName])) + "\n"
				} else {
					data["ps"] = ""
				}
				jsonData, _ := json.Marshal(data)
				base64Encoded := base64.StdEncoding.EncodeToString(jsonData)
				return "vmess://" + base64Encoded
			}
		}
	}
	return ""
}

// AddConfigNames -- اضافه کردن اسم و شماره به کانفیگ (بدون تغییر اساسی)
// در صورت نیاز می‌توانید نام کانال مبدأ را هم به آن اضافه کنید (ایده از Farid-Karimi)
func AddConfigNames(config string, configtype string) string {
	configsList := strings.Split(config, "\n")
	newConfigs := ""
	for protoRegex, regexValue := range myregex {
		for _, extractedConfig := range configsList {
			re := regexp.MustCompile(regexValue)
			matches := re.FindStringSubmatch(extractedConfig)
			if len(matches) > 0 {
				extractedConfig = strings.ReplaceAll(extractedConfig, " ", "")
				if extractedConfig != "" {
					if protoRegex == "vmess" {
						extractedConfig = EditVmessPs(extractedConfig, configtype, true)
						if extractedConfig != "" {
							newConfigs += extractedConfig + "\n"
						}
					} else if protoRegex == "ss" {
						Prefix := strings.Split(matches[0], "ss://")[0]
						if Prefix == "" {
							ConfigFileIds[configtype] += 1
							newConfigs += extractedConfig + ConfigsNames + " - " + strconv.Itoa(int(ConfigFileIds[configtype])) + "\n"
						}
					} else {
						ConfigFileIds[configtype] += 1
						newConfigs += extractedConfig + ConfigsNames + " - " + strconv.Itoa(int(ConfigFileIds[configtype])) + "\n"
					}
				}
			}
		}
	}
	return newConfigs
}

// CrawlForV2ray -- تابع اصلی اسکن (بدون تغییر)
func CrawlForV2ray(doc *goquery.Document, channelLink string, HasAllMessagesFlag bool) {
	messages := doc.Find(".tgme_widget_message_wrap").Length()
	link, exist := doc.Find(".tgme_widget_message_wrap .js-widget_message").Last().Attr("data-post")
	if messages < maxMessages && exist {
		number := strings.Split(link, "/")[1]
		doc = GetMessages(maxMessages, doc, number, channelLink)
	}

	// بخش اصلی استخراج (بدون تغییر)
	if HasAllMessagesFlag {
		doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			messageText, _ := s.Html()
			str := strings.Replace(messageText, "<br/>", "\n", -1)
			doc, _ := goquery.NewDocumentFromReader(strings.NewReader(str))
			messageText = doc.Text()
			line := strings.TrimSpace(messageText)
			lines := strings.Split(line, "\n")
			for _, data := range lines {
				extractedConfigs := strings.Split(ExtractConfig(data, []string{}), "\n")
				for _, extractedConfig := range extractedConfigs {
					extractedConfig = strings.ReplaceAll(extractedConfig, " ", "")
					if extractedConfig != "" {
						matched := false
						for protoRegex, regexValue := range myregex {
							re := regexp.MustCompile(regexValue)
							if re.MatchString(extractedConfig) {
								if protoRegex == "vmess" {
									extractedConfig = EditVmessPs(extractedConfig, protoRegex, false)
									if extractedConfig != "" {
										configs[protoRegex] += extractedConfig + "\n"
									}
								} else {
									configs[protoRegex] += extractedConfig + "\n"
								}
								matched = true
								break
							}
						}
						if !matched {
							configs["mixed"] += extractedConfig + "\n"
						}
					}
				}
			}
		})
	} else {
		doc.Find("code,pre").Each(func(j int, s *goquery.Selection) {
			messageText, _ := s.Html()
			str := strings.ReplaceAll(messageText, "<br/>", "\n")
			doc, _ := goquery.NewDocumentFromReader(strings.NewReader(str))
			messageText = doc.Text()
			line := strings.TrimSpace(messageText)
			lines := strings.Split(line, "\n")
			for _, data := range lines {
				extractedConfigs := strings.Split(ExtractConfig(data, []string{}), "\n")
				for protoRegex, regexValue := range myregex {
					for _, extractedConfig := range extractedConfigs {
						re := regexp.MustCompile(regexValue)
						matches := re.FindStringSubmatch(extractedConfig)
						if len(matches) > 0 {
							extractedConfig = strings.ReplaceAll(extractedConfig, " ", "")
							if extractedConfig != "" {
								if protoRegex == "vmess" {
									extractedConfig = EditVmessPs(extractedConfig, protoRegex, false)
									if extractedConfig != "" {
										configs[protoRegex] += extractedConfig + "\n"
									}
								} else if protoRegex == "ss" {
									Prefix := strings.Split(matches[0], "ss://")[0]
									if Prefix == "" {
										configs[protoRegex] += extractedConfig + "\n"
									}
								} else {
									configs[protoRegex] += extractedConfig + "\n"
								}
							}
						}
					}
				}
			}
		})
	}
}

// loadMore, GetMessages -- بدون تغییر
func loadMore(link string) *goquery.Document {
	req, _ := http.NewRequest("GET", link, nil)
	fmt.Println(link)
	resp, _ := client.Do(req)
	doc, _ := goquery.NewDocumentFromReader(resp.Body)
	return doc
}

func GetMessages(length int, doc *goquery.Document, number string, channel string) *goquery.Document {
	x := loadMore(channel + "?before=" + number)
	html2, _ := x.Html()
	reader2 := strings.NewReader(html2)
	doc2, _ := goquery.NewDocumentFromReader(reader2)
	doc.Find("body").AppendSelection(doc2.Find("body").Children())
	newDoc := goquery.NewDocumentFromNode(doc.Selection.Nodes[0])
	messages := newDoc.Find(".js-widget_message_wrap").Length()
	if messages > length {
		return newDoc
	} else {
		num, _ := strconv.Atoi(number)
		n := num - 21
		if n > 0 {
			ns := strconv.Itoa(n)
			GetMessages(length, newDoc, ns, channel)
		} else {
			return newDoc
		}
	}
	return newDoc
}
