package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mrvcoder/V2rayCollector/collector"
	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	client       = &http.Client{Timeout: 15 * time.Second}
	maxMessages  = 100
	ConfigsNames = "@Vip_Security join us"
	configs      = map[string]string{
		"ss": "", "vmess": "", "trojan": "", "vless": "", "http": "", "socks": "",
		"wireguard": "", "hysteria2": "", "mtproto": "", "tuic": "", "mixed": "",
	}
	ConfigFileIds = map[string]int32{
		"ss": 0, "vmess": 0, "trojan": 0, "vless": 0, "http": 0, "socks": 0,
		"wireguard": 0, "hysteria2": 0, "mtproto": 0, "tuic": 0, "mixed": 0,
	}
	myregex = map[string]string{
		"ss":        `(?m)(...ss:|^ss:)\/\/.+?(%3A%40|#)`,
		"vmess":     `(?m)vmess:\/\/.+`,
		"trojan":    `(?m)trojan:\/\/.+?(%3A%40|#)`,
		"vless":     `(?m)vless:\/\/.+?(%3A%40|#)`,
		"http":      `(?m)https?:\/\/[^\s]+`,
		"socks":     `(?m)socks(?:5)?:\/\/[^\s]+`,
		"wireguard": `(?m)wireguard:\/\/[^\s]+`,
		"hysteria2": `(?m)hysteria2:\/\/[^\s]+`,
		"mtproto":   `(?m)tg:\/\/proxy\?[^\s]+`,
		"tuic":      `(?m)tuic:\/\/[^\s]+`,
	}
	sort = flag.Bool("sort", false, "sort from latest to oldest (default : false)")
)

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	// Read channels.csv
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
					continue
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
			gologger.Warning().Msg("Error parsing channels.csv: " + err.Error())
		}
	} else {
		gologger.Warning().Msg("channels.csv not found, skipping...")
	}

	// Read Sources.json
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

	gologger.Info().Msg("Creating output files !")

	for proto, configcontent := range configs {
		lines := collector.RemoveDuplicate(configcontent)
		lines = AddConfigNames(lines, proto)
		if *sort {
			linesArr := strings.Split(lines, "\n")
			linesArr = collector.Reverse(linesArr)
			lines = strings.Join(linesArr, "\n")
		} else {
			linesArr := strings.Split(lines, "\n")
			linesArr = collector.Reverse(linesArr)
			linesArr = collector.Reverse(linesArr)
			lines = strings.Join(linesArr, "\n")
		}
		lines = strings.TrimSpace(lines)
		collector.WriteToFile(lines, proto+"_iran.txt")
	}

	gologger.Info().Msg("All Done :D")
}

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
		matched := false
		for protoRegex, regexValue := range myregex {
			re := regexp.MustCompile(regexValue)
			if re.MatchString(line) {
				if protoRegex == "vmess" {
					line = EditVmessPs(line, protoRegex, false)
				}
				if line != "" {
					configs[protoRegex] += line + "\n"
				}
				matched = true
				break
			}
		}
		if !matched {
			configs["mixed"] += line + "\n"
		}
	}
}

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

func CrawlForV2ray(doc *goquery.Document, channelLink string, HasAllMessagesFlag bool) {
	messages := doc.Find(".tgme_widget_message_wrap").Length()
	link, exist := doc.Find(".tgme_widget_message_wrap .js-widget_message").Last().Attr("data-post")

	if messages < maxMessages && exist {
		number := strings.Split(link, "/")[1]
		doc = GetMessages(maxMessages, doc, number, channelLink)
	}

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
