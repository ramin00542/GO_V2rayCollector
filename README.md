<div dir="rtl" align="center">

# 🚀 V2rayCollector – جمع‌آوری خودکار کانفیگ V2Ray | تلگرام + ساب‌لینک + فورک‌های گیت‌هاب

[![GitHub release](https://img.shields.io/github/v/release/ramin00542/GO_V2rayCollector?style=flat-square&logo=github)](https://github.com/ramin00542/GO_V2rayCollector/releases)
[![GitHub Repo stars](https://img.shields.io/github/stars/ramin00542/GO_V2rayCollector?style=flat-square&logo=github)](https://github.com/ramin00542/GO_V2rayCollector/stargazers)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/ramin00542/GO_V2rayCollector/Collector.yml?branch=main&style=flat-square&logo=githubactions)](https://github.com/ramin00542/GO_V2rayCollector/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/ramin00542/GO_V2rayCollector?style=flat-square)](https://goreportcard.com/report/github.com/ramin00542/GO_V2rayCollector)
[![License](https://img.shields.io/github/license/ramin00542/GO_V2rayCollector?style=flat-square)](LICENSE)

**یک ربات تمام‌خودکار برای جمع‌آوری کانفیگ‌های رایگان V2Ray، Xray، Shadowsocks و ...**  
⚡ بدون نیاز به سرور شخصی – فقط با گیت‌هاب اکشنز ⚡

</div>

---

## 🧠 **درباره پروژه**

<div dir="rtl">

**V2rayCollector** یک ابزار قدرتمند است که با اجرای خودکار روی **GitHub Actions**، هر ۲۰ دقیقه یک‌بار جدیدترین کانفیگ‌های پروکسی را از منابع زیر جمع‌آوری می‌کند:

* 📡 **کانال‌های عمومی تلگرام** (با قابلیت ادامه از آخرین پیام خوانده شده)
* 🔗 **ساب‌لینک‌های مختلف** (پشتیبانی از base64 و gzip)
* 🍴 **فورک‌های مخازن گیت‌هاب** (جستجوی خودکار ساب‌لینک در فورک‌های مخازن هدف)

سپس آن‌ها را **فیلتر امنیتی** کرده (حذف `allowInsecure=true`)، **تکراری‌ها را حذف** می‌کند و در قالب **ساختاری شفاف و قابل استفاده** در مخزن شما ذخیره می‌سازد.  
✅ همه چیز **کاملاً خودکار** و **رایگان** است.

</div>

---

## ✨ **قابلیت‌های کلیدی**

<div dir="rtl">

| قابلیت | توضیح |
|--------|-------|
| 🤖 **بدون نیاز به سرور** | اجرا روی GitHub Actions – کاملاً رایگان |
| ⏱️ **اجرای دوره‌ای** | هر ۲۰ دقیقه یکبار (قابل تنظیم در فایل workflow) |
| 📡 **تلگرام هوشمند** | دریافت کانفیگ از کانال‌های عمومی، همراه با ذخیره `offset` برای ادامه از آخرین پیام |
| 🔗 **ساب‌لینک حرفه‌ای** | پشتیبانی از فرمت‌های base64 و gzip – سازگار با اکثر سورس‌ها |
| 🍴 **اسکن فورک گیت‌هاب** | به‌طور خودکار فورک‌های مخازن معروف را جستجو کرده و ساب‌لینک جدید پیدا می‌کند |
| 🛡️ **فیلتر امنیتی پیشرفته** | حذف کانفیگ‌های با `allowInsecure=true` یا فاقد TLS |
| 🔄 **دداپلیکیشن هوشمند** | حذف تکراری‌ها بر اساس اثرانگشت (Fingerprint) – حتی اگر لینک متفاوت باشد |
| 📊 **گزارش آماری زیبا** | فایل `collector_stats.md` با جداول، ایموجی و تفکیک پروتکل‌ها و کانال‌ها |
| 📁 **خروجی با ایموجی** | نام فایل‌ها شامل ایموجی (🔵 VMess.txt، 🟢 VLess.txt و …) |
| 📋 **لینک‌های دانلود به‌روز** | فایل `links.md` شامل جدولی با وضعیت 🔴/🟢، تعداد کانفیگ و تاریخ آخرین بروزرسانی هر فایل |
| 📱 **ارسال گزارش به تلگرام** | در صورت تنظیم توکن، خلاصه گزارش پس از هر اجرا به کانال شما ارسال می‌شود |
| ⚡ **پشتیبانی از پروکسی** | در صورت نیاز می‌توانید از فلگ `-proxy` استفاده کنید |
| 🗂️ **آرشیو روزانه** | هر روز یک کپی از تمام فایل‌های مهم در `daily_archive/تاریخ` ذخیره می‌شود |

</div>

---

## 📂 **ساختار خروجی (پس از اجرا)**

```
📦 GO_V2rayCollector
 └ 📂 .github/workflows
   ├── ⚙️ .github/
   │   └── workflows/
   │       ├── 🤖 Collector.yml
   │       ├── 📅 daily-channel-scan.yml
   │       ├── 🔧 fix-gosum.yml
   │       ├── 🧹 optimize-sources.yml
   │       ├── 🩹 patch-code.yml
   │       ├── 🔄 revive-channels.yml
   │       ├── 📱 telegram-test.yml
   │       ├── ⬆️ update-dependencies.yml
   │       └── 📆 yearly-old-scan.yml
   │
   ├── 💾 Backup/
   │
   ├── 🧹 collector/
   │   └── 🛠️ helpers.go
   │
   ├── 📁 data/
   │   ├── ☠️ dead_channels_old.json
   │   ├── 🕒 dead_channels_recent.json
   │   ├── ☠️ dead_sources_old.json
   │   └── 🕒 dead_sources_recent.json
   │
   ├── 📈 reports/
   │   ├── 📝 channels_report.md
   │   ├── 📊 collector_stats.md
   │   ├── 📄 collector_stats.txt
   │   ├── 🔗 links.md
   │   └── 📝 sources_report.md
   │
   ├── 📱 telegram-tester/
   │   ├── 📡 channel_scanner.go
   │   ├── 🏁 main.go
   │   ├── 🔄 revive_scanner.go
   │   └── ✅ sources_checker.go
   │
   ├── 📡 telegram/                (root-level, empty or other content)
   │
   ├── 🔗 subscription/            (root-level, empty or other content)
   │
   ├── 🗄️ daily_archive/
   │
   ├── 📦 all_configs/
   │   ├── 📡 telegram/
   │   │   ├── 📄 all_protocols.txt
   │   │   ├── 🧦 SOCKS5 Proxy.txt
   │   │   ├── 📱 MTProto Proxy.txt
   │   │   ├── 🧩 Tuic.txt
   │   │   ├── 🔄 SSR.txt
   │   │   ├── ☁️ Argo.txt
   │   │   ├── 🌐 HTTP_HTTPS.txt
   │   │   ├── 🕸️ slipnet.txt
   │   │   ├── 🛡️ Invizible_Pro.txt
   │   │   └── 🌌 WARP.txt
   │   └── 🔗 subscription/
   │       ├── 📄 all_protocols.txt
   │       ├── 🧦 SOCKS5 Proxy.txt
   │       ├── 📱 MTProto Proxy.txt
   │       ├── 🧩 Tuic.txt
   │       ├── 🔄 SSR.txt
   │       ├── ☁️ Argo.txt
   │       ├── 🌐 HTTP_HTTPS.txt
   │       ├── 🕸️ slipnet.txt
   │       ├── 🛡️ Invizible_Pro.txt
   │       └── 🌌 WARP.txt
   │
   ├── 🙈 .gitignore
   ├── 📖 README.md
   ├── 📦 Sources.json
   ├── 📊 channels.csv
   ├── ⚙️ clash-config.yaml
   ├── 📜 collector_full.log
   ├── 🗃️ config_cache.json
   ├── 🐹 go.mod
   ├── 🔐 go.sum
   ├── ⏱️ last_archive_time.txt
   ├── 🏁 main.go          (top-level main.go)
   ├── 📱 myapp
   └── 🔗 subscription_links.txtهمین فایل
```

---

## 🛠️ **راه‌اندازی در ۳ دقیقه (فقط با چند کلیک!)**

<div dir="rtl">

### ۱. **فورک مخزن**
روی دکمه **Fork** در بالای این صفحه کلیک کنید تا یک کپی از پروژه در اکانت خود داشته باشید.

### ۲. **فعال کردن دسترسی‌های گیت‌هاب اکشنز**
به مخزن خود بروید:  
`Settings → Actions → General`  
- گزینه **Allow all actions** را انتخاب کنید.  
- قسمت **Workflow permissions** را روی **Read and write permissions** قرار دهید.  
- ذخیره کنید.

### ۳. **(اختیاری) تنظیم فایل‌های ورودی**
- **`channels.csv`** : لیست کانال‌های تلگرام (نمونه در مخزن موجود است).  
- **`Sources.json`** : لیست ساب‌لینک‌های دلخواه (نمونه موجود است).  
اگر می‌خواهید فقط از اسکن فورک‌ها استفاده کنید، این فایل‌ها را خالی بگذارید.

### ۴. **(اختیاری اما پیشنهادی) تنظیم گزارش تلگرام**
برای دریافت خودکار گزارش آماری به کانال خود، دو **Secret** در مخزن بسازید:  
`Settings → Secrets and variables → Actions → New repository secret`

| نام Secret | مقدار | توضیح |
|------------|-------|-------|
| `TELEGRAM_BOT_TOKEN` | توکن ربات | از @BotFather در تلگرام بگیرید |
| `TELEGRAM_CHAT_ID` | آیدی عددی کانال/چت | با @userinfobot دریافت کنید |

### ۵. **اجرای دستی (برای تست اولیه)**
به تب **Actions** بروید، روی workflow **Collector** کلیک کنید و دکمه **Run workflow** را بزنید.  
چند دقیقه بعد، تمام خروجی‌ها در مخزن شما ظاهر می‌شوند.

</div>

---

## 📈 **مشاهده خروجی و آمار**

<div dir="rtl">

- **`links.md`** : صفحه اصلی لینک‌ها – برای مشاهده سریع همه فایل‌های خروجی.  
- **`collector_stats.md`** : گزارش کامل آماری (تعداد کل کانفیگ‌ها، پروتکل‌ها، کانال‌های فعال، ...).  
- **`daily_archive/`** : بکاپ روزانه از فایل‌های مهم – برای حفظ تاریخچه.  
- **`telegram/` و `subscription/`** : فایل‌های کانفیگ به تفکیک پروتکل و ایموجی.

</div>

---

## ⚙️ **تنظیمات پیشرفته (اختیاری)**

<div dir="rtl">

می‌توانید با تغییر فلگ‌های خط فرمان در فایل `Collector.yml` رفتار ربات را سفارشی کنید:

| فلگ | توضیح | پیش‌فرض |
|-----|-------|---------|
| `-sort` | مرتب‌سازی کانفیگ‌ها از جدید به قدیم | `false` |
| `-dedup` | فعال‌سازی حذف تکراری پیشرفته | `true` |
| `-clash` | تولید فایل `clash-config.yaml` | `true` (در workflow فعال است) |
| `-fork-scan` | اسکن فورک‌های گیت‌هاب | `true` |
| `-proxy` | آدرس پروکسی (در صورت نیاز) | خالی |

</div>

---

## 🧠 **نحوه عملکرد (جریان داده)**

<div dir="rtl">

1. هر ۲۰ دقیقه، GitHub Actions کد را اجرا می‌کند.  
2. کانال‌های `channels.csv` + ساب‌لینک‌های `Sources.json` + فورک‌های مخزن هدف پردازش می‌شوند.  
3. کانفیگ‌های استخراج شده از نظر امنیت فیلتر می‌شوند.  
4. کانفیگ‌های تکراری با استفاده از اثرانگشت حذف می‌شوند.  
5. خروجی‌ها (فایل‌های متنی) در پوشه‌های مربوطه ذخیره می‌شوند.  
6. فایل‌های `links.md` و `collector_stats.md` تولید می‌شوند.  
7. تمام تغییرات به مخزن commit و push می‌شوند.  
8. در صورت تنظیم توکن، گزارش به تلگرام ارسال می‌گردد.

</div>

---

## ❓ **سوالات متداول**

<div dir="rtl">

### ۱. **آیا این ربات هزینه‌ای دارد؟**  
خیر – GitHub Actions برای مخازن عمومی کاملاً رایگان است.

### ۲. **چرا پوشه `telegram` خالی است؟**  
یا `channels.csv` معتبر ندارید، یا کانال‌ها کانفیگی منتشر نکرده‌اند. می‌توانید با `telegram-test.yml` اتصال را تست کنید.

### ۳. **حجم فایل `config_cache.json` بالاست، چکار کنم؟**  
برای کاهش حجم آن را می‌توانید به `.gitignore` اضافه کنید؛ در این صورت ربات هر بار از صفر شروع می‌کند.

### ۴. **چگونه زمان اجرا را تغییر دهم؟**  
در فایل `.github/workflows/Collector.yml` مقدار `cron` را اصلاح کنید (مثلاً `"*/30 * * * *"` برای هر ۳۰ دقیقه).

### ۵. **آیا می‌توانم از پروکسی استفاده کنم؟**  
بله، فلگ `-proxy "http://user:pass@host:port"` را به مرحله `Run collector` اضافه کنید.

</div>

---

## 📄 **مجوز پروژه**

<div dir="rtl">

این پروژه تحت مجوز **MIT** منتشر شده است – برای مطالعه بیشتر به فایل [LICENSE](LICENSE) مراجعه کنید.

</div>

---

## 🌟 **حمایت از پروژه**

<div dir="rtl">

اگر این پروژه برای شما مفید بوده، لطفاً با **⭐️ ستاره** دادن به آن از ما حمایت کنید.  
همچنین جهت بهبود پروژه، **Pull Request** و **ایده‌های جدید** شما بسیار ارزشمند است.

</div>

---

<div align="center" dir="rtl">

**با ❤️ برای جامعه متن‌باز و دسترسی آزاد به اطلاعات**

[⬆ بازگشت به بالا](#)

</div>
```
