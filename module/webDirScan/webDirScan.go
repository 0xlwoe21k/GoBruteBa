package webDirScan

import (
	"GoBruteBa/common"
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/kataras/golog"
	"github.com/schollz/progressbar/v3"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//mutli goroutine scan ,build-in dictionary is used by default  ,but you can specify the dir path to scan

var local_wdsi common.WebDirScanType

var (
	err      error
	wg       sync.WaitGroup
	payload  chan string
	tr       *http.Transport
	httpPool *sync.Pool
	tResult  []string
	fResult  []string
	chTarget chan string
	chErr    chan string
	bar      *progressbar.ProgressBar
)

func handResult() {
	fmt.Printf("%s\n", "\n|--------------------------------------OTHER RESULT-----------------------------------|\n")
	for _, vaule := range fResult {
		fmt.Printf("%s\n", vaule)
	}
	fmt.Printf("%s\n", "\n|--------------------------------------OTHER RESULT-----------------------------------|\n")

	fmt.Printf("\x1b[1;32m%s\x1b[0m\n", "\n|-------------------------------------【200】RESULT---------------------------------|\n")
	for _, vaule := range tResult {
		fmt.Printf("\x1b[1;40;36m%s\x1b[0m\n", vaule)
	}
	fmt.Printf("\x1b[1;32m%s\x1b[0m\n", "\n|----------------------------------------RESULT-------------------------------------|\n")
}

func WebDirScan(wdsi common.WebDirScanType) {
	local_wdsi = wdsi
	chTarget = make(chan string, 20)
	chErr = make(chan string)
	var payloads []string

	ctx, cancel := context.WithCancel(context.Background())

	//fmt.Println(wdsi.TargetDirPath)
	if wdsi.Target == "" && wdsi.TargetDirPath == "" {
		golog.Error("scan target is required.")
		return
	}

	go errorLog(ctx)

	httpPool = &sync.Pool{
		New: func() interface{} {
			tr = &http.Transport{
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				MaxConnsPerHost:       0,
				TLSHandshakeTimeout:   2 * time.Second,
				ResponseHeaderTimeout: time.Duration(wdsi.Timeout) * time.Second,
				DisableKeepAlives:     false,
			}
			tmpClient := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(wdsi.Timeout) * time.Second,
			}
			return tmpClient
		},
	}

	if wdsi.PayloadDirPath != "" {
		payloads, err = loadPathFile(wdsi.PayloadDirPath)
		if err != nil {
			golog.Error("[webDurScab.go line 86] ", err)
			return
		}
	} else {
		payloads = []string{"actuator", "jenkins", "env", ".svn/entries", ".git", "source", "source.php", "source.php.bak", ".source.php.bak", "source.php.swp", "README.MD", ".gitignore", ".svn/entries", "user.php.bak", ".DS_store", "WEB-INF/web.xml", "WEB-INF/classes", "WEB-INF/database.propertie", "phpinfo.php", "robots.txt", ".htaccess", ".bash_history", ".svn", ".index.php.swp", "index.php.swp", "index.php.bak", "login.php", "register", "register.php", "test.php", "upload.php", "phpinfo.php", "www.zip", "www.rar", "www.zip", "www.7z", "www.tar.gz", "www.tar", "web.zip", "web.rar", "web.zip", "web.7z", "web.tar.gz", "web.tar", "log.txt", "wwwroot.rar", "web.rar", "dede", "admin", "edit", "Fckeditor", "ewebeditor", "Editor", "manage", "shopadmin", "web_Fckeditor", "login", "webadmin", "admin/WebEditor", "admin/daili/webedit", "login/", "database/", "tmp/", "manager/", "manage/", "web/", "admin/", "wp-includes/", "edit/", "editor/", "user/", "users/", "admin/", "home/", "test/", "backdoor/", "flag/", "upload/", "uploads/", "download/", "downloads/", "root.zip", "root.rar", "wwwroot.zip", "wwwroot.rar", "backup.zip", "backup.rar", ".git/config", ".ds_store", "login.php", "register.php", "upload.php", "home.php", "log.php", "logs.php", "config.php", "member.php", "user.php", "users.php", "robots.php", "info.php", "phpinfo.php", "backdoor.php", "mysql.bak", "dump.sql", "data.sql", "backup.sql", "backup.sql.gz", "backup.zip", "rss.xml", "crossdomain.xml", "1.txt", "flag.txt", "wp-config.php", "configuration.php", "sites/default/settings.php", "system/config/default.php", "lib", "includes/config.php", "test/", "backdoor/", "uploads/", "download/", "downloads/", "manager/", "phpmyadmin/", "phpMyAdmin/", "_async/AsyncResponseService"}
	}

	payload = make(chan string, len(payloads))

	golog.Info("target: ", wdsi.Target)
	golog.Info("thread num: ", wdsi.ThreadNum)
	golog.Info("payload num: ", len(payloads))
	golog.Info("webdirscan start...")

	go Generatehttpclient()
	var targets []string

	//多目标扫描
	if wdsi.TargetDirPath != "" {
		targets, err = handlerTargetFromPath(wdsi.TargetDirPath)
		if err != nil {
			golog.Error("[webDirScan.go] read target from file error! line: 94 err:", err)
		}

		option := progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerPadding: " ",
			BarStart:      "|",
			BarEnd:        "|",
			SaucerHead:    "[green]>[reset]",
		})
		bar = progressbar.NewOptions(len(payloads)*len(targets), option,
			progressbar.OptionSetDescription("[GoBruteBa] Scan..."),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount())

		go handTarget(chTarget, payloads, targets, cancel)
		//var childCtx []context.Context
		for i := 0; i < wdsi.ThreadNum; i++ {
			wg.Add(1)

			go func(tId int, wdsi common.WebDirScanType, ctx context.Context) {
				//handler url
				xctx := context.Context(ctx)
				for {
					select {
					case tg := <-chTarget:
						_ = bar.Add(1)
						wdScan(tg, wdsi)

					case <-xctx.Done():
						wg.Done()
						return
					}
				}
			}(i, wdsi, ctx)
		}
	} else if wdsi.Target != "" {
		//后续再解偶
		//单目标扫描
		option := progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerPadding: " ",
			BarStart:      "|",
			BarEnd:        "|",
			SaucerHead:    "[green]>[reset]",
		})
		bar = progressbar.NewOptions(len(payloads), option,
			progressbar.OptionSetDescription("[GoBruteBa] Scan..."),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount())

		go handParam(payloads)
		wg.Add(1)
		for i := 0; i < wdsi.ThreadNum; i++ {
			wg.Add(1)
			go func(tId int, target string, wdsi common.WebDirScanType) {
				for len(payload) > 0 {
					select {
					case Uri := <-payload:
						_ = bar.Add(1)
						var tmpurl string
						if !strings.Contains(target, "http") {
							target = "http://" + target
						}
						if target[len(target)-1] == '/' {
							tmpurl = target + Uri
						} else {
							tmpurl = target + "/" + Uri
						}
						oneurl := tmpurl[:7]
						twourl := tmpurl[7:]

						if strings.Contains(tmpurl[7:], "//") {
							twourl = strings.Replace(twourl, "//", "/", -1)
						}
						tmpurl = oneurl + twourl
						wdScan(tmpurl, wdsi)
					default:
					}
				}
				wg.Done()
			}(i, wdsi.Target, wdsi)
		}
	}

	wg.Wait()
	//cancel()
	if len(fResult)+len(tResult) > 0 {
		handResult()
	} else {
		fmt.Println()
		golog.Info("nothing found.")
	}
}

func handlerTargetFromPath(tpath string) ([]string, error) {
	var targets []string = make([]string, 0)
	file, err := os.Open(tpath)
	defer file.Close()
	if err != nil {
		return nil, err
	}
	//系统自带的NewScanner逐行读取
	scanner := bufio.NewScanner(file)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, err
}

func Generatehttpclient() {
	//每隔5秒生成一个client
	if local_wdsi.Proxy != "" {
		localProxy := func(_ *http.Request) (*url.URL, error) { return url.Parse(local_wdsi.Proxy) }
		tr = &http.Transport{
			Proxy:                 localProxy,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxConnsPerHost:       0,
			TLSHandshakeTimeout:   2 * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
			DisableKeepAlives:     false,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxConnsPerHost:       0,
			TLSHandshakeTimeout:   2 * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
			DisableKeepAlives:     false,
		}
	}
	//生成15个cline测试看看
	for i := 0; i < 50; i++ {
		tmpClient := &http.Client{
			Transport: tr,
			Timeout:   3 * time.Second,
		}
		httpPool.Put(tmpClient)
	}
}

func getHttpConnect(wdsi common.WebDirScanType) *http.Client {
	return httpPool.Get().(*http.Client)
}

func errorLog(ctx context.Context) {
	var logStr string
	errFp, err := os.OpenFile("errlog.txt", os.O_CREATE|os.O_RDWR|os.O_APPEND, os.ModeAppend|os.ModePerm)
	if err != nil {
		golog.Error("[webDirScan.og] line:297 open errlog.txt failed!")
		return
	}
	for {
		select {
		case logStr = <-chErr:
			_, _ = errFp.WriteString(logStr + "\n")
		case <-ctx.Done():
			_ = errFp.Close()
			return
		default:

		}
	}

}

func wdScan(tmpurl string, wdsi common.WebDirScanType) {

	req, err := http.NewRequest("HEAD", tmpurl, nil)
	if err != nil {
		//错误导入文件
		//golog.Error("[webDurScab.go line 177] ", err.Error())
		chErr <- err.Error()
		return
	}

	if wdsi.UserAgent == "" {
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 Edg/90.0.818.62")
	}
	req.Header.Add("User-Agent", wdsi.UserAgent)

	client := getHttpConnect(wdsi)

	resp, err := client.Do(req)
	if err != nil {
		//println(err)
		//golog.Error("[webDirScan.go line:189] ", err.Error())
		chErr <- err.Error()
		return
	}
	httpPool.Put(client)

	if resp.ContentLength == -1 || resp.ContentLength == 0 {
		return
	}
	if resp.StatusCode == 200 {
		fmt.Println("\n\x1b[36m" + tmpurl + "\x1b[0m")
		res := "Status[\x1b[32m200\x1b[0m]" + " URL[\x1b[36m" + tmpurl + "\x1b[0m]" + " [content-length][" + strconv.Itoa(int(resp.ContentLength)) + "]"
		tResult = append(tResult, res)
	} else if resp.StatusCode != 404 {
		//fmt.Println("\nStatus[\x1b[32m"+strconv.Itoa(resp.StatusCode)+"\x1b[0m]"+"URL[\x1b[36m" + tmpurl + "\x1b[0m]")
		res := "Status[\x1b[32m" + resp.Status + "\x1b[0m]" + " URL[\x1b[36m" + tmpurl + "\x1b[0m]" + " [content-length][" + strconv.Itoa(int(resp.ContentLength)) + "]"
		fResult = append(fResult, res)
	}
	//用完之后回收client

	defer resp.Body.Close()
}

func handTarget(chTarget chan string, payloads []string, targets []string, cancel context.CancelFunc) {
	for _, t := range targets {
		for i := 0; i < len(payloads); i++ {

			var tmpurl string
			if !strings.Contains(t, "http") {
				t = "https://" + t
			}
			if t[len(t)-1] == '/' {
				tmpurl = t + payloads[i]
			} else {
				tmpurl = t + "/" + payloads[i]
			}
			oneurl := tmpurl[:7]
			twourl := tmpurl[7:]

			if strings.Contains(tmpurl[7:], "//") {
				twourl = strings.Replace(twourl, "//", "/", -1)
			}
			tmpurl = oneurl + twourl

			chTarget <- tmpurl
		}
	}

	time.Sleep(5 * time.Second)
	defer cancel()
}

func handParam(dirDic []string) {
	for _, dc := range dirDic {
		payload <- dc
	}
	wg.Done()
}

func loadPathFile(FilePath string) ([]string, error) {
	var dirpath []string = make([]string, 0)
	file, err := os.Open(FilePath)
	defer file.Close()
	if err != nil {
		return nil, err
	}
	//系统自带的NewScanner逐行读取
	scanner := bufio.NewScanner(file)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		dirpath = append(dirpath, line)
	}
	if err := scanner.Err(); err != nil {
		return dirpath, err
	}
	return dirpath, err
}
