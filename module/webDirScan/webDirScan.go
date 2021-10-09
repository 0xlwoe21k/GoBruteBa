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

type ScanResult struct {
	Status        int
	domain        string
	URL           string
	ContentLength int64
}

type chTarget struct {
	WholeUrl string
	target   string
}

var (
	err         error
	wg          sync.WaitGroup
	payload     chan string
	tr          *http.Transport
	httpPool    *sync.Pool
	otherResult []ScanResult
	OpenResult  []ScanResult
	chtar       chan chTarget
	chErr       chan string
	bar         *progressbar.ProgressBar
)

func handResult() {
	//结果去重两个指标,1.域名一样 2.长度一样,算是重复
	fmt.Printf("%s\n", "\n|--------------------------------------OTHER RESULT-----------------------------------|\n")
	//var onlyOne map[string]int

	for _, vaule := range otherResult {
		fmt.Printf("status[%d] URL[%s] length[%d]\n", vaule.Status, vaule.URL, vaule.ContentLength)
	}
	fmt.Printf("%s\n", "\n|--------------------------------------OTHER RESULT-----------------------------------|\n")

	fmt.Printf("\x1b[1;32m%s\x1b[0m\n", "\n|-------------------------------------【200】RESULT---------------------------------|\n")
	for _, vaule := range OpenResult {
		fmt.Println("Status[\x1b[32m200\x1b[0m]" + " URL[\x1b[36m" + vaule.URL + "\x1b[0m]" + " [content-length][" + strconv.Itoa(int(vaule.ContentLength)) + "]")

	}
	fmt.Printf("\x1b[1;32m%s\x1b[0m\n", "\n|----------------------------------------RESULT-------------------------------------|\n")
}

func WebDirScan(wdsi common.WebDirScanType, rCtx context.Context) {
	local_wdsi = wdsi
	chtar = make(chan chTarget, 10)
	chErr = make(chan string)
	var payloads []string

	subCtx, cancel := context.WithCancel(rCtx)

	if wdsi.Target == "" && wdsi.TargetDirPath == "" {
		golog.Error("scan target is required.")
		return
	}

	go errorLog(subCtx)

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
	} else if wdsi.Payload != "" {
		payloads = []string{wdsi.Payload}
	} else {
		payloads = []string{"/service/actuator/././////12/../health", "/service/actuator/", ".well-known/apple-app-site-association", "/graphql", "/tenant/sources", "logs.html", "search.html", "WEB-INF", "druid", "monitoring", "actuator/env", "script", "jenkins", "env", ".svn/entries", "source", ".DS_store", "WEB-INF/web.xml", "phpinfo.php", "robots.txt", ".htaccess", ".bash_history", "login", "register", "test", "www.zip", "www.rar", "web.zip", "log.txt", "admin", "console", "edit", "manage", "webadmin", "database/", "tmp/", "wp-includes/", "home/", "upload/", "download/", "root.zip", "root.rar", "wwwroot.zip", ".git/config", ".bashrc", ".bash_history", ".ssh/authorized_keys", "backup.sql", "crossdomain.xml", "lib", "phpMyAdmin/", "_async/AsyncResponseService", "wls-wsat/CoordinatorPortType"}

	}

	payload = make(chan string, len(payloads))

	if wdsi.Target == "" {
		golog.Info("target path: ", wdsi.TargetDirPath)

	} else {
		golog.Info("target: ", wdsi.Target)
	}
	golog.Info("thread num: ", wdsi.ThreadNum)
	golog.Info("payload num: ", len(payloads))
	golog.Info("webdirscan start...")

	go Generatehttpclient()
	var targets []string

	//多目标扫描
	if wdsi.TargetDirPath != "" {
		targets, err = handlerTargetFromPath(wdsi.TargetDirPath)
		if err != nil {
			golog.Error("[webDirScan.go] line:130 read target from file error! line: 94 err:", err)
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

		go handTarget(chtar, payloads, targets, cancel)

		for i := 0; i < wdsi.ThreadNum; i++ {
			wg.Add(1)

			go func(tId int, wdsi common.WebDirScanType, ctx context.Context) {
				//handler url
				var ok bool
				var tg chTarget
				tg, ok = <-chtar
				for ok {
					select {
					case tg, ok = <-chtar:
						bar.Add(1)
						wdScan(tg.WholeUrl, tg.target, wdsi)

					case <-ctx.Done():
						wg.Done()
						return
					}
				}
				wg.Done()
			}(i, wdsi, subCtx)
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

		go handParam(payloads, cancel)
		for i := 0; i < wdsi.ThreadNum; i++ {
			wg.Add(1)
			go func(tId int, target string, wdsi common.WebDirScanType, ctx context.Context) {
				for len(payload) > 0 {
					select {
					case Uri := <-payload:
						_ = bar.Add(1)
						var tmpurl string
						var local_target string = target
						if !strings.Contains(target, "http") {
							local_target = "http://" + local_target
						}
						if local_target[len(local_target)-1] == '/' {
							tmpurl = local_target + Uri
						} else {
							tmpurl = local_target + "/" + Uri
						}
						oneurl := tmpurl[:7]
						twourl := tmpurl[7:]

						if strings.Contains(tmpurl[7:], "//") {
							twourl = strings.Replace(twourl, "//", "/", -1)
						}
						tmpurl = oneurl + twourl
						wdScan(tmpurl, target, wdsi)
					case <-ctx.Done():
						//log.Println("recv parent context cancel signal web dir scan exit.")
						wg.Done()
						return
					default:
					}
				}
				wg.Done()
			}(i, wdsi.Target, wdsi, subCtx)
		}
	}

	wg.Wait()
	//cancel()
	if len(OpenResult)+len(otherResult) > 0 {
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
			Timeout:   2 * time.Second,
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

func wdScan(tmpurl string, target string, wdsi common.WebDirScanType) {

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
		chErr <- err.Error()
		return
	}
	httpPool.Put(client)

	var tmpResult ScanResult
	var countFlag bool = false

	if resp.StatusCode == 200 {

		tmpResult.domain = target
		tmpResult.URL = tmpurl
		tmpResult.Status = resp.StatusCode
		tmpResult.ContentLength = resp.ContentLength

		for _, v := range OpenResult {
			if strings.Contains(v.domain, target) && (v.ContentLength == resp.ContentLength) {
				countFlag = true
			}
		}
		if !countFlag {
			bar.Clear()
			fmt.Println("\x1b[36m" + tmpurl + " --> " + strconv.Itoa(resp.StatusCode) + "    " + "size[" + strconv.Itoa(int(resp.ContentLength)) + "]" + "\x1b[0m")
			OpenResult = append(OpenResult, tmpResult)
		}

	} else if resp.StatusCode == 301 || resp.StatusCode == 302 {
		tmpResult.domain = target
		tmpResult.URL = tmpurl
		tmpResult.Status = resp.StatusCode
		tmpResult.ContentLength = resp.ContentLength

		for _, v := range otherResult {
			if strings.Contains(v.domain, target) && (v.ContentLength == resp.ContentLength) {
				countFlag = true
			}
		}
		if !countFlag {
			bar.Clear()
			fmt.Println("\x1b[36m" + tmpurl + " --> " + strconv.Itoa(resp.StatusCode) + "    " + resp.Header.Get("Location") + "\x1b[0m")
			otherResult = append(otherResult, tmpResult)
		}
	} else if resp.StatusCode != 404 {

		tmpResult.domain = target
		tmpResult.URL = tmpurl
		tmpResult.Status = resp.StatusCode
		tmpResult.ContentLength = resp.ContentLength

		for _, v := range otherResult {
			if strings.Contains(v.domain, target) && (v.ContentLength == resp.ContentLength) {
				countFlag = true
			}
		}
		if !countFlag {
			bar.Clear()
			fmt.Println("\x1b[36m" + tmpurl + " --> " + strconv.Itoa(resp.StatusCode) + "\x1b[0m")
			otherResult = append(otherResult, tmpResult)
		}
	}
	defer resp.Body.Close()
}

func handTarget(chtar chan chTarget, payloads []string, targets []string, cancel context.CancelFunc) {
	for _, t := range targets {
		for i := 0; i < len(payloads); i++ {
			t = strings.TrimSpace(t)
			var tmpurl chTarget
			tmpurl.target = t
			if strings.Contains(t, "443") {
				t = "https://" + t
			}
			if !strings.Contains(t, "http") {
				t = "https://" + t
			}
			if t[len(t)-1] == '/' {
				tmpurl.WholeUrl = t + payloads[i]
			} else {
				tmpurl.WholeUrl = t + "/" + payloads[i]
			}
			oneurl := tmpurl.WholeUrl[:7]
			twourl := tmpurl.WholeUrl[7:]

			if strings.Contains(tmpurl.WholeUrl[7:], "//") {
				twourl = strings.Replace(twourl, "//", "/", -1)
			}
			tmpurl.WholeUrl = oneurl + twourl
			chtar <- tmpurl
		}
	}
	//time.Sleep(10)
	close(chtar)
	//cancel()
	//time.Sleep(5 * time.Second)
}

func handParam(dirDic []string, cancel context.CancelFunc) {
	for _, dc := range dirDic {
		payload <- dc
	}
	//cancel()
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
