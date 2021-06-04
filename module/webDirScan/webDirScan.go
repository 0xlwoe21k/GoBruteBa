package webDirScan

import (
	"GoBruteBa/common"
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/briandowns/spinner"
	"github.com/kataras/golog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//mutli goroutine scan ,build-in dictionary is used by default  ,but you can specify the dir path to scan

var local_wdsi common.WebDirScanInfo

var (
	err      error
	wg       sync.WaitGroup
	urls     chan string
	chResult chan string
	tr       *http.Transport
	httpPool *sync.Pool
	count    int
	clo      chan bool
	tResult  []string
	fResult  []string
	req      *http.Request
)

func handResult() {
	fmt.Printf("%s\n", "\n|--------------------------------------OTHER RESULT-----------------------------------|\n")
	for _, vaule := range fResult {
		fmt.Printf("%s\n", vaule)
	}
	fmt.Printf("%s\n", "\n|----------------------------------------RESULT-------------------------------------|\n")

	fmt.Printf("\x1b[1;32m%s\x1b[0m\n", "\n|-------------------------------------【200】RESULT---------------------------------|\n")
	for _, vaule := range tResult {
		fmt.Printf("\x1b[1;40;32m%s\x1b[0m\n", vaule)
	}
	fmt.Printf("\x1b[1;32m%s\x1b[0m\n", "\n|----------------------------------------RESULT-------------------------------------|\n")
}

func WebDirScan(wdsi common.WebDirScanInfo) {
	local_wdsi = wdsi
	chResult = make(chan string, 5)
	clo = make(chan bool)

	if wdsi.Target == "" {
		golog.Error("scan target is required.")
		return
	}

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
	dirArray := []string{"actuator", "jenkins", "env", ".git", ".svn/entries", ".git", "source", "source.php", "source.php.bak", ".source.php.bak", "source.php.swp", "README.MD", ".gitignore", ".svn/entries", "user.php.bak", ".DS_store", "WEB-INF/web.xml", "WEB-INF/classes", "WEB-INF/database.propertie", "phpinfo.php", "robots.txt", ".htaccess", ".bash_history", ".svn", ".index.php.swp", "index.php.swp", "index.php.bak", "login.php", "register", "register.php", "test.php", "upload.php", "phpinfo.php", "www.zip", "www.rar", "www.zip", "www.7z", "www.tar.gz", "www.tar", "web.zip", "web.rar", "web.zip", "web.7z", "web.tar.gz", "web.tar", "log.txt", "wwwroot.rar", "web.rar", "dede", "admin", "edit", "Fckeditor", "ewebeditor", "Editor", "manage", "shopadmin", "web_Fckeditor", "login", "webadmin", "admin/WebEditor", "admin/daili/webedit", "login/", "database/", "tmp/", "manager/", "manage/", "web/", "admin/", "wp-includes/", "edit/", "editor/", "user/", "users/", "admin/", "home/", "test/", "backdoor/", "flag/", "upload/", "uploads/", "download/", "downloads/", "root.zip", "root.rar", "wwwroot.zip", "wwwroot.rar", "backup.zip", "backup.rar", ".git/config", ".ds_store", "login.php", "register.php", "upload.php", "home.php", "log.php", "logs.php", "config.php", "member.php", "user.php", "users.php", "robots.php", "info.php", "phpinfo.php", "backdoor.php", "mysql.bak", "a.sql", "b.sql", "db.sql", "bdb.sql", "users.sql", "mysql.sql", "dump.sql", "data.sql", "backup.sql", "backup.sql.gz", "backup.zip", "rss.xml", "crossdomain.xml", "1.txt", "flag.txt", "wp-config.php", "configuration.php", "sites/default/settings.php", "system/config/default.php", "lib", "includes/config.php", "test/", "backdoor/", "uploads/", "download/", "downloads/", "manager/", "phpmyadmin/", "phpMyAdmin/", "_async/AsyncResponseService"}
	//dirArray := []string{"actuator", "jenkins", "env", ".git","login"}

	//if dirpath not empty,then load the path to scan
	if wdsi.DirPath != "" {
		dirArray, err = loadPathFile(wdsi.DirPath)
		CheckErr("[webDirScan.go line:74] ", err)
	}
	urls = make(chan string, len(dirArray))

	golog.Info("thread num: ", wdsi.ThreadNum)
	golog.Info("payload num: ", len(dirArray))
	golog.Info("webdirscan start...")
	//Multithreading scan
	go handParam(dirArray)
	wg.Add(1)
	Generatehttpclient()

	s := spinner.New(spinner.CharSets[35], 100*time.Millisecond) // Build our new spinner
	s.Start()

	for i := 0; i < wdsi.ThreadNum; i++ {
		wg.Add(1)
		go func(tId int, target string, wdsi common.WebDirScanInfo) {
			//handler url
			var Uri string
			for len(urls) > 0 {
				select {
				case Uri = <-urls:
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

	wg.Wait()
	s.Stop()
	if len(fResult)+len(tResult) > 0 {
		handResult()
	} else {
		golog.Info("nothing found.")
	}
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

func getHttpConnect(wdsi common.WebDirScanInfo) *http.Client {
	return httpPool.Get().(*http.Client)
}

func Init() {

}

func wdScan(tmpurl string, wdsi common.WebDirScanInfo) {

	req, err := http.NewRequest("HEAD", tmpurl, nil)
	if err != nil {
		golog.Error("[webDurScab.go line 177] ", err)
		return
	}

	if wdsi.UserAgent == "" {
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 Edg/90.0.818.62")
	}
	req.Header.Add("User-Agent", wdsi.UserAgent)

	client := getHttpConnect(wdsi)

	resp, err := client.Do(req)
	if err != nil {
		println(err)
		golog.Error("[webDirScan.go line:189] ", err.Error())
		return
	}

	if resp.StatusCode == 200 {
		//fmt.Printf("\x1b[1;40;32m%s\x1b[0m\n", tmpurl)
		tResult = append(tResult, tmpurl+"【content-length】【"+strconv.Itoa(int(resp.ContentLength))+"】")
	} else if resp.StatusCode != 404 {
		fResult = append(fResult, "[*] ["+strconv.Itoa(resp.StatusCode)+"] "+tmpurl)
	}
	//用完之后回收client
	httpPool.Put(client)
	defer resp.Body.Close()
}

func handParam(dirDic []string) {
	for _, tar := range dirDic {
		urls <- tar
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
	file.Close()
	return dirpath, err
}

func CheckErr(text string, err error) {
	if err != nil {
		golog.Error(text, err)
	}
}
