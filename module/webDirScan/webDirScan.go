package webDirScan

import (
	"GoBruteBa/common"
	"bufio"
	"crypto/tls"
	"github.com/kataras/golog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//mutli goroutine scan ,build-in dictionary is used by default  ,but you can specify the dir path to scan

var wdsi common.WebDirScanInfo

var (
	err  error
	wg   sync.WaitGroup
	urls chan string
)

func WebDirScan(wdsi common.WebDirScanInfo) {
	urls = make(chan string, 100)
	dirArray := []string{"actuator", "jenkins", "env", ".git", "/.svn/entries", ".git", "source", "source.php", "source.php.bak", ".source.php.bak", "source.php.swp", "README.MD", ".gitignore", ".svn/entries", "user.php.bak", ".DS_store", "WEB-INF/web.xml", "WEB-INF/classes", "WEB-INF/database.propertie", "phpinfo.php", "robots.txt", ".htaccess", ".bash_history", ".svn/", ".index.php.swp", "index.php.swp", "index.php.bak", "login.php", "register", "register.php", "test.php", "upload.php", "phpinfo.php", "www.zip", "www.rar", "www.zip", "www.7z", "www.tar.gz", "www.tar", "web.zip", "web.rar", "web.zip", "web.7z", "web.tar.gz", "web.tar", "log.txt", "wwwroot.rar", "web.rar", "dede", "admin", "edit", "Fckeditor", "ewebeditor", "Editor", "manage", "shopadmin", "web_Fckeditor", "login", "webadmin", "admin/WebEditor", "admin/daili/webedit", "login/", "database/", "tmp/", "manager/", "manage/", "web/", "admin/", "wp-includes/", "edit/", "editor/", "user/", "users/", "admin/", "home/", "test/", "backdoor/", "flag/", "upload/", "uploads/", "download/", "downloads/", "manager/", "root.zip", "root.rar", "wwwroot.zip", "wwwroot.rar", "backup.zip", "backup.rar", ".git/config", ".ds_store", "login.php", "register.php", "upload.php", "home.php", "log.php", "logs.php", "config.php", "member.php", "user.php", "users.php", "robots.php", "info.php", "phpinfo.php", "backdoor.php", "mysql.bak", "a.sql", "b.sql", "db.sql", "bdb.sql", "users.sql", "mysql.sql", "dump.sql", "data.sql", "backup.sql", "backup.sql.gz", "backup.zip", "rss.xml", "crossdomain.xml", "1.txt", "flag.txt", "/wp-config.php", "/configuration.php", "/sites/default/settings.php", "/config.php", "/config.inc.php", "/system/config/default.php", "/lib", "/includes/config.php", "test/", "backdoor/", "uploads/", "download/", "downloads/", "manager/", "phpmyadmin/", "phpMyAdmin/"}
	//if dirpath not empty,then load the path to scan
	if wdsi.DirPath != "" {
		dirArray, err = loadPathFile(wdsi.DirPath)
		CheckErr("[webDirScan.go] ", err)
	}
	golog.Info("thread num: ", wdsi.ThreadNum)
	golog.Info("webdirscan start...")
	//Multithreading scan
	go handParam(dirArray)
	wg.Add(1)
	for i := 0; i < wdsi.ThreadNum; i++ {
		wg.Add(1)
		go func(tId int, target string, wdsi common.WebDirScanInfo) {
			//handler url
			var Uri string
			for len(urls) > 0 {
				Uri = <-urls
				var tmpurl string
				if !strings.Contains(target, "http") {
					target = "http://" + target
				}
				if target[len(target)-1] == '/' {
					tmpurl = target + Uri
				} else {
					tmpurl = target + "/" + Uri
				}
				wdScan(tmpurl, wdsi)
				//scan https
				if !strings.Contains(target, "http") {
					wdScan(strings.Replace(tmpurl, "http", "https", -1), wdsi)

				}
				golog.Info(tmpurl)
			}
			wg.Done()
		}(i, wdsi.Target, wdsi)
	}
	wg.Wait()
}

func wdScan(tmpurl string, wdsi common.WebDirScanInfo) {

	req, err := http.NewRequest("HEAD", tmpurl, nil)
	CheckErr("[webDurScab,go]", err)

	req.Header.Add("User-Agent", wdsi.UserAgent)

	var tr *http.Transport
	if wdsi.Proxy != "" {
		localProxy := func(_ *http.Request) (*url.URL, error) { return url.Parse(wdsi.Proxy) }
		tr = &http.Transport{
			Proxy:           localProxy,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
		}
	}
	client := http.Client{
		Transport: tr,
		Timeout:   2 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		println(err)
		golog.Error("[webDirScan.go line:99] ", err.Error())
		return
	}
	if resp.StatusCode == 200 {
		golog.Info(tmpurl)
	}
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

	}
}
