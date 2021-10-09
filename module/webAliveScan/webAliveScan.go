package webAliveScan

import (
	"GoBruteBa/common"
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/kataras/golog"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	clinet   [20]*http.Client
	httpPool *sync.Pool
	fproxy   string
	tr       *http.Transport
	fp       *os.File
	err      error
)

func WebAliveScan(was common.WebAliveScanType) {
	wg := new(sync.WaitGroup)
	if was.Out != "" {
		fp, err = os.OpenFile(was.Out, os.O_CREATE|os.O_RDWR, 744)
		if err != nil {
			log.Println("webAliveScan.go line:33 error:", err)
			return
		}
	}
	if was.Proxy != "" {
		p := func(_ *http.Request) (*url.URL, error) { return url.Parse(was.Proxy) }
		tr.Proxy = p
	}
	if was.Target != "" {
		webAliveScanSingle(was)
	} else {
		webAliveScanMulti(was, wg)
	}
	wg.Wait()
	defer fp.Close()
}

func handlerParam(targets []string, targetchan chan string, wg *sync.WaitGroup) {

	for _, line := range targets {
		targetchan <- line
	}
	close(targetchan)
	wg.Done()
}

func init() {
	tr = &http.Transport{
		//Proxy:               p,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		DisableKeepAlives:     false,
	}

	httpPool = &sync.Pool{
		New: func() interface{} {
			tmpClient := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(10) * time.Second,
			}
			return tmpClient
		},
	}

	for i := 0; i < 20; i++ {
		tmpClient := &http.Client{
			Transport: tr,
			Timeout:   time.Duration(10) * time.Second,
		}
		httpPool.Put(tmpClient)
	}
}

func getHttpClient() *http.Client {
	return httpPool.Get().(*http.Client)
}

func webAliveScanMulti(was common.WebAliveScanType, wg *sync.WaitGroup) {
	targetchan := make(chan string, 10)
	threadNo := 20

	targets := readTargetFromFile(was.DirPath)
	go handlerParam(targets, targetchan, wg)
	wg.Add(1)

	for i := 0; i < threadNo; i++ {
		wg.Add(1)
		go func(targetchan chan string, wg *sync.WaitGroup) {
			t, ok := <-targetchan

			for ok {
				req, err := http.NewRequest("GET", t, nil)
				if err != nil {
					golog.Error("webAliveScan.go line:42 ", err)
					t, ok = <-targetchan
					continue
				}
				//增加shiro检测
				req.Header.Add("Cookie", "rememberMe=nosiffer")
				req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 Edg/90.0.818.62")

				Client := getHttpClient()

				resp, err := Client.Do(req)
				if err != nil {
					t, ok = <-targetchan
					continue
				}
				httpPool.Put(Client)
				//发送一个不存在的页面来获取指纹信息
				req.URL, err = url.Parse(t + "/_gobruteba")
				if err != nil {
					t, ok = <-targetchan
					continue
				}
				respSec, err := Client.Do(req)

				handlerResult(resp, respSec, t)

				t, ok = <-targetchan
			}
			wg.Done()
		}(targetchan, wg)
	}
}

type WASResult struct {
	URL           string
	Title         string
	StatusCode    int
	ContentLength int
	Server        string
	Application   []string
}

func (this *WASResult) String() string {
	var app string
	for _, v := range this.Application {
		app += "[" + v + "]"
	}
	return fmt.Sprintf("URL:%s   Title:%s   StatusCode:%d   ContentLength:%d   Server:%s   Application:%s",
		this.URL, this.Title, this.StatusCode, this.ContentLength, this.Server, app)
}

func (this *WASResult) ColorString() string {
	var app string
	var totalStr string
	totalStr = fmt.Sprintf("URL[\x1b[36m%s\x1b[0m] StatusCode[\x1b[32m%d\x1b[0m] ContentLength[\x1b[32m%d\x1b[0m] ", this.URL, this.StatusCode, this.ContentLength)

	if this.Server != "" {
		totalStr += "Server[\x1b[32m" + this.Server + "\x1b[0m] "
	}
	if this.Title != "" {
		totalStr += "Title[\x1b[32m" + this.Title + "\x1b[0m] "
	}
	if this.Application != nil {
		for _, v := range this.Application {
			app += "[" + v + "]"
		}
		totalStr += "Application\x1b[32m" + app + "\x1b[0m "
	}
	return totalStr
}

func handlerResult(resp *http.Response, respSecond *http.Response, t string) {
	var rs WASResult
	if resp != nil {
		rs.URL = t
		rs.StatusCode = resp.StatusCode

		if resp.ContentLength != -1 {
			rs.ContentLength = int(resp.ContentLength)
		}
		serv := resp.Header.Get("Server")
		if serv != "" {
			rs.Server = serv
		}

		Cookie := resp.Header.Get("Set-Cookie")
		if Cookie != "" {
			if strings.Contains(Cookie, "rememberMe") {
				rs.Application = append(rs.Application, "Shiro")
			}
		}

		title := ""
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {

			exp := regexp.MustCompile(`<title>(.*?)</title>`)
			result := exp.FindAllStringSubmatch(string(body), -1)
			for _, text := range result {
				title = text[1]
			}
		}
		if title != "" {
			rs.Title = title
		}
	}

	if fp != nil {
		fp.WriteString(rs.String())
		fp.WriteString("\n")
	}
	//处理第二个请求,定义一个数组，如果内容中包含了就确定为此应用
	flagStr := [...]string{"Tomcat", "Java", "ASP.NET"}
	if respSecond != nil {
		body, err := ioutil.ReadAll(respSecond.Body)
		if err != nil {
			log.Println(rs.ColorString())
			return
		}
		for _, v := range flagStr {
			if strings.Contains(string(body), v) {
				rs.Application = append(rs.Application, v)
			}
		}

		//for _,v :=  range respSecond.Header{
		//
		//}
	}
	log.Println(rs.ColorString())
}

func webAliveScanSingle(was common.WebAliveScanType) {
	_url := was.Target
	//var localProxy *url.URL
	var tr *http.Transport
	if was.Proxy != "" {
		localProxy := func(_ *http.Request) (*url.URL, error) { return url.Parse(was.Proxy) }
		tr = &http.Transport{
			Proxy:                 localProxy,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   time.Duration(2) * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
			DisableKeepAlives:     false,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   time.Duration(2) * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
			DisableKeepAlives:     false,
		}
	}

	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		golog.Error("webAliveScan.go line:42 ", err)
		return
	}
	req.Header.Add("Cookie", "rememberMe=nosiffer")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 Edg/90.0.818.62")

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(5) * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		golog.Error("webAliveScan.go line:185 ", err)
		return
	}
	defer resp.Body.Close()
	req.URL, err = url.Parse(strings.TrimSpace(_url) + "/_gobruteba")
	if err != nil {
		fmt.Println("webAliveScan.go line:267 err:", err)
		return
	}
	respSec, err := client.Do(req)
	if err != nil {
		fmt.Println("webAliveScan.go line:272 err:", err)
	}
	handlerResult(resp, respSec, _url)
}

func readTargetFromFile(path string) []string {
	var dirpath []string = make([]string, 0)
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		golog.Error("[webAliveScan.go line:198]", err)
		return nil
	}
	//系统自带的NewScanner逐行读取
	scanner := bufio.NewScanner(file)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		if !strings.Contains(line, "http") {
			line = "http://" + line
			dirpath = append(dirpath, line)
			line = "https://" + line
			dirpath = append(dirpath, line)
		} else {
			dirpath = append(dirpath, line)
		}

	}
	if err := scanner.Err(); err != nil {
		golog.Error("[webAliveScan.go line:209]", err)
		return dirpath
	}
	return dirpath
}
