package webAliveScan

import (
	"GoBruteBa/common"
	"bufio"
	"crypto/tls"
	"github.com/kataras/golog"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var clinet [20]*http.Client
var httpPool *sync.Pool
var fproxy string

func WebAliveScan(was common.WebAliveScanInfo) {
	wg := new(sync.WaitGroup)
	if was.Target != "" {
		webAliveScanSingle(was)
	} else {
		webAliveScanMulti(was, wg)
	}
	wg.Wait()
}

func handlerParam(targets []string, targetchan chan string, wg *sync.WaitGroup) {

	for _, line := range targets {
		targetchan <- line
	}
	close(targetchan)
	wg.Done()
}

func init() {
	p := func(_ *http.Request) (*url.URL, error) { return url.Parse("http://127.0.0.1:8080") }
	tr := &http.Transport{
		Proxy:               p,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 8 * time.Second,
		DisableKeepAlives:   false,
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

func webAliveScanMulti(was common.WebAliveScanInfo, wg *sync.WaitGroup) {
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
					//golog.Error("webAliveScan.go line:83 ",err)
					t, ok = <-targetchan
					continue
				}
				httpPool.Put(Client)
				handlerResult(resp, t)

				t, ok = <-targetchan
			}
			wg.Done()
		}(targetchan, wg)
	}

}

func handlerResult(resp *http.Response, t string) {
	var resultstring string = "URL[" + t + "]"
	Status := strconv.Itoa(resp.StatusCode)
	resultstring = resultstring + " Status[" + Status + "]"
	Length := strconv.Itoa(int(resp.ContentLength))
	resultstring = resultstring + " Length[" + Length + "]"
	serv := resp.Header.Get("Server")
	if serv != "" {
		resultstring = resultstring + " Server[" + serv + "]"
	}

	Cookie := resp.Header.Get("Set-Cookie")
	if Cookie != "" {
		if strings.Contains(Cookie, "rememberMe") {
			resultstring = resultstring + " Application[Shiro]"
		}
	}

	title := ""
	body, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		//golog.Error("webAliveScan.go line:118",err)
		//do nothing
		exp := regexp.MustCompile(`<title>(.*?)</title>`)
		result := exp.FindAllStringSubmatch(string(body), -1)
		for _, text := range result {
			title = text[1]
		}
	}
	if title != "" {
		resultstring = resultstring + " Title[" + title + "]"
	}

	//log(resultstring)
	log.Println(resultstring)
}

func webAliveScanSingle(was common.WebAliveScanInfo) {
	_url := was.Target
	//var localProxy *url.URL
	var tr *http.Transport
	if was.Proxy != "" {
		localProxy := func(_ *http.Request) (*url.URL, error) { return url.Parse(was.Proxy) }
		tr = &http.Transport{
			Proxy:               localProxy,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: time.Duration(2) * time.Second,
			DisableKeepAlives:   false,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: time.Duration(2) * time.Second,
			DisableKeepAlives:   false,
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
	handlerResult(resp, _url)
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
		}
		dirpath = append(dirpath, line)
	}
	if err := scanner.Err(); err != nil {
		golog.Error("[webAliveScan.go line:209]", err)
		return dirpath
	}
	return dirpath
}
