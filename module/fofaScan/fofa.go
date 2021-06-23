package fofa

import (
	"GoBruteBa/common"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/kataras/golog"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func GetInfoByRule(param common.Fofa) {
	_rule := param.Rule
	var baseUrl string
	if param.Doamin {
		baseUrl = "https://fofa.so/api/v1/search/all?email=zjgelen@gmail.com&key=&qbase64=%s&page=1&size=10&fields=domain"
	} else if param.IP {
		baseUrl = "https://fofa.so/api/v1/search/all?email=zjgelen@gmail.com&key=&qbase64=%s&page=1&size=10&fields=ip"
	} else {
		baseUrl = "https://fofa.so/api/v1/search/all?email=zjgelen@gmail.com&key=&qbase64=%s&page=1&size=10&fields=host"
	}

	_rule_b64str := base64.StdEncoding.EncodeToString([]byte(_rule))
	baseUrl = fmt.Sprintf(baseUrl, _rule_b64str)

	//fmt.Println(baseUrl)
	p := func(_ *http.Request) (*url.URL, error) { return url.Parse("http://127.0.0.1:8080") }
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: p}
	client := http.Client{Timeout: 3 * time.Second, Transport: tr}

	resp, err := client.Get(baseUrl)
	if err != nil {
		golog.Error("fofa.go line:30 ", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		golog.Error("fofa.go line:36 ", err)
		return
	}

	jsdata, _ := simplejson.NewJson(body)
	results, err := jsdata.Get("results").Array()
	fmt.Println("------------------------------ressults------------------------------")
	for _, v := range results {
		fmt.Println(v)
	}
	fmt.Println("--------------------------------------------------------------------")

	//fmt.Println(string(body))

}
