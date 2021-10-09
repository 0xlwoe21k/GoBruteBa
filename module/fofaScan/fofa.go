package fofa

import (
	"GoBruteBa/common"
	"GoBruteBa/module/config"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/kataras/golog"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func GetInfoByRule(param common.FofaType) {
	_rule := param.Rule
	var baseUrl string
	var fofaKey string
	var fofaEmail string
	//从配置文件读取key
	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		golog.Error("cannot found config.yaml.please create it. err:", err)
		return
	}
	cfg := new(config.Cfg)
	err = yaml.Unmarshal(yamlFile, cfg)
	if err != nil {
		golog.Error("fofa.go line 26 err:", err)
		return
	}

	fofaEmail = cfg.Fofa.Email
	fofaKey = cfg.Fofa.Key

	_rule_b64str := base64.StdEncoding.EncodeToString([]byte(_rule))

	if param.Title && param.Doamin {
		baseUrl = fmt.Sprintf("https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=1&size=10000&fields=domain,title", fofaEmail, fofaKey, _rule_b64str)
	} else if param.Title && param.IP {
		baseUrl = fmt.Sprintf("https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=1&size=10000&fields=ip,title", fofaEmail, fofaKey, _rule_b64str)
	} else if param.Title && param.Host {
		baseUrl = fmt.Sprintf("https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=1&size=10000&fields=host,title", fofaEmail, fofaKey, _rule_b64str)
	} else if param.IP {
		baseUrl = fmt.Sprintf("https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=1&size=10000&fields=ip", fofaEmail, fofaKey, _rule_b64str)
	} else if param.Doamin {
		baseUrl = fmt.Sprintf("https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=1&size=10000&fields=domain", fofaEmail, fofaKey, _rule_b64str)
	} else if param.Title {
		baseUrl = fmt.Sprintf("https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=1&size=10000&fields=title", fofaEmail, fofaKey, _rule_b64str)
	} else {
		baseUrl = fmt.Sprintf("https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=1&size=10000&fields=host", fofaEmail, fofaKey, _rule_b64str)
	}

	//p := func(_ *http.Request) (*url.URL, error) { return url.Parse("http://127.0.0.1:8080") }
	//tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: p}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := http.Client{Timeout: 5 * time.Second, Transport: tr}

	resp, err := client.Get(baseUrl)
	if err != nil {
		golog.Error("fofa.go line:30 ", err)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		golog.Error("fofa.go line:36 ", err)
		return
	}

	jsdata, _ := simplejson.NewJson(body)
	results, err := jsdata.Get("results").Array()
	if err != nil {
		s, _ := jsdata.Get("errmsg").String()
		fmt.Println("[err] from fofa response " + s)
		return
	}
	fmt.Println("[+] rule:", param.Rule)
	fmt.Println("[+] total result:", len(results))
	if param.Out != "" {
		fmt.Println("[+] save path:", param.Out)
	}

	var fp *os.File
	if param.Out != "" {
		fp, err = os.OpenFile(param.Out, os.O_CREATE|os.O_RDWR, 744)
		if err != nil {
			golog.Error("fofa.go line:88 err:", err)
		}
		if len(results) > 0 {
			for _, v := range results {
				fp.WriteString(fmt.Sprintf("%v", v))
				fp.WriteString("\n")
			}
		}
	}

	for _, v := range results {
		fmt.Println(v)
	}

	defer func() {
		resp.Body.Close()
		fp.Close()
	}()

}
