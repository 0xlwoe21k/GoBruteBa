package config

import (
	"GoBruteBa/common"
	"github.com/kataras/golog"
	"io"
	"os"
)

type Cfg struct {
	Resolvers      []string `yaml:"resolvers,omitempty"`
	Sources        []string `yaml:"sources,omitempty"`
	Binaryedge     []string `yaml:binaryedge`
	Censys         []string `yaml:censys`
	Certspotter    []string `yaml:certspotter`
	Passivetotal   []string `yaml:passivetotal`
	Securitytrails []string `yaml:securitytrails`
	Fofa           struct {
		Email string `yaml:email`
		Key   string `yaml:key`
	}
	Shodan []string `yaml:shodan`
	Github []string `yaml:github`
}

func NewConfig(cfg common.SystemConfigType) {
	if cfg.GenConfig {
		var wireteString = `resolvers:
  - 1.1.1.1
  - 1.0.0.1
sources:
  - binaryedge
  - bufferover
  - censys
  - passivetotal
  - sitedossier
binaryedge:
  - 0bf8919b-aab9-42e4-9574-d3b639324597
  - ac244e2f-b635-4581-878a-33f4e79a2c13
censys:
  - ac244e2f-b635-4581-878a-33f4e79a2c13:dd510d6e-1b6e-4655-83f6-f347b363def9
certspotter: []
passivetotal:
  - sample-email@user.com:sample_password
securitytrails: []
fofa:
    email: zjgelen@gmail.com
    key: 32a24b1e1af2b70c108facf54b899918
shodan:
  - AAAAClP1bJJSRMEYJazgwhJKrggRwKA
github:
  - d23a554bbc1aabb208c9acfbd2dd41ce7fc9db39
  - asdsd54bbc1aabb208c9acfbd2dd41ce7fc9db39`
		var filename = "./config.yaml"
		var fout *os.File
		var err error
		if checkFileIsExist(filename) { //如果文件存在
			golog.Info("[options.go line:93] file already existed.")
			os.Exit(0)
		} else {
			fout, err = os.Create(filename) //创建文件
		}
		if err != nil {
			golog.Error("[options.go line:99] Open file failed!")
			os.Exit(0)
		}
		_, err = io.WriteString(fout, wireteString)
		if err != nil {
			golog.Error("[options.go line:104] write data failed")
			golog.Error(err)
			os.Exit(0)
		}
		golog.Info("success! create file config.yaml.")
		os.Exit(0)
	}

}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}
