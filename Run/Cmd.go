package Run

import (
	"GoBruteBa/common"
	"GoBruteBa/module/webDirScan"
	"flag"
	"github.com/kataras/golog"
	"os"
)

var (
	wdsi common.WebDirScanInfo
	hi   common.HostInfo
	sci  common.SystemConfigInfo
	help string
)

//golog.SetLevel("debug")
//
//golog.Println("This is a raw message, no levels, no colors.")
//golog.Info("This is an info message, with colors (if the output is terminal)")
//golog.Warn("This is a warning message")
//golog.Error("This is an error message")
//golog.Debug("This is a debug message")
//golog.Fatal(`Fatal will exit no matter what,

func Run(cmd []string) {
	Banner()
	wdsCmd := flag.NewFlagSet("wds", flag.ExitOnError)
	wdsCmd.StringVar(&wdsi.Target, "t", "", "set a target")
	wdsCmd.StringVar(&wdsi.DirPath, "dp", "", "set dirpath")
	wdsCmd.IntVar(&wdsi.ThreadNum, "thread", 20, "set thread num.")
	wdsCmd.StringVar(&wdsi.Proxy, "proxy", "", "set proxy. (usage:--proxy http://127.0.0.1:8080)")
	wdsCmd.StringVar(&wdsi.UserAgent, "ua", "", "set http request User Agent.")
	flag.StringVar(&help, "help", "", "help for GoBruteBa.")
	flag.Parse()

	if len(cmd) == 1 {
		Usage()
		os.Exit(0)
	} else if len(cmd) < 2 {
		golog.Error("[Cmd.go] no enough arguments.")
		os.Exit(1)
	}

	switch cmd[1] {
	case "webdirscan":
	case "wds":
		wdsCmd.Parse(cmd[2:])
		webDirScan.WebDirScan(wdsi)

	case "webalivescan":
	case "was":
		//do something

	default:
	}
}
