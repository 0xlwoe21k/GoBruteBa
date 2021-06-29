package Run

import (
	"GoBruteBa/common"
	"GoBruteBa/module/config"
	fofa "GoBruteBa/module/fofaScan"
	subDomainScan "GoBruteBa/module/subDomainScan"
	"GoBruteBa/module/subDomainScan/source/runner"
	"GoBruteBa/module/webAliveScan"
	"GoBruteBa/module/webDirScan"
	"flag"
	"os"
)

var (
	wdsi      common.WebDirScanType
	hi        common.HostInfoType
	cfg       common.SystemConfigType
	was       common.WebAliveScanType
	fofaParam common.FofaType
	edt       common.EncodeDecodeType
	help      string
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
	wdsCmd.StringVar(&wdsi.Target, "u", "", "set a target(url)")
	wdsCmd.StringVar(&wdsi.TargetDirPath, "tF", "", "set multil target dirpath")
	wdsCmd.StringVar(&wdsi.PayloadDirPath, "pF", "", "set payload dirpath")
	wdsCmd.IntVar(&wdsi.ThreadNum, "thread", 30, "set thread num.")
	wdsCmd.StringVar(&wdsi.Proxy, "proxy", "", "set proxy. (usage:--proxy http://127.0.0.1:8080)")
	wdsCmd.StringVar(&wdsi.UserAgent, "ua", "", "set http request User Agent.")
	wdsCmd.IntVar(&wdsi.Timeout, "timeout", 2, "set http request timeout")

	wasCmd := flag.NewFlagSet("was", flag.ExitOnError)
	wasCmd.StringVar(&was.Target, "t", "", "set target(url)")
	wasCmd.StringVar(&was.DirPath, "tF", "", "set target file path")
	wasCmd.StringVar(&was.Proxy, "proxy", "", "set proxy. (usage:--proxy http://127.0.0.1:8080)")

	edtCmd := flag.NewFlagSet("edc", flag.ExitOnError)
	edtCmd.StringVar(&was.Target, "t", "", "set target(url)")
	edtCmd.StringVar(&was.DirPath, "tF", "", "set target file path")
	edtCmd.StringVar(&was.Proxy, "proxy", "", "set proxy. (usage:--proxy http://127.0.0.1:8080)")

	fofaCmd := flag.NewFlagSet("fofa", flag.ExitOnError)
	fofaCmd.StringVar(&fofaParam.Rule, "rule", "", "set fofa rule string")
	fofaCmd.BoolVar(&fofaParam.Doamin, "domain", false, "get domain information via rule")
	fofaCmd.BoolVar(&fofaParam.IP, "ip", false, "get domain information via rule")
	fofaCmd.BoolVar(&fofaParam.Title, "title", false, "get title information via rule")
	fofaCmd.BoolVar(&fofaParam.Host, "host", false, "get host information via rule")

	cfgCmd := flag.NewFlagSet("cfg", flag.ExitOnError)
	cfgCmd.BoolVar(&cfg.GenConfig, "new", false, "create default config file.")

	sdsCmd := flag.NewFlagSet("sds", flag.ExitOnError)
	options := &runner.Options{}
	sdsCmd.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	sdsCmd.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output")
	sdsCmd.IntVar(&options.Threads, "t", 10, "Number of concurrent goroutines for resolving")
	sdsCmd.IntVar(&options.Timeout, "timeout", 30, "Seconds to wait before timing out")
	sdsCmd.IntVar(&options.MaxEnumerationTime, "max-time", 10, "Minutes to wait for enumeration results")
	sdsCmd.StringVar(&options.Domain, "d", "", "Domain to find subdomains for")
	sdsCmd.StringVar(&options.DomainsFile, "dL", "", "File containing list of domains to enumerate")
	sdsCmd.StringVar(&options.OutputFile, "o", "", "File to write output to (optional)")
	sdsCmd.StringVar(&options.OutputDirectory, "oD", "", "Directory to write enumeration results to (optional)")
	sdsCmd.BoolVar(&options.JSON, "json", false, "Write output in JSON lines Format")
	sdsCmd.BoolVar(&options.CaptureSources, "collect-sources", false, "Output host source as array of sources instead of single (first) source")
	sdsCmd.BoolVar(&options.JSON, "oJ", false, "Write output in JSON lines Format")
	sdsCmd.BoolVar(&options.HostIP, "oI", false, "Write output in Host,IP format")
	sdsCmd.BoolVar(&options.Silent, "silent", false, "Show only subdomains in output")
	sdsCmd.BoolVar(&options.Recursive, "recursive", false, "Use only recursive subdomain enumeration sources")
	sdsCmd.BoolVar(&options.All, "all", false, "Use all sources (slow) for enumeration")
	sdsCmd.StringVar(&options.Sources, "sources", "", "Comma separated list of sources to use")
	sdsCmd.BoolVar(&options.ListSources, "ls", false, "List all available sources")
	sdsCmd.StringVar(&options.ExcludeSources, "exclude-sources", "", "List of sources to exclude from enumeration")
	sdsCmd.StringVar(&options.Resolvers, "r", "", "Comma-separated list of resolvers to use")
	sdsCmd.StringVar(&options.ResolverList, "rL", "", "Text file containing list of resolvers to use")
	sdsCmd.BoolVar(&options.RemoveWildcard, "nW", false, "Remove Wildcard & Dead Subdomains from output")
	sdsCmd.StringVar(&options.ConfigFile, "config", "config.yaml", "Configuration file for API Keys, etc")
	sdsCmd.BoolVar(&options.Version, "version", false, "Show version of subfinder")

	if len(cmd) < 2 {
		Usage()
		os.Exit(0)
	}

	switch cmd[1] {
	case "webdirscan", "wds":
		wdsCmd.Parse(cmd[2:])
		webDirScan.WebDirScan(wdsi)
	case "webalivescan", "was":
		wasCmd.Parse(cmd[2:])
		webAliveScan.WebAliveScan(was)
	case "subdomainscan", "sds":
		sdsCmd.Parse(cmd[2:])
		subDomainScan.SubDomainScan(options)
	case "fofa":
		fofaCmd.Parse(cmd[2:])
		fofa.GetInfoByRule(fofaParam)
	case "cfg":
		cfgCmd.Parse(cmd[2:])
		config.NewConfig(cfg)
	case "help", "h":
		Usage()
		os.Exit(0)
	default:
		Usage()
		os.Exit(0)
	}
}
