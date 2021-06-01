package Run

import (
	"GoBruteBa/common"
	subDomainScan "GoBruteBa/module/subDomainScan"
	"GoBruteBa/module/subDomainScan/source/runner"
	"GoBruteBa/module/webDirScan"
	"flag"
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
	sdsCmd.BoolVar(&options.NewConfigFile, "gconfig", false, "create default config.yaml.")

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
		//do something
	case "subdomainscan", "sds":
		sdsCmd.Parse(cmd[2:])
		subDomainScan.SubDomainScan(options)
	case "help", "h":
		Usage()
		os.Exit(0)
	default:
		Usage()
		os.Exit(0)
	}
}
