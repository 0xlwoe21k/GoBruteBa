package Run

import (
	"flag"
	"fmt"
	"os"
)

func Banner() {

	banner := `
   ______      ____             __       ____       
  / ____/___  / __ )_______  __/ /____  / __ )____ _
 / / __/ __ \/ __  / ___/ / / / __/ _ \/ __  / __  /
/ /_/ / /_/ / /_/ / /  / /_/ / /_/  __/ /_/ / /_/ / 
\____/\____/_____/_/   \__,_/\__/\___/_____/\__,_/
							GoBruteBa version: 0.2

`
	print(banner)
}

func Usage() {
	fmt.Fprintf(os.Stderr, `
NAME:
	GoBruteBa  - A super tool

USAGE: 
	GoBruteBa [global options] command [command options] [arguments...]

COMMAND:
	webdirscan, wds		Run a web dir scan task
	webalivescan,was	Run a web alive scan task
	subdomainscan,sds	scan and brute subdomain via subfinder
	fofa				get vuln doamin or ip via rule
	cfg					new config file.
	help,h				help for GoBruteBa.

EXAMPLE:
	./GoBruteBa wds -t http://127.0.0.1  -thread 30
	./GoBruteBa wds -t http://127.0.0.1  -fF ./ctf.txt -thread 30
	./GoBruteBa sds -d http://example.com -confg confiy.yaml -all
	./GoBruteBa was -fF target.txt
	./GoBruteBa fofa -rule 'Shiro' -domain

NOTICE:
	first run. need create config.yaml use 'cfg' option.(usage:GoBurteBa cfg --new).
`)
	flag.PrintDefaults()
}
