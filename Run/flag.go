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
							GoBruteBa version: 0.1v

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
	webdirscan, wds		Run a webdirscan task
	webalivescan,was	Run a webalivescan task

EXAMPLE:
	./GoBruteBa wds -t http://127.0.0.1  -thread 30
	./GoBruteBa wds -t http://127.0.0.1  -dp /Users/jack/tool/dic/fuzzDicts-master/ctfDict/ctf.txt -thread 30
`)
	flag.PrintDefaults()
}
