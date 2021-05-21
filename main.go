package main

import (
	"GoBruteBa/Run"
	"fmt"
	"os"
	"runtime"
	"time"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	t := time.Now()
	//log.Fatalln()
	Run.Run(os.Args)

	fmt.Println("[*] run time:", time.Since(t))
}
