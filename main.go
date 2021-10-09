package main

import (
	"GoBruteBa/Run"
	"context"
	"fmt"
	"github.com/kataras/golog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	sigs := make(chan os.Signal, 1)

	rootCtx, cancel := context.WithCancel(context.Background())
	t := time.Now()

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		cancel()
		fmt.Print("\n")
		golog.Info("receive signal:", sig)
		golog.Info("task exit.")
		golog.Info("Wait for the task to end.")
		time.Sleep(3)
		os.Exit(0)
	}()
	Run.Run(os.Args, rootCtx)
	fmt.Println("[*] run time:", time.Since(t))
}
