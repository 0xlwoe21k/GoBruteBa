package Server

import (
	"github.com/webview/webview"
	"log"
)

func EventBind(w webview.WebView, counter int) {
	w.Bind("noop", func() string {
		log.Println("hello")
		return "hello"
	})
	w.Bind("add", func(a, b int) int {
		return a + b
	})
}
