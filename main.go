package main

import (
	"GoBruteBa/assets"
	Server "GoBruteBa/server"
	"fmt"
	"github.com/maxence-charriere/go-app/v8/pkg/app"
	_ "github.com/maxence-charriere/go-app/v8/pkg/app"
	"github.com/webview/webview"
	_ "github.com/webview/webview"
	_ "github.com/zserge/lorca"
)

type GoBruteBa struct {
	app.Compo

	name string
}

func main() {
	counter := 0
	w := webview.New(true)

	w.SetTitle("The fastest port scan tool of the world!")
	w.SetSize(800, 600, webview.HintFixed)

	Server.EventBind(w, counter)

	w.Init(string(assets.GetAssetsBytes("assets/js/jquery.min.js")))
	w.Init(string(assets.GetAssetsBytes("assets/bootstrap/js/bootstrap.js")))

	html := string(assets.GetAssetsBytes("html/index.html"))
	indexHtml := fmt.Sprintf("data:text/html,%s", html)

	minBootcss := string(assets.GetAssetsBytes("assets/bootstrap/css/bootstrap.css"))
	w.Eval(assets.InjectCss(minBootcss))
	w.Navigate(indexHtml)
	w.Run()

	defer w.Destroy()
}

//func main() {
//	// Create UI with basic HTML passed via data URI
//	ui, err := lorca.New("data:text/html,"+url.PathEscape(`
//	<html>
//		<head><title>Hello</title></head>
//		<body><h1>Hello, world!</h1></body>
//	</html>
//	`), "", 480, 320)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer ui.Close()
//	// Wait until UI window is closed
//	<-ui.Done()
//}

//make exection
//1.GOARCH=wasm GOOS=js go build -o web/app.wasm
//2.go build

//Example
//w := New(true)
//defer w.Destroy()
//w.SetTitle("Hello")
//w.Bind("noop", func() string {
//	log.Println("hello")
//	return "hello"
//})
//w.Bind("add", func(a, b int) int {
//	return a + b
//})
//w.Bind("quit", func() {
//	w.Terminate()
//})
//w.Navigate(`data:text/html,
//		<!doctype html>
//		<html>
//			<body>hello</body>
//			<script>
//				window.onload = function() {
//					document.body.innerText = ` + "`hello, ${navigator.userAgent}`" + `;
//					noop().then(function(res) {
//						console.log('noop res', res);
//						add(1, 2).then(function(res) {
//							console.log('add res', res);
//							quit();
//						});
//					});
//				};
//			</script>
//		</html>
//	)`)
//w.Run()
