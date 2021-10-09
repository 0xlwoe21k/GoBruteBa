package webDirScan

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func Test_putColorTest(t *testing.T) {

	clenit := &http.Client{}
	resp, _ := clenit.Get("http://www.baidu.com")

	for _, v := range resp.Header {
		fmt.Println(v)
	}
	//fmt.Printf("\033[32;40m%s\033[0m\n", "红色文字，黑色底哒")
	//fmt.Printf("\x1b[32m%s 32: 绿 \x1b[0m", "test")
	//
	//tmpurl := "https://test.com//123"
	//oneurl := tmpurl[7:]
	//twourl := tmpurl[:7]
	//
	//if strings.Contains(tmpurl[7:], "//") {
	//	oneurl = strings.Replace(oneurl, "//", "/", -1)
	//}
	//
	//fmt.Println(twourl + oneurl)
}

//func Test_timer1(t *testing.T) {
//	ticker := time.NewTicker(5 * time.Second)
//
//	for {
//		select {
//		case <- ticker.C:
//			fmt.Println("ticker .")
//		default:
//
//		}
//	}
//}

func Test_putcharTest(t *testing.T) {
	messagxx := make(chan string)
	go func() {
		for true {
			messagxx <- "123"
			time.Sleep(2 * time.Second)
		}
	}()

	for true {
		select {
		case msg := <-messagxx:
			fmt.Println("received message", msg)
		default:
			fmt.Println("no message received")
		}
	}

}
