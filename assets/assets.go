package assets

import (
	"fmt"
	"html/template"
	"io/ioutil"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func GetAssetsBytes(name string) []byte {
	data, err := ioutil.ReadFile(name)
	check(err)
	return data
}

func InjectCss(css string) string {
	res := fmt.Sprintf(`window.onload = function() {
                         (function(css) {
                                var style = document.createElement('style');
                                style.setAttribute('type', 'text/css');
                                style.appendChild(document.createTextNode(css));
                                document.head.appendChild(style);
                                //console.log("Injected CSS");
                        })("%s")
                }`, template.JSEscapeString(css))
	return res
}
