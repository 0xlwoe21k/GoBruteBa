##GoBruteBa
###背景
目前市场上已经有各式各样的扫描工具，为什么我还要写一个呢？
* 日常使用中你们有没有碰到这种场景，用nmap或masscan扫端口发现A主机开放了一个22,然后你打开AB工具去暴破一波，暴破期间发现他还开放了3306端口，然后你又打开另一个AC工具继续暴破。这时你会不会想要是有一个工具集成所有的暴破功能于一体好了？
* 暴破端口A时，输入命令./xx ssh -user /path/userdic -pass /path/passdic。好了，过一会暴破然后又要输一遍，就很烦，这时是不是特别希望有一个windows下的图形化操作界面？
* 比如发现windows平台有一个好用的工具的时候，而你用的是mac，是不是在想，要是有mac版就好了

###功能
如上所述，此工具平台就是要解决这些场景
- [x] 图形化  
使用go+webview实现跨平台使用


###TO DO
* 跨平台
* 端口暴破
* NMAP、MASCCAN扫描结果处理+自动化暴破
* 端口扫描(待定)
* 编解码、加密解密功能
