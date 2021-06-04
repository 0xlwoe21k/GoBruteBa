package common

type HostInfo struct {
	Host      string
	Ports     string
	Domain    string
	Url       string
	Timeout   int64
	Scantype  string
	Command   string
	Username  string
	Password  string
	Usernames []string
	Passwords []string
}

type SystemConfigInfo struct {
	ThreadNum int
}

type WebDirScanInfo struct {
	Target     string
	DirPath    string
	BuildInDir []string
	ThreadNum  int
	Proxy      string
	UserAgent  string
	Timeout    int
}
