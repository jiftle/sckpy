package main

import (
	"flag"
	"log"

	"github.com/shikanon/socks5proxy"
)

func main() {
	listenAddr := flag.String("port", ":1080", "Input server listen address(Default 8888):")
	serverAddr := flag.String("server", "", "Input server listen address:")
	passwd := flag.String("passwd", "123456", "Input server proxy password:")
	encrytype := flag.String("type", "random", "Input encryption type:")
	recvHTTPProto := flag.String("recv", "sock5", "use http or sock5 protocol(default sock5):")

	flag.Parse()
	if *serverAddr == "" {
		flag.PrintDefaults()
		log.Fatal("[ERROR] 请输入服务器地址")
	}

	socks5proxy.Client(*listenAddr, *serverAddr, *encrytype, *passwd, *recvHTTPProto)
}
