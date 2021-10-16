package socks5proxy

import (
	"log"
	"net"
	"sync"
)

type TcpClient struct {
	conn   *net.TCPConn
	server *net.TCPAddr
}

func handleProxyRequest(localClient *net.TCPConn, serverAddr *net.TCPAddr, auth socks5Auth, recvHTTPProto string) {

	// 远程连接IO
	dstServer, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		log.Printf("---> 服务器[%s]连接失败, %v", serverAddr.String(), err)
		return
	}
	defer dstServer.Close()
	defer localClient.Close()
	//log.Printf("---> 连接远程服务器[%s] ....", serverAddr.String())

	// 和远程端建立安全信道
	wg := new(sync.WaitGroup)
	wg.Add(2)

	if recvHTTPProto == "sock5" {
		// -----------> 本地的内容copy到远程端
		go func() {
			defer wg.Done()
			SecureCopy_Client2Server(localClient, dstServer, auth.Encrypt)
		}()

		// ------------> 远程得到的内容copy到源地址
		go func() {
			defer wg.Done()
			SecureCopy_Server2Client(dstServer, localClient, auth.Decrypt)
		}()
		wg.Wait()
	} else {
		log.Fatalf("-X-> not support proto: %v", recvHTTPProto)
	}

}

func Client(listenAddrString string, serverAddrString string, encrytype string, passwd string, recvHTTPProto string) {
	//所有客户服务端的流都加密,
	auth, err := CreateAuth(encrytype, passwd)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("---> 你的密码是: %s ,请保管好你的密码", passwd)

	// proxy地址
	serverAddr, err := net.ResolveTCPAddr("tcp", serverAddrString)
	if err != nil {
		log.Fatal(err)
	}

	listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("---> server port: %v, proto: %v", listenAddrString, recvHTTPProto)

	for {
		localClient, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}

		// 处理代理请求
		go handleProxyRequest(localClient, serverAddr, auth, recvHTTPProto)
	}
}
