package socks5proxy

import (
	"fmt"
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

}

func Client(listenAddrString string, serverAddrString string, encrytype string, passwd string, recvHTTPProto string) {
	//所有客户服务端的流都加密,
	auth, err := CreateAuth(encrytype, passwd)
	if err != nil {
		log.Fatal(err)
	}

	// 服务端
	serverAddr, err := net.ResolveTCPAddr("tcp", serverAddrString)
	if err != nil {
		log.Fatal(err)
	}

	listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		log.Fatal(err)
	}

	// 本地侦听
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[INFO] local server port: %v, proto: %v", listenAddrString, recvHTTPProto)

	for {
		localClient, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("[ERROR] accept tcp connect fail, %v", err)
		} else {
			// 处理代理请求
			// go handleProxyRequest(localClient, serverAddr, auth, recvHTTPProto)
			go handleProxyRequest_Direct(localClient, serverAddr, auth, recvHTTPProto)
		}
	}
}

func handleProxyRequest_Direct(localClient *net.TCPConn, serverAddr *net.TCPAddr, auth socks5Auth, recvHTTPProto string) {
	var serverAddrString string

	src := localClient
	i := 0
	size := 1024
	buf := make([]byte, size)

	for {
		i++

		// --------- read buf from client ---------
		nr, err := src.Read(buf)
		if err != nil {
			log.Printf("[WARN] read src data pack fail, %v", err)
			break
		}

		if i == 1 {
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
			// --------------- 认证协商 ----------------
			var proto ProtocolVersion

			// handshake
			resp, err := proto.HandleHandshake(buf[0:nr])
			if err != nil {
				log.Printf("[WARN] handshake fail, %v", err)
				break
			}

			src.Write(resp)

		} else if i == 2 {
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
			var sock5Resolve Socks5Resolution
			resp, err := sock5Resolve.LSTRequest(buf[:nr])
			if err != nil {
				log.Printf("[WARN] data package resolve fail, %v", err)
				break
			}
			log.Printf("[INFO] %s:%d", sock5Resolve.DSTDOMAIN, sock5Resolve.DSTPORT)
			src.Write(resp)

			// ---------------- read data handler -----------------
			serverAddrString = fmt.Sprintf("%s:%d", sock5Resolve.DSTDOMAIN, sock5Resolve.DSTPORT)

			break
		} else {
			log.Printf("--fuck-|c2s|--[%02d]->len=%d, %v", i, nr, buf[:nr])
		}
	}

	serverAddr, err := net.ResolveTCPAddr("tcp", serverAddrString)
	if err != nil {
		log.Fatal(err)
	}

	// connet real server
	dstServer, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		log.Printf("---> 服务器[%s]连接失败, %v", serverAddr.String(), err)
		return
	}
	defer dstServer.Close()
	defer localClient.Close()

	// 和远程端建立安全信道
	wg := new(sync.WaitGroup)
	wg.Add(2)

	// -----------> 本地的内容copy到远程端
	go func() {
		defer wg.Done()
		SockCopy_C2S(localClient, dstServer)
	}()

	// ------------> 远程得到的内容copy到源地址
	go func() {
		defer wg.Done()
		SockCopy_S2C(dstServer, localClient)
	}()
	wg.Wait()

}
