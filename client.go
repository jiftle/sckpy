package socks5proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

type TcpClient struct {
	conn   *net.TCPConn
	server *net.TCPAddr
}

func handleProxyRequest_Proxy(localClient *net.TCPConn, dstServer *net.TCPConn, auth socks5Auth, recvHTTPProto string) {

	defer dstServer.Close()
	defer localClient.Close()

	// 和远程端建立安全信道
	wg := new(sync.WaitGroup)
	wg.Add(2)

	// -----------> 本地的内容copy到远程端
	go func() {
		defer wg.Done()
		SecureCopyNew_Client2Server(localClient, dstServer, auth.Encrypt)
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
			go handleProxyRequest(localClient, serverAddr, auth, recvHTTPProto)
		}
	}
}

func handleProxyRequest_Direct(localClient *net.TCPConn, serverAddr *net.TCPAddr, auth socks5Auth, recvHTTPProto string) {
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

func handleProxyRequest(localClient *net.TCPConn, serverAddr *net.TCPAddr, auth socks5Auth, recvHTTPProto string) {
	var serverAddrString string

	src := localClient
	i := 0
	size := 1024
	buf := make([]byte, size)

	var handshake_buf_step1 []byte
	var handshake_buf_step2 []byte

	for {
		i++

		// --------- read buf from client ---------
		nr, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("[WARN] read src data pack fail, %v", err)
			return
		}

		if i == 1 {
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
			// --------------- 认证协商 ----------------
			var proto ProtocolVersion

			// handshake
			resp, err := proto.HandleHandshake(buf[0:nr])
			if err != nil {
				log.Printf("[WARN] handshake fail, %v", err)
				return
			}
			handshake_buf_step1 = make([]byte, nr)
			copy(handshake_buf_step1, buf[0:nr])
			//handshake_buf_step1 = buf[0:nr]

			src.Write(resp)

		} else if i == 2 {
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
			//handshake_buf_step2 = buf[:nr]
			handshake_buf_step2 = make([]byte, nr)
			copy(handshake_buf_step2, buf[0:nr])

			var sock5Resolve Socks5Resolution
			resp, err := sock5Resolve.LSTRequest(buf[:nr])
			if err != nil {
				log.Printf("[WARN] data package resolve fail, %v", err)
				break
			}
			//log.Printf("[INFO] %s:%d", sock5Resolve.DSTDOMAIN, sock5Resolve.DSTPORT)
			src.Write(resp)

			// ---------------- read data handler -----------------
			serverAddrString = fmt.Sprintf("%s:%d", sock5Resolve.DSTDOMAIN, sock5Resolve.DSTPORT)

			break
		} else {
			log.Printf("--fuck-|c2s|--[%02d]->len=%d, %v", i, nr, buf[:nr])
		}
	}

	proxyType := GetProxyType(serverAddrString)
	if proxyType == 2 {
		log.Printf("[INFO] direct, %v", serverAddrString)
		serverAddr, err := net.ResolveTCPAddr("tcp", serverAddrString)
		if err != nil {
			log.Fatal(err)
		}
		//log.Printf("connect [%s]", serverAddr.String())
		handleProxyRequest_Direct(src, serverAddr, auth, recvHTTPProto)
	} else if proxyType == 1 {
		log.Printf("[INFO] proxy, %v", serverAddrString)

		//log.Printf("connect [%s]", serverAddr.String())
		// connect sckpy server
		dstServer, err := net.DialTCP("tcp", nil, serverAddr)
		if err != nil {
			log.Printf("---> 服务器[%s]连接失败, %v", serverAddr.String(), err)
			return
		}

		// -------------------- 与服务器进行sock5握手 ------------------
		//step 1
		buf = handshake_buf_step1
		//log.Printf("s1, %v", buf)
		auth.Encrypt(buf)
		//log.Printf("s1, enc, %v", buf)
		_, err = dstServer.Write(buf)
		if err != nil {
			log.Printf("[ERROR] handshake step1 to server fail, %v", err)
			return
		}
		nr, err := dstServer.Read(buf)
		if nr > 0 {
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
			auth.Decrypt(buf)
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
		}

		//step 2
		buf = handshake_buf_step2
		//log.Printf("s2, %v", buf)
		auth.Encrypt(buf)
		//log.Printf("s2, enc, %v", buf)
		_, err = dstServer.Write(buf)
		if err != nil {
			log.Printf("[ERROR] handshake step2 to server fail, %v", err)
			return
		}
		nr, err = dstServer.Read(buf)
		if nr > 0 {
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
			auth.Decrypt(buf)
			//log.Printf("c->s, [%02d], len=%d, %v", i, nr, buf[:nr])
		}
		handleProxyRequest_Proxy(src, dstServer, auth, recvHTTPProto)
	}
}

func GetProxyType(domain string) int {
	// 1 代理 2 不代理
	if domain[0:1] == ":" {
		return 2
	}

	if strings.Contains(domain, "dingtalk.com") {
		return 2
	} else if strings.Contains(domain, "dingtalkapps.com") {
		return 2
	} else if strings.Contains(domain, "aliyuncs.com") {
		return 2
	} else if strings.Contains(domain, "alicdn.com") {
		return 2
	} else if strings.Contains(domain, "aliapp.org") {
		return 2
	} else if strings.Contains(domain, "alipay.com") {
		return 2
	} else if strings.Contains(domain, "aliimg.com") {
		return 2
	} else if strings.Contains(domain, "aliwork.com") {
		return 2
	} else if strings.Contains(domain, "mmstat.com") {
		return 2
	} else if strings.Contains(domain, "taobao.com") {
		return 2
	} else if strings.Contains(domain, "taobao.net") {
		return 2
	} else if strings.Contains(domain, "tbcdn.cn") {
		return 2
	} else if strings.Contains(domain, "tmall.com") {
		return 2
	} else if strings.Contains(domain, "csdn.net") {
		return 2
	} else if strings.Contains(domain, "csdnimg.cn") {
		return 2
	} else if strings.Contains(domain, "cnblogs.com") {
		return 2
	} else if strings.Contains(domain, "googleapis.com") {
		return 2
	} else {
		return 1
	}
}
