package socks5proxy

import (
	"fmt"
	"log"
	"net"
	"sync"
)

func handleClientRequest(client *net.TCPConn, auth socks5Auth) {
	if client == nil {
		return
	}
	defer client.Close()

	// 初始化一个字符串buff
	buff := make([]byte, 255)

	// --------------- 认证协商 ----------------
	var proto ProtocolVersion
	n, err := auth.DecodeRead(client, buff) //解密

	// handshake
	resp, err := proto.HandleHandshake(buff[0:n])

	// write to client
	auth.EncodeWrite(client, resp) //加密
	if err != nil {
		log.Printf("[ERROR] %v, %v", client.RemoteAddr(), err)
		return
	}

	//获取客户端代理的请求
	var request Socks5Resolution
	n, err = auth.DecodeRead(client, buff)
	resp, err = request.LSTRequest(buff[0:n])

	auth.EncodeWrite(client, resp)
	if err != nil {
		log.Print(client.RemoteAddr(), err)
		return
	}

	log.Printf("[INFO] %s, %s:%d", client.RemoteAddr().String(), request.DSTDOMAIN, request.DSTPORT)

	// 连接真正的远程服务
	dstServer, err := net.DialTCP("tcp", nil, request.RAWADDR)
	if err != nil {
		log.Printf("------> 连接服务端[%s]失败, %s", request.RAWADDR.String(), err.Error())
		return
	}
	defer dstServer.Close()
	//log.Printf("------> 连接服务端[%s]成功", request.RAWADDR.String())

	wg := new(sync.WaitGroup)
	wg.Add(2)

	// 本地的内容copy到远程端
	go func() {
		defer wg.Done()
		n, err := SecureCopy(client, dstServer, auth.Decrypt)
		if err != nil {
			log.Printf("[WARN] c->s, send fail, %v", err)
		} else {
			log.Printf("[INFo] c->s, %s:%d,len=%s", request.DSTDOMAIN, request.DSTPORT, Len2Str(n))
		}
	}()

	// 远程得到的内容copy到源地址
	go func() {
		defer wg.Done()
		n, err := SecureCopy(dstServer, client, auth.Encrypt)
		if err != nil {
			log.Printf("[WARN] s->c, send fail, %v", err)
		} else {
			log.Printf("[INFo] s->c, %s:%d,len=%s", request.DSTDOMAIN, request.DSTPORT, Len2Str(n))
		}
	}()
	wg.Wait()

}

func Len2Str(n int64) string {
	var s string

	if n < 1024 {
		s = fmt.Sprintf("%dB", n)
	} else if n < 1024*1024 {
		s = fmt.Sprintf("%.2fKB", float64(n)/1024.0)
	} else if n < 1024*1024*1024 {
		s = fmt.Sprintf("%.2fMB", float64(n)/1024.0/1024.0)
	} else {
		s = fmt.Sprintf("%dB", n)
	}

	return s
}

func Server(listenAddrString string, encrytype string, passwd string) {
	//所有客户服务端的流都加密,
	auth, err := CreateAuth(encrytype, passwd)
	if err != nil {
		log.Fatal(err)
	}
	//log.Printf("你的密码是:%s ,请保管好你的密码", passwd)

	// 监听客户端
	listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[INFO] listen port: %s", listenAddrString)

	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		go handleClientRequest(conn, auth)
	}
}
