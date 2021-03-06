package socks5proxy

import (
	"errors"
	"io"
	"log"
)

const (
	RANDOM_A = 13
	RANDOM_B = 7
	RANDOM_M = 256
)

type socks5Auth interface {
	Encrypt([]byte) error
	Decrypt([]byte) error
	EncodeWrite(io.ReadWriter, []byte) (int, error)
	DecodeRead(io.ReadWriter, []byte) (int, error)
}

type DefaultAuth struct {
	Encode *[256]byte //编码表
	Decode *[256]byte //解码表
}

/**
加密方法：根据编码表将字符串进行编码
**/

func (s *DefaultAuth) Encrypt(b []byte) error {
	for i, v := range b {
		// 编码
		if int(v) >= len(s.Encode) {
			return errors.New("socks5Auth Encode 超出范围")
		}
		b[i] = s.Encode[v]
	}
	return nil
}

func (s *DefaultAuth) Decrypt(b []byte) error {
	for i, v := range b {
		// 编码
		if int(v) >= len(s.Encode) {
			return errors.New("socks5Auth Encode 超出范围")
		}
		b[i] = s.Decode[v]
	}
	return nil
}

func (s *DefaultAuth) EncodeWrite(c io.ReadWriter, b []byte) (int, error) {
	// 编码
	err := s.Encrypt(b)
	if err != nil {
		return 0, err
	}
	return c.Write(b)
}

func (s *DefaultAuth) DecodeRead(c io.ReadWriter, b []byte) (int, error) {
	// 解码
	n, err := c.Read(b)
	if err != nil {
		return 0, err
	}
	err = s.Decrypt(b)
	if err != nil {
		return 0, err
	}
	return n, err
}

func CreateSimpleCipher(passwd string) (*DefaultAuth, error) {
	var s *DefaultAuth
	// 采用最简单的凯撒位移法
	sumint := 0
	if len(passwd) == 0 {
		return nil, errors.New("密码不能为空")
	}
	for v := range passwd {
		sumint += int(v)
	}
	sumint = sumint % 256
	var encodeString [256]byte
	var decodeString [256]byte
	for i := 0; i < 256; i++ {
		encodeString[i] = byte((i + sumint) % 256)
		decodeString[i] = byte((i - sumint + 256) % 256)
	}
	s = &DefaultAuth{
		Encode: &encodeString,
		Decode: &decodeString,
	}
	return s, nil
}

func CreateRandomCipher(passwd string) (*DefaultAuth, error) {
	var s *DefaultAuth
	// 采用随机编码表进行加密
	sumint := 0
	if len(passwd) == 0 {
		return nil, errors.New("密码不能为空")
	}
	for v := range passwd {
		sumint += int(v)
	}
	var encodeString [256]byte
	var decodeString [256]byte
	// 创建随机数 (a*x + b) mod m
	for i := 0; i < 256; i++ {
		encodeString[i] = byte((RANDOM_A*sumint + RANDOM_B) % RANDOM_M)
		decodeString[(RANDOM_A*sumint+RANDOM_B)%RANDOM_M] = byte(i)
		sumint = (RANDOM_A*sumint + RANDOM_B) % RANDOM_M
	}
	s = &DefaultAuth{
		Encode: &encodeString,
		Decode: &decodeString,
	}
	return s, nil
}

// 创建认证证书
func CreateAuth(encrytype string, passwd string) (socks5Auth, error) {
	if len(passwd) == 0 {
		return nil, errors.New("密码不能为空")
	}
	var s socks5Auth
	var err error
	switch encrytype {
	case "simple":
		s, err = CreateSimpleCipher(passwd)

	case "random":
		s, err = CreateRandomCipher(passwd)
	default:
		return nil, errors.New("错误加密方法类型！")
	}

	if err != nil {
		return nil, err
	}
	return s, nil
}

// 加密io复制，可接收加密函数作为参数
func SecureCopy(src io.ReadWriteCloser, dst io.ReadWriteCloser, secure func(b []byte) error) (written int64, err error) {
	size := 1024
	buf := make([]byte, size)
	for {
		// --------- read buf from client ---------
		nr, er := src.Read(buf)
		// ------------ encrypt data
		secure(buf)
		if nr > 0 {
			// -------------- write buf to server -----------
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, nil
}

// 加密io复制，可接收加密函数作为参数
func SecureCopy_Client2Server(src io.ReadWriteCloser, dst io.ReadWriteCloser, secure func(b []byte) error) (written int64, err error) {
	i := 0
	size := 1024
	buf := make([]byte, size)
	for {
		i++

		// --------- read buf from client ---------
		nr, er := src.Read(buf)
		if i == 1 {
			//log.Printf("---|c2s|--[%02d]->len=%d, %v", i, nr, buf[:nr])
		} else if i == 2 {
			//log.Printf("---|c2s|--[%02d]->len=%d, %v", i, nr, buf[:nr])
			var sock5Resolve Socks5Resolution
			_, err = sock5Resolve.LSTRequest(buf[:nr])
			if err != nil {
				log.Printf("[WARN] data package resolve fail, %v", err)
			}
			log.Printf("[INFO] %s:%d", sock5Resolve.DSTDOMAIN, sock5Resolve.DSTPORT)
			//} else if i == 3 {
			//log.Printf("---|c2s|--[%02d]->len=%d, %v", i, nr, buf[:nr])
		}

		// ------------ encrypt data
		secure(buf)
		if nr > 0 {
			// -------------- write buf to server -----------
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// 加密io复制，可接收加密函数作为参数
func SecureCopy_Server2Client(src io.ReadWriteCloser, dst io.ReadWriteCloser, secure func(b []byte) error) (written int64, err error) {
	// --------------------------- sock5 -----------------------
	i := 0
	size := 1024
	buf := make([]byte, size)
	for {
		i++

		// --------- read buf from client ---------
		nr, er := src.Read(buf)
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
		// ------------ encrypt data
		secure(buf)
		if nr > 0 {
			// -------------- write buf to server -----------
			nw, ew := dst.Write(buf[0:nr])
			if ew != nil {
				err = ew
				//log.Printf("[ERRO] s->c, write to client fail, %v", err)
				break
			}
			if nw > 0 {
				written += int64(nw)
			}
			if nr != nw {
				err = io.ErrShortWrite
				//log.Printf("[ERRO] s->c, write to client fail, %v", err)
				break
			}
		}
	}

	//log.Printf("[INFO] ------------ s to c, proxy done")

	return written, err
}

func SockCopy_C2S(src io.ReadWriteCloser, dst io.ReadWriteCloser) (written int64, err error) {
	i := 0
	size := 1024
	buf := make([]byte, size)
	for {
		i++

		// --------- read buf from client ---------
		nr, er := src.Read(buf)
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
		if nr > 0 {
			//log.Printf("c->s, [%03d], len=%d, %v", i, nr, buf[0:nr])
			// -------------- write buf to server -----------
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
	}

	return written, err
}

func SockCopy_S2C(src io.ReadWriteCloser, dst io.ReadWriteCloser) (written int64, err error) {
	i := 0
	size := 1024
	buf := make([]byte, size)
	for {
		i++

		// --------- read buf from client ---------
		nr, er := src.Read(buf)
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
		if nr > 0 {
			//log.Printf("s->c, [%03d], len=%d, %v", i, nr, buf[0:nr])
			// -------------- write buf to server -----------
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
	}

	return written, err
}

func SecureCopyNew_Client2Server(src io.ReadWriteCloser, dst io.ReadWriteCloser, secure func(b []byte) error) (written int64, err error) {
	i := 0
	size := 1024
	buf := make([]byte, size)
	for {
		i++

		// --------- read buf from client ---------
		nr, er := src.Read(buf)
		if er != nil {
			if er != io.EOF {
				err = er
			}

			//log.Printf("[ERROR] EOF, c 2 s,  %v", err)
			break
		}
		// ------------ encrypt data
		secure(buf)
		if nr > 0 {
			// -------------- write buf to server -----------
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite

				break
			}
		}
	}

	//log.Printf("----------------- proxy done ---------------")
	return written, err
}
