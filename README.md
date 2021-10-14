<img src="./img/logo.png" width="600">

# Socks5Proxy

[![GitHub license](https://img.shields.io/github/license/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/network)
[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://golang.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/shikanon/socks5proxy)](https://goreportcard.com/report/github.com/shikanon/socks5proxy)


用golang 实现了一个简单的socks5协议来实现代理转发，主要应用场景是給公司内部做VPN登陆，提供内网访问。*(声明：由于采用的是原始的socks5协议，并没有对协议做改造加工，并不一定能防范GFW的主动探测，请勿用于非法用途)*


文件结构
```
cryptogram.go       `加密算法`
socks5.go           `socks5协议实现`
server.go           `服务端实现`
client.go           `客户端实现`
cmd/server/main.go  `服务端主启动程序`
cmd/client/main.go  `客户端主启动程`
```


- [SOCKS5协议介绍](./docs/socks5.md)
- [加密算法介绍](./docs/cryptogram.md)
- [软件下载及版本说明](./docs/release.md)

#### 使用说明

**服务端**
在服务器端中启动路径，打开。/cmd/server/，运行`go run main.go`
服务端命令参数有三个：
```
  -local string #设置服务器对外端口
    	Input server listen address(Default 8888): (default ":18888")
  -passwd string #设置服务器对外密码
    	Input server proxy password: (default "123456")
  -type string #设置加密类型
    	Input encryption type: (default "random")
```

**客户端**
在客户端中启动路径，打开。/cmd/client/，运行`go run main.go`
服务端命令参数有四个：
```
  -local string #设置客户端的本地转发端口
        Input server listen address(Default 8888): (default ":8888")
  -passwd string #设置服务器的密码
        Input server proxy password: (default "123456")
  -server string #设置服务器ip地址和端口
        Input server listen address, for example: 16.158.6.16:18181
  -type string #设置加密类型
    	Input encryption type: (default "random")
```

## TODO

* [ * ] 混淆加密
* [ * ] 客户端