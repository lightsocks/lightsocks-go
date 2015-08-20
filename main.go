// lightsocks project main.go
package main

import (
	"net"
	"strconv"
)

var config Config

func main() {
	config.localIp = "127.0.0.1"
	config.localPort = 1080
	config.serverIp = "127.0.0.1"
	config.serverPort = 8888
	config.method = "aes-cfb-128"
	config.password = "Password!01"
	config.crptorParam = getCrptorParam(config.method)
	listen(config.localIp, config.localPort)
}

func listen(localAddress string, port int) {
	ln, err := net.Listen("tcp", localAddress+":"+strconv.Itoa(port))
	if err != nil {
		// handle error
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
		}
		go handleConnection(conn)
	}
}
