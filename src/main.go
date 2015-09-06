// lightsocks project main.go
package main

import (
	"flag"
	"log"
	"net"
	"strconv"
)

var config Config

func main() {
	var configFile string
	flag.StringVar(&configFile, "-c", "config.json", "specify config file")
	myconfig, err := parseConfig(configFile)
	if err != nil {
		log.Println("parse config error:", err)
	}
	flag.StringVar(&config.ServerIp, "-s", myconfig.ServerIp, "server address")
	flag.IntVar(&config.ServerPort, "-p", myconfig.ServerPort, "server port")
	flag.StringVar(&config.Password, "-k", myconfig.Password, "password")
	flag.StringVar(&config.Method, "-m", myconfig.Method, "encryption method, default: aes-128-cfb")
	flag.StringVar(&config.LocalIp, "-b", myconfig.LocalIp, "local address")
	flag.IntVar(&config.LocalPort, "-l", myconfig.LocalPort, "local port")

	var help string
	flag.StringVar(&help, "-h", "1", "help")
	flag.Parse()
	if help != "1" {
		flag.PrintDefaults()
		return
	}
	if !(&config).checkConifg() {
		return
	}
	config.CrptorParam = getCrptorParam(config.Method)
	listen(config.LocalIp, config.LocalPort)
}

func listen(localAddress string, port int) {
	var address = localAddress + ":" + strconv.Itoa(port)
	ln, err := net.Listen("tcp", address)
	if err != nil {
		// handle error
	}
	log.Println("proxy is ready ,address:", address)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
		}
		go handleConnection(conn)
	}
}
