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
	flag.StringVar(&config.ServerIp, "-s", myconfig.ServerIp, "server address")
	flag.IntVar(&config.ServerPort, "-p", myconfig.ServerPort, "server port")
	flag.StringVar(&config.Password, "-k", myconfig.Password, "password")
	flag.StringVar(&config.Method, "-m", myconfig.Method, "encryption method, default: aes-128-cfb")
	flag.StringVar(&config.LocalIp, "-b", myconfig.LocalIp, "local address")
	flag.IntVar(&config.LocalPort, "-l", myconfig.LocalPort, "local port")
	if err != nil {
		log.Println("parse config error:", err)
	}
	var help string
	flag.StringVar(&help, "-h", "1", "help")
	flag.Parse()
	if help != "1" {
		flag.PrintDefaults()
		return
	}
	if checkConifg(config) == false {
		return
	}
	config.CrptorParam = getCrptorParam(config.Method)
	listen(config.LocalIp, config.LocalPort)
}

func listen(localAddress string, port int) {
	var address = localAddress + ":" + strconv.Itoa(port)
	log.Println("proxy is ready ,address:", address)
	ln, err := net.Listen("tcp", address)
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
