// config
package main

type CrptorParam struct {
	keyLen   int
	ivLen    int
	cryptType string
}

type Config struct {
	serverIp    string
	serverPort  int
	localIp     string
	localPort   int
	password    string
	method      string
	crptorParam *CrptorParam
}

