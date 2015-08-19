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

var aes1 = CrptorParam{16, 16, "AES"}

func getCrptorParam(method string) *CrptorParam {
	if method == "aes-cfb-128" {
		return &aes1
	}
	return &aes1
}
