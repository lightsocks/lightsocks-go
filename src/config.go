// config
package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type CrptorParam struct {
	keyLen    int
	ivLen     int
	cryptType string
}

type Config struct {
	ServerIp    string `json:"server_ip"`
	ServerPort  int    `json:"server_port"`
	LocalIp     string `json:"local_ip"`
	LocalPort   int    `json:"local_port"`
	Password    string `json:"password"`
	Method      string `json:"method"`
	CrptorParam *CrptorParam
}

func parseConfig(configFile string) (config *Config, err error) {
	file, err := os.Open(configFile) // For read access.
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	config = &Config{}
	err = json.Unmarshal(data, config)
	return 
}

func(config *Config) checkConifg() bool {
	if config.ServerIp == "" {
		return false
	}
	if config.ServerPort == 0 {
		return false
	}
	if config.LocalIp == "" {
		return false
	}
	if config.LocalPort == 0 {
		return false
	}
	if config.Password == "" {
		return false
	}
	if config.Method == "" {
		return false
	}
	return true
}
