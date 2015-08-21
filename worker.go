// Worker
package main

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
)

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

func handleConnection(conn net.Conn) {
	var err error = nil
	if err = handShake(conn); err != nil {
		log.Fatalln("socks handshake:", err)
		return
	}
	rawaddr, addr, err := getRequest(conn)

	log.Println("target server address:", addr)

	if err != nil {
		log.Println("send connection confirmation:", err)
		return
	}
	remote, err := createServerConn()

	if err != nil {
		log.Println("send connection confirmation:", err)
		return
	}

	go localToRemote(conn, remote, rawaddr)
	remoteToLocal(remote, conn)
}

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := make([]byte, 258)

	var n int
	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	if buf[idVer] != socksVer5 {
		return errVer
	}
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func getRequest(conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]

	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

func createServerConn() (remote net.Conn, err error) {
	remote, err = net.Dial("tcp", config.ServerIp+":"+strconv.Itoa(config.ServerPort))
	if err != nil {
		return nil, err
	}
	return remote, err
}

func localToRemote(conn net.Conn, remote net.Conn, rawaddr []byte) {
	defer remote.Close()
	//send iv
	iv, err := initIV(config.CrptorParam.ivLen)
	if err != nil {
		return
	}
	key := evpBytesToKey(config.Password, config.CrptorParam.keyLen)

	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, uint32(config.CrptorParam.ivLen))
	if _, err := remote.Write(head); err != nil {
		return
	}
	if _, err := remote.Write(head); err != nil {
		return
	}
	if _, err := remote.Write(iv); err != nil {
		return
	}

	stream, err := newModelStream(key, iv, config.CrptorParam.cryptType, Encrypt)
	if err != nil {
		return
	}
	//send address
	validate := len(rawaddr)
	if validate > 16 {
		padding := 16 - validate%16
		total := validate + padding
		address := make([]byte, total)
		copy(address, rawaddr)
		if _, err := forwardData(remote, address, stream); err != nil {
			return
		}
	} else {
		if _, err := forwardData(remote, rawaddr, stream); err != nil {
			return
		}
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := forwardData(remote, buf[0:n], stream); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func remoteToLocal(remote net.Conn, conn net.Conn) {
	defer conn.Close()
	head := make([]byte, 4)
	if _, err := io.ReadAtLeast(remote, head, 4); err != nil {
		return
	}
	if _, err := io.ReadAtLeast(remote, head, 4); err != nil {
		return
	}
	iv := make([]byte, config.CrptorParam.ivLen)
	if _, err := io.ReadAtLeast(remote, iv, config.CrptorParam.ivLen); err != nil {
		return
	}
	key := evpBytesToKey(config.Password, config.CrptorParam.keyLen)
	stream, err := newModelStream(key, iv, config.CrptorParam.cryptType, Decrypt)
	if err != nil {
		return
	}
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		return
	}

	for {
		if _, err := io.ReadAtLeast(remote, head, 4); err != nil {
			break
		}
		validate := binary.BigEndian.Uint32(head)
		if _, err := io.ReadAtLeast(remote, head, 4); err != nil {
			break
		}
		length := binary.BigEndian.Uint32(head)
		src := make([]byte, length)
		dst := make([]byte, length)
		n, err := io.ReadAtLeast(remote, src, int(length))
		stream.XORKeyStream(dst, src)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := conn.Write(dst[0:validate]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func forwardData(conn net.Conn, data []byte, stream cipher.Stream) (n int, err error) {
	left := len(data) % 16
	first := len(data) - left
	n1 := 0
	if first != 0 {
		dst := make([]byte, 8+first)
		binary.BigEndian.PutUint32(dst, uint32(first))
		binary.BigEndian.PutUint32(dst[4:], uint32(first))
		stream.XORKeyStream(dst[8:], data[0:first])
		n1, err = conn.Write(dst)
		if err != nil {
			return n1, err
		}
	}
	n2 := 0
	if left != 0 {
		src := make([]byte, 16)
		dst := make([]byte, 8+16)
		copy(src, data[first:])
		binary.BigEndian.PutUint32(dst, uint32(left))
		binary.BigEndian.PutUint32(dst[4:], uint32(16))
		stream.XORKeyStream(dst[8:], src)
		n2, err = conn.Write(dst)
		if err != nil {
			return n2, err
		}
	}
	return n1 + n2, err
}
