// Worker
package main

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"errors"
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
	closed := false
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	var err error = nil
	if err = handShake(conn); err != nil {
		log.Println("socks handshake:", err)
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

	defer func() {
		if !closed {
			remote.Close()
		}
	}()

	go localToRemote(conn, remote, rawaddr)
	remoteToLocal(remote, conn)
	closed = true
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
	remote, err = net.Dial("tcp", config.serverIp+":"+strconv.Itoa(config.serverPort))
	if err != nil {
		return nil, err
	}
	return remote, err
}


func localToRemote(conn net.Conn, remote net.Conn, rawaddr []byte) {

	defer remote.Close()
	//write iv
	iv, err := initIV(config.crptorParam.ivLen)
	if err != nil {
		return
	}
	key := evpBytesToKey(config.password, config.crptorParam.keyLen)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(config.crptorParam.ivLen))
	remote.Write(b)
	remote.Write(b)
	remote.Write(iv)

	stream, err := newModelStream(key, iv,"AES", Encrypt)
	if err != nil {
		return
	}
	//send address
	validate := len(rawaddr)
	if validate > 16 {
		padding := 16 - validate%16
		total := validate + padding
		b := make([]byte, total)
		for i := 0; i < validate; i++ {
			b[i] = rawaddr[i]
		}
		forwardData(remote, b, stream)
	} else {
		forwardData(remote, rawaddr, stream)
	}

	for {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := forwardData(remote, buf[0:n], stream); err != nil {
				log.Println("write:", err)
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}

func remoteToLocal(remote net.Conn, conn net.Conn) {
	defer conn.Close()
	dst := make([]byte, 4)
	io.ReadAtLeast(remote, dst, 4)
	io.ReadAtLeast(remote, dst, 4)
	iv := make([]byte, config.crptorParam.ivLen)
	io.ReadAtLeast(remote, iv, config.crptorParam.ivLen)
	key := evpBytesToKey(config.password, config.crptorParam.keyLen)
	stream, err := newModelStream(key, iv,config.crptorParam.cryptType, Decrypt)
	if err != nil {
		return
	}
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})

	for {
		io.ReadAtLeast(remote, dst, 4)
		validate := binary.BigEndian.Uint32(dst)
		io.ReadAtLeast(remote, dst, 4)
		length := binary.BigEndian.Uint32(dst)
		src := make([]byte, length)
		dst := make([]byte, length)
		n, err := io.ReadAtLeast(remote, src, int(length))
		stream.XORKeyStream(dst, src)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := conn.Write(dst[0:validate]); err != nil {
				log.Println("write:", err)
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}


func forwardData(conn net.Conn, data []byte, stream cipher.Stream) (n int, err error) {
	var left = len(data) % 16
	var first = len(data) - left
	err = nil
	var m1 = 0
	var m2 = 0
	if first != 0 {
		dst := make([]byte, first)
		validate := make([]byte, 4)
		binary.BigEndian.PutUint32(validate, uint32(first))
		conn.Write(validate)
		conn.Write(validate)
		stream.XORKeyStream(dst, data[0:first])
		m1, err = conn.Write(dst)
	}
	if left != 0 {
		src := make([]byte, 16)
		dst := make([]byte, 16)
		for i := 0; i < left; i++ {
			src[i] = data[first+i]
		}
		validate := make([]byte, 4)
		binary.BigEndian.PutUint32(validate, uint32(left))
		conn.Write(validate)
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(16))
		conn.Write(length)
		stream.XORKeyStream(dst, src)
		m2, err = conn.Write(dst)
	}
	return m1 + m2, err
}