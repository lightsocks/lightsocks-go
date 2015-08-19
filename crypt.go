// crypt
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"io"
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newModelStream(key, iv []byte, cryptType string, doe DecOrEnc) (cipher.Stream, error) {
	block, err := newCipher(key, cryptType)
	return newStream(block, err, key, iv, doe)
}

func newCipher(key []byte, cryptType string) (cipher.Block, error) {
	if cryptType == "AES" {
		return aes.NewCipher(key)
	}
	return aes.NewCipher(key)
}

func newStream(block cipher.Block, err error, key, iv []byte,
	doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func initIV(ivLen int) (iv []byte, err error) {
	iv = make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}
