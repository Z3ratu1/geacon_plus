package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
)

const HmacHashLen = 16

// **YOU SHOULD NEVER CHANGE IT!!!!!**
var IV = []byte("abcdefghijklmnop")

// GlobalKey 16 bytes global key, generate randomly at each execute, send to server when in meta info.
// can be changed at each package
var GlobalKey []byte

// AesKey  first 16 bytes of GlobalKey hash, used for latter communication
var AesKey []byte

// HmacKey latter 16 bytes of GlobalKey hash
var HmacKey []byte

func PaddingWithA(rawData []byte) []byte {
	newBuf := bytes.NewBuffer(rawData)
	step := 16
	for pad := newBuf.Len() % step; pad < step; pad++ {
		newBuf.Write([]byte("A"))
	}
	return newBuf.Bytes()
}

func AesCBCEncrypt(rawData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	rawData = PaddingWithA(rawData)
	cipherText := make([]byte, len(rawData))
	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(cipherText, rawData)
	return cipherText, nil
}

func AesCBCDecrypt(encryptData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	// seems need to padding if base64 payload was returned?
	encryptData = PaddingWithA(encryptData)
	if len(encryptData) < blockSize {
		panic("ciphertext too short")
	}
	if len(encryptData)%blockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, IV)
	mode.CryptBlocks(encryptData, encryptData)
	return encryptData, nil
}

func HmacHash(encrytedBytes []byte) []byte {
	hmacEntry := hmac.New(sha256.New, HmacKey)
	hmacEntry.Write(encrytedBytes)
	return hmacEntry.Sum(nil)[:16]
}
