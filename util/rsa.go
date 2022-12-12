package util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"main/config"
)

func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(config.RsaPublicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// sometimes public key was padded with \x00
	pubInterface, err := x509.ParsePKIXPublicKey(bytes.Trim(block.Bytes, "\x00"))
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func RsaDecrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(config.RsaPrivateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv := privInterface.(*rsa.PrivateKey)
	return rsa.DecryptPKCS1v15(rand.Reader, priv, origData)
}
