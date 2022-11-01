package config

import (
	"time"
)

var (
	C2    = ""
	http  = "http://"
	https = "https://"
	// change to switch http(s)
	Host = http + C2

	// RsaPublicKey only used when first send meta info to server
	RsaPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----`)
	// RsaPrivateKey private key is not needed
	RsaPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----`)

	VerifySSLCert               = true
	TimeOut       time.Duration = 30 //seconds

	// **YOU SHOULD NEVER CHANGE IT!!!!!**
	IV = []byte("abcdefghijklmnop")
	// GlobalKey 16 bytes global key, generate randomly at each execute, send to server when in meta info.
	// can be changed at each package
	GlobalKey []byte
	// AesKey  first 16 bytes of GlobalKey hash, used for latter communication
	AesKey []byte
	// HmacKey latter 16 bytes of GlobalKey hash
	HmacKey            []byte
	Counter            = 0
	ComputerNameLength = 0

	// change remote dll inject to inject self
	// but execute asm will not get echo
	InjectSelf = false

	Support41Plus = true
	// proxy config
	ProxyUrl = ""
)
