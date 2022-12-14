package config

import (
	"time"
)

var (
	C2    = ""
	http  = "http://"
	https = "https://"
	// change to switch http(s)
	Host = https + C2

	// RsaPublicKey only used when first send meta info to server
	RsaPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----`)
	// RsaPrivateKey private key is not needed
	RsaPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----`)

	VerifySSLCert               = true
	TimeOut       time.Duration = 30          //seconds
	DownloadSize                = 1024 * 1024 // size of download
	/* custom options here  */
	// change remote dll inject to inject self, but execute asm will not get echo
	InjectSelf    = false
	DeleteSelf    = true
	Support41Plus = false
	// if debug is false there will be no output
	Debug      = false
	TimeLayout = "2006-01-02 15:04:05"
	EndTime    = ""
	// proxy config
	ProxyUrl = ""
	// domain fronting host
	DomainFrontHost = ""
)
