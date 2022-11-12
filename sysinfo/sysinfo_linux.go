package sysinfo

import (
	"encoding/binary"
	"main/util"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
)

func arrayToString(x [65]int8) string {
	var buf [65]byte
	for i, b := range x {
		buf[i] = byte(b)
	}
	str := string(buf[:])
	if i := strings.Index(str, "\x00"); i != -1 {
		str = str[:i]
	}
	return str
}

func getUname() syscall.Utsname {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		util.Printf("Uname: %v", err)
		return syscall.Utsname{} //nil
	}
	return uname
}

func GetOSVersion() string {
	uname := getUname()

	if len(uname.Release) > 0 {
		return arrayToString(uname.Release)
	}
	return "0.0"
}

func GetOSVersion41Plus() string {
	// no idea about linux
	//uname := getUname()

	//if len(uname.Release) > 0 {
	//	return arrayToString(uname.Release)
	//}
	return "0.0.0"
}

// just assume 64bit linux only run 64bit app
func GetProcessArch(pid uint32) int {
	if IsOSX64() {
		return ProcessArch64
	} else {
		return ProcessArch86
	}
}

// just return 0
func GetProcessSessionId(pid int32) uint32 {
	return 0
}

func IsHighPriv() bool {
	fd, err := os.Open("/root")
	defer fd.Close()
	if err != nil {
		return false
	}
	return true
}

func IsOSX64() bool {
	uname := getUname()
	if arrayToString(uname.Machine) == "x86_64" {
		return true
	}
	return false
}

// seems use go arch to judge is a good idea
func IsProcessX64() bool {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || runtime.GOARCH == "arm64be" {
		return true
	}
	return false
}

// charset, refer https://xz.aliyun.com/t/11055
func GetCodePageANSI() []byte {
	// linux use default utf-8 codepage
	b := make([]byte, 2)
	ANSICodePage = 65001
	binary.LittleEndian.PutUint16(b, 65001)
	return b
}

func GetCodePageOEM() []byte {
	// linux use default utf-8 codepage
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, 65001)
	return b
}

func GetUsername() string {
	user, err := user.Current()
	if err != nil {
		return ""
	}
	usr := user.Username
	return usr
}
