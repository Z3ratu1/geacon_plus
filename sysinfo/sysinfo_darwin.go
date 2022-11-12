package sysinfo

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"os/user"
	"runtime"
)

func GetOSVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	out, _ := cmd.CombinedOutput()
	return string(out[:])
}

func GetOSVersion41Plus() string {
	// no idea about darwin

	return "0.0.0"
}

func IsHighPriv() bool {
	fd, err := os.Open("/root")
	defer fd.Close()
	if err != nil {
		return false
	}
	return false
}

func IsOSX64() bool {
	cmd := exec.Command("sysctl", "hw.cpu64bit_capable")
	out, _ := cmd.CombinedOutput()
	out = bytes.ReplaceAll(out, []byte("hw.cpu64bit_capable: "), []byte(""))
	if string(out) == "1" {
		return true
	}
	return false
}

func IsProcessX64() bool {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || runtime.GOARCH == "arm64be" {
		return true
	}
	return false
}

// simply assume 64bit mac only run 64bit app
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

func GetCodePageANSI() []byte {
	// darwin use default utf8? I guess
	b := make([]byte, 2)
	ANSICodePage = 65001
	binary.LittleEndian.PutUint16(b, 65001)
	return b
}

func GetCodePageOEM() []byte {
	//darwin use default utf8? I guess
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
