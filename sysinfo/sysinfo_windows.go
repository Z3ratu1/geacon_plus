package sysinfo

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

var (
	Kernel32   = windows.NewLazyDLL("Kernel32.dll")
	systemInfo = SystemInfo{}
)

type SystemInfo struct {
	ProcessorArchitecture     ProcessorArchitecture
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uint64
	NumberOfProcessors        uint32
	ProcessorType             ProcessorType
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type ProcessorArchitecture uint16

const (
	ProcessorArchitectureAMD64   ProcessorArchitecture = 9
	ProcessorArchitectureARM     ProcessorArchitecture = 5
	ProcessorArchitectureARM64   ProcessorArchitecture = 12
	ProcessorArchitectureIA64    ProcessorArchitecture = 6
	ProcessorArchitectureIntel   ProcessorArchitecture = 0
	ProcessorArchitectureUnknown ProcessorArchitecture = 0xFFFF
)

type ProcessorType uint32

const (
	ProcessorTypeIntel386     ProcessorType = 386
	ProcessorTypeIntel486     ProcessorType = 486
	ProcessorTypeIntelPentium ProcessorType = 586
	ProcessorTypeIntelIA64    ProcessorType = 2200
	ProcessorTypeAMDX8664     ProcessorType = 8664
)

// init system info here
func init() {
	fnGetNativeSystemInfo := Kernel32.NewProc("GetNativeSystemInfo")
	if fnGetNativeSystemInfo.Find() != nil {
		panic("not found GetNativeSystemInfo")
	}
	fnGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&systemInfo)))
}

func GetOSVersion() string {
	version, err := syscall.GetVersion()
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return ""
	}
	return fmt.Sprintf("%d.%d", byte(version), uint8(version>>8))
}

func GetOSVersion41Plus() string {
	version, err := syscall.GetVersion()
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return ""
	}
	return fmt.Sprintf("%d.%d.%d\n", byte(version), uint8(version>>8), version>>16)
}

func IsHighPriv() bool {
	token, err := syscall.OpenCurrentProcessToken()
	defer func(token syscall.Token) {
		err := token.Close()
		if err != nil {

		}
	}(token)
	if err != nil {
		fmt.Printf("open current process token failed: %v\n", err)
		return false
	}
	/*
		ref:
		C version https://vimalshekar.github.io/codesamples/Checking-If-Admin
		Go package https://github.com/golang/sys/blob/master/windows/security_windows.go ---> IsElevated
		maybe future will use ---> golang/x/sys/windows
	*/
	var isElevated uint32
	var outLen uint32
	err = syscall.GetTokenInformation(token, syscall.TokenElevation, (*byte)(unsafe.Pointer(&isElevated)), uint32(unsafe.Sizeof(isElevated)), &outLen)
	if err != nil {
		return false
	}
	return outLen == uint32(unsafe.Sizeof(isElevated)) && isElevated != 0
}

func IsOSX64() bool {
	switch systemInfo.ProcessorArchitecture {
	case ProcessorArchitectureAMD64:
		return true
	case ProcessorArchitectureARM64:
		return true
	default:
		return false
	}
}

func GetProcessArch(pid uint32) int {
	arch := ProcessArchUnknown
	// https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
	switch systemInfo.ProcessorArchitecture {
	// isWow64 can't work on arm64, but we still give it a try
	case ProcessorArchitectureARM64:
		fallthrough
	case ProcessorArchitectureAMD64:
		// 0x00100000 PROCESS_QUERY_LIMITED_INFORMATION,this privilege should be permitted in the most situation
		handler, _ := windows.OpenProcess(uint32(0x1000), false, pid)
		defer windows.CloseHandle(handler)
		var isWow64 bool
		_ = windows.IsWow64Process(handler, &isWow64)
		if isWow64 {
			arch = ProcessArch86
		} else {
			arch = ProcessArch64
		}
	default:
		arch = ProcessArch86

	}
	return arch
}

func GetProcessSessionId(pid int32) uint32 {
	var sessionId uint32
	err := windows.ProcessIdToSessionId(uint32(pid), &sessionId)
	if err != nil {
		sessionId = 0
	}
	return sessionId

}

func IsProcessX64() bool {
	switch systemInfo.ProcessorArchitecture {
	// isWow64 can't work on arm64, but we still give it a try
	case ProcessorArchitectureARM64:
		fallthrough
	case ProcessorArchitectureAMD64:
		// 0x00100000 PROCESS_QUERY_LIMITED_INFORMATION,this privilege should be permitted in the most situation
		var isWow64 bool
		hProcess, err := windows.GetCurrentProcess()
		defer windows.CloseHandle(hProcess)
		if err != nil {
			panic(err)
		}
		_ = windows.IsWow64Process(hProcess, &isWow64)
		if isWow64 {
			return false
		} else {
			return true
		}
	default:
		return false

	}
}

func GetUsername() string {
	username := make([]uint16, 128)
	usernameLen := uint32(len(username)) - 1
	err := windows.GetUserNameEx(windows.NameSamCompatible, &username[0], &usernameLen)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return ""
	}
	usernameStr := windows.UTF16ToString(username)
	// seems username be like computerName\username, so we split it here
	arr := strings.Split(usernameStr, "\\")
	usernameStr = arr[len(arr)-1]
	return usernameStr
}

// IMPORTANT!!! charset is very important in beacon and server's communication
// because go handle string as utf8, so all use utf8 should be a better choice?
// need to transfer encoding manually when get output from pipe
func GetCodePageANSI() []byte {
	fnGetACP := Kernel32.NewProc("GetACP")
	if fnGetACP.Find() != nil {
		fmt.Println("GetACP not found")
		return nil
	}
	acp, _, _ := fnGetACP.Call()
	fmt.Printf("ANSI CodePage %v\n", acp)
	ANSICodePage = uint32(acp)
	acpbytes := make([]byte, 2)
	//binary.LittleEndian.PutUint32(acpbytes, uint32(acp))
	binary.LittleEndian.PutUint16(acpbytes, 65001)
	return acpbytes

}

func GetCodePageOEM() []byte {
	fnGetOEMCP := Kernel32.NewProc("GetOEMCP")
	if fnGetOEMCP.Find() != nil {
		fmt.Println("GetOEMCP not found")
		return nil
	}
	// ignore OEM codepage(maybe will cause problem?)
	_, _, _ = fnGetOEMCP.Call()
	//fmt.Printf("OEM CodePage %v\n", acp)
	acpbytes := make([]byte, 4)
	//binary.LittleEndian.PutUint32(acpbytes, uint32(acp))
	binary.LittleEndian.PutUint32(acpbytes, 65001)
	return acpbytes[:2]
}
