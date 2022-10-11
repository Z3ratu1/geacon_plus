package command

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

var (
	advapi32                = windows.NewLazyDLL("Advapi32.dll")
	createProcessWithLogonW = advapi32.NewProc("CreateProcessWithLogonW")
	adjustTokenPrivileges   = advapi32.NewProc("AdjustTokenPrivileges")
	logonUserA              = advapi32.NewProc("LogonUserA")
)

// TODO verify validity
func RunAs(domain []byte, username []byte, password []byte, cmd []byte) error {
	lpUsername := windows.StringToUTF16Ptr(string(username))
	lpDomain := windows.StringToUTF16Ptr(string(domain))
	lpPassword := windows.StringToUTF16Ptr(string(password))
	lpCommandLine := windows.StringToUTF16Ptr(string(cmd))
	startUpInfo := &windows.StartupInfo{}
	procInfo := &windows.ProcessInformation{}
	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
	// may I need to wait for it? I guess not, but maybe I should collect its output
	_, _, err := createProcessWithLogonW.Call(uintptr(unsafe.Pointer(lpUsername)), uintptr(unsafe.Pointer(lpDomain)), uintptr(unsafe.Pointer(lpPassword)), 2, 0, uintptr(unsafe.Pointer(lpCommandLine)), 0x04000000, 0, uintptr(unsafe.Pointer(startUpInfo)), uintptr(unsafe.Pointer(procInfo)))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return err
	}
	return nil
}

func GetPrivs(privs []string) (string, error) {
	result := ""
	// it always returns a invalidHandler?
	p := windows.CurrentProcess()
	var token windows.Token
	err := windows.OpenProcessToken(p, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return result, err
	}
	LUIDs := make([]windows.LUID, len(privs))
	for i, priv := range privs {
		_ = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(priv), &LUIDs[i])
	}

	// use struct can only add one privilege, so just do some black magic
	//var b bytes.Buffer
	//_ = binary.Write(&b, binary.LittleEndian, uint32(len(privs)))
	//for _, p := range privs {
	//	_ = binary.Write(&b, binary.LittleEndian, p)
	//	_ = binary.Write(&b, binary.LittleEndian, windows.SE_PRIVILEGE_ENABLED)
	//}

	// but I need to know which privilege had set, so set one each time

	for i, LUID := range LUIDs {
		var tokenPrivileges windows.Tokenprivileges
		tokenPrivileges.PrivilegeCount = 1
		tokenPrivileges.Privileges[0] = windows.LUIDAndAttributes{
			Luid:       LUID,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}
		_, _, err := adjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tokenPrivileges)), 0, 0, 0)
		if err != nil {
			if err == windows.ERROR_NOT_ALL_ASSIGNED {
				continue
			} else if err == windows.SEVERITY_SUCCESS {
				result += fmt.Sprintf("%s\n", privs[i])
			} else {
				return result, err
			}
		}
	}
	return result, nil
}

func MakeToken(domain []byte, username []byte, password []byte) error {
	var token windows.Token
	lpUsername := windows.StringToUTF16Ptr(string(username))
	lpDomain := windows.StringToUTF16Ptr(string(domain))
	lpPassword := windows.StringToUTF16Ptr(string(password))
	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera
	// LOGON32_LOGON_NEW_CREDENTIALS = 9
	// LOGON32_PROVIDER_DEFAULT = 0
	logonUserA.Call(uintptr(unsafe.Pointer(lpUsername)), uintptr(unsafe.Pointer(lpDomain)), uintptr(unsafe.Pointer(lpPassword)), 9, 0, uintptr(unsafe.Pointer(&token)))
	return nil
}
