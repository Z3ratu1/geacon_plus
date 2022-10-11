package command

import (
	"errors"
	"golang.org/x/sys/windows"
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
func Run(path string, args string) ([]byte, error) {
	return RunNative(path, args)
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
	return ExecNative(b)
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
func RunNative(path string, args string) ([]byte, error) {
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
		return nil, err
	}

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
	err = windows.CreateProcess(pathPtr, windows.StringToUTF16Ptr(args), nil, nil, true, 0, nil, nil, &sI, &pI)

	if err != nil {
		return nil, err
	}

	_, _ = windows.WaitForSingleObject(pI.Process, windows.INFINITE)
	_, _ = windows.WaitForSingleObject(pI.Thread, windows.INFINITE)

	buf := make([]byte, 10*8192+1)
	//var done uint32 = 4096
	var read windows.Overlapped
	_ = windows.ReadFile(hRPipe, buf, nil, &read)

	//fmt.Printf("buf:%s\n", buf[:read.InternalHigh])

	err = windows.CloseHandle(pI.Process)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(pI.Thread)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(hWPipe)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(hRPipe)
	if err != nil {
		return nil, err
	}

	return buf[:read.InternalHigh], nil
}

func ExecNative(b []byte) error {
	var sI windows.StartupInfo
	var pI windows.ProcessInformation

	program, _ := windows.UTF16PtrFromString(string(b))
	// when appName set to null, will use the first part of commandLine as the app, and rest as args
	return windows.CreateProcess(nil, program, nil, nil, true, 0, nil, nil, &sI, &pI)
}
