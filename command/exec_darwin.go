package command

import (
	"errors"
	"os/exec"
	"strings"
)

func Exec(b []byte) error {
	cmd := exec.Command("/bin/bash", "-c", string(b))
	return cmd.Start()
}

// implement of run and shell cmd
func Run(path string, args string) ([]byte, error) {
	path = strings.Trim(path, " ")
	args = strings.Trim(args, " ")
	if path == "%COMSPEC%" && strings.HasPrefix(args, "/C") {
		args = args[3:]
		cmd := exec.Command("/bin/bash", "-c", args)
		return cmd.CombinedOutput()
	} else {
		// there shouldn't be a path in run cmd
		if len(path) != 0 {
			return nil, errors.New("get a path from run cmd")
		}
		parts := strings.Split(args, " ")
		var cmd *exec.Cmd
		if len(parts) > 1 {
			cmd = exec.Command(parts[0], parts[1:]...)
		} else {
			cmd = exec.Command(parts[0])
		}
		return cmd.CombinedOutput()
	}
}
