package command

/*
deploy command
*/
import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func ParseCommandShell(b []byte) (string, []byte, error) {
	buf := bytes.NewBuffer(b)
	path, err := ParseAnArg(buf)
	if err != nil {
		return "", nil, err
	}
	cmd, err := ParseAnArg(buf)
	if err != nil {
		return "", nil, err
	}
	envKey := strings.ReplaceAll(string(path), "%", "")
	app := os.Getenv(envKey)
	return app, cmd, nil
}

/*
	Shell this function should handler to function, `shell` and `run`

shell would send a payload like `%COMSPEC% /C cmd`, and run would send just `cmd`
%COMSPEC% point to cmd.exe usually, and we always read %COMSPEC% as app, follow as args
*/
func Shell(path string, args []byte) ([]byte, error) {
	args = bytes.Trim(args, " ")
	switch runtime.GOOS {
	case "windows":
		argsArray := strings.Split(string(args), " ")
		if len(path) == 0 {
			path = argsArray[0]
			argsArray = argsArray[1:]
		}
		cmd := exec.Command(path, argsArray...)
		// CombinedOutput return both stdout&stderr
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("exec failed with %s\n", err)
			return nil, err
		}
		return out, nil
	case "darwin":
		path = "/bin/bash"
	case "linux":
		path = "/bin/sh"
	default:
		panic("unsupported os: " + runtime.GOOS)
	}
	var argsArray []string
	// handler `run` command
	if len(path) == 0 {
		argsArray = strings.Split(string(args), " ")
		path = argsArray[0]
		argsArray = argsArray[1:]
	} else {
		startPos := bytes.Index(args, []byte("/C"))
		args = args[startPos+3:]
		argsArray = []string{"-c", string(args)}

	}
	cmd := exec.Command(path, argsArray...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("exec failed with %s\n", err)
		return nil, err
	}
	return out, nil

}

// exec has no echo(maybe)
func Exec(b []byte) error {
	switch runtime.GOOS {
	case "windows":
		app := os.Getenv("COMSPEC")
		cmd := exec.Command(app, "/C", string(b))
		err := cmd.Start()
		if err != nil {
			return err
		}
	case "linux":
		cmd := exec.Command("/bin/sh", "-c", string(b))
		err := cmd.Start()
		if err != nil {
			return err
		}
	case "darwin":
		cmd := exec.Command("/bin/bash", "-c", string(b))
		err := cmd.Start()
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported os " + runtime.GOOS)
	}
	return nil
}
