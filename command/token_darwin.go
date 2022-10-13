package command

import (
	"errors"
	"runtime"
)

func RunAs(domain []byte, username []byte, password []byte, cmd []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func GetPrivs(privs []string) (string, error) {
	return "", errors.New("unsupported for " + runtime.GOOS)
}

func Rev2self() error {
	return "", errors.New("unsupported for " + runtime.GOOS)
}

func MakeToken(domain []byte, username []byte, password []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}
