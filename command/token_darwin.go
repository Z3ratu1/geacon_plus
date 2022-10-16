package command

import (
	"errors"
	"runtime"
)

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
