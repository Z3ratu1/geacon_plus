package command

import (
	"errors"
	"runtime"
)

func InjectDllSelfX86(dll []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func InjectDllSelfX64(dll []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func SpawnAndInjectDllX64(dll []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func SpawnAndInjectDllX86(dll []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func HandlerJob(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}
