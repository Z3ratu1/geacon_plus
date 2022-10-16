package command

import (
	"errors"
	"runtime"
)

func InjectDll(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func SpawnAndInjectDllX64(dll []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func SpawnAndInjectDllX86(dll []byte) error {
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
