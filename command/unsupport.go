//go:build linux || darwin

package command

import (
	"errors"
	"runtime"
)

// put unsupported func in linux and darwin here

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

func ExecAsm(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}

func PowershellImport(b []byte) {

}
func WebDelivery(b []byte) {

}
