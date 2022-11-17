//go:build linux || darwin

package command

import (
	"errors"
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

func listDrivesInner(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}
func TimeStompInner(b []byte) error {
	return errors.New("unsupported for " + runtime.GOOS)
}
