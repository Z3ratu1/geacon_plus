package util

import (
	"fmt"
	"main/config"
)

func Print(a ...any) {
	if config.Debug {
		fmt.Print(a...)
	}
}

func Printf(format string, a ...any) {
	if config.Debug {
		fmt.Printf(format, a...)
	}
}

func Println(a ...any) {
	if config.Debug {
		fmt.Println(a...)
	}
}

func Errorf(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}

// seems no need to implement sprintf?
func Sprintf(format string, a ...any) string {
	return fmt.Sprintf(format, a...)
}
