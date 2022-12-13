package util

import (
	"math/rand"
)

func RandomInt(min, max int) int {
	return min + rand.Intn(max-min)
}

func RandomAESKey() {
	GlobalKey = make([]byte, 16)
	// read func actually write random bytes
	_, err := rand.Read(GlobalKey[:])
	if err != nil {
		panic(err)
	}
}
