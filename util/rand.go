package util

import (
	"main/config"
	"math/rand"
)

func RandomInt(min, max int) int {
	return min + rand.Intn(max-min)
}

func RandomAESKey() {
	config.GlobalKey = make([]byte, 16)
	// read func actually write random bytes
	_, err := rand.Read(config.GlobalKey[:])
	if err != nil {
		panic(err)
	}
}
