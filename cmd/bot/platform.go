package main

import (
	"math/rand"
	"runtime"
	"time"
)

func isWindows() bool { return runtime.GOOS == "windows" }

func goosName() string   { return runtime.GOOS }
func goarchName() string { return runtime.GOARCH }

func newRand() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}
