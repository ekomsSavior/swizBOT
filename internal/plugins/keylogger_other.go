//go:build !windows

package plugins

import "errors"

// Start is unavailable off Windows (GetAsyncKeyState polling).
func (k *Keylogger) Start() error {
	return errors.New("keylogger requires the Windows build")
}
