//go:build !windows

package plugins

import "errors"

// CaptureScreen is unavailable off Windows.
func CaptureScreen() ([]byte, int, int, error) {
	return nil, 0, 0, errors.New("screenshot requires the Windows build")
}
