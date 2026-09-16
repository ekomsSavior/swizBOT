package plugins

import (
	"fmt"
	"os"
	"path/filepath"
)

// Screenshot captures the primary display and writes a PNG.
// CaptureScreen is platform-specific (GDI on Windows, error elsewhere).
type Screenshot struct{}

// SavePNG captures the screen and writes it to path.
func (s *Screenshot) SavePNG(path string) error {
	bgra, w, h, err := CaptureScreen()
	if err != nil {
		return err
	}
	return writeBGRAAsPNG(path, bgra, w, h)
}

// Path returns a screenshot file path under the OS temp dir.
func (s *Screenshot) Path() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("swiz_shot_%d.png", os.Getpid()))
}
