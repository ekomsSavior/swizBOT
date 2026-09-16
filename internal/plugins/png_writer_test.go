package plugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPNGWriterProducesValidFile(t *testing.T) {
	// 2x2 BGRA image: red, green, blue, white
	bgra := []byte{
		0, 0, 255, 255, 0, 255, 0, 255,
		255, 0, 0, 255, 255, 255, 255, 255,
	}
	path := filepath.Join(t.TempDir(), "test.png")
	if err := writeBGRAAsPNG(path, bgra, 2, 2); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// PNG magic + IHDR must be present
	if len(data) < 33 {
		t.Fatalf("png too small: %d", len(data))
	}
	if string(data[1:4]) != "PNG" {
		t.Fatal("missing PNG magic")
	}
	if string(data[12:16]) != "IHDR" {
		t.Fatal("missing IHDR")
	}
	if string(data[len(data)-8:len(data)-4]) != "IEND" {
		t.Fatal("missing IEND")
	}
}

func TestPNGWriterRejectsBadInput(t *testing.T) {
	if err := writeBGRAAsPNG(filepath.Join(t.TempDir(), "x.png"), []byte("short"), 4, 4); err == nil {
		t.Fatal("expected error for undersized buffer")
	}
}
