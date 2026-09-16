package plugins

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	gdi32                      = syscall.NewLazyDLL("gdi32.dll")
	user32Shot                 = syscall.NewLazyDLL("user32.dll")
	procGetDC                  = user32Shot.NewProc("GetDC")
	procReleaseDC              = user32Shot.NewProc("ReleaseDC")
	procGetSystemMetrics       = user32Shot.NewProc("GetSystemMetrics")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
)

const (
	srcCopy      = 0x00CC0020
	smCxscreen   = 0
	smCyscreen   = 1
	biRgb        = 0
	dibRgbColors = 0
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// CaptureScreen returns raw BGRA pixels, width and height of the
// primary display. The caller converts to a file format.
func CaptureScreen() ([]byte, int, int, error) {
	width, _, _ := procGetSystemMetrics.Call(smCxscreen)
	height, _, _ := procGetSystemMetrics.Call(smCyscreen)
	if width == 0 || height == 0 {
		return nil, 0, 0, fmt.Errorf("GetSystemMetrics failed")
	}
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return nil, 0, 0, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, hdc)

	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)

	// build a DIB section so GetDIBits can read pixels directly
	bmi := bitmapInfoHeader{
		BiSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		BiWidth:       int32(width),
		BiHeight:      -int32(height), // negative = top-down rows
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: biRgb,
	}
	var bits unsafe.Pointer
	hbmp, _, _ := procCreateDIBSection.Call(hdc,
		uintptr(unsafe.Pointer(&bmi)), dibRgbColors,
		uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hbmp == 0 {
		return nil, 0, 0, fmt.Errorf("CreateDIBSection failed")
	}
	defer procDeleteObject.Call(hbmp)
	procSelectObject.Call(memDC, hbmp)

	// copy the screen into the DIB
	if r, _, _ := procBitBlt.Call(memDC, 0, 0, width, height, hdc, 0, 0, srcCopy); r == 0 {
		return nil, 0, 0, fmt.Errorf("BitBlt failed")
	}

	// read the pixel bits (GetDIBits into the same DIB section)
	if r, _, _ := procGetDIBits.Call(hdc, hbmp, 0, uintptr(height),
		uintptr(bits), uintptr(unsafe.Pointer(&bmi)), dibRgbColors); r == 0 {
		return nil, 0, 0, fmt.Errorf("GetDIBits failed")
	}

	rowSize := int(width) * 4
	buf := make([]byte, rowSize*int(height))
	src := unsafe.Slice((*byte)(bits), len(buf))
	copy(buf, src)

	// DIB is BGRA; PNG encoders expect RGB order. Return BGRA plus a
	// flag so the writer can convert.
	return buf, int(width), int(height), nil
}
