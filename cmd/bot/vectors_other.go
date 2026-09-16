//go:build !windows

package main

// USB and network-share vectors are Windows-only (drive letters,
// net.exe, attrib, WScript.Shell shortcuts). No-ops elsewhere.
func (w *Worm) infectRemovableDrives() {}
func (w *Worm) sharesOnce()            {}
