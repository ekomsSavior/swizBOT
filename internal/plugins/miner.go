package plugins

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Miner runs an xmrig-compatible miner binary against a pool.
// The binary is supplied as a local path or an http(s) URL; it is
// never assumed to exist at a magic location.
type Miner struct {
	pool    string
	wallet  string
	threads int
	source  string // local path or http(s) URL

	path    string // resolved executable
	cmd     *exec.Cmd
	running bool
}

// NewMiner creates a miner job. source may be empty to look up
// "xmrig" (or "xmrig.exe" on Windows) on PATH.
func NewMiner(pool, wallet string, threads int, source string) *Miner {
	return &Miner{pool: pool, wallet: wallet, threads: threads, source: source}
}

// Resolve downloads (URL) or locates (path/PATH) the miner binary.
func (m *Miner) Resolve() error {
	if m.threads < 1 {
		m.threads = 1
	}
	if m.pool == "" || m.wallet == "" {
		return fmt.Errorf("pool and wallet are required")
	}

	src := m.source
	if src == "" {
		name := "xmrig"
		if runtime.GOOS == "windows" {
			name = "xmrig.exe"
		}
		p, err := exec.LookPath(name)
		if err != nil {
			return fmt.Errorf("no miner source given and %q not found on PATH", name)
		}
		m.path = p
		return nil
	}

	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		path, err := m.download(src)
		if err != nil {
			return err
		}
		m.path = path
		return nil
	}

	if fi, err := os.Stat(src); err != nil || fi.IsDir() {
		return fmt.Errorf("miner path %q is not a file", src)
	}
	m.path = src
	return nil
}

func (m *Miner) download(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "xmrig-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Chmod(0o700)
	return tmp.Name(), nil
}

// buildArgs returns the xmrig command line for the job.
func (m *Miner) buildArgs() []string {
	return []string{
		"-o", m.pool,
		"-u", m.wallet,
		"-t", fmt.Sprintf("%d", m.threads),
		"-k", // keepalive
	}
}

// Start launches the miner after Resolve has succeeded.
func (m *Miner) Start() error {
	if m.path == "" {
		return fmt.Errorf("call Resolve before Start")
	}
	if m.running {
		return fmt.Errorf("miner already running")
	}
	cmd := exec.Command(m.path, m.buildArgs()...)
	if err := cmd.Start(); err != nil {
		return err
	}
	m.cmd = cmd
	m.running = true
	// reap the process when it exits so no zombie remains
	go cmd.Wait()
	return nil
}

// Stop terminates the miner.
func (m *Miner) Stop() {
	if m.running && m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Kill()
		m.cmd.Wait()
		m.running = false
		os.Remove(filepath.Clean(m.path)) // remove downloaded copy
	}
}
