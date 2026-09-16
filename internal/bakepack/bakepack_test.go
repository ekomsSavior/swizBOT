package bakepack

import (
	"errors"
	"strings"
	"testing"
)

var canaries = map[string]string{
	"c2_urls":    "https://c2.canary.example:8443",
	"bot_secret": "SUPER-SECRET-CANARY-TOKEN",
	"bot_key":    "1111111111111111111111111111111111111111111111111111111111111111",
	"interval":   "45s",
	"bot_id":     "canary-host",
}

func TestObfuscatedRoundTrip(t *testing.T) {
	token, err := Pack(canaries, "")
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if IsSealed(token) {
		t.Fatal("empty passphrase must produce an obfuscated token")
	}
	got, err := Unpack(token, "")
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	for k, v := range canaries {
		if got[k] != v {
			t.Fatalf("roundtrip %q: got %q want %q", k, got[k], v)
		}
	}
}

func TestSealedRoundTrip(t *testing.T) {
	const pass = "correct horse battery staple"
	token, err := Pack(canaries, pass)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if !IsSealed(token) {
		t.Fatal("passphrase must produce a sealed token")
	}
	got, err := Unpack(token, pass)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	for k, v := range canaries {
		if got[k] != v {
			t.Fatalf("roundtrip %q: got %q want %q", k, got[k], v)
		}
	}
}

func TestSealedRequiresPassphrase(t *testing.T) {
	token, err := Pack(canaries, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(token, ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("want ErrPassphraseRequired, got %v", err)
	}
}

func TestSealedWrongPassphrase(t *testing.T) {
	token, err := Pack(canaries, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(token, "hunter3"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
}

// TestNoPlaintextLeaks is the core regression guard: no canary value (or
// recognizable substring of it) may appear verbatim in either token form.
func TestNoPlaintextLeaks(t *testing.T) {
	leaks := []string{
		"CANARY", "canary.example", "SUPER-SECRET", "canary-host",
		"1111111111111111", "bot_secret", "op_pubkey", "c2_urls",
	}
	for _, pass := range []string{"", "hunter2"} {
		token, err := Pack(canaries, pass)
		if err != nil {
			t.Fatalf("pack(pass=%q): %v", pass, err)
		}
		for _, leak := range leaks {
			if strings.Contains(token, leak) {
				t.Fatalf("token (pass=%q) leaks plaintext %q: %s", pass, leak, token)
			}
		}
	}
}

func TestTamperRejected(t *testing.T) {
	token, err := Pack(canaries, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	// flip a byte inside the base64 body (after the tag) and expect auth fail
	body := []byte(token)
	idx := len(body) - 3
	if body[idx] == 'A' {
		body[idx] = 'B'
	} else {
		body[idx] = 'A'
	}
	if _, err := Unpack(string(body), "hunter2"); err == nil {
		t.Fatal("tampered sealed token must not authenticate")
	}
}

func TestUnrecognizedToken(t *testing.T) {
	if _, err := Unpack("zz.deadbeef", ""); err == nil {
		t.Fatal("unrecognized token must error")
	}
}

func TestEmptyPack(t *testing.T) {
	if _, err := Pack(map[string]string{"a": "", "b": ""}, ""); err == nil {
		t.Fatal("packing only empty values must error")
	}
	if _, err := Pack(nil, ""); err == nil {
		t.Fatal("packing nil must error")
	}
}
