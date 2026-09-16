package channel

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	privHex, pubHex, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(privHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubHex)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte(`{"bot_id":"lab-1","output":"secret result"}`)
	sealed, err := Seal(pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("sealed payload leaks plaintext")
	}
	opened, err := Open(priv, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("round-trip mismatch")
	}
}

func TestTamperFails(t *testing.T) {
	_, pubHex, _ := GeneratePrivateKey()
	privHex, _, _ := GeneratePrivateKey() // different operator key
	priv, _ := ParsePrivateKey(privHex)
	pub, _ := ParsePublicKey(pubHex)

	sealed, err := Seal(pub, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// wrong operator key must not decrypt
	if _, err := Open(priv, sealed); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
	// flipped ciphertext bit must fail auth
	sealed[len(sealed)-1] ^= 0x01
	if _, err := Open(priv, sealed); err == nil {
		t.Fatal("tampered payload authenticated")
	}
}

func TestKeyParsingErrors(t *testing.T) {
	if _, err := ParsePrivateKey("zz"); err == nil {
		t.Fatal("expected hex error")
	}
	if _, err := ParsePrivateKey("aabb"); err == nil { // 2 bytes, not 32
		t.Fatal("expected length error")
	}
	if _, err := ParsePublicKey("aabb"); err == nil {
		t.Fatal("expected length error")
	}
	if _, _, err := GeneratePrivateKey(); err != nil {
		t.Fatal(err)
	}
}

func TestShortPayloadRejected(t *testing.T) {
	privHex, _, _ := GeneratePrivateKey()
	priv, _ := ParsePrivateKey(privHex)
	if _, err := Open(priv, []byte("tiny")); err == nil {
		t.Fatal("expected short-payload error")
	}
}

func TestForwardSecrecy(t *testing.T) {
	// every Seal must produce a different ephemeral key
	_, pubHex, _ := GeneratePrivateKey()
	pub, _ := ParsePublicKey(pubHex)
	a, _ := Seal(pub, []byte("x"))
	b, _ := Seal(pub, []byte("x"))
	if bytes.Equal(a[:PublicKeyLen], b[:PublicKeyLen]) {
		t.Fatal("ephemeral key reused - no forward secrecy")
	}
}
