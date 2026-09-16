package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCachePreservesPlaintext guards a regression: in XOR (legacy) mode the
// result body must be cached as plaintext JSON so FlushCache can unmarshal
// and re-send it. An in-place XOR mask previously corrupted the cache and
// FlushCache silently deleted the un-parseable file, losing the result.
func TestCachePreservesPlaintext(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	cfg := LoadConfig()
	cfg.C2URLs = []string{"https://127.0.0.1:9"} // nothing listening -> cache path
	cfg.BotSecret = ""
	cfg.XOR = 0x42
	c := NewC2Client(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp := Response{BotID: "cachebot", CommandID: "c1", Output: "hello-cache", Status: "success"}
	if err := c.SendResult(ctx, resp); err == nil {
		t.Fatal("expected a cache-fallback error with a dead endpoint")
	}

	entries, err := os.ReadDir(c.cacheDir())
	if err != nil || len(entries) == 0 {
		t.Fatalf("no cache file written: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(c.cacheDir(), entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var got Response
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("cached body is not plaintext JSON (regression): %v; raw=%q", err, data)
	}
	if got.Output != "hello-cache" || got.CommandID != "c1" {
		t.Fatalf("cached body wrong: %+v", got)
	}
}
