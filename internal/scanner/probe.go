package scanner

import (
	"context"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

var commonPorts = []int{22, 80, 443, 445, 3389, 8080, 548, 5900}

const tcpWait = 350 * time.Millisecond

type probeResult struct {
	pingOK bool
	ports  []int
}

func pingArgs(ip string) []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"-n", "1", "-w", "400", ip}
	case "darwin":
		return []string{"-c", "1", "-W", "400", "-t", "1", ip}
	default:
		return []string{"-c", "1", "-W", "1", ip}
	}
}

func pingHost(ctx context.Context, ip string) bool {
	cmd := exec.CommandContext(ctx, "ping", pingArgs(ip)...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return false
		}
		return false
	}
	return true
}

func probeTCP(ctx context.Context, ip string) []int {
	var (
		mu    sync.Mutex
		ports []int
		wg    sync.WaitGroup
	)

	for _, port := range commonPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			dialer := net.Dialer{Timeout: tcpWait}
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				log.Printf("close %s: %v", addr, err)
			}
			mu.Lock()
			ports = append(ports, port)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	sort.Ints(ports)
	return ports
}

func probeHost(ctx context.Context, ip string) probeResult {
	var (
		wg     sync.WaitGroup
		pingOK bool
		ports  []int
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		pingOK = pingHost(ctx, ip)
	}()
	go func() {
		defer wg.Done()
		ports = probeTCP(ctx, ip)
	}()
	wg.Wait()

	return probeResult{pingOK: pingOK, ports: ports}
}

func detectionMethod(pingOK bool, ports []int) string {
	hasTCP := len(ports) > 0
	switch {
	case pingOK && hasTCP:
		return "both"
	case pingOK:
		return "ping"
	default:
		return "tcp"
	}
}
