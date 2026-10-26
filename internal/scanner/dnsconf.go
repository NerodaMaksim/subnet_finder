package scanner

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// dnsConfig records which unicast resolvers the system has, split by the
// interface they are scoped to. A VPN installs its own resolver as the
// unscoped default, which is why an unscoped PTR query for a LAN address stops
// working the moment the tunnel comes up: the query goes to the VPN's server,
// which knows nothing about the local network. Keeping the scoped servers lets
// us ask the resolver that actually serves the subnet being scanned.
type dnsConfig struct {
	byIndex map[int][]string
	global  []string
}

func loadDNSConfig() dnsConfig {
	cfg := dnsConfig{byIndex: make(map[int][]string)}
	if runtime.GOOS == "darwin" {
		cfg.loadSCUtil()
	}
	cfg.global = appendUnique(cfg.global, resolvConfServers()...)
	return cfg
}

// serversFor returns the resolvers to try for a target reached over l, most
// specific first.
func (c dnsConfig) serversFor(l *link) []string {
	var out []string
	if l != nil {
		out = appendUnique(out, c.byIndex[l.index]...)
	}
	return appendUnique(out, c.global...)
}

// loadSCUtil reads the per-interface resolver table from scutil, which is the
// only place macOS exposes it; /etc/resolv.conf is a legacy stub that lists a
// single unscoped server.
func (c *dnsConfig) loadSCUtil() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		log.Printf("scutil --dns: %v", err)
		return
	}
	c.parseSCUtil(bytes.NewReader(out))
}

func (c *dnsConfig) parseSCUtil(r io.Reader) {
	var (
		servers []string
		index   int
		mdns    bool
	)
	flush := func() {
		// mDNS pseudo-resolvers have no nameserver to talk to; they are handled
		// by lookupMDNS instead.
		if len(servers) > 0 && !mdns {
			if index > 0 {
				c.byIndex[index] = appendUnique(c.byIndex[index], servers...)
			} else {
				c.global = appendUnique(c.global, servers...)
			}
		}
		servers, index, mdns = nil, 0, false
	}

	scan := bufio.NewScanner(r)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		switch {
		case strings.HasPrefix(line, "resolver #"):
			flush()
		case strings.HasPrefix(line, "nameserver["):
			if _, value, ok := strings.Cut(line, ":"); ok {
				if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
					servers = append(servers, ip.String())
				}
			}
		case strings.HasPrefix(line, "if_index"):
			if _, value, ok := strings.Cut(line, ":"); ok {
				// "12 (en0)" - the index is the leading field.
				field := strings.Fields(strings.TrimSpace(value))
				if len(field) > 0 {
					if n, err := strconv.Atoi(field[0]); err == nil {
						index = n
					}
				}
			}
		case strings.HasPrefix(line, "options"):
			if strings.Contains(line, "mdns") {
				mdns = true
			}
		}
	}
	if err := scan.Err(); err != nil {
		log.Printf("parse scutil --dns: %v", err)
	}
	flush()
}

func resolvConfServers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("open resolv.conf: %v", err)
		}
		return nil
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("close resolv.conf: %v", err)
		}
	}()

	var servers []string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			servers = append(servers, ip.String())
		}
	}
	if err := scan.Err(); err != nil {
		log.Printf("parse resolv.conf: %v", err)
	}
	return servers
}

func appendUnique(dst []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}
