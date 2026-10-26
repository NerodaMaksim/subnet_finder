package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

const (
	// hostnameWait bounds a whole lookup, not a single query; the three
	// sources run concurrently.
	hostnameWait    = 1200 * time.Millisecond
	hostnameTTL     = 5 * time.Minute
	hostnameMissTTL = 1 * time.Minute
	// Retransmit intervals: both queries ride on unreliable UDP, and a
	// multicast reply in particular is easily lost on a busy network.
	mdnsRetry    = 350 * time.Millisecond
	netbiosRetry = 400 * time.Millisecond
)

// Hostname sources, listed best first. mDNS wins because the answer comes from
// the device itself: it stays correct when two machines claim the same name
// (Bonjour renames the duplicate) and when a VPN takes over unicast DNS.
const (
	sourceMDNS    = "mdns"
	sourceDNS     = "dns"
	sourceNetBIOS = "netbios"
)

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

func sourceRank(source string) int {
	switch source {
	case sourceMDNS:
		return 0
	case sourceDNS:
		return 1
	case sourceNetBIOS:
		return 2
	default:
		return 3
	}
}

type hostname struct {
	name   string
	source string
}

type hostnameResolver struct {
	dns   dnsConfig
	links []link
}

// newHostnameResolver snapshots the resolver and interface tables, which
// change when a tunnel goes up or down.
func newHostnameResolver() *hostnameResolver {
	return &hostnameResolver{dns: loadDNSConfig(), links: loadLinks()}
}

func (r *hostnameResolver) lookup(ctx context.Context, ip string) hostname {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil {
		return hostname{}
	}
	if cached, ok := loadCachedHostname(ip); ok {
		return cached
	}

	ctx, cancel := context.WithTimeout(ctx, hostnameWait)
	defer cancel()

	addr = addr.To4()
	l := linkFor(r.links, addr)

	var (
		mu   sync.Mutex
		best hostname
		wg   sync.WaitGroup
	)
	try := func(source string, fn func() string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := strings.TrimSpace(fn())
			if name == "" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if best.source == "" || sourceRank(source) < sourceRank(best.source) {
				best = hostname{name: name, source: source}
			}
		}()
	}

	try(sourceMDNS, func() string { return lookupMDNS(ctx, addr, l) })
	try(sourceDNS, func() string { return r.lookupPTR(ctx, addr, l) })
	try(sourceNetBIOS, func() string { return lookupNetBIOS(ctx, addr, l) })
	wg.Wait()

	// A cancelled scan means "unknown", not "no name" - don't poison the cache.
	if ctx.Err() == nil || best.name != "" {
		storeCachedHostname(ip, best)
	}
	return best
}

// lookupMDNS sends a reverse PTR query to the multicast group. macOS only
// routes .local and link-local reverse zones to mDNS, so a PTR for a private
// LAN address never reaches Bonjour through the system resolver; asking the
// group directly is what makes the device answer for itself.
func lookupMDNS(ctx context.Context, ip net.IP, l *link) string {
	arpa, err := reverseARPA(ip)
	if err != nil {
		return ""
	}
	query, err := ptrQuery(arpa)
	if err != nil {
		log.Printf("build mdns query for %s: %v", ip, err)
		return ""
	}

	// Binding an ephemeral source port marks this a one-shot query, so the
	// responder replies unicast straight back to us.
	local := &net.UDPAddr{}
	if l != nil {
		local.IP = l.local
	}
	conn, err := net.ListenUDP("udp4", local)
	if err != nil {
		return ""
	}
	defer closeConn(conn, "mdns")

	if l != nil && l.iface != nil {
		if err := ipv4.NewPacketConn(conn).SetMulticastInterface(l.iface); err != nil {
			log.Printf("mdns multicast interface %s: %v", l.name, err)
		}
	}
	buf := make([]byte, 1500)
	return udpRetry(ctx, mdnsRetry, conn.SetReadDeadline,
		func() error {
			_, err := conn.WriteToUDP(query, mdnsGroup)
			return err
		},
		func() (string, error) {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return "", err
			}
			return parsePTRAnswer(buf[:n], arpa), nil
		})
}

// udpRetry drives one unreliable UDP query: it retransmits every retry
// interval and keeps reading until recv yields a name or the context deadline
// passes. Replies that do not match are ignored rather than ending the wait.
func udpRetry(ctx context.Context, retry time.Duration, setReadDeadline func(time.Time) error, send func() error, recv func() (string, error)) string {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(hostnameWait)
	}

	for next := time.Now(); ; {
		now := time.Now()
		if !now.Before(deadline) {
			return ""
		}
		if !now.Before(next) {
			if err := send(); err != nil {
				return ""
			}
			next = now.Add(retry)
		}

		until := next
		if deadline.Before(until) {
			until = deadline
		}
		if err := setReadDeadline(until); err != nil {
			return ""
		}

		name, err := recv()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return ""
		}
		if name != "" {
			return name
		}
	}
}

// lookupPTR asks the resolvers scoped to the interface serving the target
// rather than the system default, which a VPN will have replaced.
func (r *hostnameResolver) lookupPTR(ctx context.Context, ip net.IP, l *link) string {
	target := ip.String()
	for _, server := range r.dns.serversFor(l) {
		if ctx.Err() != nil {
			return ""
		}
		names, err := scopedResolver(server, l).LookupAddr(ctx, target)
		if err != nil || len(names) == 0 {
			continue
		}
		if name := trimDot(names[0]); name != "" {
			return name
		}
	}
	return ""
}

// scopedResolver talks to one specific server, sourced from the local address
// of the interface the target sits on. PreferGo is required for Dial to be
// honoured; the cgo resolver ignores it and re-applies the system config.
func scopedResolver(server string, l *link) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			serverIP := net.ParseIP(server)
			if serverIP == nil {
				return nil, fmt.Errorf("invalid dns server: %s", server)
			}

			var dialer net.Dialer
			// Only bind a source address when the families match, otherwise
			// the dial fails outright.
			if l != nil && serverIP.To4() != nil {
				if strings.HasPrefix(network, "tcp") {
					dialer.LocalAddr = &net.TCPAddr{IP: l.local}
				} else {
					dialer.LocalAddr = &net.UDPAddr{IP: l.local}
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
}

func ptrQuery(arpa string) ([]byte, error) {
	name, err := dnsmessage.NewName(arpa)
	if err != nil {
		return nil, err
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func parsePTRAnswer(msg []byte, arpa string) string {
	var parser dnsmessage.Parser
	if _, err := parser.Start(msg); err != nil {
		return ""
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return ""
	}

	for {
		header, err := parser.AnswerHeader()
		if err != nil {
			return ""
		}
		if header.Type != dnsmessage.TypePTR || !strings.EqualFold(header.Name.String(), arpa) {
			if err := parser.SkipAnswer(); err != nil {
				return ""
			}
			continue
		}
		record, err := parser.PTRResource()
		if err != nil {
			return ""
		}
		return trimDot(record.PTR.String())
	}
}

func reverseARPA(ip net.IP) (string, error) {
	v4 := ip.To4()
	if v4 == nil {
		return "", fmt.Errorf("not ipv4: %s", ip)
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0]), nil
}

// dialUDP opens a connected socket sourced from the interface the target is
// reachable over, so replies come back on the expected path.
func dialUDP(ctx context.Context, l *link, remote *net.UDPAddr) (*net.UDPConn, error) {
	var dialer net.Dialer
	if l != nil {
		dialer.LocalAddr = &net.UDPAddr{IP: l.local}
	}

	conn, err := dialer.DialContext(ctx, "udp4", remote.String())
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		closeConn(conn, "udp")
		return nil, fmt.Errorf("unexpected conn type %T", conn)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := udp.SetDeadline(deadline); err != nil {
			closeConn(udp, "udp")
			return nil, err
		}
	}
	return udp, nil
}

func closeConn(conn net.Conn, what string) {
	if err := conn.Close(); err != nil {
		log.Printf("close %s socket: %v", what, err)
	}
}

func trimDot(name string) string {
	return strings.TrimSuffix(name, ".")
}
