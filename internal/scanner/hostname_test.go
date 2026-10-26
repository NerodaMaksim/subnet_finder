package scanner

import (
	"encoding/binary"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseSCUtilSplitsScopedResolvers(t *testing.T) {
	// Trimmed from real `scutil --dns` output with a tunnel up: the VPN owns
	// the unscoped resolver while the LAN server survives scoped to en0.
	const out = `DNS configuration

resolver #1
  nameserver[0] : 100.100.100.100
  flags    : Request A records
  reach    : 0x00020002 (Reachable)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.2.1
  nameserver[1] : 192.168.2.2
  if_index : 12 (en0)
  flags    : Scoped, Request A records
`

	cfg := dnsConfig{byIndex: make(map[int][]string)}
	cfg.parseSCUtil(strings.NewReader(out))

	if want := []string{"100.100.100.100"}; !reflect.DeepEqual(cfg.global, want) {
		t.Errorf("global = %v, want %v", cfg.global, want)
	}
	if want := []string{"192.168.2.1", "192.168.2.2"}; !reflect.DeepEqual(cfg.byIndex[12], want) {
		t.Errorf("byIndex[12] = %v, want %v", cfg.byIndex[12], want)
	}
	// The mdns pseudo-resolver has no server to talk to.
	if len(cfg.byIndex) != 1 {
		t.Errorf("byIndex = %v, want only en0", cfg.byIndex)
	}
}

func TestServersForPrefersScoped(t *testing.T) {
	cfg := dnsConfig{
		byIndex: map[int][]string{12: {"192.168.2.1"}},
		global:  []string{"100.100.100.100", "192.168.2.1"},
	}

	got := cfg.serversFor(&link{index: 12})
	want := []string{"192.168.2.1", "100.100.100.100"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("serversFor(en0) = %v, want %v", got, want)
	}
	if got := cfg.serversFor(nil); !reflect.DeepEqual(got, cfg.global) {
		t.Errorf("serversFor(nil) = %v, want %v", got, cfg.global)
	}
}

func TestLinkForPrefersMostSpecific(t *testing.T) {
	links := []link{
		{name: "en0", network: cidr(t, "192.168.0.0/16")},
		{name: "en9", network: cidr(t, "192.168.10.0/24")},
		{name: "utun0", network: cidr(t, "100.64.0.0/10")},
	}

	for _, tc := range []struct{ ip, want string }{
		{"192.168.10.5", "en9"},
		{"192.168.2.5", "en0"},
		{"100.101.45.2", "utun0"},
		{"8.8.8.8", ""},
	} {
		got := ""
		if l := linkFor(links, net.ParseIP(tc.ip)); l != nil {
			got = l.name
		}
		if got != tc.want {
			t.Errorf("linkFor(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestReverseARPA(t *testing.T) {
	got, err := reverseARPA(net.ParseIP("192.168.2.59"))
	if err != nil {
		t.Fatalf("reverseARPA: %v", err)
	}
	if want := "59.2.168.192.in-addr.arpa."; got != want {
		t.Errorf("reverseARPA = %q, want %q", got, want)
	}
	if _, err := reverseARPA(net.ParseIP("2001:db8::1")); err == nil {
		t.Error("reverseARPA(ipv6) = nil error, want error")
	}
}

func TestParsePTRAnswerMatchesQuestion(t *testing.T) {
	const arpa = "125.2.168.192.in-addr.arpa."
	msg := ptrResponse(t, arpa, "workshop-pi.local.")

	if got := parsePTRAnswer(msg, arpa); got != "workshop-pi.local" {
		t.Errorf("parsePTRAnswer = %q, want %q", got, "workshop-pi.local")
	}
	// A reply for a different address must not be adopted; on a shared
	// multicast group other hosts' answers do arrive.
	if got := parsePTRAnswer(msg, "1.2.168.192.in-addr.arpa."); got != "" {
		t.Errorf("parsePTRAnswer(mismatched) = %q, want %q", got, "")
	}
	if got := parsePTRAnswer([]byte{0x00, 0x01}, arpa); got != "" {
		t.Errorf("parsePTRAnswer(truncated) = %q, want %q", got, "")
	}
}

func TestEncodeNetBIOSName(t *testing.T) {
	// "*" padded with NULs: 0x2a -> "CK", each 0x00 -> "AA".
	want := "CK" + strings.Repeat("AA", 15)
	if got := string(encodeNetBIOSName("*")); got != want {
		t.Errorf("encodeNetBIOSName = %q, want %q", got, want)
	}
}

func TestParseNetBIOSStatusSkipsGroupNames(t *testing.T) {
	msg := netbiosResponse(t, []netbiosEntry{
		{name: "DESKTOP-A1B2C3D", suffix: 0x20},                    // file service
		{name: "WORKGROUP", suffix: 0x00, flags: netbiosGroupFlag}, // workgroup
		{name: "DESKTOP-A1B2C3D", suffix: 0x00},                    // machine name
	})

	if got := parseNetBIOSStatus(msg); got != "DESKTOP-A1B2C3D" {
		t.Errorf("parseNetBIOSStatus = %q, want %q", got, "DESKTOP-A1B2C3D")
	}

	onlyGroup := netbiosResponse(t, []netbiosEntry{
		{name: "WORKGROUP", suffix: 0x00, flags: netbiosGroupFlag},
	})
	if got := parseNetBIOSStatus(onlyGroup); got != "" {
		t.Errorf("parseNetBIOSStatus(group only) = %q, want %q", got, "")
	}

	// A truncated name table must not read past the buffer.
	if got := parseNetBIOSStatus(msg[:len(msg)-4]); got != "" {
		t.Errorf("parseNetBIOSStatus(truncated) = %q, want %q", got, "")
	}
}

func TestHostnameCacheExpiry(t *testing.T) {
	t.Cleanup(func() {
		hostnameCacheMu.Lock()
		defer hostnameCacheMu.Unlock()
		hostnameCache = make(map[string]cachedHostname)
	})

	storeCachedHostname("10.0.0.1", hostname{name: "pi", source: sourceMDNS})
	got, ok := loadCachedHostname("10.0.0.1")
	if !ok || got.name != "pi" || got.source != sourceMDNS {
		t.Errorf("loadCachedHostname = %+v, %v, want pi/mdns cached", got, ok)
	}
	if _, ok := loadCachedHostname("10.0.0.2"); ok {
		t.Error("loadCachedHostname(unknown) = cached, want miss")
	}

	// A miss expires sooner than a hit, so a host that was merely quiet gets
	// re-asked on the next scan.
	hostnameCacheMu.Lock()
	hostnameCache["10.0.0.3"] = cachedHostname{expires: time.Now().Add(-time.Second)}
	hostnameCacheMu.Unlock()
	if _, ok := loadCachedHostname("10.0.0.3"); ok {
		t.Error("loadCachedHostname(expired) = cached, want miss")
	}
}

func TestSourceRankPrefersDeviceAnswers(t *testing.T) {
	if sourceRank(sourceMDNS) >= sourceRank(sourceDNS) {
		t.Error("mdns must outrank unicast dns")
	}
	if sourceRank(sourceDNS) >= sourceRank(sourceNetBIOS) {
		t.Error("unicast dns must outrank netbios")
	}
	if sourceRank("") <= sourceRank(sourceNetBIOS) {
		t.Error("unknown source must rank last")
	}
}

func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse cidr %s: %v", s, err)
	}
	return n
}

// ptrResponse builds a DNS reply carrying a single PTR record, the shape an
// mDNS responder sends back to a one-shot query.
func ptrResponse(t *testing.T, arpa, target string) []byte {
	t.Helper()

	name, err := dnsmessage.NewName(arpa)
	if err != nil {
		t.Fatalf("name %s: %v", arpa, err)
	}
	ptr, err := dnsmessage.NewName(target)
	if err != nil {
		t.Fatalf("name %s: %v", target, err)
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	if err := builder.StartAnswers(); err != nil {
		t.Fatalf("start answers: %v", err)
	}
	header := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}
	if err := builder.PTRResource(header, dnsmessage.PTRResource{PTR: ptr}); err != nil {
		t.Fatalf("ptr resource: %v", err)
	}
	msg, err := builder.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return msg
}

type netbiosEntry struct {
	name   string
	suffix byte
	flags  uint16
}

// netbiosResponse builds an NBSTAT reply with the given name table.
func netbiosResponse(t *testing.T, entries []netbiosEntry) []byte {
	t.Helper()

	msg := make([]byte, 0, 128)
	msg = binary.BigEndian.AppendUint16(msg, 0x1234) // transaction id
	msg = binary.BigEndian.AppendUint16(msg, 0x8400) // response, authoritative
	msg = binary.BigEndian.AppendUint16(msg, 0)      // no questions echoed
	msg = binary.BigEndian.AppendUint16(msg, 1)      // one answer
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)

	msg = append(msg, 0x20)
	msg = append(msg, encodeNetBIOSName("*")...)
	msg = append(msg, 0x00)
	msg = binary.BigEndian.AppendUint16(msg, netbiosNBSTAT)
	msg = binary.BigEndian.AppendUint16(msg, netbiosIN)
	msg = binary.BigEndian.AppendUint32(msg, 0) // ttl
	msg = binary.BigEndian.AppendUint16(msg, uint16(1+len(entries)*18))

	msg = append(msg, byte(len(entries)))
	for _, e := range entries {
		padded := make([]byte, 15)
		copy(padded, e.name)
		for i := len(e.name); i < 15; i++ {
			padded[i] = ' '
		}
		msg = append(msg, padded...)
		msg = append(msg, e.suffix)
		msg = binary.BigEndian.AppendUint16(msg, e.flags)
	}
	return msg
}
