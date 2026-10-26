package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
)

func hostRange(cidr string) (first, last uint32, err error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, fmt.Errorf("parse cidr %q: %w", cidr, err)
	}

	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return 0, 0, fmt.Errorf("not ipv4 cidr: %s", cidr)
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return 0, 0, fmt.Errorf("not ipv4 cidr: %s", cidr)
	}

	var mask uint32
	if ones > 0 {
		mask = ^uint32(0) << (32 - ones)
	}
	network := binary.BigEndian.Uint32(ip4) & mask
	broadcast := network | ^mask

	switch {
	case ones >= 32:
		return network, network, nil
	case ones == 31:
		return network, broadcast, nil
	default:
		return network + 1, broadcast - 1, nil
	}
}

func ipString(n uint32) string {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).String()
}

func uniqueCIDRs(cidrs []string) []string {
	seen := make(map[string]struct{}, len(cidrs))
	out := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}
