package scanner

import (
	"log"
	"net"
)

// link is the local interface a target address is reachable over. Hostname
// lookups bind to it so multicast queries leave the right NIC and unicast
// queries are sourced from the address the target will answer to.
type link struct {
	index   int
	name    string
	local   net.IP
	iface   *net.Interface
	network *net.IPNet
}

func loadLinks() []link {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("list interfaces for hostname lookup: %v", err)
		return nil
	}

	var links []link
	for i := range ifaces {
		iface := ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("addresses for %s: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				continue
			}
			links = append(links, link{
				index:   iface.Index,
				name:    iface.Name,
				local:   ip,
				iface:   &iface,
				network: &net.IPNet{IP: ip.Mask(ipnet.Mask), Mask: ipnet.Mask},
			})
		}
	}
	return links
}

// linkFor picks the interface whose subnet contains ip, preferring the most
// specific match when subnets overlap.
func linkFor(links []link, ip net.IP) *link {
	var best *link
	bestOnes := -1
	for i := range links {
		if !links[i].network.Contains(ip) {
			continue
		}
		ones, _ := links[i].network.Mask.Size()
		if ones > bestOnes {
			bestOnes = ones
			best = &links[i]
		}
	}
	return best
}
