package netinfo

import (
	"log"
	"net"
	"sort"
)

type Subnet struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
	Address   string `json:"address"`
}

func List() ([]Subnet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("list interfaces: %v", err)
		return nil, err
	}

	var subnets []Subnet
	seen := make(map[string]struct{})

	for _, iface := range ifaces {
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

			ones, bits := ipnet.Mask.Size()
			if bits != 32 || ones == 0 {
				continue
			}

			network := &net.IPNet{IP: ip.Mask(ipnet.Mask), Mask: ipnet.Mask}
			cidr := network.String()
			key := iface.Name + "|" + cidr + "|" + ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			subnets = append(subnets, Subnet{
				Interface: iface.Name,
				CIDR:      cidr,
				Address:   ip.String(),
			})
		}
	}

	sort.Slice(subnets, func(i, j int) bool {
		if subnets[i].Interface != subnets[j].Interface {
			return subnets[i].Interface < subnets[j].Interface
		}
		return subnets[i].CIDR < subnets[j].CIDR
	})

	if subnets == nil {
		subnets = []Subnet{}
	}
	return subnets, nil
}

func ContainsCIDR(subnets []Subnet, cidr string) bool {
	for _, s := range subnets {
		if s.CIDR == cidr {
			return true
		}
	}
	return false
}
