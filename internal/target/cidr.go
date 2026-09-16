package target

import (
	"fmt"
	"net"
	"strings"
)

// Expand parses CIDR ranges and single IPs and returns every host address they
// cover, in input order and with duplicates suppressed. A single IP needs no
// prefix length. Lines beginning with "#" are skipped, so a targets file may be
// commented. A /32 and a /31 (RFC 3021) keep every address they name; any wider
// network excludes its own network and broadcast addresses.
func Expand(cidrs []string) ([]net.IP, error) {
	var hosts []net.IP
	seen := make(map[string]struct{})

	// add records ip unless an earlier target already covered it.
	add := func(ip net.IP) {
		key := ip.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		hosts = append(hosts, cloneIP(ip))
	}

	for _, cidr := range cidrs {
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}

		if ip := net.ParseIP(cidr); ip != nil {
			add(ip)
			continue
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse target %q: not a CIDR range or IP address", cidr)
		}

		ones, bits := network.Mask.Size()
		// A /31 has no room for a network and a broadcast address, and a /32 names
		// a single host, so for both every address in the range is usable.
		keepAll := ones >= bits-1

		for ip := cloneIP(network.IP); network.Contains(ip); inc(ip) {
			if keepAll || !isNetworkOrBroadcast(ip, network) {
				add(ip)
			}
		}
	}
	return hosts, nil
}

// inc advances ip to the next address in place.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

// isNetworkOrBroadcast reports whether ip is the network address of network (all
// host bits zero) or its broadcast address (all host bits one).
func isNetworkOrBroadcast(ip net.IP, network *net.IPNet) bool {
	if ip.Equal(network.IP) {
		return true
	}
	broadcast := make(net.IP, len(network.IP))
	for i := range network.IP {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}
