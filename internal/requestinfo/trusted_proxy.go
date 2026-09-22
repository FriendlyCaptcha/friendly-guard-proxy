package requestinfo

import (
	"fmt"
	"net"
)

type TrustedProxySet struct {
	ranges []*net.IPNet
}

func NewTrustedProxySet(values []string) (TrustedProxySet, error) {
	var out TrustedProxySet
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return TrustedProxySet{}, fmt.Errorf("error parsing trusted proxy %q: %w", value, err)
		}
		out.ranges = append(out.ranges, network)
	}
	return out, nil
}

func (s TrustedProxySet) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range s.ranges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
