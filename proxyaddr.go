// Package proxyaddr is a middleware for determining client address for proxied requests.
package proxyaddr

import (
	"net"
	"net/http"
	"strings"
)

// ProxyAddr stores the group of CIDR of trusted proxies. With these and HTTP "x-forwarded-for" header,
// ProxyAddr determines actual IP address of the connecting client.
type ProxyAddr struct {
	trustedProxies []*net.IPNet
}

const (
	// CIDRLoopback represents IPv4 and IPv6 loopback addresses
	CIDRLoopback = "loopback"

	// CIDRLinkLocal represents IPv4 and IPv6 link-local addresses
	CIDRLinkLocal = "linklocal"

	// CIDRUniqueLocal represents IPv4 private addresses and IPv6 unique local addresses
	CIDRUniqueLocal = "uniquelocal"
)

var commonCIDR = map[string][]string{
	CIDRLinkLocal:   {"169.254.0.0/16", "fe80::/10"},
	CIDRLoopback:    {"127.0.0.1/8", "::1/128"},
	CIDRUniqueLocal: {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
}

// Init initializes the list of trusted proxies with provided string values.
// Without initializing, ProxyAddr trusts no IP address at all, and does not change RemoteAddr field.
//
// Parameters of Init can only be exported constants of this package or CIDR-formatted strings (like 10.0.0.0/8).
func (pa *ProxyAddr) Init(trustedProxies ...string) error {
	pa.trustedProxies = nil
	var trustedNetworks []*net.IPNet
	for _, proxyCIDR := range trustedProxies {
		if cidrList, ok := commonCIDR[proxyCIDR]; ok {
			for _, cidr := range cidrList {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					panic(err)
				}
				trustedNetworks = append(trustedNetworks, network)
			}
			continue
		}
		_, network, err := net.ParseCIDR(proxyCIDR)
		if err != nil {
			return err
		}
		trustedNetworks = append(trustedNetworks, network)
	}
	pa.trustedProxies = trustedNetworks
	return nil
}

func (pa *ProxyAddr) trusted(ip net.IP) bool {
	for _, network := range pa.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (pa *ProxyAddr) getRemoteAddr(r *http.Request) string {
	addr, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	remoteAddr := net.ParseIP(addr)
	if xff := r.Header.Get("x-forwarded-for"); xff != "" {
		ipList := strings.Split(xff, ",")
		for i := len(ipList) - 1; i >= 0; i-- {
			if !pa.trusted(remoteAddr) {
				break
			}
			ip := net.ParseIP(strings.TrimSpace(ipList[i]))
			if ip == nil {
				break
			}
			remoteAddr = ip
		}
	}
	return net.JoinHostPort(remoteAddr.String(), port)
}

// Handler is the plain http.Handler which updates RemoteAddr with actual IP from x-forwarded-for header.
func (pa *ProxyAddr) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = pa.getRemoteAddr(r)
		h.ServeHTTP(w, r)
	})
}

// ServeHTTP is the implementation of Negroni middleware interface.
func (pa *ProxyAddr) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	r.RemoteAddr = pa.getRemoteAddr(r)
	next(w, r)
}
