package checkproxy

import (
	"net"
	"net/http"
)

var (
	xForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
	xRealIP       = http.CanonicalHeaderKey("X-Real-IP")
)

// CheckIPInNetworkList checks for an IP address in a list of networks
// The list of networks can be IP addresses or CIDR blocks
func CheckIPInNetworkList(clientIP string, networkList []string) bool {
	ip := net.ParseIP(clientIP)

	if ip == nil {
		return false
	}

	for _, network := range networkList {
		var trustedIP net.IP

		_, trustedSubnet, err := net.ParseCIDR(network)
		if err != nil {
			serr, _ := err.(*net.ParseError)
			if serr.Type == "CIDR address" {
				trustedIP = net.ParseIP(network)
			}
		}

		if trustedSubnet != nil {
			if trustedSubnet.Contains(ip) {
				return true
			}
		} else if trustedIP != nil {
			if trustedIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// CheckProxies is a middleware that checks the RequestAddr against a list of known
// trusted proxies.
func CheckProxies(useProxy bool, trustedProxies []string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			forwardedFor := r.Header.Get(xForwardedFor)
			// Check if the application is expecting to use a proxy
			if !useProxy {
				// If there's an X-Forwarded-For header, we've used a proxy without expecting one
				if forwardedFor != "" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("Detected proxy: but application is not configured to use one"))
					return
				}
			} else {
				// We expected a proxy,but didn't find an X-Forwarded-For header
				if forwardedFor == "" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("Expected a proxy: X-Forwarded-For empty"))
					return
				}
				// Find the origin IP from the request
				ip, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				// Check origin IP vs the list of trusted proxies
				if !CheckIPInNetworkList(ip, trustedProxies) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("Untrusted proxy"))
					return
				}
			}
			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
