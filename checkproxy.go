package checkproxy

import (
	"net"
	"net/http"
)

var (
	xForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
	xRealIP       = http.CanonicalHeaderKey("X-Real-IP")
)

type ProxyChecker struct {
	ErrorFunc      func(statusCode int, message string, w http.ResponseWriter, r *http.Request)
	UseProxy       bool
	TrustedProxies []string
}

func (p ProxyChecker) Handle(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		forwardedFor := r.Header.Get(xForwardedFor)
		// Check if the application is expecting to use a proxy
		if !p.UseProxy {
			// If there's an X-Forwarded-For header, we've used a proxy without expecting one
			if forwardedFor != "" {
				p.ErrorFunc(http.StatusBadRequest, "Detected proxy: but application is not configured to use one", w, r)
				return
			}
		} else {
			// We expected a proxy,but didn't find an X-Forwarded-For header
			if forwardedFor == "" {
				p.ErrorFunc(http.StatusBadRequest, "Expected a proxy: X-Forwarded-For empty", w, r)
				return
			}
			// Find the origin IP from the request
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			// Check origin IP vs the list of trusted proxies
			if !CheckIPInNetworkList(ip, p.TrustedProxies) {
				p.ErrorFunc(http.StatusBadRequest, "Untrusted proxy", w, r)
				return
			}
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func defaultErrorFunc(statusCode int, message string, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

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

// CheckProxy is a middleware that checks the RequestAddr against a list of known
// trusted proxies.
func CheckProxy(useProxy bool, trustedProxies []string) func(http.Handler) http.Handler {
	p := ProxyChecker{
		ErrorFunc:      defaultErrorFunc,
		UseProxy:       useProxy,
		TrustedProxies: trustedProxies,
	}
	return p.Handle
}
