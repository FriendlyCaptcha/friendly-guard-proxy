package requestinfo

import (
	"net"
	"net/http"
	"path"
	"strings"
)

type RequestDetails struct {
	PeerIP   string
	ClientIP string
	Method   string
	Scheme   string
	Host     string
	Path     string

	HeaderUserAgent      string
	HeaderAccept         string
	HeaderAcceptLanguage string
	HeaderSecFetchDest   string
	HeaderSecFetchMode   string
	HeaderSecFetchSite   string
	HeaderSecFetchUser   string
	HeaderSignature      string
	HeaderSignatureInput string
	HeaderSignatureAgent string

	ForwardedFor []string
}

func DetailsFromRequest(r *http.Request, trusted TrustedProxySet) RequestDetails {
	remote := remoteIP(r.RemoteAddr)
	trustForwarded := trusted.contains(remote)
	peerIP := ""
	if remote != nil {
		peerIP = remote.String()
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if trustForwarded {
		if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
			scheme = forwarded
		}
	}

	host := r.Host
	if trustForwarded {
		if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
			host = forwarded
		}
	}

	// We use Header.Values() to get all values of the X-Forwarded-For header.
	// Usually a load balancer sends only one X-Forwarded-For header, but it's possible to send multiple.
	// For example by enabling `option forwardfor` in HAProxy, it will send multiple X-Forwarded-For headers.
	forwards := r.Header.Values("X-Forwarded-For")

	clientIP, forwardedFor := clientIPAndForwardedFor(remote, forwards, r.Header.Get("X-Real-IP"), trusted)
	normalizedPath := NormalizePath(r.URL.Path)

	return RequestDetails{
		PeerIP:               peerIP,
		ClientIP:             clientIP,
		Method:               r.Method,
		Scheme:               scheme,
		Host:                 host,
		Path:                 normalizedPath,
		HeaderUserAgent:      strings.Join(r.Header.Values("User-Agent"), ", "),
		HeaderAccept:         strings.Join(r.Header.Values("Accept"), ", "),
		HeaderAcceptLanguage: strings.Join(r.Header.Values("Accept-Language"), ", "),
		HeaderSecFetchDest:   strings.Join(r.Header.Values("Sec-Fetch-Dest"), ", "),
		HeaderSecFetchMode:   strings.Join(r.Header.Values("Sec-Fetch-Mode"), ", "),
		HeaderSecFetchSite:   strings.Join(r.Header.Values("Sec-Fetch-Site"), ", "),
		HeaderSecFetchUser:   strings.Join(r.Header.Values("Sec-Fetch-User"), ", "),
		HeaderSignature:      strings.Join(r.Header.Values("Signature"), ", "),
		HeaderSignatureInput: strings.Join(r.Header.Values("Signature-Input"), ", "),
		HeaderSignatureAgent: strings.Join(r.Header.Values("Signature-Agent"), ", "),
		ForwardedFor:         forwardedFor,
	}
}

// clientIPAndForwardedFor resolves the effective client IP and the sanitized
// incoming X-Forwarded-For chain. Forwarding headers are only trusted when the
// direct socket peer is configured as trusted. For trusted peers, X-Forwarded-For
// is authoritative; X-Real-IP is only a fallback for proxies that do not send XFF.
// If trusted forwarding data is absent or invalid, the socket peer becomes the client.
func clientIPAndForwardedFor(remote net.IP, forwards []string, xRealIP string, trusted TrustedProxySet) (string, []string) {
	if remote == nil {
		return "", nil
	}

	if !trusted.contains(remote) {
		return remote.String(), nil
	}

	if len(forwards) == 0 {
		if realIP := net.ParseIP(strings.TrimSpace(xRealIP)); realIP != nil {
			canonicalIP := realIP.String()
			return canonicalIP, []string{canonicalIP}
		}
		return remote.String(), nil
	}

	// We walk the forwards right-to-left. A malformed value invalidates XFF and falls back
	// to the remote address; values left of the first untrusted client address are intentionally ignored.
	var chain []string
	for i := len(forwards) - 1; i >= 0; i-- {
		values := strings.Split(forwards[i], ",")
		for j := len(values) - 1; j >= 0; j-- {
			ip := net.ParseIP(strings.TrimSpace(values[j]))
			if ip == nil {
				return remote.String(), nil
			}

			canonicalIP := ip.String()
			chain = append([]string{canonicalIP}, chain...)
			if !trusted.contains(ip) {
				return canonicalIP, chain
			}
		}
	}

	return chain[0], chain
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

// NormalizePath expects a value from URL.Path and returns a normalized path.
func NormalizePath(value string) string {
	if value == "" {
		return "/"
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return path.Clean(value)
}
