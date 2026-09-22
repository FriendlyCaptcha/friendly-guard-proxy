package requestinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestInfoUsesTrustedProxyHeaders(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected?x=1", nil)
	req.RemoteAddr = "10.1.2.3:12345" //nolint:goconst // More readable if inline
	req.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.8")
	req.Header.Set("X-Real-IP", "198.51.100.21")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")

	details := DetailsFromRequest(req, trusted)
	if details.PeerIP != "10.1.2.3" || details.ClientIP != "203.0.113.8" || details.Scheme != "https" || details.Host != "example.com" || details.Path != "/protected" { //nolint:goconst // More readable if inline
		t.Fatalf("unexpected trusted details: %#v", details)
	}
	if got, want := strings.Join(details.ForwardedFor, ", "), "203.0.113.8"; got != want {
		t.Fatalf("unexpected sanitized forwarding chain: got %q want %q", got, want)
	}
}

func TestRequestInfoUsesTrustedRealIPWithoutForwardedFor(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected?x=1", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")

	details := DetailsFromRequest(req, trusted)
	if details.PeerIP != "10.1.2.3" || details.ClientIP != "203.0.113.9" || details.Scheme != "https" || details.Host != "example.com" || details.Path != "/protected" {
		t.Fatalf("unexpected trusted details: %#v", details)
	}

	if got, want := strings.Join(details.ForwardedFor, ", "), "203.0.113.9"; got != want {
		t.Fatalf("unexpected sanitized forwarding chain: got %q want %q", got, want)
	}
}

func TestRequestInfoWalksTrustedProxyChain(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.8, 10.2.3.4")

	details := DetailsFromRequest(req, trusted)
	if details.ClientIP != "203.0.113.8" {
		t.Fatalf("unexpected client IP: %q", details.ClientIP)
	}
	if got, want := strings.Join(details.ForwardedFor, ", "), "203.0.113.8, 10.2.3.4"; got != want {
		t.Fatalf("unexpected forwarding chain: got %q want %q", got, want)
	}
}

func TestRequestInfoHandlesMultipleForwardedForHeaderLines(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Add("X-Forwarded-For", "198.51.100.20, 203.0.113.8")
	req.Header.Add("X-Forwarded-For", "10.2.3.4")

	details := DetailsFromRequest(req, trusted)
	if got, want := details.ClientIP, "203.0.113.8"; got != want {
		t.Fatalf("unexpected client IP: got %q want %q", got, want)
	}
	if got, want := strings.Join(details.ForwardedFor, ", "), "203.0.113.8, 10.2.3.4"; got != want {
		t.Fatalf("unexpected forwarding chain: got %q want %q", got, want)
	}
}

func TestRequestInfoFallsBackToRemoteForMalformedForwardedIP(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name         string
		forwardedFor string
	}{
		{name: "invalid address", forwardedFor: "198.51.100.20, not-an-ip, 10.2.3.4"},
		{name: "address with port", forwardedFor: "203.0.113.8:1234"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected", nil)
			req.RemoteAddr = "10.1.2.3:12345"
			req.Header.Set("X-Forwarded-For", test.forwardedFor)

			details := DetailsFromRequest(req, trusted)
			if got, want := details.ClientIP, "10.1.2.3"; got != want {
				t.Fatalf("unexpected client IP: got %q want %q", got, want)
			}
			if got, want := strings.Join(details.ForwardedFor, ", "), ""; got != want {
				t.Fatalf("unexpected forwarding chain: got %q want %q", got, want)
			}
		})
	}
}

func TestRequestInfoFallsBackToRemoteForMalformedTrustedRealIP(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Real-IP", "not-an-ip")

	details := DetailsFromRequest(req, trusted)
	if got, want := details.ClientIP, "10.1.2.3"; got != want {
		t.Fatalf("unexpected client IP: got %q want %q", got, want)
	}
	if got, want := strings.Join(details.ForwardedFor, ", "), ""; got != want {
		t.Fatalf("unexpected forwarding chain: got %q want %q", got, want)
	}
}

func TestRequestInfoIgnoresMalformedValuesLeftOfClient(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "not-an-ip, 203.0.113.8, 10.2.3.4")

	details := DetailsFromRequest(req, trusted)
	if got, want := details.ClientIP, "203.0.113.8"; got != want {
		t.Fatalf("unexpected client IP: got %q want %q", got, want)
	}
	if got, want := strings.Join(details.ForwardedFor, ", "), "203.0.113.8, 10.2.3.4"; got != want {
		t.Fatalf("unexpected forwarding chain: got %q want %q", got, want)
	}
}

func TestRequestInfoIgnoresUntrustedProxyHeaders(t *testing.T) {
	trusted, err := NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")
	req.Header.Set("X-Real-IP", "203.0.113.9")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")

	details := DetailsFromRequest(req, trusted)
	if details.PeerIP != "192.0.2.10" || details.ClientIP != "192.0.2.10" || details.Scheme != "http" || details.Host != "internal.local" {
		t.Fatalf("unexpected untrusted details: %#v", details)
	}
	if got, want := strings.Join(details.ForwardedFor, ", "), ""; got != want {
		t.Fatalf("unexpected forwarding chain: got %q want %q", got, want)
	}
}

func TestRequestInfoHandlesMalformedRemoteAddress(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal.local/protected", nil)
	req.RemoteAddr = "not-an-address"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")

	details := DetailsFromRequest(req, TrustedProxySet{})
	if details.ClientIP != "" || len(details.ForwardedFor) != 0 {
		t.Fatalf("unexpected details for malformed remote address: %#v", details)
	}
}

func TestRequestInfoExtractsDecisionHeaders(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/protected", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "session=secret")
	req.Header.Set("X-Api-Key", "secret")
	req.Header.Set("X-Internal-Debug", "do-not-forward")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Signature", "sig1=:signature:")
	req.Header.Set("Signature-Input", `sig1=("@method" "@authority")`)
	req.Header.Set("Signature-Agent", `"https://example.com"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Full-Version", `"143.0.0.0"`)
	req.Header.Set("Cache-Control", "no-cache")

	details := DetailsFromRequest(req, TrustedProxySet{})
	if details.HeaderUserAgent != "Mozilla/5.0" ||
		details.HeaderAccept != "text/html" ||
		details.HeaderAcceptLanguage != "en" ||
		details.HeaderSecFetchDest != "document" ||
		details.HeaderSecFetchMode != "navigate" ||
		details.HeaderSecFetchSite != "same-origin" ||
		details.HeaderSecFetchUser != "?1" ||
		details.HeaderSignature != "sig1=:signature:" ||
		details.HeaderSignatureInput != `sig1=("@method" "@authority")` ||
		details.HeaderSignatureAgent != `"https://example.com"` {
		t.Fatalf("unexpected decision headers: %#v", details)
	}
}
