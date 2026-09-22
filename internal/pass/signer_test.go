package pass

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testSitekey      = "guard-sitekey"
	testPassSecret   = "secret"
	sharedSecret     = "shared-secret"
	otherTestSitekey = "FCOTHER"
)

func TestPassSigner(t *testing.T) {
	now := time.Now()
	s, err := NewSigner(testSitekey, []byte(testPassSecret))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }

	req := newPassRequest(t, "")
	signedPass, err := s.NewForRequest(req, time.Minute)
	if err != nil || !signedPass.Valid {
		t.Fatal("expected pass to validate")
	}
	pass := signedPass.Token
	parsedPass := s.ParseForRequest(pass, req)
	if !parsedPass.Valid || parsedPass.ID != signedPass.ID || parsedPass.Token != pass {
		t.Fatal("expected signed pass to parse")
	}
	if strings.Count(pass, ".") != 2 {
		t.Fatalf("expected pass to be a JWT, got %q", pass)
	}
	claims := &validatingPassClaims{expectedBinding: bindingValue(bindingAttrsForRequest(req))}
	token, err := jwt.ParseWithClaims(pass, claims, func(_ *jwt.Token) (any, error) {
		return []byte(testPassSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired(), jwt.WithAudience(testSitekey), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !token.Valid {
		t.Fatalf("expected JWT to parse: token=%v err=%v", token, err)
	}
	if claims.Version != passTokenVersion || len(claims.Audience) != 1 || claims.Audience[0] != testSitekey || claims.ExpiresAt.Unix() != now.Add(time.Minute).Unix() {
		t.Fatal("expected JWT claims to contain pass version, sitekey audience, and expiry")
	}
	if claims.ID == "" {
		t.Fatal("expected JWT claims to contain a unique token ID")
	}
	if s.ParseForRequest(pass+"x", req).Valid {
		t.Fatal("expected tampered pass to fail")
	}
	now = now.Add(2 * time.Minute)
	if s.ParseForRequest(pass, req).Valid {
		t.Fatal("expected expired pass to fail")
	}
}

func TestPassSignerCreatesUniquePasses(t *testing.T) {
	s, err := NewSigner(testSitekey, []byte(testPassSecret))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }

	req := newPassRequest(t, "")
	first, err := s.NewForRequest(req, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.NewForRequest(req, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == second.Token || first.ID == second.ID {
		t.Fatal("expected passes issued at the same time to be unique")
	}
}

func TestPassSignerRejectsNonJWTPassFormat(t *testing.T) {
	s, err := NewSigner(testSitekey, []byte(testPassSecret))
	if err != nil {
		t.Fatal(err)
	}
	if s.ParseForRequest("payload.signature", newPassRequest(t, "")).Valid {
		t.Fatal("expected non-JWT pass format to be invalid")
	}
}

func TestPassSignerRequestBinding(t *testing.T) {
	s, err := NewSigner(testSitekey, []byte(testPassSecret))
	if err != nil {
		t.Fatal(err)
	}

	req := newPassRequest(t, "browser")
	signedPass, err := s.NewForRequest(req, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parsedPass := s.ParseForRequest(signedPass.Token, req)
	if !parsedPass.Valid || parsedPass.ID == "" || parsedPass.ID != signedPass.ID || parsedPass.Token != signedPass.Token {
		t.Fatal("expected matching request to return the valid signed pass")
	}

	otherReq := newPassRequest(t, "other")
	parsedPass = s.ParseForRequest(signedPass.Token, otherReq)
	if parsedPass.Valid {
		t.Fatal("expected changed user agent to fail binding")
	}
	if parsedPass.ID != "" {
		t.Fatal("expected changed user agent not to expose the pass token ID")
	}
	if parsedPass.Token != signedPass.Token {
		t.Fatal("expected invalid parsed pass to retain its token")
	}
}

func TestPassSignerRejectsPassFromDifferentSitekey(t *testing.T) {
	signer, err := NewSigner(testSitekey, []byte(sharedSecret))
	if err != nil {
		t.Fatal(err)
	}
	req := newPassRequest(t, "browser")
	signedPass, err := signer.NewForRequest(req, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	otherSiteSigner, err := NewSigner(otherTestSitekey, []byte(sharedSecret))
	if err != nil {
		t.Fatal(err)
	}
	if otherSiteSigner.ParseForRequest(signedPass.Token, req).Valid {
		t.Fatal("expected pass from different sitekey to be invalid")
	}
}

func TestPassSignerExpiresAtExactBoundary(t *testing.T) {
	now := time.Now()
	signer, err := NewSigner(testSitekey, []byte(testPassSecret))
	if err != nil {
		t.Fatal(err)
	}
	signer.now = func() time.Time { return now }
	req := newPassRequest(t, "")
	signedPass, err := signer.NewForRequest(req, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Minute)
	if signer.ParseForRequest(signedPass.Token, req).Valid {
		t.Fatal("expected token to be invalid at its exp boundary")
	}
}

func TestBindingValueIsIndependentOfMapIterationOrder(t *testing.T) {
	first := bindingValue(bindingAttrs{"user_agent": "browser", "client_ip": "203.0.113.8"})
	second := bindingValue(bindingAttrs{"client_ip": "203.0.113.8", "user_agent": "browser"})
	if first != second {
		t.Fatalf("binding values differ: %q != %q", first, second)
	}
}

func TestPassSignerRejectsInvalidClaimsAndAlgorithm(t *testing.T) {
	now := time.Now()
	signer, err := NewSigner(testSitekey, []byte(testPassSecret))
	if err != nil {
		t.Fatal(err)
	}
	signer.now = func() time.Time { return now }
	req := newPassRequest(t, "")

	validClaims := passClaims{
		Version: passTokenVersion,
		Binding: bindingValue(bindingAttrsForRequest(req)),
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{testSitekey},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			ID:        "pass-id",
		},
	}
	missingExpiry := validClaims
	missingExpiry.ExpiresAt = nil
	missingID := validClaims
	missingID.ID = ""
	wrongVersion := validClaims
	wrongVersion.Version++

	for _, test := range []struct {
		name   string
		method jwt.SigningMethod
		claims passClaims
	}{
		{name: "missing expiry", method: jwt.SigningMethodHS256, claims: missingExpiry},
		{name: "missing ID", method: jwt.SigningMethodHS256, claims: missingID},
		{name: "wrong version", method: jwt.SigningMethodHS256, claims: wrongVersion},
		{name: "wrong algorithm", method: jwt.SigningMethodHS384, claims: validClaims},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := jwt.NewWithClaims(test.method, test.claims).SignedString([]byte(testPassSecret))
			if err != nil {
				t.Fatal(err)
			}
			if signer.ParseForRequest(token, req).Valid {
				t.Fatal("expected invalid pass")
			}
		})
	}
}

func newPassRequest(t *testing.T, userAgent string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://guard.example/protected", nil)
	req.Header.Set("User-Agent", userAgent)
	return req
}
