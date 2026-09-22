package pass

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SignedPass struct {
	ID    string
	Token string
	Valid bool
}

const passTokenVersion = 1

type bindingAttrs map[string]string

type passClaims struct {
	Version int    `json:"version"`
	Binding string `json:"binding,omitempty"`
	jwt.RegisteredClaims
}

type validatingPassClaims struct {
	Version         int    `json:"version"`
	Binding         string `json:"binding,omitempty"`
	expectedBinding string
	jwt.RegisteredClaims
}

func (c *validatingPassClaims) Validate() error {
	if c.Version != passTokenVersion {
		return errors.New("invalid pass token version")
	}
	if c.ID == "" {
		return errors.New("pass token has no ID")
	}
	if c.Binding != c.expectedBinding {
		return errors.New("invalid pass token binding")
	}
	return nil
}

type Signer struct {
	secret  []byte
	sitekey string
	now     func() time.Time
}

func NewSigner(sitekey string, secret []byte) (*Signer, error) {
	if sitekey == "" {
		return nil, fmt.Errorf("pass signer has no sitekey")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("pass signer has no secret")
	}
	return &Signer{
		secret:  secret,
		sitekey: sitekey,
		now:     time.Now,
	}, nil
}

func (s *Signer) NewForRequest(r *http.Request, ttl time.Duration) (SignedPass, error) {
	return s.newSigned(ttl, bindingAttrsForRequest(r))
}

func (s *Signer) ParseForRequest(tokenString string, r *http.Request) SignedPass {
	claims, valid := s.validClaims(tokenString, bindingAttrsForRequest(r))
	if !valid {
		return SignedPass{Token: tokenString}
	}
	return SignedPass{ID: claims.ID, Token: tokenString, Valid: true}
}

func (s *Signer) newSigned(ttl time.Duration, attrs bindingAttrs) (SignedPass, error) {
	now := s.now()
	tokenID := make([]byte, 16)
	if _, err := rand.Read(tokenID); err != nil {
		return SignedPass{}, fmt.Errorf("error generating pass token ID: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(tokenID)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, passClaims{
		Version: passTokenVersion,
		Binding: bindingValue(attrs),
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{s.sitekey},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        id,
		},
	})
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return SignedPass{}, fmt.Errorf("error signing pass token: %w", err)
	}
	return SignedPass{ID: id, Token: signed, Valid: true}, nil
}

func (s *Signer) validClaims(tokenString string, attrs bindingAttrs) (*validatingPassClaims, bool) {
	claims := &validatingPassClaims{expectedBinding: bindingValue(attrs)}
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(_ *jwt.Token) (any, error) {
			return s.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(s.sitekey),
		jwt.WithTimeFunc(s.now),
	)
	return claims, err == nil && token.Valid
}

func bindingAttrsForRequest(r *http.Request) bindingAttrs {
	return bindingAttrs{"user_agent": r.UserAgent()}
}

func bindingValue(attrs bindingAttrs) string {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(attrs)*2)
	for _, name := range names {
		parts = append(parts, name, attrs[name])
	}
	payload := []byte(strings.Join(parts, "\x00"))

	// Hash the payload to have a fixed-length binding value.
	digest := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
