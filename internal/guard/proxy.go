package guard

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/friendlycaptcha/friendly-guard-proxy/internal/api"
	"github.com/friendlycaptcha/friendly-guard-proxy/internal/config"
	"github.com/friendlycaptcha/friendly-guard-proxy/internal/pass"
	"github.com/friendlycaptcha/friendly-guard-proxy/internal/ratelimit"
	"github.com/friendlycaptcha/friendly-guard-proxy/internal/requestinfo"
)

const (
	continuePath   = "/__friendly-guard/v1/continue"
	healthPath     = "/__friendly-guard/v1/healthz"
	passCookieName = "friendly_guard_pass"
	defaultPassTTL = 15 * time.Minute
)

type Proxy struct {
	cfg         config.Config
	proxy       *httputil.ReverseProxy
	matcher     *matcher
	pass        *pass.Signer
	rateLimiter *ratelimit.Limiter
	apiClient   *api.Client
	trusted     requestinfo.TrustedProxySet
}

func NewProxy(cfg config.Config) (*Proxy, error) {
	upstream, err := url.Parse(cfg.Upstream.Origin)
	if err != nil {
		return nil, fmt.Errorf("parse upstream origin: %w", err)
	}
	m, err := newMatcher(cfg.GuardedRoutes)
	if err != nil {
		return nil, err
	}
	apiEndpoint, err := config.ResolveAPIEndpoint(cfg.FriendlyGuardAPI.APIEndpoint)
	if err != nil {
		return nil, err
	}
	client := api.NewClient(
		apiEndpoint,
		cfg.FriendlyGuardAPI.APIKey,
		time.Duration(cfg.FriendlyGuardAPI.TimeoutSeconds)*time.Second,
	)
	passSecret, err := passSigningSecret(cfg.PassSigningSecret)
	if err != nil {
		return nil, err
	}
	passSigner, err := pass.NewSigner(cfg.FriendlyGuardAPI.Sitekey, passSecret)
	if err != nil {
		return nil, err
	}
	var rateLimiter *ratelimit.Limiter
	if cfg.PassRequestLimit > 0 {
		rateLimiter, err = ratelimit.New(cfg.PassRequestLimit, defaultPassTTL)
		if err != nil {
			return nil, err
		}
	}
	trusted, err := requestinfo.NewTrustedProxySet(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		cfg:         cfg,
		proxy:       newReverseProxy(upstream, trusted),
		matcher:     m,
		pass:        passSigner,
		rateLimiter: rateLimiter,
		apiClient:   client,
		trusted:     trusted,
	}, nil
}

func passSigningSecret(cfgSecret string) ([]byte, error) {
	if cfgSecret != "" {
		return []byte(cfgSecret), nil
	}
	secret := make([]byte, config.MinPassSigningSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate pass signing secret: %w", err)
	}
	slog.Warn("pass_signing_secret is not configured; generated an ephemeral pass signing secret; pass cookies will be invalidated on restart")
	return secret, nil
}

func newReverseProxy(upstream *url.URL, trusted requestinfo.TrustedProxySet) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			reqDetails := requestinfo.DetailsFromRequest(req.In, trusted)
			req.SetURL(upstream)

			req.Out.Header.Del("X-Real-IP")
			if reqDetails.ClientIP != "" {
				req.Out.Header.Set("X-Real-IP", reqDetails.ClientIP)
			}

			// The X-Forwarded-* headers are already cleared by the ReverseProxy so we don't need to clear them again.
			forwardedFor := append([]string{}, reqDetails.ForwardedFor...)
			if reqDetails.PeerIP != "" {
				forwardedFor = append(forwardedFor, reqDetails.PeerIP)
			}
			if len(forwardedFor) > 0 {
				req.Out.Header.Set("X-Forwarded-For", strings.Join(forwardedFor, ", "))
			}
			if reqDetails.Host != "" {
				req.Out.Header.Set("X-Forwarded-Host", reqDetails.Host)
			}
			if reqDetails.Scheme != "" {
				req.Out.Header.Set("X-Forwarded-Proto", reqDetails.Scheme)
			}
		},
	}
	proxy.Transport = newUpstreamTransport()
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Default().
			With("request_id", requestIDFromContext(r)).
			Error("upstream proxy failed", "error", err)
		http.Error(w, "Friendly Guard Proxy upstream unavailable", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		slog.Debug("upstream response", "request_id", requestIDFromContext(resp.Request), "upstream_status", resp.StatusCode)
		return nil
	}
	return proxy
}

func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func (g *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	r = r.WithContext(contextWithRequestID(r.Context(), requestID))
	logger := slog.Default().With(
		"request_id", requestID,
		"method", r.Method,
		"path", normalizePath(r.URL.Path),
	)

	if g.handleInternal(w, r) {
		return
	}

	signedPass := g.passCookie(r)
	if signedPass.Token != "" && !signedPass.Valid {
		g.clearPass(w, r)
	}

	protected := g.matcher.protected(r.URL.Path)
	if !protected || r.Method == http.MethodOptions {
		logger.Debug("proxying request", "route_protected", protected)
		g.proxy.ServeHTTP(w, r)
		return
	}
	if signedPass.Valid {
		if g.allowPassRequest(signedPass.ID) {
			logger.Debug("proxying request", "route_protected", protected)
			g.proxy.ServeHTTP(w, r)
			return
		}
		logger.Debug("pass request limit reached", "pass_request_limit", g.cfg.PassRequestLimit)
		g.clearPass(w, r)
	}
	if r.Method != http.MethodGet {
		logger.Debug("rejecting unsafe method without pass", "route_protected", protected)
		http.Error(w, "Friendly Guard Proxy pass required", http.StatusForbidden)
		return
	}
	g.handlePrescreen(w, r, logger)
}

func (g *Proxy) handleInternal(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case healthPath:
		writeHealth(w, r)
		return true
	case continuePath:
		g.handleContinue(w, r, slog.Default().With("request_id", requestIDFromContext(r)))
		return true
	default:
		return false
	}
}

func (g *Proxy) handlePrescreen(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	reqDetails := requestinfo.DetailsFromRequest(r, g.trusted)

	result, err := g.apiClient.Prescreen(r.Context(), api.PrescreenRequest{
		Sitekey: g.cfg.FriendlyGuardAPI.Sitekey,
		RequestContext: api.PreescreenRequestContext{
			ClientIP:             reqDetails.ClientIP,
			Method:               reqDetails.Method,
			Scheme:               reqDetails.Scheme,
			Host:                 reqDetails.Host,
			Path:                 reqDetails.Path,
			HeaderUserAgent:      reqDetails.HeaderUserAgent,
			HeaderAccept:         reqDetails.HeaderAccept,
			HeaderAcceptLanguage: reqDetails.HeaderAcceptLanguage,
			HeaderSecFetchDest:   reqDetails.HeaderSecFetchDest,
			HeaderSecFetchMode:   reqDetails.HeaderSecFetchMode,
			HeaderSecFetchSite:   reqDetails.HeaderSecFetchSite,
			HeaderSecFetchUser:   reqDetails.HeaderSecFetchUser,
			HeaderSignature:      reqDetails.HeaderSignature,
			HeaderSignatureInput: reqDetails.HeaderSignatureInput,
			HeaderSignatureAgent: reqDetails.HeaderSignatureAgent,
		},
	})
	if failureErr := decisionFailureError(result, err); failureErr != nil {
		failOpen := g.failureModeOpen() && decisionFailureUnavailable(result.StatusCode, failureErr)
		logger.Error("prescreen decision failed", "error", failureErr, "status", result.StatusCode, "fail_open", failOpen)
		if failOpen {
			g.allowPrescreen(w, r, logger)
			return
		}
		writeDecisionFailure(w, result.StatusCode, failureErr)
		return
	}

	resp, err := result.Data()
	if err != nil {
		logger.Error("prescreen decision response was invalid", "error", err)
		writeGuardError(w, http.StatusBadGateway, "Friendly Guard Proxy received an invalid decision response")
		return
	}
	logger.Debug("prescreen decision returned", "outcome", resp.Outcome)

	switch resp.Outcome {
	case api.OutcomeAllow:
		g.allowPrescreen(w, r, logger)
	case api.OutcomeBlock:
		if g.cfg.DryRun {
			logger.Debug("dry-run decision allowed", "outcome", resp.Outcome)
			g.allowPrescreen(w, r, logger)
			return
		}
		g.blockPrescreen(w, r)
	case api.OutcomeCheck:
		if resp.InterstitialHTML == "" {
			logger.Error("prescreen returned CHECK without interstitial")
			writeGuardError(w, http.StatusBadGateway, "Friendly Guard Proxy received an invalid interstitial response")
			return
		}
		writeInterstitial(w, resp.InterstitialHTML)
	default:
		failOpen := g.failureModeOpen()
		logger.Warn("prescreen returned unknown outcome", "outcome", resp.Outcome, "fail_open", failOpen)
		if failOpen {
			g.allowPrescreen(w, r, logger)
			return
		}
		writeGuardError(w, http.StatusBadGateway, "Friendly Guard Proxy received an unknown decision outcome")
	}
}

type continueRequest struct {
	ScreeningContext string `json:"screening_context"`
	RiskToken        string `json:"risk_token,omitempty"`
	CaptchaResponse  string `json:"captcha_response,omitempty"`
}

type continueResponse struct {
	Outcome          api.Outcome `json:"outcome"`
	ScreeningContext string      `json:"screening_context,omitempty"`
	RedirectURL      string      `json:"redirect_url,omitempty"`
}

func (g *Proxy) handleContinue(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	var input continueRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)) // 64 KiB
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if input.ScreeningContext == "" {
		http.Error(w, "screening_context is required", http.StatusBadRequest)
		return
	}

	result, err := g.apiClient.Decide(r.Context(), api.DecideRequest{
		Sitekey:          g.cfg.FriendlyGuardAPI.Sitekey,
		ScreeningContext: input.ScreeningContext,
		RiskToken:        input.RiskToken,
		CaptchaResponse:  input.CaptchaResponse,
	})
	if failureErr := decisionFailureError(result, err); failureErr != nil {
		failOpen := g.failureModeOpen() && decisionFailureUnavailable(result.StatusCode, failureErr)
		logger.Warn("continuation decision failed", "error", failureErr, "status", result.StatusCode, "fail_open", failOpen)
		if failOpen {
			g.allowContinuation(w, r, logger)
			return
		}
		writeJSON(w, http.StatusBadGateway, continueResponse{Outcome: api.OutcomeError})
		return
	}

	resp, err := result.Data()
	if err != nil {
		logger.Warn("continuation decision response was invalid", "error", err)
		writeJSON(w, http.StatusBadGateway, continueResponse{Outcome: api.OutcomeError})
		return
	}
	logger.Debug("continuation decision returned", "outcome", resp.Outcome)

	switch resp.Outcome {
	case api.OutcomeAllow:
		g.allowContinuation(w, r, logger)
	case api.OutcomeBlock:
		if g.cfg.DryRun {
			logger.Debug("dry-run decision allowed", "outcome", resp.Outcome)
			g.allowContinuation(w, r, logger)
			return
		}
		writeJSON(w, http.StatusOK, continueResponse{
			Outcome:     api.OutcomeBlock,
			RedirectURL: g.cfg.BlockRedirectURL,
		})
	case api.OutcomeChallenge:
		if resp.ScreeningContext == "" {
			logger.Error("continuation returned CHALLENGE without rotated screening context")
			writeJSON(w, http.StatusBadGateway, continueResponse{Outcome: api.OutcomeError})
			return
		}
		if g.cfg.DryRun {
			logger.Debug("dry-run decision allowed", "outcome", resp.Outcome)
			g.allowContinuation(w, r, logger)
			return
		}
		writeJSON(w, http.StatusOK, continueResponse{Outcome: api.OutcomeChallenge, ScreeningContext: resp.ScreeningContext})
	default:
		failOpen := g.failureModeOpen()
		logger.Warn("continuation returned unknown outcome", "outcome", resp.Outcome, "fail_open", failOpen)
		if failOpen {
			g.allowContinuation(w, r, logger)
			return
		}
		writeJSON(w, http.StatusBadGateway, continueResponse{Outcome: api.OutcomeError})
	}
}

func (g *Proxy) allowPrescreen(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	// The allowed prescreen request is immediately proxied upstream, so it counts as the pass's first request.
	if err := g.setPass(w, r, 1); err != nil {
		logger.Error("failed to set pass", "error", err)
		writeGuardError(w, http.StatusBadGateway, "Friendly Guard Proxy failed to set pass")
		return
	}
	g.proxy.ServeHTTP(w, r)
}

func (g *Proxy) allowContinuation(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	// The continuation request does not access the protected upstream. The subsequent page reload counts as the pass's first request.
	if err := g.setPass(w, r, 0); err != nil {
		logger.Error("failed to set pass", "error", err)
		writeJSON(w, http.StatusBadGateway, continueResponse{Outcome: api.OutcomeError})
		return
	}
	writeJSON(w, http.StatusOK, continueResponse{Outcome: api.OutcomeAllow})
}

func (g *Proxy) failureModeOpen() bool {
	return g.cfg.FailureMode == "open"
}

func (g *Proxy) blockPrescreen(w http.ResponseWriter, r *http.Request) {
	if g.cfg.BlockRedirectURL != "" {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, g.cfg.BlockRedirectURL, http.StatusSeeOther)
		return
	}
	writeBlocked(w)
}

func (g *Proxy) passCookie(r *http.Request) pass.SignedPass {
	cookie, err := r.Cookie(passCookieName)
	if err != nil {
		return pass.SignedPass{}
	}
	return g.pass.ParseForRequest(cookie.Value, r)
}

func (g *Proxy) setPass(w http.ResponseWriter, r *http.Request, initialRequests int) error {
	signedPass, err := g.pass.NewForRequest(r, defaultPassTTL)
	if err != nil {
		return err
	}
	g.trackPassRequests(signedPass.ID, initialRequests)
	http.SetCookie(w, &http.Cookie{
		Name:     passCookieName,
		Value:    signedPass.Token,
		Path:     "/",
		MaxAge:   int(defaultPassTTL.Seconds()),
		Expires:  time.Now().Add(defaultPassTTL),
		HttpOnly: true,
		Secure:   g.passCookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (g *Proxy) allowPassRequest(id string) bool {
	return g.rateLimiter == nil || g.rateLimiter.Allow(id)
}

func (g *Proxy) trackPassRequests(id string, initialRequests int) {
	if g.rateLimiter != nil {
		g.rateLimiter.Track(id, initialRequests)
	}
}

func (g *Proxy) clearPass(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     passCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   g.passCookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (g *Proxy) passCookieSecure(r *http.Request) bool {
	return requestinfo.DetailsFromRequest(r, g.trusted).Scheme == "https"
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func writeHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func writeInterstitial(w http.ResponseWriter, html string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func writeDecisionFailure(w http.ResponseWriter, statusCode int, err error) {
	if decisionFailureRejected(statusCode) {
		writeGuardError(w, http.StatusBadGateway, "Friendly Guard API rejected the request")
		return
	}
	if decisionFailureUnavailable(statusCode, err) {
		writeGuardError(w, http.StatusServiceUnavailable, "Friendly Guard API is unavailable")
		return
	}
	writeGuardError(w, http.StatusBadGateway, "Friendly Guard Proxy decision failed")
}

func decisionFailureError(result api.Result, err error) error {
	if err != nil {
		return err
	}
	if result.Failed() {
		if err := result.Error(); err != nil {
			return err
		}
		return errors.New("Guard API response failed") //nolint:staticcheck // Guard should be capitalized
	}
	return nil
}

func decisionFailureUnavailable(statusCode int, err error) bool {
	if errors.Is(err, api.ErrMalformedResponse) {
		return false
	}
	return errors.Is(err, api.ErrGuardRequest) || statusCode >= http.StatusInternalServerError
}

func decisionFailureRejected(statusCode int) bool {
	return statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError
}

func writeGuardError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}

func writeBlocked(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("<!doctype html><title>Request blocked</title><h1>Request blocked</h1><p>Friendly Guard Proxy blocked this request.</p>"))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Default().Debug("failed to encode JSON response", "error", err)
	}
}
