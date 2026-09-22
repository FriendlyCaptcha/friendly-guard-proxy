package guard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/friendlycaptcha/friendly-guard-proxy/internal/api"
	"github.com/friendlycaptcha/friendly-guard-proxy/internal/config"
	"github.com/friendlycaptcha/friendly-guard-proxy/internal/requestinfo"
)

type testDecisionRequest struct {
	Sitekey          string
	ScreeningContext string
	RiskToken        string
	CaptchaResponse  string
	RequestContext   api.PreescreenRequestContext
}

func validConfig() config.Config {
	return config.Config{
		Server:   config.ServerConfig{Listen: ":8080"},
		Upstream: config.UpstreamConfig{Origin: "http://127.0.0.1:3000"},
		FriendlyGuardAPI: config.FriendlyGuardAPIConfig{
			APIEndpoint:    "eu",
			Sitekey:        "guard-sitekey",
			APIKey:         "api-key",
			TimeoutSeconds: 1,
		},
		PassSigningSecret: "0123456789abcdef0123456789abcdef",
		PassRequestLimit:  100,
		GuardedRoutes:     []string{"^/protected(/.*)?$"},
		FailureMode:       "open",
	}
}

func newTestProxy(t *testing.T, action func(testDecisionRequest) api.ResponseData) (*Proxy, *httptest.Server) {
	t.Helper()
	return newTestProxyWithConfig(t, nil, action)
}

func newTestProxyWithConfig(
	t *testing.T,
	configure func(*config.Config),
	action func(testDecisionRequest) api.ResponseData,
) (*Proxy, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "true")
		_, _ = io.WriteString(w, "upstream:"+r.Method+":"+r.URL.RequestURI()+":"+string(body)) //nolint:gosec // Test upstream intentionally echoes request details.
	}))
	t.Cleanup(upstream.Close)
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data api.ResponseData
		switch r.URL.Path {
		case "/api/v2/guard/prescreen":
			var req api.PrescreenRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			data = action(testDecisionRequest{
				Sitekey:        req.Sitekey,
				RequestContext: req.RequestContext,
			})
		case "/api/v2/guard/decide":
			var req api.DecideRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			data = action(testDecisionRequest{
				Sitekey:          req.Sitekey,
				ScreeningContext: req.ScreeningContext,
				RiskToken:        req.RiskToken,
				CaptchaResponse:  req.CaptchaResponse,
			})
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(api.Response{Success: true, Data: &data})
	}))
	t.Cleanup(apiServer.Close)

	cfg := validConfig()
	cfg.Upstream.Origin = upstream.URL
	cfg.FriendlyGuardAPI.APIEndpoint = apiServer.URL
	cfg.FriendlyGuardAPI.TimeoutSeconds = 1
	if configure != nil {
		configure(&cfg)
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return proxy, apiServer
}

func TestGuardProxyGeneratesPassSigningSecret(t *testing.T) {
	secret, err := passSigningSecret("")
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != config.MinPassSigningSecretBytes {
		t.Fatalf("expected generated pass signing secret to be %d bytes, got %d", config.MinPassSigningSecretBytes, len(secret))
	}
}

func newTestRequest(t *testing.T, method string, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func doTestRequest(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // Test helper only calls local httptest servers.
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getTest(t *testing.T, url string) *http.Response {
	t.Helper()
	return doTestRequest(t, newTestRequest(t, http.MethodGet, url, nil))
}

func postJSONTest(t *testing.T, url string, body io.Reader) *http.Response {
	t.Helper()
	req := newTestRequest(t, http.MethodPost, url, body)
	req.Header.Set("Content-Type", "application/json")
	return doTestRequest(t, req)
}

func TestGuardProxyProxyAndMethodMatrix(t *testing.T) {
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	server := httptest.NewServer(proxy)
	defer server.Close()

	for _, tc := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/public?q=1", http.StatusOK},
		{http.MethodGet, "/protected?q=1", http.StatusOK},
		{http.MethodOptions, "/protected", http.StatusOK},
		{http.MethodPost, "/protected", http.StatusForbidden},
		{http.MethodPost, "/public%3F/../protected", http.StatusForbidden},
		{http.MethodPost, "/public%3f/%2e%2e/protected", http.StatusForbidden},
		{http.MethodPost, "/public%3Fignored/../protected?query=ignored", http.StatusForbidden},
		{http.MethodPost, "/public?next=/../protected", http.StatusOK},
		{http.MethodHead, "/protected", http.StatusForbidden},
		{http.MethodPut, "/protected", http.StatusForbidden},
		{http.MethodPatch, "/protected", http.StatusForbidden},
		{http.MethodDelete, "/protected", http.StatusForbidden},
	} {
		req := newTestRequest(t, tc.method, server.URL+tc.path, nil)
		resp := doTestRequest(t, req)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s %s: got %d want %d", tc.method, tc.path, resp.StatusCode, tc.status)
		}
	}
}

func TestGuardProxyCanonicalizesForwardingHeaders(t *testing.T) {
	received := make(chan http.Header, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	cfg := validConfig()
	cfg.Upstream.Origin = upstream.URL
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("trusted proxy", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://internal.local/public", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		req.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.8")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "example.com")
		req.Header.Set("X-Real-IP", "198.51.100.21")
		req.Header.Set("Forwarded", "for=198.51.100.23")

		response := httptest.NewRecorder()
		proxy.ServeHTTP(response, req)
		if response.Code != http.StatusNoContent {
			t.Fatalf("unexpected status: %d", response.Code)
		}

		headers := <-received
		if got, want := headers.Get("X-Forwarded-For"), "203.0.113.8, 10.1.2.3"; got != want {
			t.Fatalf("unexpected X-Forwarded-For: got %q want %q", got, want)
		}
		if got, want := headers.Get("X-Real-IP"), "203.0.113.8"; got != want {
			t.Fatalf("unexpected X-Real-IP: got %q want %q", got, want)
		}
		if got, want := headers.Get("X-Forwarded-Proto"), "https"; got != want {
			t.Fatalf("unexpected X-Forwarded-Proto: got %q want %q", got, want)
		}
		if got, want := headers.Get("X-Forwarded-Host"), "example.com"; got != want {
			t.Fatalf("unexpected X-Forwarded-Host: got %q want %q", got, want)
		}
		if value := headers.Get("Forwarded"); value != "" {
			t.Fatalf("unexpected Forwarded header: %q", value)
		}
	})

	t.Run("trusted proxy with real ip only", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://guard.example/public", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		req.Header.Set("X-Real-IP", "203.0.113.9")

		response := httptest.NewRecorder()
		proxy.ServeHTTP(response, req)
		if response.Code != http.StatusNoContent {
			t.Fatalf("unexpected status: %d", response.Code)
		}

		headers := <-received
		if got, want := headers.Get("X-Forwarded-For"), "203.0.113.9, 10.1.2.3"; got != want {
			t.Fatalf("unexpected X-Forwarded-For: got %q want %q", got, want)
		}
		if got, want := headers.Get("X-Real-IP"), "203.0.113.9"; got != want {
			t.Fatalf("unexpected X-Real-IP: got %q want %q", got, want)
		}
	})

	t.Run("untrusted peer", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://guard.example/public", nil)
		req.RemoteAddr = "192.0.2.10:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.8")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "spoofed.example")
		req.Header.Set("X-Real-IP", "203.0.113.9")

		response := httptest.NewRecorder()
		proxy.ServeHTTP(response, req)
		if response.Code != http.StatusNoContent {
			t.Fatalf("unexpected status: %d", response.Code)
		}

		headers := <-received
		if got, want := headers.Get("X-Forwarded-For"), "192.0.2.10"; got != want {
			t.Fatalf("unexpected X-Forwarded-For: got %q want %q", got, want)
		}
		if got, want := headers.Get("X-Real-IP"), "192.0.2.10"; got != want {
			t.Fatalf("unexpected X-Real-IP: got %q want %q", got, want)
		}
		if got, want := headers.Get("X-Forwarded-Proto"), "http"; got != want {
			t.Fatalf("unexpected X-Forwarded-Proto: got %q want %q", got, want)
		}
		if got, want := headers.Get("X-Forwarded-Host"), "guard.example"; got != want {
			t.Fatalf("unexpected X-Forwarded-Host: got %q want %q", got, want)
		}
	})
}

func TestGuardProxyAllowSetsPassAndBypassesFutureDecisions(t *testing.T) {
	decisions := 0
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		decisions++
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	_ = resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected pass cookie: %#v", cookies)
	}
	if cookies[0].Name != passCookieName || cookies[0].MaxAge != 900 {
		t.Fatalf("unexpected pass cookie metadata: %#v", cookies[0])
	}

	req := newTestRequest(t, http.MethodPost, server.URL+"/protected?submitted=1", strings.NewReader("body"))
	req.AddCookie(cookies[0])
	resp = doTestRequest(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || decisions != 1 {
		t.Fatalf("expected valid pass to bypass decision API, status=%d decisions=%d", resp.StatusCode, decisions)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream:POST:/protected?submitted=1:body" {
		t.Fatalf("proxy did not preserve request query and body: %q", body)
	}
}

func TestGuardProxyTracksPassRequestsByID(t *testing.T) {
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.PassRequestLimit = 1 },
		func(_ testDecisionRequest) api.ResponseData {
			return api.ResponseData{Outcome: api.OutcomeAllow}
		},
	)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://guard.example/protected", nil)
	response := httptest.NewRecorder()

	if err := proxy.setPass(response, req, 1); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one pass cookie, got %#v", cookies)
	}
	signedPass := proxy.pass.ParseForRequest(cookies[0].Value, req)
	if !signedPass.Valid {
		t.Fatal("expected issued pass to validate")
	}
	if proxy.rateLimiter.Allow(signedPass.ID) {
		t.Fatal("expected pass ID to already be at the request limit")
	}
	if !proxy.rateLimiter.Allow(cookies[0].Value) {
		t.Fatal("expected raw pass not to have a request count")
	}
}

func TestGuardProxyRescreensAfterPassRequestLimit(t *testing.T) {
	decisions := 0
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.PassRequestLimit = 2 },
		func(_ testDecisionRequest) api.ResponseData {
			decisions++
			return api.ResponseData{Outcome: api.OutcomeAllow}
		},
	)
	server := httptest.NewServer(proxy)
	defer server.Close()

	first := getTest(t, server.URL+"/protected")
	_ = first.Body.Close()
	firstCookies := first.Cookies()
	if first.StatusCode != http.StatusOK || decisions != 1 || len(firstCookies) != 1 {
		t.Fatalf("unexpected first request: status=%d decisions=%d cookies=%#v", first.StatusCode, decisions, firstCookies)
	}

	secondReq := newTestRequest(t, http.MethodGet, server.URL+"/protected", nil)
	secondReq.AddCookie(firstCookies[0])
	second := doTestRequest(t, secondReq)
	_ = second.Body.Close()
	if second.StatusCode != http.StatusOK || decisions != 1 || len(second.Cookies()) != 0 {
		t.Fatalf("expected second request to use existing pass: status=%d decisions=%d cookies=%#v", second.StatusCode, decisions, second.Cookies())
	}

	thirdReq := newTestRequest(t, http.MethodGet, server.URL+"/protected", nil)
	thirdReq.AddCookie(firstCookies[0])
	third := doTestRequest(t, thirdReq)
	_ = third.Body.Close()
	thirdCookies := third.Cookies()
	if third.StatusCode != http.StatusOK || decisions != 2 || len(thirdCookies) != 2 {
		t.Fatalf("expected third request to be rescreened: status=%d decisions=%d cookies=%#v", third.StatusCode, decisions, thirdCookies)
	}
	if thirdCookies[0].Name != passCookieName || thirdCookies[0].MaxAge >= 0 || thirdCookies[1].Name != passCookieName || thirdCookies[1].Value == firstCookies[0].Value {
		t.Fatalf("expected exhausted pass to be cleared and replaced: cookies=%#v", thirdCookies)
	}
}

func TestGuardProxyPassRequestLimitCanBeDisabled(t *testing.T) {
	decisions := 0
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.PassRequestLimit = 0 },
		func(_ testDecisionRequest) api.ResponseData {
			decisions++
			return api.ResponseData{Outcome: api.OutcomeAllow}
		},
	)
	if proxy.rateLimiter != nil {
		t.Fatal("expected zero pass request limit not to construct a rate limiter")
	}
	server := httptest.NewServer(proxy)
	defer server.Close()

	first := getTest(t, server.URL+"/protected")
	_ = first.Body.Close()
	passCookies := first.Cookies()
	if first.StatusCode != http.StatusOK || decisions != 1 || len(passCookies) != 1 {
		t.Fatalf("unexpected first request: status=%d decisions=%d cookies=%#v", first.StatusCode, decisions, passCookies)
	}

	for range 100 {
		req := newTestRequest(t, http.MethodGet, server.URL+"/protected", nil)
		req.AddCookie(passCookies[0])
		resp := doTestRequest(t, req)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request with disabled pass limit returned %d", resp.StatusCode)
		}
	}
	if decisions != 1 {
		t.Fatalf("expected disabled pass limit not to trigger re-screening, decisions=%d", decisions)
	}
}

func TestGuardProxyOnlyCountsProtectedRequestsTowardPassLimit(t *testing.T) {
	decisions := 0
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.PassRequestLimit = 2 },
		func(_ testDecisionRequest) api.ResponseData {
			decisions++
			return api.ResponseData{Outcome: api.OutcomeAllow}
		},
	)
	server := httptest.NewServer(proxy)
	defer server.Close()

	first := getTest(t, server.URL+"/protected")
	_ = first.Body.Close()
	passCookie := first.Cookies()[0]

	for _, target := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/public"},
		{method: http.MethodOptions, path: "/protected"},
	} {
		req := newTestRequest(t, target.method, server.URL+target.path, nil)
		req.AddCookie(passCookie)
		resp := doTestRequest(t, req)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s returned %d", target.method, target.path, resp.StatusCode)
		}
	}

	secondReq := newTestRequest(t, http.MethodGet, server.URL+"/protected", nil)
	secondReq.AddCookie(passCookie)
	second := doTestRequest(t, secondReq)
	_ = second.Body.Close()
	if decisions != 1 {
		t.Fatalf("expected public and OPTIONS requests not to consume pass, decisions=%d", decisions)
	}
}

func TestGuardProxyContinuationPassStartsCountingOnReload(t *testing.T) {
	decisions := 0
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.PassRequestLimit = 1 },
		func(_ testDecisionRequest) api.ResponseData {
			decisions++
			return api.ResponseData{Outcome: api.OutcomeAllow}
		},
	)
	server := httptest.NewServer(proxy)
	defer server.Close()

	continuation := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque"}`))
	_ = continuation.Body.Close()
	passCookie := continuation.Cookies()[0]

	reloadReq := newTestRequest(t, http.MethodGet, server.URL+"/protected", nil)
	reloadReq.AddCookie(passCookie)
	reload := doTestRequest(t, reloadReq)
	_ = reload.Body.Close()
	if reload.StatusCode != http.StatusOK || decisions != 1 {
		t.Fatalf("expected reload to use continuation pass: status=%d decisions=%d", reload.StatusCode, decisions)
	}

	nextReq := newTestRequest(t, http.MethodGet, server.URL+"/protected", nil)
	nextReq.AddCookie(passCookie)
	next := doTestRequest(t, nextReq)
	_ = next.Body.Close()
	if next.StatusCode != http.StatusOK || decisions != 2 {
		t.Fatalf("expected next request to be rescreened: status=%d decisions=%d", next.StatusCode, decisions)
	}
}

func TestGuardProxyBlock(t *testing.T) {
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		return api.ResponseData{Outcome: api.OutcomeBlock}
	})
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected blocked response: %d %#v", resp.StatusCode, resp.Header)
	}
}

func TestGuardProxyBlockRedirect(t *testing.T) {
	const redirectURL = "https://example.com/request-blocked"
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.BlockRedirectURL = redirectURL },
		func(_ testDecisionRequest) api.ResponseData {
			return api.ResponseData{Outcome: api.OutcomeBlock}
		},
	)
	server := httptest.NewServer(proxy)
	defer server.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req := newTestRequest(t, http.MethodGet, server.URL+"/protected", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != redirectURL || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected block redirect: status=%d headers=%#v", resp.StatusCode, resp.Header)
	}

	continueResp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque"}`))
	defer continueResp.Body.Close()
	var result continueResponse
	_ = json.NewDecoder(continueResp.Body).Decode(&result)
	if continueResp.StatusCode != http.StatusOK || result.Outcome != api.OutcomeBlock || result.RedirectURL != redirectURL || len(continueResp.Cookies()) != 0 {
		t.Fatalf("unexpected continuation block redirect: status=%d result=%#v cookies=%#v", continueResp.StatusCode, result, continueResp.Cookies())
	}
}

func TestGuardProxyDryRunAllowsPrescreenBlock(t *testing.T) {
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.DryRun = true },
		func(_ testDecisionRequest) api.ResponseData {
			return api.ResponseData{Outcome: api.OutcomeBlock}
		},
	)
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Upstream") != "true" || len(resp.Cookies()) != 1 {
		t.Fatalf("unexpected dry-run response: status=%d headers=%#v cookies=%#v", resp.StatusCode, resp.Header, resp.Cookies())
	}
}

func TestGuardProxyDryRunContinuesToBrowserCheck(t *testing.T) {
	proxy, _ := newTestProxyWithConfig(
		t,
		func(cfg *config.Config) { cfg.DryRun = true },
		func(_ testDecisionRequest) api.ResponseData {
			return api.ResponseData{
				Outcome:          api.OutcomeCheck,
				InterstitialHTML: "<p>check</p>",
			}
		},
	)
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "<p>check</p>" || len(resp.Cookies()) != 0 {
		t.Fatalf("unexpected dry-run check response: status=%d body=%q cookies=%#v", resp.StatusCode, body, resp.Cookies())
	}
}

func TestGuardProxyInterstitialAndContinuation(t *testing.T) {
	proxy, _ := newTestProxy(t, func(req testDecisionRequest) api.ResponseData {
		if req.Sitekey != "guard-sitekey" {
			t.Errorf("continuation used unexpected sitekey: %q", req.Sitekey)
		}
		if req.ScreeningContext == "" {
			return api.ResponseData{
				Outcome:          api.OutcomeCheck,
				InterstitialHTML: "<p>check</p>",
			}
		}
		if req.ScreeningContext != "opaque-frcapi-context" && req.ScreeningContext != "opaque-challenge-context" {
			t.Errorf("continuation used unexpected screening context: %q", req.ScreeningContext)
		}
		if req.ScreeningContext == "opaque-frcapi-context" {
			return api.ResponseData{Outcome: api.OutcomeChallenge, ScreeningContext: "opaque-challenge-context"}
		}
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" || string(body) != "<p>check</p>" {
		t.Fatalf("unexpected interstitial: status=%d headers=%#v body=%q", resp.StatusCode, resp.Header, body)
	}
	payload := `{"screening_context":"opaque-frcapi-context","risk_token":"real-token"}`
	continueResp := postJSONTest(t, server.URL+continuePath, strings.NewReader(payload))
	var result continueResponse
	_ = json.NewDecoder(continueResp.Body).Decode(&result)
	_ = continueResp.Body.Close()
	if result.Outcome != api.OutcomeChallenge || result.ScreeningContext != "opaque-challenge-context" {
		t.Fatalf("unexpected continuation: %#v", result)
	}

	payload = `{"screening_context":"opaque-challenge-context","captcha_response":"real-response"}`
	continueResp = postJSONTest(t, server.URL+continuePath, strings.NewReader(payload))
	_ = json.NewDecoder(continueResp.Body).Decode(&result)
	_ = continueResp.Body.Close()
	if result.Outcome != api.OutcomeAllow || len(continueResp.Cookies()) != 1 {
		t.Fatalf("unexpected challenge continuation: %#v cookies=%#v", result, continueResp.Cookies())
	}
}

func TestGuardProxyFailsOpenForRequestError(t *testing.T) {
	proxy, apiServer := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	apiServer.Close()
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	defer resp.Body.Close()
	if resp.Header.Get("X-Upstream") != "true" {
		t.Fatal("expected API failure to proxy upstream")
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != passCookieName || cookies[0].MaxAge != 900 {
		t.Fatalf("expected prescreen API failure to fail open with 15-minute pass: cookies=%#v", cookies)
	}

	continueResp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque","risk_token":"token"}`))
	defer continueResp.Body.Close()
	var result continueResponse
	_ = json.NewDecoder(continueResp.Body).Decode(&result)
	if continueResp.StatusCode != http.StatusOK || result.Outcome != api.OutcomeAllow || len(continueResp.Cookies()) != 1 {
		t.Fatalf("expected continuation API failure to fail open with pass: status=%d result=%#v cookies=%#v", continueResp.StatusCode, result, continueResp.Cookies())
	}
}

func TestGuardProxyFailsOpenForServerDecisionStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Upstream", "true")
	}))
	defer upstream.Close()
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"success":false,"error":{"detail":"unavailable"}}`)
	}))
	defer apiServer.Close()

	cfg := validConfig()
	cfg.Upstream.Origin = upstream.URL
	cfg.FriendlyGuardAPI.APIEndpoint = apiServer.URL
	cfg.FriendlyGuardAPI.TimeoutSeconds = 1
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Upstream") != "true" || len(resp.Cookies()) != 1 {
		t.Fatalf("expected prescreen server API status to fail open: status=%d cookies=%#v", resp.StatusCode, resp.Cookies())
	}

	continueResp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque","risk_token":"token"}`))
	defer continueResp.Body.Close()
	var result continueResponse
	_ = json.NewDecoder(continueResp.Body).Decode(&result)
	if continueResp.StatusCode != http.StatusOK || result.Outcome != api.OutcomeAllow || len(continueResp.Cookies()) != 1 {
		t.Fatalf("expected continuation server API status to fail open: status=%d result=%#v cookies=%#v", continueResp.StatusCode, result, continueResp.Cookies())
	}
}

func TestGuardProxyFailClosedForRequestError(t *testing.T) {
	proxy, apiServer := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	apiServer.Close()
	proxy.cfg.FailureMode = "closed"
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/protected")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected prescreen fail-closed 503, got %d", resp.StatusCode)
	}

	continueResp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque","risk_token":"token"}`))
	_ = continueResp.Body.Close()
	if continueResp.StatusCode != http.StatusBadGateway || len(continueResp.Cookies()) != 0 {
		t.Fatalf("expected continuation fail-closed without pass, status=%d cookies=%#v", continueResp.StatusCode, continueResp.Cookies())
	}
}

func TestGuardProxyClientDecisionStatusNeverMintsPass(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid api key", http.StatusUnauthorized)
	}))
	defer apiServer.Close()

	cfg := validConfig()
	cfg.Upstream.Origin = upstream.URL
	cfg.FriendlyGuardAPI.APIEndpoint = apiServer.URL
	cfg.FriendlyGuardAPI.TimeoutSeconds = 1
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()

	prescreenResp := getTest(t, server.URL+"/protected")
	_ = prescreenResp.Body.Close()
	if prescreenResp.StatusCode != http.StatusBadGateway || len(prescreenResp.Cookies()) != 0 || prescreenResp.Header.Get("X-Upstream") != "" {
		t.Fatalf("expected client decision status without pass or proxying, status=%d cookies=%#v", prescreenResp.StatusCode, prescreenResp.Cookies())
	}

	resp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque","risk_token":"token"}`))
	defer resp.Body.Close()
	var result continueResponse
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusBadGateway || result.Outcome != api.OutcomeError || len(resp.Cookies()) != 0 {
		t.Fatalf("expected client decision status without pass, status=%d result=%#v cookies=%#v", resp.StatusCode, result, resp.Cookies())
	}
}

func TestGuardProxyInternalEndpointsAreReserved(t *testing.T) {
	decisions := 0
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		decisions++
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	server := httptest.NewServer(proxy)
	defer server.Close()

	for _, test := range []struct {
		name   string
		method string
		path   string
		status int
		body   string
	}{
		{name: "health", method: http.MethodGet, path: healthPath, status: http.StatusOK, body: "ok\n"},
		{name: "health wrong method", method: http.MethodPost, path: healthPath, status: http.StatusMethodNotAllowed, body: "method not allowed\n"},
		{name: "continue wrong method", method: http.MethodGet, path: continuePath, status: http.StatusMethodNotAllowed, body: "method not allowed\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resp := doTestRequest(t, newTestRequest(t, test.method, server.URL+test.path, nil))
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != test.status || string(body) != test.body {
				t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, body)
			}
			if resp.Header.Get("X-Upstream") != "" {
				t.Fatal("internal endpoint reached upstream")
			}
		})
	}
	if decisions != 0 {
		t.Fatalf("internal endpoints made %d decision calls", decisions)
	}
}

func TestGuardProxyRejectsMalformedContinuationRequests(t *testing.T) {
	decisions := 0
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		decisions++
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	server := httptest.NewServer(proxy)
	defer server.Close()

	for _, test := range []struct {
		name        string
		contentType string
		body        string
		status      int
	}{
		{name: "missing content type", body: `{"screening_context":"opaque"}`, status: http.StatusUnsupportedMediaType},
		{name: "wrong content type", contentType: "text/plain", body: `{"screening_context":"opaque"}`, status: http.StatusUnsupportedMediaType},
		{name: "malformed JSON", contentType: "application/json", body: `{`, status: http.StatusBadRequest},
		{name: "multiple JSON values", contentType: "application/json", body: `{"screening_context":"opaque"}{}`, status: http.StatusBadRequest},
		{name: "oversized body", contentType: "application/json", body: `{"screening_context":"` + strings.Repeat("a", 64<<10) + `"}`, status: http.StatusBadRequest},
		{name: "missing screening context", contentType: "application/json", body: `{"risk_token":"token"}`, status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := newTestRequest(t, http.MethodPost, server.URL+continuePath, strings.NewReader(test.body))
			if test.contentType != "" {
				req.Header.Set("Content-Type", test.contentType)
			}
			resp := doTestRequest(t, req)
			_ = resp.Body.Close()
			if resp.StatusCode != test.status || len(resp.Cookies()) != 0 {
				t.Fatalf("unexpected response: status=%d cookies=%#v", resp.StatusCode, resp.Cookies())
			}
		})
	}
	if decisions != 0 {
		t.Fatalf("malformed requests made %d decision calls", decisions)
	}
}

func TestGuardProxyRejectsInvalidDecisionPayloads(t *testing.T) {
	for _, test := range []struct {
		name     string
		response api.ResponseData
	}{
		{name: "browser check without HTML", response: api.ResponseData{Outcome: api.OutcomeCheck}},
		{name: "empty outcome", response: api.ResponseData{}},
	} {
		t.Run("prescreen "+test.name, func(t *testing.T) {
			proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData { return test.response })
			server := httptest.NewServer(proxy)
			defer server.Close()

			resp := getTest(t, server.URL+"/protected")
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway || len(resp.Cookies()) != 0 || resp.Header.Get("X-Upstream") != "" {
				t.Fatalf("unexpected response: status=%d cookies=%#v", resp.StatusCode, resp.Cookies())
			}
		})
	}

	for _, test := range []struct {
		name     string
		response api.ResponseData
	}{
		{name: "challenge without rotated token", response: api.ResponseData{Outcome: api.OutcomeChallenge}},
		{name: "empty outcome", response: api.ResponseData{}},
	} {
		t.Run("continuation "+test.name, func(t *testing.T) {
			proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData { return test.response })
			server := httptest.NewServer(proxy)
			defer server.Close()

			resp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque"}`))
			defer resp.Body.Close()
			var result continueResponse
			_ = json.NewDecoder(resp.Body).Decode(&result)
			if resp.StatusCode != http.StatusBadGateway || result.Outcome != api.OutcomeError || len(resp.Cookies()) != 0 {
				t.Fatalf("unexpected response: status=%d result=%#v cookies=%#v", resp.StatusCode, result, resp.Cookies())
			}
		})
	}
}

func TestGuardProxyContinuationBlockDoesNotMintPass(t *testing.T) {
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		return api.ResponseData{Outcome: api.OutcomeBlock}
	})
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque"}`))
	defer resp.Body.Close()
	var result continueResponse
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK || result.Outcome != api.OutcomeBlock || len(resp.Cookies()) != 0 {
		t.Fatalf("unexpected block response: status=%d result=%#v cookies=%#v", resp.StatusCode, result, resp.Cookies())
	}
}

func TestGuardProxyDryRunAllowsContinuationDecisions(t *testing.T) {
	for _, outcome := range []api.Outcome{api.OutcomeBlock, api.OutcomeChallenge} {
		t.Run(outcome, func(t *testing.T) {
			proxy, _ := newTestProxyWithConfig(
				t,
				func(cfg *config.Config) { cfg.DryRun = true },
				func(_ testDecisionRequest) api.ResponseData {
					return api.ResponseData{
						Outcome:          outcome,
						ScreeningContext: "opaque-challenge-context",
					}
				},
			)
			server := httptest.NewServer(proxy)
			defer server.Close()

			resp := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque"}`))
			defer resp.Body.Close()
			var result continueResponse
			_ = json.NewDecoder(resp.Body).Decode(&result)
			if resp.StatusCode != http.StatusOK || result.Outcome != api.OutcomeAllow || len(resp.Cookies()) != 1 {
				t.Fatalf("unexpected dry-run response: status=%d result=%#v cookies=%#v", resp.StatusCode, result, resp.Cookies())
			}
		})
	}
}

func TestGuardProxyUnknownOutcomeRespectsFailureMode(t *testing.T) {
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
				return api.ResponseData{Outcome: "UNKNOWN"}
			})
			proxy.cfg.FailureMode = mode
			server := httptest.NewServer(proxy)
			defer server.Close()

			prescreen := getTest(t, server.URL+"/protected")
			_ = prescreen.Body.Close()
			if mode == "open" {
				if prescreen.StatusCode != http.StatusOK || prescreen.Header.Get("X-Upstream") != "true" || len(prescreen.Cookies()) != 1 {
					t.Fatalf("unexpected fail-open prescreen response: status=%d cookies=%#v", prescreen.StatusCode, prescreen.Cookies())
				}
			} else if prescreen.StatusCode != http.StatusBadGateway || len(prescreen.Cookies()) != 0 {
				t.Fatalf("unexpected fail-closed prescreen response: status=%d cookies=%#v", prescreen.StatusCode, prescreen.Cookies())
			}

			continuation := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque"}`))
			defer continuation.Body.Close()
			var result continueResponse
			_ = json.NewDecoder(continuation.Body).Decode(&result)
			if mode == "open" {
				if continuation.StatusCode != http.StatusOK || result.Outcome != api.OutcomeAllow || len(continuation.Cookies()) != 1 {
					t.Fatalf("unexpected fail-open continuation response: status=%d result=%#v cookies=%#v", continuation.StatusCode, result, continuation.Cookies())
				}
			} else if continuation.StatusCode != http.StatusBadGateway || result.Outcome != api.OutcomeError || len(continuation.Cookies()) != 0 {
				t.Fatalf("unexpected fail-closed continuation response: status=%d result=%#v cookies=%#v", continuation.StatusCode, result, continuation.Cookies())
			}
		})
	}
}

func TestGuardProxyMalformedDecisionResponseNeverFailsOpen(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
				return api.ResponseData{Outcome: api.OutcomeAllow}
			})
			apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "{")
			}))
			defer apiServer.Close()
			proxy.apiClient = api.NewClient(apiServer.URL, "api-key", time.Second)
			server := httptest.NewServer(proxy)
			defer server.Close()

			prescreen := getTest(t, server.URL+"/protected")
			_ = prescreen.Body.Close()
			if prescreen.StatusCode != http.StatusBadGateway || len(prescreen.Cookies()) != 0 || prescreen.Header.Get("X-Upstream") != "" {
				t.Fatalf("unexpected prescreen response: status=%d cookies=%#v", prescreen.StatusCode, prescreen.Cookies())
			}

			continuation := postJSONTest(t, server.URL+continuePath, strings.NewReader(`{"screening_context":"opaque"}`))
			var result continueResponse
			_ = json.NewDecoder(continuation.Body).Decode(&result)
			_ = continuation.Body.Close()
			if continuation.StatusCode != http.StatusBadGateway || result.Outcome != api.OutcomeError || len(continuation.Cookies()) != 0 {
				t.Fatalf("unexpected continuation response: status=%d result=%#v cookies=%#v", continuation.StatusCode, result, continuation.Cookies())
			}
		})
	}
}

func TestGuardProxyClearsBindingMismatchedPass(t *testing.T) {
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	passRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://guard.example/protected", nil)
	passRequest.Header.Set("User-Agent", "original-browser")
	signedPass, err := proxy.pass.NewForRequest(passRequest, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()

	req := newTestRequest(t, http.MethodPost, server.URL+"/protected", nil)
	req.Header.Set("User-Agent", "different-browser")
	req.AddCookie(&http.Cookie{Name: passCookieName, Value: signedPass.Token})
	resp := doTestRequest(t, req)
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if resp.StatusCode != http.StatusForbidden || len(cookies) != 1 || cookies[0].Name != passCookieName || cookies[0].MaxAge >= 0 || cookies[0].Value != "" {
		t.Fatalf("expected mismatched pass to be cleared: status=%d cookies=%#v", resp.StatusCode, cookies)
	}
}

func TestGuardProxyPassCookieSecureUsesTrustedScheme(t *testing.T) {
	proxy, _ := newTestProxy(t, func(_ testDecisionRequest) api.ResponseData {
		return api.ResponseData{Outcome: api.OutcomeAllow}
	})
	trusted, err := requestinfo.NewTrustedProxySet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	proxy.trusted = trusted

	for _, test := range []struct {
		name       string
		remoteAddr string
		secure     bool
	}{
		{name: "trusted HTTPS proxy", remoteAddr: "10.1.2.3:12345", secure: true},
		{name: "untrusted spoofed scheme", remoteAddr: "192.0.2.10:12345", secure: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://guard.example/protected", nil)
			req.RemoteAddr = test.remoteAddr
			req.Header.Set("X-Forwarded-Proto", "https")
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Secure != test.secure {
				t.Fatalf("unexpected pass cookie: %#v", cookies)
			}
		})
	}
}

func TestGuardProxyPreservesUpstreamResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Upstream-Response", "preserved")
		http.SetCookie(w, &http.Cookie{Name: "upstream_session", Value: "value", Path: "/"})
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer upstream.Close()

	cfg := validConfig()
	cfg.Upstream.Origin = upstream.URL
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/public")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("X-Upstream-Response") != "preserved" || string(body) != "created" {
		t.Fatalf("upstream response was not preserved: status=%d headers=%#v body=%q", resp.StatusCode, resp.Header, body)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "upstream_session" || cookies[0].Value != "value" {
		t.Fatalf("upstream cookie was not preserved: %#v", cookies)
	}
}

func TestGuardProxyReturnsBadGatewayWhenUpstreamIsUnavailable(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstreamURL := upstream.URL
	upstream.Close()

	cfg := validConfig()
	cfg.Upstream.Origin = upstreamURL
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()

	resp := getTest(t, server.URL+"/public")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || string(body) != "Friendly Guard Proxy upstream unavailable\n" {
		t.Fatalf("unexpected upstream failure response: status=%d body=%q", resp.StatusCode, body)
	}
}
