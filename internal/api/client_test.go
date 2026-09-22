package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestAPIClientRequestContract(t *testing.T) {
	type recordedRequest struct {
		method      string
		path        string
		contentType string
		apiKey      string
		body        []byte
	}
	requests := make(chan recordedRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- recordedRequest{
			method:      r.Method,
			path:        r.URL.Path,
			contentType: r.Header.Get("Content-Type"),
			apiKey:      r.Header.Get("X-Api-Key"),
			body:        body,
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"data":{"screening_id":"screening-id","outcome":"ALLOW"}}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, "api-key", time.Second)
	requestCtx := PreescreenRequestContext{
		ClientIP:             "203.0.113.8",
		Method:               http.MethodGet,
		Scheme:               "https",
		Host:                 "example.com",
		Path:                 "/protected",
		HeaderUserAgent:      "Mozilla/5.0",
		HeaderAccept:         "text/html",
		HeaderAcceptLanguage: "en",
		HeaderSecFetchDest:   "document",
		HeaderSecFetchMode:   "navigate",
		HeaderSecFetchSite:   "same-origin",
		HeaderSecFetchUser:   "?1",
		HeaderSignature:      "sig1=:signature:",
		HeaderSignatureInput: `sig1=("@method" "@authority")`,
		HeaderSignatureAgent: `"https://example.com"`,
	}
	if result, err := client.Prescreen(context.Background(), PrescreenRequest{Sitekey: "guard-sitekey", RequestContext: requestCtx}); err != nil {
		t.Fatal(err)
	} else if result.Failed() {
		t.Fatal(result.Error())
	} else if data, dataErr := result.Data(); dataErr != nil {
		t.Fatal(dataErr)
	} else if data.ScreeningID != "screening-id" {
		t.Fatalf("unexpected prescreen screening ID: %q", data.ScreeningID)
	}
	if result, err := client.Decide(context.Background(), DecideRequest{Sitekey: "guard-sitekey", ScreeningContext: "screening-context", RiskToken: "risk-token"}); err != nil {
		t.Fatal(err)
	} else if result.Failed() {
		t.Fatal(result.Error())
	} else if data, dataErr := result.Data(); dataErr != nil {
		t.Fatal(dataErr)
	} else if data.ScreeningID != "screening-id" {
		t.Fatalf("unexpected decide screening ID: %q", data.ScreeningID)
	}

	prescreen := <-requests
	if prescreen.method != http.MethodPost || prescreen.path != "/api/v2/guard/prescreen" || prescreen.contentType != "application/json" || prescreen.apiKey != "api-key" {
		t.Fatalf("unexpected prescreen request: %#v", prescreen)
	}
	var prescreenBody PrescreenRequest
	if err := json.Unmarshal(prescreen.body, &prescreenBody); err != nil {
		t.Fatal(err)
	}
	if prescreenBody.Sitekey != "guard-sitekey" || !reflect.DeepEqual(prescreenBody.RequestContext, requestCtx) {
		t.Fatalf("unexpected prescreen body: %#v", prescreenBody)
	}
	var prescreenJSON map[string]any
	if err := json.Unmarshal(prescreen.body, &prescreenJSON); err != nil {
		t.Fatal(err)
	}
	if _, ok := prescreenJSON["api_endpoint"]; ok {
		t.Fatalf("prescreen body should not contain api_endpoint: %#v", prescreenJSON)
	}

	decide := <-requests
	if decide.method != http.MethodPost || decide.path != "/api/v2/guard/decide" || decide.contentType != "application/json" || decide.apiKey != "api-key" {
		t.Fatalf("unexpected decide request: %#v", decide)
	}
	var decideBody map[string]any
	if err := json.Unmarshal(decide.body, &decideBody); err != nil {
		t.Fatal(err)
	}
	if decideBody["sitekey"] != "guard-sitekey" || decideBody["screening_context"] != "screening-context" || decideBody["risk_token"] != "risk-token" {
		t.Fatalf("unexpected decide body: %#v", decideBody)
	}
	if _, ok := decideBody["captcha_response"]; ok {
		t.Fatalf("empty captcha response should be omitted: %#v", decideBody)
	}
}

func TestAPIClientReturnsDecisionResponseError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "server error", status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"success":false,"error":{"error_code":"auth_invalid","detail":"nope"}}`)
			}))
			defer server.Close()
			client := NewClient(server.URL, "api-key", time.Second)
			result, err := client.Prescreen(context.Background(), PrescreenRequest{Sitekey: "guard-sitekey", RequestContext: PreescreenRequestContext{Method: http.MethodGet, Path: "/"}})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Failed() {
				t.Fatal("expected failed result")
			}
			if result.StatusCode != tc.status {
				t.Fatalf("unexpected status: got %d want %d", result.StatusCode, tc.status)
			}
			if result.Response.Error == nil || result.Response.Error.ErrorCode != "auth_invalid" || result.Response.Error.Detail != "nope" {
				t.Fatalf("unexpected response error: %#v", result.Response.Error)
			}
		})
	}
}

func TestAPIClientReturnsDecodeErrorForMalformedErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer server.Close()
	client := NewClient(server.URL, "api-key", time.Second)
	result, err := client.Prescreen(context.Background(), PrescreenRequest{Sitekey: "guard-sitekey", RequestContext: PreescreenRequestContext{Method: http.MethodGet, Path: "/"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("expected malformed response error, got %v", err)
	}
	if result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected status: got %d want %d", result.StatusCode, http.StatusUnauthorized)
	}
}

func TestAPIClientReturnsDecodeErrorForMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer server.Close()
	client := NewClient(server.URL, "api-key", time.Second)
	result, err := client.Prescreen(context.Background(), PrescreenRequest{Sitekey: "guard-sitekey", RequestContext: PreescreenRequestContext{Method: http.MethodGet, Path: "/"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("expected malformed response error, got %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", result.StatusCode)
	}
}

func TestAPIClientReturnsCanceledRequestError(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "api-key", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Prescreen(ctx, PrescreenRequest{Sitekey: "guard-sitekey", RequestContext: PreescreenRequestContext{}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrGuardRequest) {
		t.Fatalf("expected decision request error, got %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected wrapped cancellation, got %v", err)
	}
}
