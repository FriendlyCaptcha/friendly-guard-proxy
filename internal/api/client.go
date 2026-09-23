package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/friendlycaptcha/friendly-guard-proxy/internal/buildinfo"
)

type PrescreenRequest struct {
	Sitekey        string                   `json:"sitekey"`
	RequestContext PreescreenRequestContext `json:"request_context"`
}

type PreescreenRequestContext struct {
	ClientIP             string `json:"client_ip"`
	Method               string `json:"method"`
	Scheme               string `json:"scheme"`
	Host                 string `json:"host"`
	Path                 string `json:"path"`
	HeaderUserAgent      string `json:"header_user_agent"`
	HeaderAccept         string `json:"header_accept"`
	HeaderAcceptLanguage string `json:"header_accept_language"`
	HeaderSecFetchDest   string `json:"header_sec_fetch_dest"`
	HeaderSecFetchMode   string `json:"header_sec_fetch_mode"`
	HeaderSecFetchSite   string `json:"header_sec_fetch_site"`
	HeaderSecFetchUser   string `json:"header_sec_fetch_user"`
	HeaderSignature      string `json:"header_signature"`
	HeaderSignatureInput string `json:"header_signature_input"`
	HeaderSignatureAgent string `json:"header_signature_agent"`
}

type DecideRequest struct {
	Sitekey          string `json:"sitekey"`
	ScreeningContext string `json:"screening_context"`
	RiskToken        string `json:"risk_token,omitempty"`
	CaptchaResponse  string `json:"captcha_response,omitempty"`
}

type Outcome = string

const (
	OutcomeAllow     Outcome = "ALLOW"
	OutcomeBlock     Outcome = "BLOCK"
	OutcomeCheck     Outcome = "CHECK"
	OutcomeChallenge Outcome = "CHALLENGE"
	OutcomeError     Outcome = "ERROR"
)

const guardSDKName = "guard-proxy"

var (
	// ErrGuardRequest is returned when a Guard API request fails.
	ErrGuardRequest = errors.New("Guard API request failed") //nolint:staticcheck // Guard should be capitalized
	// ErrMalformedResponse is returned when a Guard API response cannot be decoded.
	ErrMalformedResponse = errors.New("Guard API response is malformed") //nolint:staticcheck // Guard should be capitalized
)

type Response struct {
	Success bool           `json:"success"`
	Data    *ResponseData  `json:"data,omitempty"`
	Error   *ResponseError `json:"error,omitempty"`
}

type ResponseData struct {
	ScreeningID      string  `json:"screening_id"`
	Outcome          Outcome `json:"outcome"`
	ScreeningContext string  `json:"screening_context,omitempty"`
	InterstitialHTML string  `json:"interstitial_html,omitempty"`
}

type ResponseError struct {
	ErrorCode string `json:"error_code"`
	Detail    string `json:"detail"`
}

type Result struct {
	StatusCode int
	Response   Response
}

func (r Result) Failed() bool {
	return !r.Response.Success || r.StatusCode < http.StatusOK || r.StatusCode >= http.StatusMultipleChoices
}

func (r Result) Error() error {
	switch {
	case r.Response.Error != nil && r.Response.Error.ErrorCode != "" && r.Response.Error.Detail != "":
		return fmt.Errorf("API status=%d error_code=%s detail=%s", r.StatusCode, r.Response.Error.ErrorCode, r.Response.Error.Detail)
	case r.Response.Error != nil && r.Response.Error.ErrorCode != "":
		return fmt.Errorf("API status=%d error_code=%s", r.StatusCode, r.Response.Error.ErrorCode)
	case r.Response.Error != nil && r.Response.Error.Detail != "":
		return fmt.Errorf("API status=%d detail=%s", r.StatusCode, r.Response.Error.Detail)
	case r.StatusCode != 0:
		return fmt.Errorf("API status=%d", r.StatusCode)
	default:
		return nil
	}
}

func (r Result) Data() (ResponseData, error) {
	if r.Response.Data == nil {
		return ResponseData{}, fmt.Errorf("decision response data is nil")
	}
	if r.Response.Data.Outcome == "" {
		return ResponseData{}, fmt.Errorf("decision response outcome is empty")
	}
	return *r.Response.Data, nil
}

type Client struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

func NewClient(endpoint string, apiKey string, timeout time.Duration) *Client {
	return &Client{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: timeout},
	}
}

func (c *Client) Prescreen(ctx context.Context, request PrescreenRequest) (Result, error) {
	return c.post(ctx, "/api/v2/guard/prescreen", request)
}

func (c *Client) Decide(ctx context.Context, request DecideRequest) (Result, error) {
	return c.post(ctx, "/api/v2/guard/decide", request)
}

func (c *Client) post(ctx context.Context, path string, request any) (Result, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return Result{}, fmt.Errorf("failed to marshal API request: %w", err)
	}

	url, err := url.JoinPath(c.endpoint, path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to build API URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("failed to build API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Frc-Guard-Sdk", fmt.Sprintf("%s@%s", guardSDKName, buildinfo.Version()))

	resp, err := c.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrGuardRequest, err)
	}
	defer resp.Body.Close()

	result := Result{StatusCode: resp.StatusCode}
	if err := json.NewDecoder(resp.Body).Decode(&result.Response); err != nil {
		return result, fmt.Errorf("%w: failed to decode API response: %w", ErrMalformedResponse, err)
	}
	return result, nil
}
