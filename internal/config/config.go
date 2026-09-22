package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// MinPassSigningSecretBytes is the minimum length of a configured pass signing secret.
const MinPassSigningSecretBytes = 32

type Config struct {
	Server            ServerConfig           `yaml:"server"`
	Upstream          UpstreamConfig         `yaml:"upstream"`
	FriendlyGuardAPI  FriendlyGuardAPIConfig `yaml:"friendly_guard_api"`
	PassSigningSecret string                 `yaml:"pass_signing_secret"`
	PassRequestLimit  int                    `yaml:"pass_request_limit"`
	TrustedProxies    []string               `yaml:"trusted_proxies"`
	GuardedRoutes     []string               `yaml:"guarded_routes"`
	FailureMode       string                 `yaml:"failure_mode"`
	DryRun            bool                   `yaml:"dry_run"`
	BlockRedirectURL  string                 `yaml:"block_redirect_url"`
}

type ServerConfig struct {
	Listen string `yaml:"listen"`
}

type UpstreamConfig struct {
	Origin string `yaml:"origin"`
}

type FriendlyGuardAPIConfig struct {
	APIEndpoint    string `yaml:"api_endpoint"`
	Sitekey        string `yaml:"sitekey"`
	APIKey         string `yaml:"api_key"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

func defaultConfig() Config {
	return Config{
		Server: ServerConfig{
			Listen: ":8080",
		},
		FriendlyGuardAPI: FriendlyGuardAPIConfig{
			APIEndpoint:    "eu",
			TimeoutSeconds: 5,
		},
		PassRequestLimit: 100,
		FailureMode:      "open",
	}
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	expanded := []byte(os.ExpandEnv(string(data)))
	decoder := yaml.NewDecoder(bytes.NewReader(expanded))
	decoder.KnownFields(true)
	cfg := defaultConfig()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	switch {
	case c.Server.Listen == "":
		return fmt.Errorf("server.listen is required")
	case c.Upstream.Origin == "":
		return fmt.Errorf("upstream.origin is required")
	case c.FriendlyGuardAPI.APIEndpoint == "":
		return fmt.Errorf("friendly_guard_api.api_endpoint is required")
	case c.FriendlyGuardAPI.Sitekey == "":
		return fmt.Errorf("friendly_guard_api.sitekey is required")
	case c.FriendlyGuardAPI.APIKey == "":
		return fmt.Errorf("friendly_guard_api.api_key is required")
	case c.FriendlyGuardAPI.TimeoutSeconds <= 0:
		return fmt.Errorf("friendly_guard_api.timeout_seconds must be positive")
	case c.PassRequestLimit < 0:
		return fmt.Errorf("pass_request_limit must be non-negative")
	case c.PassSigningSecret != "" && len(c.PassSigningSecret) < MinPassSigningSecretBytes:
		return fmt.Errorf("pass_signing_secret must be at least %d bytes", MinPassSigningSecretBytes)
	}

	upstream, err := url.Parse(c.Upstream.Origin)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" || upstream.User != nil {
		return fmt.Errorf("upstream.origin must be an http(s) URL without credentials")
	}
	if _, err := ResolveAPIEndpoint(c.FriendlyGuardAPI.APIEndpoint); err != nil {
		return fmt.Errorf("friendly_guard_api.api_endpoint is invalid: %w", err)
	}
	if err := validateFailureMode("failure_mode", c.FailureMode); err != nil {
		return err
	}
	if c.BlockRedirectURL != "" {
		redirectURL, err := url.Parse(c.BlockRedirectURL)
		if err != nil || (redirectURL.Scheme != "http" && redirectURL.Scheme != "https") || redirectURL.Host == "" || redirectURL.User != nil {
			return fmt.Errorf("block_redirect_url must be an http(s) URL without credentials")
		}
	}
	for _, value := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("trusted_proxies contains invalid CIDR %q: %w", value, err)
		}
	}

	if len(c.GuardedRoutes) == 0 {
		return fmt.Errorf("guarded_routes must contain at least one entry")
	}
	for _, route := range c.GuardedRoutes {
		if route == "" {
			return fmt.Errorf("guarded_routes entries must be non-empty regexes")
		}
		if _, err := regexp.Compile(route); err != nil {
			return fmt.Errorf("invalid guarded_routes entry regex %q: %w", route, err)
		}
	}
	return nil
}

func validateFailureMode(name string, value string) error {
	switch value {
	case "open", "closed":
		return nil
	default:
		return fmt.Errorf("%s must be open or closed", name)
	}
}

func ResolveAPIEndpoint(endpoint string) (string, error) {
	switch strings.ToLower(endpoint) {
	case "eu":
		return "https://eu.frcapi.com", nil
	case "global":
		return "https://global.frcapi.com", nil
	}

	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("expected 'eu', 'global', or a valid URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
