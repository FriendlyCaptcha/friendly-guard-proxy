package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		Server:   ServerConfig{Listen: ":8080"},
		Upstream: UpstreamConfig{Origin: "http://127.0.0.1:3000"},
		FriendlyGuardAPI: FriendlyGuardAPIConfig{
			APIEndpoint:    "eu",
			Sitekey:        "guard-sitekey",
			APIKey:         "api-key",
			TimeoutSeconds: 1,
		},
		PassSigningSecret: "0123456789abcdef0123456789abcdef",
		PassRequestLimit:  100,
		GuardedRoutes:     []GuardedRoute{{Path: "^/protected(/.*)?$"}},
		FailureMode:       "open",
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.PassRequestLimit = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected zero pass request limit to disable rate limiting: %v", err)
	}
	cfg.PassSigningSecret = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected an empty pass signing secret to be accepted: %v", err)
	}
	cfg.BlockRedirectURL = "https://example.com/request-blocked"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid block redirect URL to be accepted: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing upstream", mutate: func(c *Config) { c.Upstream.Origin = "" }},
		{name: "invalid upstream scheme", mutate: func(c *Config) { c.Upstream.Origin = "ftp://example.com" }},
		{name: "upstream credentials", mutate: func(c *Config) { c.Upstream.Origin = "https://user:pass@example.com" }},
		{name: "missing sitekey", mutate: func(c *Config) { c.FriendlyGuardAPI.Sitekey = "" }},
		{name: "missing API key", mutate: func(c *Config) { c.FriendlyGuardAPI.APIKey = "" }},
		{name: "invalid API endpoint", mutate: func(c *Config) { c.FriendlyGuardAPI.APIEndpoint = "://" }},
		{name: "negative timeout", mutate: func(c *Config) { c.FriendlyGuardAPI.TimeoutSeconds = -1 }},
		{name: "negative pass request limit", mutate: func(c *Config) { c.PassRequestLimit = -1 }},
		{name: "short pass signing secret", mutate: func(c *Config) { c.PassSigningSecret = "too-short" }},
		{name: "invalid failure mode", mutate: func(c *Config) { c.FailureMode = "sometimes" }},
		{name: "invalid block redirect URL", mutate: func(c *Config) { c.BlockRedirectURL = "/request-blocked" }},
		{name: "block redirect URL credentials", mutate: func(c *Config) { c.BlockRedirectURL = "https://user:pass@example.com/request-blocked" }},
		{name: "invalid trusted proxy", mutate: func(c *Config) { c.TrustedProxies = []string{"not-a-cidr"} }},
		{name: "empty guarded routes", mutate: func(c *Config) { c.GuardedRoutes = nil }},
		{name: "empty guarded route", mutate: func(c *Config) { c.GuardedRoutes = []GuardedRoute{{}} }},
		{name: "invalid guarded route", mutate: func(c *Config) { c.GuardedRoutes = []GuardedRoute{{Path: "["}} }},
		{name: "invalid query regex", mutate: func(c *Config) { c.GuardedRoutes[0].Query = map[string]string{"export": "["} }},
		{name: "empty query key", mutate: func(c *Config) { c.GuardedRoutes[0].Query = map[string]string{"": ".*"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected invalid config to be rejected")
			}
		})
	}
}

func TestLoadConfigExpandsEnvironmentAndKeepsDefaultValues(t *testing.T) {
	t.Setenv("FRIENDLY_GUARD_TEST_API_KEY", "expanded-api-key")
	t.Setenv("FRIENDLY_GUARD_TEST_PASS_SIGNING_SECRET", "expanded-0123456789abcdef0123456")
	path := filepath.Join(t.TempDir(), "friendly-guard-proxy.yml")
	config := `
upstream:
  origin: http://127.0.0.1:3000
friendly_guard_api:
  sitekey: guard-sitekey
  api_key: ${FRIENDLY_GUARD_TEST_API_KEY}
pass_signing_secret: ${FRIENDLY_GUARD_TEST_PASS_SIGNING_SECRET}
guarded_routes:
  - path: ^/protected(/.*)?$
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FriendlyGuardAPI.APIKey != "expanded-api-key" || cfg.PassSigningSecret != "expanded-0123456789abcdef0123456" || cfg.Server.Listen != ":8080" || cfg.FriendlyGuardAPI.TimeoutSeconds != 5 || cfg.PassRequestLimit != 100 || cfg.FailureMode != "open" || cfg.DryRun {
		t.Fatalf("unexpected loaded config: %#v", cfg)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "friendly-guard-proxy.yml")
	config := `
upstream:
  origin: http://127.0.0.1:3000
friendly_guard_api:
  sitekey: guard-sitekey
  api_key: api-key
guarded_route_typo:
  - path: ^/protected(/.*)?$
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected unknown config field to be rejected")
	}
	if !strings.Contains(err.Error(), "field guarded_route_typo not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveAPIEndpoint(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "eu", want: "https://eu.frcapi.com"},
		{input: "GLOBAL", want: "https://global.frcapi.com"},
		{input: "https://frcapi.example/base/", want: "https://frcapi.example/base"},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, err := ResolveAPIEndpoint(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
		})
	}
}

func TestLoadConfigGuardedRoutes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routes  string
		want    []GuardedRoute
		wantErr string
	}{
		{
			name: "path-only and query rules",
			routes: `
  - path: '^/protected$'
  - path: '^/search$'
    query:
      export: '^true$'
      format: '^(csv|json)$'
  - path: '^/preview$'
    query:
      token: ''
  - path: '^/login$'
`,
			want: []GuardedRoute{
				{Path: "^/protected$"},
				{Path: "^/search$", Query: map[string]string{"export": "^true$", "format": "^(csv|json)$"}},
				{Path: "^/preview$", Query: map[string]string{"token": ""}},
				{Path: "^/login$"},
			},
		},
		{name: "unknown route field", routes: "  - path: '^/search$'\n    qurey: {}\n", wantErr: "field qurey not found"},
		{name: "missing path", routes: "  - query: {export: '^true$'}\n", wantErr: "non-empty path"},
		{name: "invalid path", routes: "  - path: '['\n", wantErr: "path regex"},
		{name: "invalid query", routes: "  - path: '^/search$'\n    query: {export: '['}\n", wantErr: "query regex"},
		{name: "empty key", routes: "  - path: '^/search$'\n    query: {'': '.*'}\n", wantErr: "query keys"},
		{name: "duplicate path", routes: "  - path: '^/search$'\n    path: '^/public$'\n", wantErr: "already defined"},
		{name: "duplicate query key", routes: "  - path: '^/search$'\n    query: {export: '^true$', export: '^false$'}\n", wantErr: "already defined"},
		{name: "query list", routes: "  - path: '^/search$'\n    query: [export]\n", wantErr: "cannot unmarshal"},
		{name: "string route", routes: "  - '^/protected$'\n", wantErr: "cannot unmarshal"},
		{name: "mixed string and object routes", routes: "  - path: '^/search$'\n  - '^/protected$'\n", wantErr: "cannot unmarshal"},
		{name: "boolean route", routes: "  - true\n", wantErr: "cannot unmarshal"},
		{name: "null route", routes: "  - null\n", wantErr: "at least one entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			data := "upstream:\n  origin: http://127.0.0.1:3000\nfriendly_guard_api:\n  sitekey: sitekey\n  api_key: key\nguarded_routes:\n" + tc.routes
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.GuardedRoutes, tc.want) {
				t.Fatalf("guarded routes = %#v, want %#v", cfg.GuardedRoutes, tc.want)
			}
		})
	}
}
