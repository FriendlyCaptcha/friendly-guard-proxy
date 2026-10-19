package guard

import (
	"net/url"
	"testing"

	"github.com/friendlycaptcha/friendly-guard-proxy/internal/config"
)

func TestMatcher(t *testing.T) {
	m, err := newMatcher([]config.GuardedRoute{{Path: "^/protected(/.*)?$"}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.protected(&url.URL{Path: "/protected/article?ignored=true"}) {
		t.Fatal("expected normalized path to be protected")
	}
	if !m.protected(&url.URL{Path: "/public?/../protected/article"}) {
		t.Fatal("expected a decoded question mark not to hide a protected path")
	}
	if !m.protected(&url.URL{Path: "/public/../protected/article"}) {
		t.Fatal("expected path that normalizes to a guarded route to be protected")
	}
	if !m.protected(&url.URL{Path: "/protected/../public"}) {
		t.Fatal("expected raw guarded path to be protected")
	}
	if m.protected(&url.URL{Path: "/public"}) {
		t.Fatal("expected public path not to be protected")
	}
}

func TestNormalizePath(t *testing.T) {
	for input, want := range map[string]string{
		"":                      "/",
		"/protected":            "/protected",
		"/protected/article":    "/protected/article",
		"protected//article/":   "/protected/article",
		"/protected/../public":  "/public",
		"/public?/../protected": "/protected",
	} {
		if got := normalizePath(input); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMatcherQueryConditions(t *testing.T) {
	m, err := newMatcher([]config.GuardedRoute{
		{Path: "^/search$", Query: map[string]string{"export": "^true$", "format": "^(csv|json)$"}},
		{Path: "^/preview$", Query: map[string]string{"token": ".*"}},
		{Path: "^/empty$", Query: map[string]string{"flag": "^$"}},
		{Path: "^/protected$"},
		{Path: "^/export(/.*)?$", Query: map[string]string{"export": "^true$"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"/search", false},
		{"/search?export=true", false},
		{"/search?format=csv", false},
		{"/search?export=false&format=csv", false},
		{"/search?export=true&format=csv", true},
		{"/search?other=1&format=json&export=true", true},
		{"/search?%65xport=tr%75e&format=csv", true},
		{"/search?export=false&export=true&format=csv", true},
		{"/search?export=true&export=false&format=csv", true},
		{"/search?export=TRUE&format=csv", false},
		{"/search?export=almosttrue&format=csv", false},
		{"/public/../search?export=true&format=csv", true},
		{"/search/../public?export=true&format=csv", false},
		{"/export/../public?export=true", true},
		{"/export/../public?export=false", false},
		{"/public?export=true&format=csv", false},
		{"/preview", false},
		{"/preview?token", true},
		{"/preview?token=", true},
		{"/preview?token=a+b", true},
		{"/empty", false},
		{"/empty?flag", true},
		{"/empty?flag=nonempty", false},
		{"/protected?export=false", true},
		{"/search?export=%zz", true},
		{"/search?export=false;format=csv", true},
		{"/public?export=%zz", false},
		{"/search%3Fexport=true?format=csv", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			u, err := url.Parse(tc.url)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.protected(u); got != tc.want {
				t.Fatalf("protected(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestMatcherQueryDecodingAndAlternativeRules(t *testing.T) {
	m, err := newMatcher([]config.GuardedRoute{
		{Path: "^/search$", Query: map[string]string{"action": "^download report$"}},
		{Path: "^/search$", Query: map[string]string{"action": "^export$"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rawQuery := range []string{"action=download+report", "action=download%20report", "action=export"} {
		if !m.protected(&url.URL{Path: "/search", RawQuery: rawQuery}) {
			t.Errorf("expected query %q to match", rawQuery)
		}
	}
}
