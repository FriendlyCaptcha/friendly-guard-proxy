package guard

import (
	"testing"
)

func TestMatcher(t *testing.T) {
	m, err := newMatcher([]string{"^/protected(/.*)?$"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.protected("/protected/article?ignored=true") {
		t.Fatal("expected normalized path to be protected")
	}
	if !m.protected("/public?/../protected/article") {
		t.Fatal("expected a decoded question mark not to hide a protected path")
	}
	if !m.protected("/public/../protected/article") {
		t.Fatal("expected path that normalizes to a guarded route to be protected")
	}
	if !m.protected("/protected/../public") {
		t.Fatal("expected raw guarded path to be protected")
	}
	if m.protected("/public") {
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
