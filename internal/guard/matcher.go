package guard

import (
	"fmt"
	"log/slog"
	"net/url"
	"regexp"

	"github.com/friendlycaptcha/friendly-guard-proxy/internal/config"
	"github.com/friendlycaptcha/friendly-guard-proxy/internal/requestinfo"
)

type matcher struct {
	routes []routeMatcher
}

type routeMatcher struct {
	path  *regexp.Regexp
	query map[string]*regexp.Regexp
}

func newMatcher(guardedRoutes []config.GuardedRoute) (*matcher, error) {
	out := &matcher{}
	for _, route := range guardedRoutes {
		re, err := regexp.Compile(route.Path)
		if err != nil {
			return nil, fmt.Errorf("compile guarded route %q: %w", route.Path, err)
		}
		compiled := routeMatcher{path: re, query: make(map[string]*regexp.Regexp, len(route.Query))}
		for key, value := range route.Query {
			pattern, err := regexp.Compile(value)
			if err != nil {
				return nil, fmt.Errorf("compile guarded route query %q: %w", key, err)
			}
			compiled.query[key] = pattern
		}
		out.routes = append(out.routes, compiled)
		slog.Info("registered guarded route", "route", route.Path, "query", route.Query)
	}
	return out, nil
}

func normalizePath(value string) string {
	return requestinfo.NormalizePath(value)
}

func (m *matcher) protected(u *url.URL) bool {
	normalized := normalizePath(u.Path)
	var query url.Values
	var queryErr error
	queryParsed := false
	for _, route := range m.routes {
		// Match both forms because the upstream may normalize dot segments before routing.
		// Protecting either interpretation prevents Guard and the upstream from disagreeing.
		if !route.path.MatchString(u.Path) && !route.path.MatchString(normalized) {
			continue
		}
		if len(route.query) == 0 {
			return true
		}
		if !queryParsed {
			query, queryErr = url.ParseQuery(u.RawQuery)
			queryParsed = true
		}
		// A partially parsed query could hide a protected operation from Guard.
		if queryErr != nil || route.matchesQuery(query) {
			return true
		}
	}
	return false
}

func (r routeMatcher) matchesQuery(query url.Values) bool {
	for key, pattern := range r.query {
		matched := false
		for _, value := range query[key] {
			if pattern.MatchString(value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
