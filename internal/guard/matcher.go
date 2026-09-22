package guard

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/friendlycaptcha/friendly-guard-proxy/internal/requestinfo"
)

type matcher struct {
	patterns []*regexp.Regexp
}

func newMatcher(guardedRoutes []string) (*matcher, error) {
	out := &matcher{}
	for _, route := range guardedRoutes {
		re, err := regexp.Compile(route)
		if err != nil {
			return nil, fmt.Errorf("compile guarded route %q: %w", route, err)
		}
		out.patterns = append(out.patterns, re)
		slog.Info("registered guarded route", "route", route)
	}
	return out, nil
}

func normalizePath(value string) string {
	return requestinfo.NormalizePath(value)
}

func (m *matcher) protected(value string) bool {
	normalized := normalizePath(value)
	for _, pattern := range m.patterns {
		// Match both forms because the upstream may normalize dot segments before routing.
		// Protecting either interpretation prevents Guard and the upstream from disagreeing.
		if pattern.MatchString(value) || pattern.MatchString(normalized) {
			return true
		}
	}
	return false
}
