// Package ratelimit provides bounded, in-memory rate limiting by opaque ID.
package ratelimit

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/maypok86/otter"
)

const maxTrackedIDs = 100_000

type counter struct {
	requests atomic.Int64
}

// Limiter counts requests by ID.
type Limiter struct {
	limit  int64
	counts *otter.Cache[string, *counter]
}

// New creates a rate limiter with the given request limit and entry TTL.
func New(limit int, ttl time.Duration) (*Limiter, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("rate limit must be positive")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("rate limit TTL must be positive")
	}

	builder, err := otter.NewBuilder[string, *counter](maxTrackedIDs)
	if err != nil {
		return nil, fmt.Errorf("create rate limiter cache: %w", err)
	}
	cache, err := builder.WithTTL(ttl).Build()
	if err != nil {
		return nil, fmt.Errorf("build rate limiter cache: %w", err)
	}
	return &Limiter{
		limit:  int64(limit),
		counts: &cache,
	}, nil
}

// Track starts tracking an ID with the given number of requests already used.
func (l *Limiter) Track(id string, requests int) {
	if requests <= 0 {
		return
	}
	tracked := &counter{}
	tracked.requests.Store(int64(requests))
	l.counts.Set(id, tracked)
}

// Allow counts a request for an ID and reports whether it is within the limit.
func (l *Limiter) Allow(id string) bool {
	tracked := l.counterFor(id)
	// Another request can increment the counter between Load and
	// CompareAndSwap. Retry with the new value so this request either claims a
	// remaining slot or observes that the limit has been reached.
	for {
		requests := tracked.requests.Load()
		if requests >= l.limit {
			return false
		}
		if tracked.requests.CompareAndSwap(requests, requests+1) {
			return true
		}
	}
}

func (l *Limiter) counterFor(id string) *counter {
	for {
		if tracked, ok := l.counts.Get(id); ok {
			return tracked
		}
		tracked := &counter{}
		if l.counts.SetIfAbsent(id, tracked) {
			return tracked
		}
	}
}
