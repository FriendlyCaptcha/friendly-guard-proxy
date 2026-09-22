package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	limiter, err := New(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	limiter.Track("partly-used-id", 1)
	if !limiter.Allow("partly-used-id") {
		t.Fatal("expected final request within limit to be allowed")
	}
	if limiter.Allow("partly-used-id") {
		t.Fatal("expected request beyond limit to be rejected")
	}

	otherLimiter, err := New(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !otherLimiter.Allow("new-id") {
		t.Fatal("expected an untracked ID to start at zero")
	}
	if otherLimiter.Allow("new-id") {
		t.Fatal("expected untracked ID to be limited after its first request")
	}
}

func TestLimiterIncrementsAtomically(t *testing.T) {
	const attempts = 20
	const limit = 5
	limiter, err := New(limit, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	var allowed atomic.Int32
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			if limiter.Allow("id") {
				allowed.Add(1)
			}
		}()
	}
	group.Wait()

	if got := allowed.Load(); got != limit {
		t.Fatalf("allowed %d concurrent requests, want %d", got, limit)
	}
	tracked, ok := limiter.counts.Get("id")
	if !ok {
		t.Fatal("expected ID to be tracked")
	}
	if got := tracked.requests.Load(); got != limit {
		t.Fatalf("counter reached %d requests, want it capped at %d", got, limit)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, test := range []struct {
		name  string
		limit int
		ttl   time.Duration
	}{
		{name: "zero limit", limit: 0, ttl: time.Minute},
		{name: "negative limit", limit: -1, ttl: time.Minute},
		{name: "zero TTL", limit: 1, ttl: 0},
		{name: "negative TTL", limit: 1, ttl: -time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.limit, test.ttl); err == nil {
				t.Fatal("expected invalid config to be rejected")
			}
		})
	}
}
