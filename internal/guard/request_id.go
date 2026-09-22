package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type requestIDContextKey struct{}

func newRequestID() string {
	// Always generate a unique request ID.
	// In the future we could have a configuration option to use a request ID from a provided header.
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func contextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func requestIDFromContext(r interface{ Context() context.Context }) string {
	value, _ := r.Context().Value(requestIDContextKey{}).(string)
	return value
}
