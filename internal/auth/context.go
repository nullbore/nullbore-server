package auth

import "context"

type contextKey string

const (
	clientIDKey contextKey = "clientID"
	tierKey     contextKey = "tier"
)

// WithClientID returns a context with the client ID set.
func WithClientID(ctx context.Context, clientID string) context.Context {
	return context.WithValue(ctx, clientIDKey, clientID)
}

// ClientIDFrom extracts the client ID from the context.
func ClientIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(clientIDKey).(string)
	return v
}

// WithTier returns a context with the tier set.
func WithTier(ctx context.Context, tier string) context.Context {
	return context.WithValue(ctx, tierKey, tier)
}

// TierFrom extracts the tier from the context.
func TierFrom(ctx context.Context) string {
	v, _ := ctx.Value(tierKey).(string)
	return v
}
