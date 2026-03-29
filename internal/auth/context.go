package auth

import "context"

type contextKey string

const clientIDKey contextKey = "clientID"

// WithClientID returns a context with the client ID set.
func WithClientID(ctx context.Context, clientID string) context.Context {
	return context.WithValue(ctx, clientIDKey, clientID)
}

// ClientIDFrom extracts the client ID from the context.
func ClientIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(clientIDKey).(string)
	return v
}
