package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Provider validates API keys and returns a client ID.
type Provider interface {
	// Validate checks a bearer token. Returns client ID and ok.
	Validate(token string) (clientID string, ok bool)

	// Middleware returns an HTTP middleware that enforces auth.
	Middleware(next http.Handler) http.Handler
}

// StaticProvider validates against a static list of API keys.
// Each key format: "nbk_<clientid>_<secret>" or just a raw token.
// For dev/testing. Production will use hashed keys from the dashboard DB.
type StaticProvider struct {
	keys map[string]string // token -> clientID
}

func NewStaticProvider(commaSeparated string) *StaticProvider {
	p := &StaticProvider{
		keys: make(map[string]string),
	}

	if commaSeparated == "" {
		return p
	}

	for _, key := range strings.Split(commaSeparated, ",") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		// Extract client ID from key format nbk_<clientid>_<secret>
		parts := strings.SplitN(key, "_", 3)
		clientID := "default"
		if len(parts) >= 2 {
			clientID = parts[1]
		}
		p.keys[key] = clientID
	}

	return p
}

func (p *StaticProvider) Validate(token string) (string, bool) {
	if len(p.keys) == 0 {
		// No keys configured = dev mode, accept everything
		return "dev", true
	}

	for key, clientID := range p.keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1 {
			return clientID, true
		}
	}
	return "", false
}

func (p *StaticProvider) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			http.Error(w, `{"error":"invalid authorization format, use Bearer <token>"}`, http.StatusUnauthorized)
			return
		}

		clientID, ok := p.Validate(token)
		if !ok {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}

		// Inject client ID into request context
		r = r.WithContext(WithClientID(r.Context(), clientID))
		next.ServeHTTP(w, r)
	})
}
