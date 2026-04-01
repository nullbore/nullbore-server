package auth

import (
	"net/http"
	"strings"
)

// ComboProvider tries Primary first, then falls back to Fallback.
// This allows remote (dashboard) auth with static keys as backup.
type ComboProvider struct {
	Primary  Provider
	Fallback Provider
}

func (c *ComboProvider) Validate(token string) (string, bool) {
	if clientID, ok := c.Primary.Validate(token); ok {
		return clientID, true
	}
	return c.Fallback.Validate(token)
}

func (c *ComboProvider) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Pass device info to remote provider if available
		deviceID := r.Header.Get("X-NullBore-Device-ID")
		deviceHostname := r.Header.Get("X-NullBore-Device-Hostname")
		deviceTakeover := r.Header.Get("X-NullBore-Device-Takeover") == "true"

		var clientID string
		var ok bool

		if rp, isRemote := c.Primary.(*RemoteProvider); isRemote && (deviceID != "" || deviceHostname != "") {
			clientID, ok = rp.ValidateWithDevice(token, deviceID, deviceHostname, deviceTakeover)
		} else {
			clientID, ok = c.Validate(token)
		}

		if !ok {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}

		ctx := WithClientID(r.Context(), clientID)

		// Set tier and device warning from remote provider cache
		if rp, isRemote := c.Primary.(*RemoteProvider); isRemote {
			if tier := rp.GetTier(token); tier != "" {
				ctx = WithTier(ctx, tier)
			}
			// Inject device warning as response header so client can display it
			if warning := rp.GetDeviceWarning(token); warning != "" {
				w.Header().Set("X-NullBore-Device-Warning", warning)
			}
		}

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
