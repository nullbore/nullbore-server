package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// RemoteProvider validates API keys by calling the dashboard's internal
// key validation endpoint. Caches valid keys to avoid hitting the dashboard
// on every request.
type RemoteProvider struct {
	dashboardURL string
	secret       string // shared secret for server→dashboard communication
	client       *http.Client

	// Cache valid keys: rawKey -> cacheEntry
	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	clientID       string
	userID         string
	tier           string
	keyID          string
	deviceWarning  string
	ipAllowlist    []string // CIDRs for IP allowlisting
	bandwidthUsed  int64
	bandwidthLimit int64
	validAt        time.Time
	expiresAt      time.Time
}

const cacheTTL = 5 * time.Minute

type validateResponse struct {
	Valid          bool     `json:"valid"`
	ClientID       string   `json:"client_id"`
	UserID         string   `json:"user_id"`
	Tier           string   `json:"tier"`
	KeyID          string   `json:"key_id"`
	DeviceID       string   `json:"device_id"`
	DeviceHostname string   `json:"device_hostname"`
	DeviceWarning  string   `json:"device_warning"`
	IPAllowlist    []string `json:"ip_allowlist"`
	BandwidthUsed  int64    `json:"bandwidth_used"`
	BandwidthLimit int64    `json:"bandwidth_limit"`
}

func NewRemoteProvider(dashboardURL, secret string) *RemoteProvider {
	return &RemoteProvider{
		dashboardURL: dashboardURL,
		secret:       secret,
		client:       &http.Client{Timeout: 5 * time.Second},
		cache:        make(map[string]*cacheEntry),
	}
}

func (p *RemoteProvider) Validate(token string) (string, bool) {
	return p.ValidateWithDevice(token, "", "", false)
}

func (p *RemoteProvider) ValidateWithDevice(token, deviceID, deviceHostname string, takeover bool) (string, bool) {
	// Check cache first
	p.mu.RLock()
	entry, ok := p.cache[token]
	p.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.clientID, true
	}

	// Build request body with device info
	bodyData, _ := json.Marshal(map[string]interface{}{
		"device_id":       deviceID,
		"device_hostname": deviceHostname,
		"takeover":        takeover,
	})

	// Call dashboard to validate
	req, err := http.NewRequest("POST", p.dashboardURL+"/internal/validate-key", bytes.NewReader(bodyData))
	if err != nil {
		log.Printf("auth: remote validate error: %v", err)
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if p.secret != "" {
		req.Header.Set("X-Internal-Secret", p.secret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("auth: dashboard unreachable: %v", err)
		// If dashboard is down, fall back to cache (even if expired) for resilience
		if ok {
			log.Printf("auth: using expired cache for key %s...", token[:12])
			return entry.clientID, true
		}
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", false
	}

	var result validateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("auth: failed to parse validate response: %v", err)
		return "", false
	}

	if !result.Valid {
		return "", false
	}

	// Use user_id as the client_id for multi-tenant isolation
	clientID := result.UserID
	if clientID == "" {
		clientID = result.ClientID
	}

	// Cache the result
	p.mu.Lock()
	p.cache[token] = &cacheEntry{
		clientID:       clientID,
		userID:         result.UserID,
		tier:           result.Tier,
		keyID:          result.KeyID,
		deviceWarning:  result.DeviceWarning,
		ipAllowlist:    result.IPAllowlist,
		bandwidthUsed:  result.BandwidthUsed,
		bandwidthLimit: result.BandwidthLimit,
		validAt:        time.Now(),
		expiresAt:      time.Now().Add(cacheTTL),
	}
	p.mu.Unlock()

	if result.DeviceWarning != "" {
		log.Printf("auth: device warning for key %s: %s", token[:12], result.DeviceWarning)
	}

	return clientID, true
}

// GetDeviceWarning returns any device warning for a cached token.
func (p *RemoteProvider) GetDeviceWarning(token string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if entry, ok := p.cache[token]; ok {
		return entry.deviceWarning
	}
	return ""
}

// GetKeyID returns the key ID for a cached token.
func (p *RemoteProvider) GetKeyID(token string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if entry, ok := p.cache[token]; ok {
		return entry.keyID
	}
	return ""
}

// GetTier returns the tier for a cached token. Returns empty string if not cached.
func (p *RemoteProvider) GetTier(token string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if entry, ok := p.cache[token]; ok {
		return entry.tier
	}
	return ""
}

// GetBandwidthInfo returns (used, limit) for a cached token.
func (p *RemoteProvider) GetBandwidthInfo(token string) (int64, int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e, ok := p.cache[token]; ok {
		return e.bandwidthUsed, e.bandwidthLimit
	}
	return 0, 0
}

func (p *RemoteProvider) Middleware(next http.Handler) http.Handler {
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

		token := authHeader
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		clientID, ok := p.Validate(token)
		if !ok {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}

		r = r.WithContext(WithClientID(r.Context(), clientID))
		next.ServeHTTP(w, r)
	})
}

// StartCacheReaper periodically cleans expired cache entries.
func (p *RemoteProvider) StartCacheReaper() {
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			now := time.Now()
			p.mu.Lock()
			for key, entry := range p.cache {
				if now.After(entry.expiresAt.Add(10 * time.Minute)) {
					delete(p.cache, key)
				}
			}
			p.mu.Unlock()
		}
	}()
}

// GetIPAllowlistForUser returns the cached IP allowlist CIDRs for a given user ID.
// Returns nil if not cached or no allowlist set.
func (p *RemoteProvider) GetIPAllowlistForUser(userID string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, entry := range p.cache {
		if entry.userID == userID {
			return entry.ipAllowlist
		}
	}
	return nil
}

func (p *RemoteProvider) String() string {
	return fmt.Sprintf("RemoteProvider{dashboard=%s}", p.dashboardURL)
}
