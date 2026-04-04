package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SubdomainResolver resolves account subdomains to user IDs.
// Queries the dashboard API and caches results.
type SubdomainResolver struct {
	dashboardURL string
	secret       string
	client       *http.Client

	mu    sync.RWMutex
	cache map[string]*subdomainEntry
}

type subdomainEntry struct {
	userID    string
	fetchedAt time.Time
	err       error
}

const subdomainCacheTTL = 2 * time.Minute

// NewSubdomainResolver creates a resolver for account subdomains.
func NewSubdomainResolver(dashboardURL, secret string) *SubdomainResolver {
	return &SubdomainResolver{
		dashboardURL: dashboardURL,
		secret:       secret,
		client:       &http.Client{Timeout: 5 * time.Second},
		cache:        make(map[string]*subdomainEntry),
	}
}

// Resolve returns the user ID for an account subdomain.
func (sr *SubdomainResolver) Resolve(name string) (string, error) {
	name = strings.ToLower(name)

	sr.mu.RLock()
	entry, ok := sr.cache[name]
	sr.mu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < subdomainCacheTTL {
		if entry.err != nil {
			return "", entry.err
		}
		return entry.userID, nil
	}

	userID, err := sr.lookup(name)

	sr.mu.Lock()
	sr.cache[name] = &subdomainEntry{
		userID:    userID,
		fetchedAt: time.Now(),
		err:       err,
	}
	sr.mu.Unlock()

	return userID, err
}

func (sr *SubdomainResolver) lookup(name string) (string, error) {
	url := fmt.Sprintf("%s/internal/resolve-subdomain?name=%s", sr.dashboardURL, name)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Internal-Secret", sr.secret)

	resp, err := sr.client.Do(req)
	if err != nil {
		slog.Warn("subdomain lookup failed", "name", name, "error", err)
		return "", fmt.Errorf("subdomain lookup failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("subdomain %q not found", name)
	}

	var result struct {
		UserID string `json:"user_id"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.UserID, nil
}

// StartCacheReaper periodically cleans expired subdomain cache entries.
func (sr *SubdomainResolver) StartCacheReaper() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sr.mu.Lock()
			for k, v := range sr.cache {
				if time.Since(v.fetchedAt) > subdomainCacheTTL*3 {
					delete(sr.cache, k)
				}
			}
			sr.mu.Unlock()
		}
	}()
}
