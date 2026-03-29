package api

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a per-key token bucket rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int           // tokens per interval
	interval time.Duration // refill interval
	burst    int           // max tokens (burst capacity)
}

type bucket struct {
	tokens    int
	lastFill  time.Time
}

// NewRateLimiter creates a rate limiter.
// rate: how many tokens to add per interval.
// interval: how often to refill.
// burst: maximum tokens (caps the bucket).
func NewRateLimiter(rate int, interval time.Duration, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		interval: interval,
		burst:    burst,
	}

	// Reaper: clean up stale buckets every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

// Allow checks if a request is allowed for the given key.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.burst, lastFill: time.Now()}
		rl.buckets[key] = b
	}

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(b.lastFill)
	refills := int(elapsed / rl.interval)
	if refills > 0 {
		b.tokens += refills * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.lastFill = now
	}

	if b.tokens <= 0 {
		return false
	}

	b.tokens--
	return true
}

// Middleware returns an HTTP middleware that rate limits by client ID.
// keyFunc extracts the rate limit key from the request.
func (rl *RateLimiter) Middleware(keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			if !rl.Allow(key) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error": "rate limit exceeded, try again later",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for key, b := range rl.buckets {
		if b.lastFill.Before(cutoff) {
			delete(rl.buckets, key)
		}
	}
}
