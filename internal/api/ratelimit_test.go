package api

import (
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	// 2 per second, burst of 3
	rl := NewRateLimiter(2, time.Second, 3)

	// First 3 should pass (burst)
	for i := 0; i < 3; i++ {
		if !rl.Allow("client1") {
			t.Fatalf("request %d should be allowed (burst)", i)
		}
	}

	// 4th should be denied
	if rl.Allow("client1") {
		t.Fatal("request should be denied (burst exhausted)")
	}

	// Different client should still be allowed
	if !rl.Allow("client2") {
		t.Fatal("different client should be allowed")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(10, 100*time.Millisecond, 2)

	// Exhaust bucket
	rl.Allow("test")
	rl.Allow("test")
	if rl.Allow("test") {
		t.Fatal("should be denied")
	}

	// Wait for refill
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if !rl.Allow("test") {
		t.Fatal("should be allowed after refill")
	}
}

func TestRateLimiterIdleTTL(t *testing.T) {
	cases := []struct {
		name           string
		rate, burst    int
		interval, want time.Duration
	}{
		{"fast refill keeps 10m floor", 10, 5, time.Minute, 10 * time.Minute},
		{"per-second proxy limiter", 1000, 2000, time.Second, 10 * time.Minute},
		{"30/hour acme limiter", 1, 30, 2 * time.Minute, time.Hour},
		{"uneven burst rounds up", 2, 5, 10 * time.Minute, 30 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rl := &RateLimiter{rate: c.rate, interval: c.interval, burst: c.burst}
			if got := rl.idleTTL(); got != c.want {
				t.Errorf("idleTTL = %v, want %v", got, c.want)
			}
		})
	}
}

// A drained slow-refill bucket must survive cleanup until it would have
// refilled on its own; otherwise cleanup hands out a fresh burst early.
func TestRateLimiterCleanupKeepsDrainedSlowBucket(t *testing.T) {
	rl := &RateLimiter{buckets: map[string]*bucket{}, rate: 1, interval: 2 * time.Minute, burst: 30}
	rl.buckets["drained"] = &bucket{tokens: 0, lastFill: time.Now().Add(-15 * time.Minute)}
	rl.buckets["stale"] = &bucket{tokens: 0, lastFill: time.Now().Add(-61 * time.Minute)}
	rl.cleanup()
	if _, ok := rl.buckets["drained"]; !ok {
		t.Error("drained bucket 15m old was dropped; would reset to a full burst")
	}
	if _, ok := rl.buckets["stale"]; ok {
		t.Error("bucket idle longer than full refill should be dropped")
	}
}
