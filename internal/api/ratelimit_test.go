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
