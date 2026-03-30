package tunnel

import (
	"testing"
	"time"
)

func TestCreateAndGet(t *testing.T) {
	r := NewRegistry()
	tun, err := r.Create("client1", 8080, "", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if tun.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if tun.Slug == "" {
		t.Fatal("expected non-empty slug")
	}
	if tun.ClientID != "client1" {
		t.Fatalf("expected client1, got %s", tun.ClientID)
	}
	if tun.LocalPort != 8080 {
		t.Fatalf("expected port 8080, got %d", tun.LocalPort)
	}
	if tun.Mode != "relay" {
		t.Fatalf("expected relay mode, got %s", tun.Mode)
	}

	// Get by ID
	got, ok := r.Get(tun.ID)
	if !ok {
		t.Fatal("Get by ID failed")
	}
	if got.ID != tun.ID {
		t.Fatalf("ID mismatch: %s vs %s", got.ID, tun.ID)
	}

	// Get by slug
	got, ok = r.GetBySlug(tun.Slug)
	if !ok {
		t.Fatal("GetBySlug failed")
	}
	if got.ID != tun.ID {
		t.Fatal("GetBySlug returned wrong tunnel")
	}
}

func TestCreateNamedTunnel(t *testing.T) {
	r := NewRegistry()
	tun, err := r.Create("client1", 8080, "myapp", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tun.Slug != "myapp" {
		t.Fatalf("expected slug 'myapp', got %s", tun.Slug)
	}

	// Duplicate name should fail
	_, err = r.Create("client1", 9090, "myapp", 1*time.Hour)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestDefaultTTL(t *testing.T) {
	r := NewRegistry()
	tun, err := r.Create("client1", 8080, "", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Default TTL is 1 hour
	expected := tun.CreatedAt.Add(1 * time.Hour)
	diff := tun.ExpiresAt.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("expected ~1h TTL, got expiry diff %v", diff)
	}
}

func TestMaxTTLCap(t *testing.T) {
	r := NewRegistry()
	tun, err := r.Create("client1", 8080, "", 48*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Should be capped at 24h
	maxExpiry := tun.CreatedAt.Add(24 * time.Hour)
	diff := tun.ExpiresAt.Sub(maxExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("expected TTL capped at 24h, got diff %v", diff)
	}
}

func TestClose(t *testing.T) {
	r := NewRegistry()
	tun, _ := r.Create("client1", 8080, "", 1*time.Hour)

	err := r.Close(tun.ID)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, ok := r.Get(tun.ID)
	if ok {
		t.Fatal("tunnel should be gone after close")
	}

	_, ok = r.GetBySlug(tun.Slug)
	if ok {
		t.Fatal("slug should be gone after close")
	}

	// Double close should error
	err = r.Close(tun.ID)
	if err == nil {
		t.Fatal("expected error closing nonexistent tunnel")
	}
}

func TestList(t *testing.T) {
	r := NewRegistry()
	r.Create("client1", 8080, "", 1*time.Hour)
	r.Create("client1", 9090, "", 1*time.Hour)
	r.Create("client2", 3000, "", 1*time.Hour)

	all := r.List("")
	if len(all) != 3 {
		t.Fatalf("expected 3 tunnels, got %d", len(all))
	}

	c1 := r.List("client1")
	if len(c1) != 2 {
		t.Fatalf("expected 2 tunnels for client1, got %d", len(c1))
	}

	c2 := r.List("client2")
	if len(c2) != 1 {
		t.Fatalf("expected 1 tunnel for client2, got %d", len(c2))
	}
}

func TestExtendTTL(t *testing.T) {
	r := NewRegistry()
	tun, _ := r.Create("client1", 8080, "", 1*time.Hour)

	oldExpiry := tun.ExpiresAt
	err := r.ExtendTTL(tun.ID, 30*time.Minute)
	if err != nil {
		t.Fatalf("ExtendTTL: %v", err)
	}

	got, _ := r.Get(tun.ID)
	if !got.ExpiresAt.After(oldExpiry) {
		t.Fatal("expiry should have been extended")
	}
}

func TestExtendTTLCappedAt24h(t *testing.T) {
	r := NewRegistry()
	tun, _ := r.Create("client1", 8080, "", 23*time.Hour)

	// Try to extend by 3h — should be capped at 24h from creation
	r.ExtendTTL(tun.ID, 3*time.Hour)

	got, _ := r.Get(tun.ID)
	maxExpiry := tun.CreatedAt.Add(24 * time.Hour)
	diff := got.ExpiresAt.Sub(maxExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("expected extension capped at 24h, got diff %v", diff)
	}
}

func TestReapExpired(t *testing.T) {
	r := NewRegistry()

	// Create a tunnel that's already expired
	tun, _ := r.Create("client1", 8080, "", 1*time.Millisecond)
	_ = tun

	// Wait for it to expire
	time.Sleep(10 * time.Millisecond)

	// Manually trigger reap
	r.reapExpired()

	all := r.List("")
	if len(all) != 0 {
		t.Fatalf("expected 0 tunnels after reap, got %d", len(all))
	}
}

func TestSlugUniqueness(t *testing.T) {
	r := NewRegistry()
	slugs := make(map[string]bool)

	for i := 0; i < 100; i++ {
		tun, err := r.Create("client1", 8080, "", 1*time.Hour)
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		if slugs[tun.Slug] {
			t.Fatalf("duplicate slug: %s", tun.Slug)
		}
		slugs[tun.Slug] = true
	}
}

func TestAddStats(t *testing.T) {
	r := NewRegistry()
	tun, _ := r.Create("client1", 8080, "", 1*time.Hour)

	tun.AddStats(1024, 2048)
	tun.AddStats(512, 256)

	if tun.BytesIn != 1536 {
		t.Fatalf("expected BytesIn 1536, got %d", tun.BytesIn)
	}
	if tun.BytesOut != 2304 {
		t.Fatalf("expected BytesOut 2304, got %d", tun.BytesOut)
	}
	if tun.Requests != 2 {
		t.Fatalf("expected Requests 2, got %d", tun.Requests)
	}
}

func TestIdleTTLExtends(t *testing.T) {
	r := NewRegistry()
	tunnel, err := r.Create("client1", 8080, "", 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.IdleTTL = true
	originalExpiry := tunnel.ExpiresAt

	// Wait a bit, then simulate activity
	time.Sleep(500 * time.Millisecond)
	tunnel.AddRequest()

	// Expiry should have been extended
	if !tunnel.ExpiresAt.After(originalExpiry) {
		t.Errorf("expected expiry to extend, got %v (was %v)", tunnel.ExpiresAt, originalExpiry)
	}
}

func TestNonIdleTTLDoesNotExtend(t *testing.T) {
	r := NewRegistry()
	tunnel, err := r.Create("client1", 8080, "", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// IdleTTL defaults to false
	originalExpiry := tunnel.ExpiresAt

	tunnel.AddRequest()

	if tunnel.ExpiresAt != originalExpiry {
		t.Errorf("expected expiry unchanged, got %v (was %v)", tunnel.ExpiresAt, originalExpiry)
	}
}

func TestAddBytesTracking(t *testing.T) {
	r := NewRegistry()
	tunnel, err := r.Create("client1", 8080, "", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tunnel.AddBytes(1024, 2048)
	tunnel.AddBytes(512, 256)

	if tunnel.BytesIn != 1536 {
		t.Errorf("expected BytesIn=1536, got %d", tunnel.BytesIn)
	}
	if tunnel.BytesOut != 2304 {
		t.Errorf("expected BytesOut=2304, got %d", tunnel.BytesOut)
	}
	if tunnel.Requests != 0 {
		t.Errorf("expected Requests=0 (AddBytes doesn't increment), got %d", tunnel.Requests)
	}
}
