package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSaveAndLoadTunnels(t *testing.T) {
	s := testStore(t)

	now := time.Now().Truncate(time.Second)
	rec := &TunnelRecord{
		ID:        "test-123",
		Slug:      "abc123",
		ClientID:  "user-1",
		LocalPort: 3000,
		Name:      "my-api",
		TTL:       3600,
		Status:    "active",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}

	if err := s.SaveTunnel(rec); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetTunnel("test-123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("tunnel not found")
	}
	if got.Slug != "abc123" || got.ClientID != "user-1" || got.LocalPort != 3000 {
		t.Errorf("tunnel = %+v", got)
	}
}

func TestLoadActiveTunnels(t *testing.T) {
	s := testStore(t)

	now := time.Now().Truncate(time.Second)

	// Active tunnel (not expired)
	s.SaveTunnel(&TunnelRecord{
		ID: "active-1", Slug: "a1", ClientID: "u1", LocalPort: 3000,
		TTL: 3600, Status: "active", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	// Expired tunnel (should not load)
	s.SaveTunnel(&TunnelRecord{
		ID: "expired-1", Slug: "e1", ClientID: "u1", LocalPort: 4000,
		TTL: 60, Status: "active", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	})

	// Closed tunnel (should not load)
	s.SaveTunnel(&TunnelRecord{
		ID: "closed-1", Slug: "c1", ClientID: "u1", LocalPort: 5000,
		TTL: 3600, Status: "closed", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	tunnels, err := s.LoadActiveTunnels()
	if err != nil {
		t.Fatal(err)
	}

	if len(tunnels) != 1 {
		t.Fatalf("expected 1 active tunnel, got %d", len(tunnels))
	}
	if tunnels[0].ID != "active-1" {
		t.Errorf("expected active-1, got %s", tunnels[0].ID)
	}
}

func TestFlushTunnelStats(t *testing.T) {
	s := testStore(t)

	now := time.Now().Truncate(time.Second)
	s.SaveTunnel(&TunnelRecord{
		ID: "stats-1", Slug: "s1", ClientID: "u1", LocalPort: 3000,
		TTL: 3600, Status: "active", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	newExpiry := now.Add(2 * time.Hour)
	if err := s.FlushTunnelStats("stats-1", 1024, 2048, 10, newExpiry); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetTunnel("stats-1")
	if got.BytesIn != 1024 || got.BytesOut != 2048 || got.Requests != 10 {
		t.Errorf("stats: in=%d out=%d reqs=%d", got.BytesIn, got.BytesOut, got.Requests)
	}
}

func TestEventStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	es, err := NewEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer es.Close()

	// Log events
	es.LogEvent("t1", "u1", "created", "port=3000")
	es.LogEvent("t1", "u1", "closed", "via API")
	es.LogEvent("t2", "u2", "created", "port=8080")

	// Get by tunnel
	events, err := es.GetEvents("t1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events for t1, got %d", len(events))
	}

	// Get by client
	events2, err := es.GetEventsByClient("u1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events2) != 2 {
		t.Errorf("expected 2 events for u1, got %d", len(events2))
	}

	// Log request
	es.LogRequest("t1", "abc", "GET", "/test", "{}", 0, "", "1.2.3.4")
	logs, err := es.ListRequests("t1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Method != "GET" {
		t.Errorf("request log = %+v", logs)
	}
}

func TestEventStoreSeparateDB(t *testing.T) {
	// Verify event store and main store use separate files
	dir := t.TempDir()

	mainDB, err := New(filepath.Join(dir, "main.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer mainDB.Close()

	eventsDB, err := NewEventStore(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer eventsDB.Close()

	// Verify both files exist
	if _, err := os.Stat(filepath.Join(dir, "main.db")); err != nil {
		t.Error("main.db not found")
	}
	if _, err := os.Stat(filepath.Join(dir, "events.db")); err != nil {
		t.Error("events.db not found")
	}
}
