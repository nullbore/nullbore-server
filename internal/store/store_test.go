package store

import (
	"database/sql"
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

// TestEventStoreInspectionRoundtrip exercises the LogRequestWithID +
// UpdateResponse + GetRequest path the replay/sniffer code depends on.
// Schema regressions (missing columns, ALTER TABLE typo) show up here
// before they show up in CI.
func TestEventStoreInspectionRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	es, err := NewEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer es.Close()

	// Mint id up-front (the relay path needs this so it can correlate the
	// response back to the row).
	id := es.NewRequestID()
	if id == "" {
		t.Fatal("NewRequestID returned empty")
	}

	gotID := es.LogRequestWithID(id, "tun-1", "abcd", "POST", "/users?x=1",
		`{"Content-Type":"application/json"}`, 7, `{"hi":1}`, "10.0.0.1")
	if gotID != id {
		t.Errorf("LogRequestWithID returned %q, want %q", gotID, id)
	}

	// Initial GetRequest: row should exist but response fields all zero.
	r, err := es.GetRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("GetRequest returned nil for fresh row")
	}
	if r.Method != "POST" || r.Path != "/users?x=1" || r.RemoteIP != "10.0.0.1" {
		t.Errorf("row contents mismatch: %+v", r)
	}
	if r.BodySnip != `{"hi":1}` {
		t.Errorf("body snippet mismatch: %q", r.BodySnip)
	}
	if r.StatusCode != 0 || r.DurationMs != 0 || r.ResponseBytes != 0 {
		t.Errorf("expected zero response fields, got status=%d ms=%d bytes=%d",
			r.StatusCode, r.DurationMs, r.ResponseBytes)
	}

	// UpdateResponse should populate them.
	es.UpdateResponse(id, 201, 42, 1234)

	r2, err := es.GetRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	if r2.StatusCode != 201 || r2.DurationMs != 42 || r2.ResponseBytes != 1234 {
		t.Errorf("after UpdateResponse: status=%d ms=%d bytes=%d, want 201/42/1234",
			r2.StatusCode, r2.DurationMs, r2.ResponseBytes)
	}

	// UpdateResponse with empty id is a no-op (shouldn't blow up).
	es.UpdateResponse("", 500, 99, 0)

	// GetRequest on unknown id returns nil, nil — not an error.
	none, err := es.GetRequest("does-not-exist")
	if err != nil {
		t.Errorf("expected nil error for unknown id, got %v", err)
	}
	if none != nil {
		t.Errorf("expected nil row for unknown id, got %+v", none)
	}

	// ListRequests should now return the row with full response fields.
	logs, err := es.ListRequests("tun-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].StatusCode != 201 {
		t.Errorf("ListRequests = %+v", logs)
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

// TestTunnelModeRoundTrip verifies the tunnel mode survives Save → Get /
// List / LoadActiveTunnels, and that an unset mode reads back as "relay".
// A passthrough tunnel that silently restored as relay would lose its
// end-to-end property after a server restart.
func TestTunnelModeRoundTrip(t *testing.T) {
	s := testStore(t)
	now := time.Now().Truncate(time.Second)

	for _, rec := range []*TunnelRecord{
		{ID: "pt", Slug: "pt1", ClientID: "u1", LocalPort: 8443, TTL: 3600, Status: "active",
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), Mode: "tls-passthrough"},
		{ID: "rl", Slug: "rl1", ClientID: "u1", LocalPort: 3000, TTL: 3600, Status: "active",
			CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour)}, // Mode unset
	} {
		if err := s.SaveTunnel(rec); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.GetTunnel("pt")
	if err != nil || got == nil {
		t.Fatalf("GetTunnel: %v %v", got, err)
	}
	if got.Mode != "tls-passthrough" {
		t.Errorf("GetTunnel mode = %q, want tls-passthrough", got.Mode)
	}
	got, _ = s.GetTunnel("rl")
	if got.Mode != "relay" {
		t.Errorf("unset mode read back as %q, want relay", got.Mode)
	}

	active, err := s.LoadActiveTunnels()
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string]string{}
	for _, r := range active {
		modes[r.ID] = r.Mode
	}
	if modes["pt"] != "tls-passthrough" || modes["rl"] != "relay" {
		t.Errorf("LoadActiveTunnels modes = %v", modes)
	}

	list, err := s.ListTunnels("u1", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("ListTunnels returned %d rows", len(list))
	}
	for _, r := range list {
		if r.Mode != modes[r.ID] {
			t.Errorf("ListTunnels %s mode = %q, want %q", r.ID, r.Mode, modes[r.ID])
		}
	}
}

// TestTunnelModeMigration opens a DB whose tunnels table pre-dates the mode
// column (the shape currently in production), and checks New() adds the
// column, existing rows read back as "relay", and reopening is idempotent.
func TestTunnelModeMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE tunnels (
			id TEXT PRIMARY KEY, slug TEXT NOT NULL, client_id TEXT NOT NULL,
			local_port INTEGER NOT NULL, name TEXT DEFAULT '', ttl_seconds INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT 'active', created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL, closed_at DATETIME,
			bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0, requests INTEGER DEFAULT 0
		);
		INSERT INTO tunnels (id, slug, client_id, local_port, ttl_seconds, created_at, expires_at)
		VALUES ('old', 'old1', 'u1', 3000, 3600, datetime('now'), datetime('now', '+1 hour'));`)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	for i := 0; i < 2; i++ { // second open must be a no-op migration
		s, err := New(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i+1, err)
		}
		got, err := s.GetTunnel("old")
		if err != nil || got == nil {
			t.Fatalf("open #%d GetTunnel: %v %v", i+1, got, err)
		}
		if got.Mode != "relay" {
			t.Errorf("open #%d: legacy row mode = %q, want relay", i+1, got.Mode)
		}
		s.Close()
	}
}
