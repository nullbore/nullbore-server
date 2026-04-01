package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// EventStore manages tunnel events and request logs in a separate database.
// Separating events from the main store makes it easy to swap to a
// time-series DB (e.g., ClickHouse, TimescaleDB) later without touching tunnels.
type EventStore struct {
	db *sql.DB
}

// NewEventStore opens or creates the events SQLite database.
func NewEventStore(path string) (*EventStore, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open events db: %w", err)
	}

	s := &EventStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate events: %w", err)
	}

	return s, nil
}

func (s *EventStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS tunnel_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tunnel_id TEXT NOT NULL,
			client_id TEXT NOT NULL DEFAULT '',
			event TEXT NOT NULL,
			detail TEXT DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_events_tunnel ON tunnel_events(tunnel_id);
		CREATE INDEX IF NOT EXISTS idx_events_client ON tunnel_events(client_id);
		CREATE INDEX IF NOT EXISTS idx_events_time ON tunnel_events(created_at);

		CREATE TABLE IF NOT EXISTS request_log (
			id TEXT PRIMARY KEY,
			tunnel_id TEXT NOT NULL,
			slug TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			headers TEXT NOT NULL DEFAULT '{}',
			body_size INTEGER NOT NULL DEFAULT 0,
			body_snippet TEXT NOT NULL DEFAULT '',
			remote_ip TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_reqlog_tunnel ON request_log(tunnel_id, created_at);
		CREATE INDEX IF NOT EXISTS idx_reqlog_time ON request_log(created_at);
	`)
	return err
}

// LogEvent records a tunnel lifecycle event.
func (s *EventStore) LogEvent(tunnelID, clientID, event, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO tunnel_events (tunnel_id, client_id, event, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
		tunnelID, clientID, event, detail, time.Now())
	return err
}

// GetEvents returns recent events for a tunnel.
func (s *EventStore) GetEvents(tunnelID string, limit int) ([]TunnelEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, tunnel_id, event, detail, created_at FROM tunnel_events WHERE tunnel_id = ? ORDER BY created_at DESC LIMIT ?`,
		tunnelID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []TunnelEvent
	for rows.Next() {
		var e TunnelEvent
		rows.Scan(&e.ID, &e.TunnelID, &e.Event, &e.Detail, &e.CreatedAt)
		events = append(events, e)
	}
	return events, nil
}

// GetEventsByClient returns recent events for a client.
func (s *EventStore) GetEventsByClient(clientID string, limit int) ([]TunnelEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, tunnel_id, event, detail, created_at FROM tunnel_events WHERE client_id = ? ORDER BY created_at DESC LIMIT ?`,
		clientID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []TunnelEvent
	for rows.Next() {
		var e TunnelEvent
		rows.Scan(&e.ID, &e.TunnelID, &e.Event, &e.Detail, &e.CreatedAt)
		events = append(events, e)
	}
	return events, nil
}

// LogRequest records an HTTP request to a tunnel.
func (s *EventStore) LogRequest(tunnelID, slug, method, path, headers string, bodySize int64, bodySnippet, remoteIP string) {
	id := hex.EncodeToString(evtRandomBytes(16))
	s.db.Exec(
		`INSERT INTO request_log (id, tunnel_id, slug, method, path, headers, body_size, body_snippet, remote_ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, tunnelID, slug, method, path, headers, bodySize, bodySnippet, remoteIP, time.Now())
}

// ListRequests returns recent request logs for a tunnel.
func (s *EventStore) ListRequests(tunnelID string, limit int) ([]RequestLog, error) {
	if limit <= 0 {
		limit = 50
	}
	var query string
	var args []interface{}
	if tunnelID != "" {
		query = `SELECT id, tunnel_id, slug, method, path, headers, body_size, body_snippet, remote_ip, created_at FROM request_log WHERE tunnel_id = ? ORDER BY created_at DESC LIMIT ?`
		args = []interface{}{tunnelID, limit}
	} else {
		query = `SELECT id, tunnel_id, slug, method, path, headers, body_size, body_snippet, remote_ip, created_at FROM request_log ORDER BY created_at DESC LIMIT ?`
		args = []interface{}{limit}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []RequestLog
	for rows.Next() {
		var r RequestLog
		if err := rows.Scan(&r.ID, &r.TunnelID, &r.Slug, &r.Method, &r.Path, &r.Headers, &r.BodySize, &r.BodySnip, &r.RemoteIP, &r.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, r)
	}
	if logs == nil {
		logs = []RequestLog{}
	}
	return logs, nil
}

// PruneEvents removes events older than the given duration.
func (s *EventStore) PruneEvents(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	s.db.Exec(`DELETE FROM tunnel_events WHERE created_at < ?`, cutoff)
}

// PruneRequestLog removes request logs older than the given duration.
func (s *EventStore) PruneRequestLog(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	s.db.Exec(`DELETE FROM request_log WHERE created_at < ?`, cutoff)
}

// Close closes the database connection.
func (s *EventStore) Close() error {
	return s.db.Close()
}

func evtRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
