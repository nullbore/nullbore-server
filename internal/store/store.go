package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"


	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Store manages persistent state in SQLite.
type Store struct {
	db *sql.DB
}

// TunnelRecord is a persistent tunnel record.
type TunnelRecord struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	ClientID  string    `json:"client_id"`
	LocalPort int       `json:"local_port"`
	Name      string    `json:"name,omitempty"`
	TTL       int64     `json:"ttl_seconds"`
	Status    string    `json:"status"` // active, expired, closed
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Requests  int64     `json:"requests"`
}

// APIKey is a stored API key.
type APIKey struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	KeyHash   string    `json:"-"` // bcrypt hash, never exposed
	KeyPrefix string    `json:"key_prefix"` // first 8 chars for identification
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	Active    bool      `json:"active"`
}

// TunnelEvent is an audit log entry.
type TunnelEvent struct {
	ID        int64     `json:"id"`
	TunnelID  string    `json:"tunnel_id"`
	Event     string    `json:"event"` // created, connected, disconnected, expired, closed, extended
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// New opens or creates a SQLite database.
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

// RequestLog represents a logged HTTP request to a tunnel.
type RequestLog struct {
	ID        string    `json:"id"`
	TunnelID  string    `json:"tunnel_id"`
	Slug      string    `json:"slug"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Headers   string    `json:"headers"` // JSON-encoded headers
	BodySize  int64     `json:"body_size"`
	BodySnip  string    `json:"body_snippet,omitempty"` // first 4KB
	RemoteIP  string    `json:"remote_ip"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS tunnels (
			id TEXT PRIMARY KEY,
			slug TEXT NOT NULL,
			client_id TEXT NOT NULL,
			local_port INTEGER NOT NULL,
			name TEXT DEFAULT '',
			ttl_seconds INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			closed_at DATETIME,
			bytes_in INTEGER DEFAULT 0,
			bytes_out INTEGER DEFAULT 0,
			requests INTEGER DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_tunnels_slug ON tunnels(slug);
		CREATE INDEX IF NOT EXISTS idx_tunnels_status ON tunnels(status);
		CREATE INDEX IF NOT EXISTS idx_tunnels_client ON tunnels(client_id);

		CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			key_hash TEXT NOT NULL,
			key_prefix TEXT NOT NULL,
			label TEXT DEFAULT '',
			created_at DATETIME NOT NULL,
			last_used DATETIME,
			active INTEGER DEFAULT 1
		);
		CREATE INDEX IF NOT EXISTS idx_keys_client ON api_keys(client_id);

		CREATE TABLE IF NOT EXISTS tunnel_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tunnel_id TEXT NOT NULL,
			event TEXT NOT NULL,
			detail TEXT DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_events_tunnel ON tunnel_events(tunnel_id);

		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		);

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

// --- Tunnel operations ---

func (s *Store) SaveTunnel(t *TunnelRecord) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO tunnels (id, slug, client_id, local_port, name, ttl_seconds, status, created_at, expires_at, closed_at, bytes_in, bytes_out, requests)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Slug, t.ClientID, t.LocalPort, t.Name, t.TTL, t.Status, t.CreatedAt, t.ExpiresAt, t.ClosedAt, t.BytesIn, t.BytesOut, t.Requests)
	return err
}

func (s *Store) GetTunnel(id string) (*TunnelRecord, error) {
	t := &TunnelRecord{}
	err := s.db.QueryRow(`SELECT id, slug, client_id, local_port, name, ttl_seconds, status, created_at, expires_at, closed_at, bytes_in, bytes_out, requests FROM tunnels WHERE id = ?`, id).
		Scan(&t.ID, &t.Slug, &t.ClientID, &t.LocalPort, &t.Name, &t.TTL, &t.Status, &t.CreatedAt, &t.ExpiresAt, &t.ClosedAt, &t.BytesIn, &t.BytesOut, &t.Requests)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *Store) ListTunnels(clientID string, status string, limit int) ([]TunnelRecord, error) {
	query := "SELECT id, slug, client_id, local_port, name, ttl_seconds, status, created_at, expires_at, closed_at, bytes_in, bytes_out, requests FROM tunnels WHERE 1=1"
	args := []interface{}{}

	if clientID != "" {
		query += " AND client_id = ?"
		args = append(args, clientID)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tunnels []TunnelRecord
	for rows.Next() {
		var t TunnelRecord
		if err := rows.Scan(&t.ID, &t.Slug, &t.ClientID, &t.LocalPort, &t.Name, &t.TTL, &t.Status, &t.CreatedAt, &t.ExpiresAt, &t.ClosedAt, &t.BytesIn, &t.BytesOut, &t.Requests); err != nil {
			return nil, err
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, nil
}

func (s *Store) CloseTunnel(id string) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE tunnels SET status = 'closed', closed_at = ? WHERE id = ?`, now, id)
	return err
}

// LoadActiveTunnels returns all tunnels that were active (not expired/closed) at shutdown.
// Used on server restart to restore tunnels to the in-memory registry.
func (s *Store) LoadActiveTunnels() ([]TunnelRecord, error) {
	now := time.Now()
	rows, err := s.db.Query(`
		SELECT id, slug, client_id, local_port, name, ttl_seconds, status, created_at, expires_at, closed_at, bytes_in, bytes_out, requests
		FROM tunnels WHERE status = 'active' AND expires_at > ?
		ORDER BY created_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tunnels []TunnelRecord
	for rows.Next() {
		var t TunnelRecord
		if err := rows.Scan(&t.ID, &t.Slug, &t.ClientID, &t.LocalPort, &t.Name, &t.TTL, &t.Status, &t.CreatedAt, &t.ExpiresAt, &t.ClosedAt, &t.BytesIn, &t.BytesOut, &t.Requests); err != nil {
			return nil, err
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, nil
}

// FlushTunnelStats batch-updates tunnel stats in the DB.
func (s *Store) FlushTunnelStats(id string, bytesIn, bytesOut, requests int64, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`UPDATE tunnels SET bytes_in = ?, bytes_out = ?, requests = ?, expires_at = ? WHERE id = ?`,
		bytesIn, bytesOut, requests, expiresAt, id)
	return err
}

func (s *Store) ExpireTunnels() (int64, error) {
	now := time.Now()
	result, err := s.db.Exec(`UPDATE tunnels SET status = 'expired', closed_at = ? WHERE status = 'active' AND expires_at < ?`, now, now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) UpdateTunnelStats(id string, bytesIn, bytesOut, requests int64) error {
	_, err := s.db.Exec(`UPDATE tunnels SET bytes_in = bytes_in + ?, bytes_out = bytes_out + ?, requests = requests + ? WHERE id = ?`,
		bytesIn, bytesOut, requests, id)
	return err
}

// --- API Key operations ---

// CreateAPIKey generates a new API key, stores the hash, and returns the raw key.
func (s *Store) CreateAPIKey(clientID, label string) (rawKey string, key *APIKey, err error) {
	secret := make([]byte, 24)
	rand.Read(secret)
	raw := fmt.Sprintf("nbk_%s_%s", clientID, hex.EncodeToString(secret))

	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	id := hex.EncodeToString(secret[:8])
	prefix := raw[:12]

	k := &APIKey{
		ID:        id,
		ClientID:  clientID,
		KeyHash:   string(hash),
		KeyPrefix: prefix,
		Label:     label,
		CreatedAt: time.Now(),
		Active:    true,
	}

	_, err = s.db.Exec(`INSERT INTO api_keys (id, client_id, key_hash, key_prefix, label, created_at, active) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.ClientID, k.KeyHash, k.KeyPrefix, k.Label, k.CreatedAt, k.Active)
	if err != nil {
		return "", nil, err
	}

	return raw, k, nil
}

// ValidateAPIKey checks a raw key against stored hashes. Returns clientID if valid.
func (s *Store) ValidateAPIKey(rawKey string) (string, bool) {
	rows, err := s.db.Query(`SELECT id, client_id, key_hash FROM api_keys WHERE active = 1`)
	if err != nil {
		return "", false
	}
	defer rows.Close()

	for rows.Next() {
		var id, clientID, hash string
		rows.Scan(&id, &clientID, &hash)
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawKey)) == nil {
			// Update last_used
			s.db.Exec(`UPDATE api_keys SET last_used = ? WHERE id = ?`, time.Now(), id)
			return clientID, true
		}
	}
	return "", false
}

func (s *Store) ListAPIKeys(clientID string) ([]APIKey, error) {
	rows, err := s.db.Query(`SELECT id, client_id, key_prefix, label, created_at, last_used, active FROM api_keys WHERE client_id = ? ORDER BY created_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		rows.Scan(&k.ID, &k.ClientID, &k.KeyPrefix, &k.Label, &k.CreatedAt, &k.LastUsed, &k.Active)
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *Store) RevokeAPIKey(id string) error {
	_, err := s.db.Exec(`UPDATE api_keys SET active = 0 WHERE id = ?`, id)
	return err
}

// --- Event logging ---

func (s *Store) LogEvent(tunnelID, event, detail string) error {
	_, err := s.db.Exec(`INSERT INTO tunnel_events (tunnel_id, event, detail, created_at) VALUES (?, ?, ?, ?)`,
		tunnelID, event, detail, time.Now())
	return err
}

func (s *Store) GetEvents(tunnelID string, limit int) ([]TunnelEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, tunnel_id, event, detail, created_at FROM tunnel_events WHERE tunnel_id = ? ORDER BY created_at DESC LIMIT ?`, tunnelID, limit)
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

// --- Dashboard sessions ---

func (s *Store) CreateSession() (string, error) {
	token := make([]byte, 32)
	rand.Read(token)
	t := hex.EncodeToString(token)

	_, err := s.db.Exec(`INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)`,
		t, time.Now(), time.Now().Add(24*time.Hour))
	return t, err
}

func (s *Store) ValidateSession(token string) bool {
	var expires time.Time
	err := s.db.QueryRow(`SELECT expires_at FROM sessions WHERE token = ?`, token).Scan(&expires)
	if err != nil {
		return false
	}
	return time.Now().Before(expires)
}

func (s *Store) CleanExpiredSessions() {
	s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
}

// --- Stats ---

type DashStats struct {
	ActiveTunnels  int   `json:"active_tunnels"`
	TotalTunnels   int   `json:"total_tunnels"`
	TotalRequests  int64 `json:"total_requests"`
	TotalBytesIn   int64 `json:"total_bytes_in"`
	TotalBytesOut  int64 `json:"total_bytes_out"`
	ActiveKeys     int   `json:"active_keys"`
}

func (s *Store) GetStats() (*DashStats, error) {
	stats := &DashStats{}
	s.db.QueryRow(`SELECT COUNT(*) FROM tunnels WHERE status = 'active'`).Scan(&stats.ActiveTunnels)
	s.db.QueryRow(`SELECT COUNT(*) FROM tunnels`).Scan(&stats.TotalTunnels)
	s.db.QueryRow(`SELECT COALESCE(SUM(requests),0), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM tunnels`).
		Scan(&stats.TotalRequests, &stats.TotalBytesIn, &stats.TotalBytesOut)
	s.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE active = 1`).Scan(&stats.ActiveKeys)
	return stats, nil
}

// --- Request log operations ---

// LogRequest records an HTTP request to a tunnel.
func (s *Store) LogRequest(tunnelID, slug, method, path, headers string, bodySize int64, bodySnippet, remoteIP string) {
	id := hex.EncodeToString(randomBytes(16))
	s.db.Exec(`INSERT INTO request_log (id, tunnel_id, slug, method, path, headers, body_size, body_snippet, remote_ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, tunnelID, slug, method, path, headers, bodySize, bodySnippet, remoteIP, time.Now())
}

// ListRequests returns recent request logs for a tunnel (or all if tunnelID is empty).
func (s *Store) ListRequests(tunnelID string, limit int) ([]RequestLog, error) {
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

// PruneRequestLog removes request logs older than the given duration.
func (s *Store) PruneRequestLog(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	s.db.Exec(`DELETE FROM request_log WHERE created_at < ?`, cutoff)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// ClientBandwidth holds aggregate bytes for a single client.
type ClientBandwidth struct {
	BytesIn  int64
	BytesOut int64
}

// BandwidthByClient returns aggregate bytes_in/bytes_out per client_id across all tunnels.
func (s *Store) BandwidthByClient() (map[string]ClientBandwidth, error) {
	rows, err := s.db.Query(`SELECT client_id, COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM tunnels GROUP BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]ClientBandwidth)
	for rows.Next() {
		var clientID string
		var bw ClientBandwidth
		if err := rows.Scan(&clientID, &bw.BytesIn, &bw.BytesOut); err != nil {
			continue
		}
		result[clientID] = bw
	}
	return result, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
