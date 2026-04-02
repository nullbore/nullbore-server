package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Tunnel represents an active tunnel connection.
type Tunnel struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	ClientID  string    `json:"client_id"`
	LocalPort int       `json:"local_port"`
	Name      string    `json:"name,omitempty"`
	TTL       Duration  `json:"ttl"`
	Mode      string    `json:"mode"` // "relay" or "direct" (v1: always relay)
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Requests  int64     `json:"requests"`

	IdleTTL    bool      `json:"idle_ttl,omitempty"`    // If true, TTL resets on activity
	LastActive time.Time `json:"last_active,omitempty"` // Last time traffic was seen

	Suspended bool `json:"suspended,omitempty"` // If true, proxy returns suspended page

	DeviceName string `json:"device_name,omitempty"` // hostname of the connecting device
	Source     string `json:"source,omitempty"`       // "cli" or "daemon"

	// Internal — not serialized
	conn            *websocket.Conn
	mu              sync.Mutex
	closed          bool
	expiringWarned  bool
	lastPing        time.Time // last control channel activity
}

// Mu returns the tunnel's mutex for external synchronization (e.g., WebSocket writes).
func (t *Tunnel) Mu() *sync.Mutex {
	return &t.mu
}

// AddRequest increments the request counter and marks activity.
// Called when a new inbound request arrives at the proxy handler.
func (t *Tunnel) AddRequest() {
	t.mu.Lock()
	t.Requests++
	t.touch()
	t.mu.Unlock()
}

// AddBytes atomically updates byte counters and marks activity.
// Called by the counting relay wrapper after a connection finishes.
func (t *Tunnel) AddBytes(bytesIn, bytesOut int64) {
	t.mu.Lock()
	t.BytesIn += bytesIn
	t.BytesOut += bytesOut
	if bytesIn > 0 || bytesOut > 0 {
		t.touch()
	}
	t.mu.Unlock()
}

// touch updates LastActive and extends TTL if in idle mode.
// Must be called with t.mu held.
func (t *Tunnel) touch() {
	t.LastActive = time.Now()
	if t.IdleTTL && !t.closed {
		t.ExpiresAt = t.LastActive.Add(time.Duration(t.TTL))
	}
}

// MarkAlive updates the last control channel activity timestamp.
// Called on pong receipt or any control message.
func (t *Tunnel) MarkAlive() {
	t.mu.Lock()
	t.lastPing = time.Now()
	t.mu.Unlock()
}

// IsStale returns true if no control channel activity for the given duration.
func (t *Tunnel) IsStale(timeout time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastPing.IsZero() {
		// Never pinged — use creation time
		return time.Since(t.CreatedAt) > timeout
	}
	return time.Since(t.lastPing) > timeout
}

// AddStats is kept for backward compatibility with tests.
func (t *Tunnel) AddStats(bytesIn, bytesOut int64) {
	t.mu.Lock()
	t.BytesIn += bytesIn
	t.BytesOut += bytesOut
	t.Requests++
	t.touch()
	t.mu.Unlock()
}

// Duration wraps time.Duration for JSON marshal/unmarshal.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, time.Duration(d).String())), nil
}

// EventType represents a tunnel lifecycle event.
type EventType string

const (
	EventCreated  EventType = "tunnel.created"
	EventClosed   EventType = "tunnel.closed"
	EventExpiring EventType = "tunnel.expiring"
)

// Event is a tunnel lifecycle event.
type Event struct {
	Type   EventType `json:"event"`
	Tunnel *Tunnel   `json:"tunnel"`
}

// EventHandler receives tunnel lifecycle events.
type EventHandler func(Event)

// Registry manages active tunnels.
type Registry struct {
	mu           sync.RWMutex
	tunnels      map[string]*Tunnel // keyed by ID
	slugs        map[string]string  // slug -> ID
	eventHandler EventHandler       // optional callback
	limits       ConnectionLimit    // per-client limits
}

func NewRegistry() *Registry {
	return &Registry{
		tunnels: make(map[string]*Tunnel),
		slugs:   make(map[string]string),
		limits:  DefaultLimits(),
	}
}

// OnEvent registers a handler for tunnel lifecycle events.
func (r *Registry) OnEvent(h EventHandler) {
	r.eventHandler = h
}

// emit fires an event to the registered handler (non-blocking).
func (r *Registry) emit(e Event) {
	if r.eventHandler != nil {
		go r.eventHandler(e)
	}
}

// ConnectionLimit defines per-client tunnel limits. Zero means unlimited.
type ConnectionLimit struct {
	MaxTunnels int
}

// DefaultLimits returns the default connection limit (10 tunnels per client).
func DefaultLimits() ConnectionLimit {
	return ConnectionLimit{MaxTunnels: 10}
}

// SetLimits sets the per-client connection limits.
func (r *Registry) SetLimits(limits ConnectionLimit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limits = limits
}

// Restore loads a tunnel into the registry from persistent storage.
// The tunnel starts without a WebSocket connection — the client must reconnect.
func (r *Registry) Restore(t *Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tunnels[t.ID] = t
	r.slugs[t.Slug] = t.ID
}

// CountByClient returns the number of active tunnels for a client.
func (r *Registry) CountByClient(clientID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	for _, t := range r.tunnels {
		if t.ClientID == clientID {
			count++
		}
	}
	return count
}

// Create registers a new tunnel and returns it.
func (r *Registry) Create(clientID string, localPort int, name string, ttl time.Duration) (*Tunnel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Enforce per-client connection limit
	if r.limits.MaxTunnels > 0 {
		count := 0
		for _, t := range r.tunnels {
			if t.ClientID == clientID {
				count++
			}
		}
		if count >= r.limits.MaxTunnels {
			return nil, fmt.Errorf("connection limit reached (%d tunnels)", r.limits.MaxTunnels)
		}
	}

	if ttl == 0 {
		ttl = 1 * time.Hour
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}

	slug := generateSlug()
	if name != "" {
		// Check if this name is already in use
		if existingID, exists := r.slugs[name]; exists {
			existing := r.tunnels[existingID]
			// If same client owns it and no active connection, reclaim it
			// (happens on reconnect after server restart)
			if existing != nil && existing.ClientID == clientID {
				existing.mu.Lock()
				hasConn := existing.conn != nil && !existing.closed
				existing.mu.Unlock()
				if !hasConn {
					// Reclaim: update TTL and port, return existing tunnel
					now := time.Now()
					existing.LocalPort = localPort
					existing.TTL = Duration(ttl)
					existing.ExpiresAt = now.Add(ttl)
					log.Printf("tunnel reclaimed: id=%s slug=%s client=%s",
						existing.ID, existing.Slug, clientID)
					return existing, nil
				}
			}
			return nil, fmt.Errorf("tunnel name %q already in use", name)
		}
		slug = name
	}

	now := time.Now()
	t := &Tunnel{
		ID:        uuid.New().String(),
		Slug:      slug,
		ClientID:  clientID,
		LocalPort: localPort,
		Name:      name,
		TTL:       Duration(ttl),
		Mode:      "relay",
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	r.tunnels[t.ID] = t
	r.slugs[t.Slug] = t.ID

	log.Printf("tunnel created: id=%s slug=%s client=%s port=%d ttl=%s",
		t.ID, t.Slug, t.ClientID, t.LocalPort, ttl)

	r.emit(Event{Type: EventCreated, Tunnel: t})

	return t, nil
}

// Get returns a tunnel by ID.
func (r *Registry) Get(id string) (*Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tunnels[id]
	return t, ok
}

// GetBySlug returns a tunnel by its slug.
func (r *Registry) GetBySlug(slug string) (*Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.slugs[slug]
	if !ok {
		return nil, false
	}
	t, ok := r.tunnels[id]
	return t, ok
}

// List returns all tunnels for a given client, or all if clientID is empty.
func (r *Registry) List(clientID string) []*Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*Tunnel
	for _, t := range r.tunnels {
		if clientID == "" || t.ClientID == clientID {
			result = append(result, t)
		}
	}
	return result
}

// Close shuts down a tunnel.
func (r *Registry) Close(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	t, ok := r.tunnels[id]
	if !ok {
		return fmt.Errorf("tunnel %s not found", id)
	}

	t.mu.Lock()
	if t.conn != nil && !t.closed {
		t.conn.Close()
	}
	t.closed = true
	t.mu.Unlock()

	delete(r.tunnels, id)
	delete(r.slugs, t.Slug)

	log.Printf("tunnel closed: id=%s slug=%s", t.ID, t.Slug)
	r.emit(Event{Type: EventClosed, Tunnel: t})
	return nil
}

// SetSuspended toggles the suspended state of a tunnel.
func (r *Registry) SetSuspended(id string, suspended bool) error {
	r.mu.RLock()
	t, ok := r.tunnels[id]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("tunnel %s not found", id)
	}
	t.mu.Lock()
	t.Suspended = suspended
	t.mu.Unlock()

	state := "resumed"
	if suspended {
		state = "suspended"
	}
	log.Printf("tunnel %s: id=%s slug=%s", state, t.ID, t.Slug)
	return nil
}

// ExtendTTL extends a tunnel's expiry.
func (r *Registry) ExtendTTL(id string, extension time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	t, ok := r.tunnels[id]
	if !ok {
		return fmt.Errorf("tunnel %s not found", id)
	}

	maxExpiry := t.CreatedAt.Add(24 * time.Hour)
	newExpiry := t.ExpiresAt.Add(extension)
	if newExpiry.After(maxExpiry) {
		newExpiry = maxExpiry
	}
	t.ExpiresAt = newExpiry
	t.TTL = Duration(newExpiry.Sub(time.Now()))

	log.Printf("tunnel extended: id=%s new_expiry=%s", t.ID, t.ExpiresAt)
	return nil
}

// SetConn associates a WebSocket connection with a tunnel.
func (r *Registry) SetConn(id string, conn *websocket.Conn) error {
	r.mu.RLock()
	t, ok := r.tunnels[id]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("tunnel %s not found", id)
	}

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	return nil
}

// GetConn returns the WebSocket connection for a tunnel.
func (r *Registry) GetConn(id string) (*websocket.Conn, error) {
	r.mu.RLock()
	t, ok := r.tunnels[id]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("tunnel %s not found", id)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return nil, fmt.Errorf("tunnel %s has no active connection", id)
	}
	return t.conn, nil
}

// StartReaper periodically closes expired tunnels.
func (r *Registry) StartReaper() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r.reapExpired()
	}
}

// StaleTimeout is how long a tunnel can go without control channel activity
// before being considered stale and reaped. Clients send pings every 25s,
// so 90s allows for ~3 missed pings.
const StaleTimeout = 90 * time.Second

func (r *Registry) reapExpired() {
	now := time.Now()
	warnThreshold := 5 * time.Minute
	r.mu.RLock()
	var expired []string
	var stale []string
	for id, t := range r.tunnels {
		if now.After(t.ExpiresAt) {
			expired = append(expired, id)
		} else if t.conn != nil && t.IsStale(StaleTimeout) {
			stale = append(stale, id)
		} else if t.ExpiresAt.Sub(now) <= warnThreshold {
			// Fire expiring event once (check if not already warned)
			t.mu.Lock()
			if !t.expiringWarned {
				t.expiringWarned = true
				t.mu.Unlock()
				r.emit(Event{Type: EventExpiring, Tunnel: t})
			} else {
				t.mu.Unlock()
			}
		}
	}
	r.mu.RUnlock()

	for _, id := range expired {
		log.Printf("reaping expired tunnel: %s", id)
		r.Close(id)
	}

	for _, id := range stale {
		log.Printf("reaping stale tunnel (no ping for %s): %s", StaleTimeout, id)
		r.Close(id)
	}
}

func generateSlug() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
