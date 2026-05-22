package api

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Control channel message types
type controlMessage struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// WSHub manages control connections and pending data connections.
//
// Flow (bore-style):
//  1. Client creates tunnel via REST API
//  2. Client opens control WebSocket (GET /ws/control?tunnel_id=X)
//  3. Inbound HTTP arrives at /t/{slug}
//  4. Server hijacks the conn, reconstructs the HTTP request bytes
//  5. Sends {"type":"connection","id":"<uuid>"} on control WS
//  6. Client opens data WebSocket (GET /ws/data?id=<uuid>)
//  7. Server writes the reconstructed request into the pipe, then io.Copy bidirectionally
type WSHub struct {
	registry *tunnel.Registry

	// Control connections keyed by tunnel ID
	controls   map[string]*controlConn
	controlsMu sync.RWMutex

	// Pending inbound connections waiting for a client data WS
	pending   map[string]*pendingConn
	pendingMu sync.Mutex

	// Active relay counter for backpressure
	activeRelays int64
}

const (
	maxPendingPerTunnel = 50  // max queued connections per tunnel before rejecting
	maxActiveRelays     = 500 // global max concurrent relays (goroutine pairs)
	relayTimeout        = 10 * time.Minute // max relay duration (kill stalled pipes)
)

// pendingConn holds a hijacked connection plus the reconstructed HTTP request.
type pendingConn struct {
	conn      net.Conn
	reqPrefix []byte // Reconstructed HTTP request (method, path, headers, body prefix)
	tunnelID  string // For byte counting after relay

	// Request inspection correlation. When reqLogID is non-empty, the relay
	// sniffs the first HTTP response line, parses the status code, and calls
	// events.UpdateResponse(reqLogID, ...) to attach status + latency to the
	// previously-inserted request_log row. nil events store disables this.
	reqLogID string
	reqStart time.Time
	events   responseRecorder
}

// responseRecorder is the minimal subset of EventStore needed by the relay
// to attach response data. Declared as an interface so ws.go doesn't have
// to import the store package.
type responseRecorder interface {
	UpdateResponse(id string, statusCode int, durationMs int64, responseBytes int64)
}

type controlConn struct {
	conn     *websocket.Conn
	tunnelID string
	mu       sync.Mutex
}

func NewWSHub(registry *tunnel.Registry) *WSHub {
	return &WSHub{
		registry: registry,
		controls: make(map[string]*controlConn),
		pending:  make(map[string]*pendingConn),
	}
}

// HandleControl handles the control WebSocket from a tunnel client.
func (h *WSHub) HandleControl(w http.ResponseWriter, r *http.Request) {
	clientID := auth.ClientIDFrom(r.Context())
	tunnelID := r.URL.Query().Get("tunnel_id")

	if tunnelID == "" {
		http.Error(w, `{"error":"tunnel_id required"}`, http.StatusBadRequest)
		return
	}

	t, ok := h.registry.Get(tunnelID)
	if !ok {
		http.Error(w, `{"error":"tunnel not found"}`, http.StatusNotFound)
		return
	}
	if t.ClientID != clientID {
		http.Error(w, `{"error":"tunnel belongs to different client"}`, http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}

	cc := &controlConn{conn: conn, tunnelID: tunnelID}

	h.controlsMu.Lock()
	h.controls[tunnelID] = cc
	h.controlsMu.Unlock()

	// Store conn on the tunnel for connection status tracking
	h.registry.SetConn(tunnelID, conn)

	log.Printf("control connected: tunnel=%s client=%s", tunnelID, clientID)

	// Keep the control connection alive with ping/pong
	defer func() {
		conn.Close()
		h.controlsMu.Lock()
		delete(h.controls, tunnelID)
		h.controlsMu.Unlock()
		// Clear conn on tunnel so status shows disconnected
		h.registry.SetConn(tunnelID, nil)
		log.Printf("control disconnected: tunnel=%s", tunnelID)
	}()

	// Mark tunnel alive on initial connection
	t.MarkAlive()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		t.MarkAlive()
		return nil
	})

	// Ping ticker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			cc.mu.Lock()
			err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			cc.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	// Read loop — keep the connection alive, track liveness
	for {
		_, _, err := conn.ReadMessage()
		t.MarkAlive()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("control read error: tunnel=%s err=%v", tunnelID, err)
			}
			return
		}
	}
}

// HandleData handles a data WebSocket from the tunnel client, matching a pending connection.
func (h *WSHub) HandleData(w http.ResponseWriter, r *http.Request) {
	connID := r.URL.Query().Get("id")
	if connID == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}

	// Find the pending inbound connection
	h.pendingMu.Lock()
	pc, ok := h.pending[connID]
	if ok {
		delete(h.pending, connID)
	}
	h.pendingMu.Unlock()

	if !ok {
		http.Error(w, `{"error":"connection not found or expired"}`, http.StatusNotFound)
		return
	}

	// Upgrade to WebSocket
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("data ws upgrade error: %v", err)
		pc.conn.Close()
		return
	}

	log.Printf("data connected: id=%s", connID)

	// Write the reconstructed HTTP request through the data WS first.
	// This is the request the inbound client sent — the HTTP handler consumed it,
	// so we reconstructed it and inject it into the pipe so the local service sees it.
	dataConn := NewWSNetConn(wsConn)

	// Look up tunnel for byte counting
	var t *tunnel.Tunnel
	if pc.tunnelID != "" {
		t, _ = h.registry.Get(pc.tunnelID)
	}

	// Count the request prefix bytes (reconstructed HTTP request headers + body)
	// These were already read during hijack and won't flow through the pipe
	prefixBytes := int64(len(pc.reqPrefix))
	if len(pc.reqPrefix) > 0 {
		if _, err := dataConn.Write(pc.reqPrefix); err != nil {
			log.Printf("data write prefix error: %v", err)
			pc.conn.Close()
			dataConn.Close()
			return
		}
	}

	// Global relay cap — reject if too many concurrent relays
	active := atomic.AddInt64(&h.activeRelays, 1)
	if active > maxActiveRelays {
		atomic.AddInt64(&h.activeRelays, -1)
		log.Printf("relay rejected: global limit reached (%d)", maxActiveRelays)
		pc.conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 19\r\n\r\nserver at capacity\n"))
		pc.conn.Close()
		dataConn.Close()
		return
	}

	// Relay with timeout — kill stalled pipes after relayTimeout
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(relayTimeout):
			log.Printf("relay timeout: id=%s (after %v)", connID, relayTimeout)
			pc.conn.Close()
			dataConn.Close()
		}
	}()

	// If inspection is enabled for this request, wrap the inbound-conn writer
	// so we sniff the first HTTP response line on the way back to the client.
	// Bytes flowing dataConn → pc.conn are the response from the local service;
	// the sniffer parses the status line and remembers the count.
	var sniffer *responseSniffer
	clientWriter := io.Writer(pc.conn)
	if pc.reqLogID != "" && pc.events != nil {
		sniffer = &responseSniffer{w: pc.conn}
		clientWriter = sniffer
	}

	// Pipe bidirectionally: inbound conn ↔ data WebSocket (with byte counting)
	pipeWithStatsWriter(pc.conn, dataConn, clientWriter, t, prefixBytes)
	close(done)
	atomic.AddInt64(&h.activeRelays, -1)

	if sniffer != nil {
		ms := time.Since(pc.reqStart).Milliseconds()
		pc.events.UpdateResponse(pc.reqLogID, sniffer.status, ms, sniffer.bytes)
	}
}

// responseSniffer wraps an io.Writer so the first ~4KB of bytes are scanned
// for an HTTP response status line ("HTTP/1.1 200 OK\r\n"). Once status is
// captured (or the prefix buffer fills), pass-through writes proceed normally
// while keeping a running byte count. WebSocket-upgrade responses look like
// "HTTP/1.1 101 Switching Protocols" — status 101 is still useful to log.
type responseSniffer struct {
	w       io.Writer
	prefix  []byte // accumulated head bytes until we've parsed (or given up)
	parsed  bool
	status  int
	bytes   int64
}

func (s *responseSniffer) Write(p []byte) (int, error) {
	if !s.parsed {
		if len(s.prefix)+len(p) > 4096 {
			s.prefix = append(s.prefix, p[:4096-len(s.prefix)]...)
		} else {
			s.prefix = append(s.prefix, p...)
		}
		// Look for the first CR (end of status line).
		for i, b := range s.prefix {
			if b == '\r' {
				s.status = parseStatusLine(s.prefix[:i])
				s.parsed = true
				break
			}
		}
		if !s.parsed && len(s.prefix) >= 4096 {
			s.parsed = true // give up; leave status = 0
		}
	}
	n, err := s.w.Write(p)
	s.bytes += int64(n)
	return n, err
}

// parseStatusLine extracts the status code from an HTTP/1.x status line.
// Returns 0 if the line is malformed.
func parseStatusLine(line []byte) int {
	// Format: "HTTP/1.1 200 OK"
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) < 2 || !bytes.HasPrefix(parts[0], []byte("HTTP/")) {
		return 0
	}
	code, err := strconv.Atoi(string(parts[1]))
	if err != nil || code < 100 || code > 599 {
		return 0
	}
	return code
}

// pipeWithStatsWriter is pipeWithStats but the b→a direction writes through
// a custom writer (e.g. responseSniffer). Useful when the response stream
// needs interception without touching the inbound→outbound side.
func pipeWithStatsWriter(a net.Conn, b io.ReadWriteCloser, aWriter io.Writer, t *tunnel.Tunnel, extraIn int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	inCounter := &countingReader{r: a}
	outCounter := &countingReader{r: b}

	cp := func(dst io.WriteCloser, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
	}

	// internet → local (bytes in)
	go cp(b, inCounter)

	// local → internet (bytes out) — routed through aWriter so callers can
	// sniff/transform; we still need to close `a` when the copy finishes so
	// the inbound→outbound direction also exits.
	go func() {
		defer wg.Done()
		io.Copy(aWriter, outCounter)
		a.Close()
	}()

	wg.Wait()
	a.Close()
	b.Close()

	if t != nil {
		t.AddBytes(inCounter.Count()+extraIn, outCounter.Count())
	}
}

// sendConnection notifies the client over the control channel that a new connection needs handling.
func (h *WSHub) sendConnection(tunnelID string, connID string) error {
	h.controlsMu.RLock()
	cc, ok := h.controls[tunnelID]
	h.controlsMu.RUnlock()

	if !ok {
		return io.ErrClosedPipe
	}

	msg := controlMessage{
		Type: "connection",
		ID:   connID,
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.conn.WriteJSON(msg)
}

// RelayConn handles an inbound connection to a tunnel.
// reqPrefix is the reconstructed HTTP request bytes (since the handler already consumed them).
func (h *WSHub) RelayConn(tunnelID string, inbound net.Conn, reqPrefix []byte) error {
	return h.RelayConnWithLog(tunnelID, inbound, reqPrefix, "", time.Time{}, nil)
}

// RelayConnWithLog is like RelayConn but also threads a request_log row id
// through to the relay so the response status + latency can be attached when
// the upstream HTTP response flows back. Pass reqLogID="" and events=nil to
// disable inspection correlation for this relay.
func (h *WSHub) RelayConnWithLog(tunnelID string, inbound net.Conn, reqPrefix []byte, reqLogID string, reqStart time.Time, events responseRecorder) error {
	// Check pending queue depth for this tunnel (prevent flood)
	h.pendingMu.Lock()
	pendingCount := 0
	for _, pc := range h.pending {
		if pc.tunnelID == tunnelID {
			pendingCount++
		}
	}
	if pendingCount >= maxPendingPerTunnel {
		h.pendingMu.Unlock()
		inbound.Close()
		return fmt.Errorf("tunnel %s: pending connection limit reached (%d)", tunnelID, maxPendingPerTunnel)
	}
	h.pendingMu.Unlock()

	connID := uuid.New().String()

	pc := &pendingConn{
		conn:      inbound,
		reqPrefix: reqPrefix,
		tunnelID:  tunnelID,
		reqLogID:  reqLogID,
		reqStart:  reqStart,
		events:    events,
	}

	// Register the pending connection
	h.pendingMu.Lock()
	h.pending[connID] = pc
	h.pendingMu.Unlock()

	// Notify the client
	if err := h.sendConnection(tunnelID, connID); err != nil {
		h.pendingMu.Lock()
		delete(h.pending, connID)
		h.pendingMu.Unlock()
		return err
	}

	// Stale connection cleanup — if client doesn't connect within 10s, drop it
	go func() {
		time.Sleep(10 * time.Second)
		h.pendingMu.Lock()
		if pc, ok := h.pending[connID]; ok {
			delete(h.pending, connID)
			pc.conn.Close()
			log.Printf("stale pending connection removed: id=%s", connID)
		}
		h.pendingMu.Unlock()
	}()

	return nil
}

// countingReader wraps an io.Reader and counts bytes read.
type countingReader struct {
	r     io.Reader
	count int64
	mu    sync.Mutex
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.count += int64(n)
		c.mu.Unlock()
	}
	return n, err
}

func (c *countingReader) Count() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// pipe copies data bidirectionally between two connections.
// If a tunnel is provided, byte counts are recorded after relay completes.
func pipe(a, b io.ReadWriteCloser) {
	pipeWithStats(a, b, nil, 0)
}

// pipeWithStats copies data bidirectionally and reports byte counts to the tunnel.
// extraIn accounts for bytes already sent (e.g., reconstructed request headers).
func pipeWithStats(a, b io.ReadWriteCloser, t *tunnel.Tunnel, extraIn int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	// a = inbound (internet client), b = data WS (tunnel client)
	// a→b = bytes "in" (from internet to local service)
	// b→a = bytes "out" (from local service to internet)
	inCounter := &countingReader{r: a}
	outCounter := &countingReader{r: b}

	cp := func(dst io.WriteCloser, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
	}

	go cp(b, inCounter)  // internet → local (bytes in)
	go cp(a, outCounter) // local → internet (bytes out)

	wg.Wait()
	a.Close()
	b.Close()

	// Report final byte counts (include pre-pipe request prefix in bytes_in)
	if t != nil {
		t.AddBytes(inCounter.Count()+extraIn, outCounter.Count())
	}
}
