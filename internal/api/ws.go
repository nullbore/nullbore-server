package api

import (
	"io"
	"log"
	"net"
	"net/http"
	"sync"
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
}

// pendingConn holds a hijacked connection plus the reconstructed HTTP request.
type pendingConn struct {
	conn       net.Conn
	reqPrefix  []byte // Reconstructed HTTP request (method, path, headers, body prefix)
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

	log.Printf("control connected: tunnel=%s client=%s", tunnelID, clientID)

	// Keep the control connection alive with ping/pong
	defer func() {
		conn.Close()
		h.controlsMu.Lock()
		delete(h.controls, tunnelID)
		h.controlsMu.Unlock()
		log.Printf("control disconnected: tunnel=%s", tunnelID)
	}()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
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

	// Read loop — just keep the connection alive, discard any client messages
	for {
		_, _, err := conn.ReadMessage()
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
	if len(pc.reqPrefix) > 0 {
		if _, err := dataConn.Write(pc.reqPrefix); err != nil {
			log.Printf("data write prefix error: %v", err)
			pc.conn.Close()
			dataConn.Close()
			return
		}
	}

	// Now pipe bidirectionally: inbound conn ↔ data WebSocket
	pipe(pc.conn, dataConn)
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
	connID := uuid.New().String()

	pc := &pendingConn{
		conn:      inbound,
		reqPrefix: reqPrefix,
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

// pipe copies data bidirectionally between two connections.
func pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst io.WriteCloser, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
	}

	go cp(a, b)
	go cp(b, a)

	wg.Wait()
	a.Close()
	b.Close()
}
