package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/store"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

// Config holds server configuration.
type Config struct {
	Host        string
	Port        string
	TLS         *TLSConfig
	Auth        auth.Provider
	Registry    *tunnel.Registry
	Store       *store.Store
	DashHandler http.Handler
}

// Server is the main HTTP server.
type Server struct {
	cfg         Config
	mux         *http.ServeMux
	wsHub       *WSHub
	rateLimiter *RateLimiter
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg:   cfg,
		mux:   http.NewServeMux(),
		wsHub: NewWSHub(cfg.Registry),
		// Rate limit: 10 tunnel creations per minute per client, burst of 5
		rateLimiter: NewRateLimiter(10, time.Minute, 5),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Health check — no auth
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Tunnel proxy — public endpoint, no auth
	// This is where internet traffic arrives and gets relayed to the client
	s.mux.HandleFunc("/t/{slug}", s.handleProxy)
	s.mux.HandleFunc("/t/{slug}/{path...}", s.handleProxy)

	// WebSocket control channel — client connects here after creating a tunnel
	s.mux.Handle("GET /ws/control", s.cfg.Auth.Middleware(http.HandlerFunc(s.wsHub.HandleControl)))

	// WebSocket data channel — client connects here for each inbound connection
	// Auth via the connection ID (only the notified client knows the ID)
	s.mux.HandleFunc("GET /ws/data", s.wsHub.HandleData)

	// REST API — all authed
	api := http.NewServeMux()
	api.HandleFunc("GET /v1/tunnels", s.handleListTunnels)
	api.HandleFunc("POST /v1/tunnels", s.handleCreateTunnel)
	api.HandleFunc("GET /v1/tunnels/{id}", s.handleGetTunnel)
	api.HandleFunc("DELETE /v1/tunnels/{id}", s.handleCloseTunnel)
	api.HandleFunc("POST /v1/tunnels/{id}/extend", s.handleExtendTunnel)

	s.mux.Handle("/v1/", s.cfg.Auth.Middleware(api))

	// Dashboard (if enabled)
	if s.cfg.DashHandler != nil {
		s.mux.Handle("/dash/", s.cfg.DashHandler)
		s.mux.Handle("/dash", s.cfg.DashHandler)
	}
}

func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%s", s.cfg.Host, s.cfg.Port)

	// Wrap with logging middleware
	handler := LoggingMiddleware(s.mux)

	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Disabled — tunnel connections are long-lived
		IdleTimeout:  60 * time.Second,
		// Disable HTTP/2 — our proxy handler requires Hijack(), which HTTP/2 doesn't support.
		// This is the same approach used by chisel and similar tunnel servers.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	// TLS handling
	if s.cfg.TLS != nil && s.cfg.TLS.IsEnabled() {
		tlsConfig, err := s.cfg.TLS.BuildTLSConfig()
		if err != nil {
			return fmt.Errorf("tls setup: %w", err)
		}
		srv.TLSConfig = tlsConfig

		if s.cfg.TLS.IsACME() {
			// ACME mode — TLSConfig is fully managed by autocert
			log.Printf("tls: listening on %s (ACME/Let's Encrypt)", addr)
			return srv.ListenAndServeTLS("", "")
		}

		// Manual cert mode
		log.Printf("tls: listening on %s (manual cert)", addr)
		return srv.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	}

	// No TLS
	return srv.ListenAndServe()
}

// --- API Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": "0.1.0",
	})
}

type createTunnelRequest struct {
	LocalPort int    `json:"local_port"`
	Name      string `json:"name,omitempty"`
	TTL       string `json:"ttl,omitempty"`
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	clientID := auth.ClientIDFrom(r.Context())

	// Rate limit by client ID
	if !s.rateLimiter.Allow(clientID) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}

	var req createTunnelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.LocalPort < 1 || req.LocalPort > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "local_port must be 1-65535"})
		return
	}

	ttl := 1 * time.Hour
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ttl format"})
			return
		}
		ttl = parsed
	}

	t, err := s.cfg.Registry.Create(clientID, req.LocalPort, req.Name, ttl)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	// Persist to store
	if s.cfg.Store != nil {
		s.cfg.Store.SaveTunnel(&store.TunnelRecord{
			ID: t.ID, Slug: t.Slug, ClientID: t.ClientID,
			LocalPort: t.LocalPort, Name: t.Name,
			TTL: int64(ttl.Seconds()), Status: "active",
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		})
		s.cfg.Store.LogEvent(t.ID, "created", fmt.Sprintf("port=%d slug=%s ttl=%s", t.LocalPort, t.Slug, ttl))
	}

	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	clientID := auth.ClientIDFrom(r.Context())
	tunnels := s.cfg.Registry.List(clientID)
	if tunnels == nil {
		tunnels = []*tunnel.Tunnel{}
	}
	writeJSON(w, http.StatusOK, tunnels)
}

func (s *Server) handleGetTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := s.cfg.Registry.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleCloseTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Registry.Close(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if s.cfg.Store != nil {
		s.cfg.Store.CloseTunnel(id)
		s.cfg.Store.LogEvent(id, "closed", "closed via API")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

type extendRequest struct {
	TTL string `json:"ttl"`
}

func (s *Server) handleExtendTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req extendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	ext, err := time.ParseDuration(req.TTL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ttl format"})
		return
	}

	if err := s.cfg.Registry.ExtendTTL(id, ext); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	t, _ := s.cfg.Registry.Get(id)
	writeJSON(w, http.StatusOK, t)
}

// --- Proxy Handler ---
//
// Handles inbound internet traffic to /t/{slug}.
// Hijacks the TCP connection and hands it to the WSHub for relay
// through the tunnel client's data WebSocket.

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	t, ok := s.cfg.Registry.GetBySlug(slug)
	if !ok {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	if time.Now().After(t.ExpiresAt) {
		http.Error(w, "tunnel expired", http.StatusGone)
		return
	}

	// Reconstruct the HTTP request as raw bytes.
	// The HTTP server has already consumed the request, so we need to rebuild it
	// so the local service on the client side receives a proper HTTP request.
	reqBytes := reconstructHTTPRequest(r)

	// Read request body (if any)
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	}

	reqPrefix := append(reqBytes, bodyBytes...)

	// Hijack the HTTP connection to get the raw TCP conn
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
		return
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		log.Printf("hijack error: %v", err)
		return
	}

	// Write any buffered data and wrap
	if buf.Reader.Buffered() > 0 {
		buffered := make([]byte, buf.Reader.Buffered())
		buf.Read(buffered)
		conn = &prefixConn{Conn: conn, prefix: buffered}
	}

	// Hand the raw connection to the hub for relay
	if err := s.wsHub.RelayConn(t.ID, conn, reqPrefix); err != nil {
		log.Printf("relay error: tunnel=%s err=%v", t.ID, err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 24\r\n\r\ntunnel client unavailable"))
		conn.Close()
		return
	}

	t.AddStats(1, 0)
}

// reconstructHTTPRequest rebuilds raw HTTP request bytes from an *http.Request.
// This is needed because the HTTP server consumes the request before we can hijack.
func reconstructHTTPRequest(r *http.Request) []byte {
	var buf bytes.Buffer

	// Request line: rewrite the path to strip the /t/{slug} prefix
	path := "/" + r.PathValue("path")
	if path == "/" && r.URL.RawQuery != "" {
		path = "/?" + r.URL.RawQuery
	} else if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}

	fmt.Fprintf(&buf, "%s %s %s\r\n", r.Method, path, r.Proto)

	// Host header — Go stores it in r.Host, not r.Header
	if r.Host != "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", r.Host)
	}

	// Force Connection: close — each inbound request gets its own data WebSocket / pipe,
	// so there's no keep-alive. Without this, HTTP/1.1 servers hold the connection open
	// and the pipe deadlocks.
	fmt.Fprintf(&buf, "Connection: close\r\n")

	// Remaining headers — skip hop-by-hop
	for key, vals := range r.Header {
		switch strings.ToLower(key) {
		case "connection", "upgrade", "proxy-connection", "te", "trailer", "host":
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, v)
		}
	}

	buf.WriteString("\r\n")
	return buf.Bytes()
}

// prefixConn prepends buffered bytes to reads from a net.Conn.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode error: %v", err)
	}
}
