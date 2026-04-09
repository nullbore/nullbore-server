package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/store"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

// Config holds server configuration.
// ServerVersion is the current API version, set at build time via -ldflags.
var ServerVersion = "0.1.0-dev"

// APIVersion is the API protocol version. Bump on breaking changes.
const APIVersion = "1"

// IPCheckerProvider is implemented by RemoteProvider to check IP allowlists.
type IPCheckerProvider interface {
	GetIPAllowlistForUser(userID string) []string
}

type Config struct {
	Host           string
	Port           string
	TLS            *TLSConfig
	Auth           auth.Provider
	Registry       *tunnel.Registry
	Store          *store.Store
	Events         *store.EventStore // separate event/request log DB (optional)
	DashHandler    http.Handler
	BaseDomain     string              // e.g. "tunnel.nullbore.com" — enables subdomain routing
	AccountDomain  string              // e.g. "nullbore.com" — for *.heroapp.nullbore.com routing
	AdminSecret    string              // shared secret for admin API (dashboard→server)
	DomainResolver    *DomainResolver    // custom domain → tunnel slug resolver (optional)
	SubdomainResolver *SubdomainResolver // account subdomain → user ID resolver (optional)
	IPChecker         IPCheckerProvider  // optional; nil means allow all IPs
	MaxBodyBytes      int64              // max request body size (0 = unlimited, default 500MB)

	// TrustedProxies is the set of CIDRs whose `X-Forwarded-For` headers
	// will be honored for client-IP determination (used by IP allowlists,
	// rate limits, and request logs). When the immediate peer
	// (r.RemoteAddr) is NOT in this list, X-F-F is ignored and r.RemoteAddr
	// is used. Empty (the default) means no proxies are trusted, which is
	// the safe stance for a server exposed directly to the internet.
	TrustedProxies []*net.IPNet
}

// Server is the main HTTP server.
type Server struct {
	cfg         Config
	mux         *http.ServeMux
	wsHub       *WSHub
	rateLimiter *RateLimiter
	// Per-tunnel request rate limiters, keyed by tier
	proxyLimiters map[string]*RateLimiter
	httpServer    *http.Server
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg:   cfg,
		mux:   http.NewServeMux(),
		wsHub: NewWSHub(cfg.Registry),
		// Rate limit: 10 tunnel creations per minute per client, burst of 5
		rateLimiter: NewRateLimiter(10, time.Minute, 5),
		// Per-tunnel proxy rate limiters by tier.
		// Use per-second refill intervals to avoid minute-boundary starvation.
		proxyLimiters: map[string]*RateLimiter{
			"free":  NewRateLimiter(10, time.Second, 60),      // moderate guardrail for abuse
			"hobby": NewRateLimiter(1000, time.Second, 2000),  // effectively unbounded for normal web traffic
			"pro":   NewRateLimiter(10000, time.Second, 10000), // practically unlimited
		},
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
	api.HandleFunc("GET /v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version":     ServerVersion,
			"api_version": APIVersion,
		})
	})
	api.HandleFunc("GET /v1/tunnels", s.handleListTunnels)
	api.HandleFunc("POST /v1/tunnels", s.handleCreateTunnel)
	api.HandleFunc("GET /v1/tunnels/{id}", s.handleGetTunnel)
	api.HandleFunc("DELETE /v1/tunnels/{id}", s.handleCloseTunnel)
	api.HandleFunc("POST /v1/tunnels/{id}/suspend", s.handleSuspendTunnel)
	api.HandleFunc("POST /v1/tunnels/{id}/extend", s.handleExtendTunnel)
	api.HandleFunc("GET /v1/tunnels/{id}/requests", s.handleListRequests)

	s.mux.Handle("/v1/", s.cfg.Auth.Middleware(api))

	// Admin API — authenticated by shared secret (dashboard→server)
	admin := http.NewServeMux()
	admin.HandleFunc("GET /v1/admin/tunnels", s.handleAdminListTunnels)
	admin.HandleFunc("DELETE /v1/admin/tunnels/{id}", s.handleAdminCloseTunnel)
	admin.HandleFunc("POST /v1/admin/tunnels/{id}/suspend", s.handleAdminSuspendTunnel)
	s.mux.Handle("/v1/admin/", s.adminMiddleware(admin))

	// Dashboard (if enabled)
	if s.cfg.DashHandler != nil {
		s.mux.Handle("/dash/", s.cfg.DashHandler)
		s.mux.Handle("/dash", s.cfg.DashHandler)
	}
}

// subdomainHandler wraps the main mux to intercept subdomain-based tunnel requests.
// If the Host header matches {slug}.{baseDomain}, it routes to the proxy handler.
// Otherwise it falls through to the normal mux.
func (s *Server) subdomainHandler(next http.Handler) http.Handler {
	if s.cfg.BaseDomain == "" {
		return next
	}
	suffix := "." + s.cfg.BaseDomain
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Strip port if present
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}

		// Check if this is a tunnel subdomain request: {slug}.tunnel.nullbore.com
		if strings.HasSuffix(host, suffix) && host != s.cfg.BaseDomain {
			slug := strings.TrimSuffix(host, suffix)
			if slug != "" && !strings.Contains(slug, ".") {
				s.handleSubdomainProxy(w, r, slug)
				return
			}
		}

		// Check if this is an account subdomain request: {tunnel}.{account}.nullbore.com
		if s.cfg.AccountDomain != "" {
			acctSuffix := "." + s.cfg.AccountDomain
			if strings.HasSuffix(host, acctSuffix) && host != s.cfg.AccountDomain {
				sub := strings.TrimSuffix(host, acctSuffix)
				parts := strings.SplitN(sub, ".", 2)
				if len(parts) == 2 {
					// Two-level: web.heroapp.nullbore.com → tunnel="web", account="heroapp"
					s.handleAccountSubdomainProxy(w, r, parts[1], parts[0])
					return
				}
				if len(parts) == 1 && parts[0] != "tunnel" && parts[0] != "www" {
					// Single-level account subdomain: heroapp.nullbore.com → show index/default tunnel
					s.handleAccountSubdomainProxy(w, r, parts[0], "")
					return
				}
			}
		}

		// Check if this is a custom domain request
		if s.cfg.DomainResolver != nil && host != s.cfg.BaseDomain && !strings.HasSuffix(host, suffix) {
			slug, _, err := s.cfg.DomainResolver.Resolve(host)
			if err == nil && slug != "" {
				s.handleSubdomainProxy(w, r, slug)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// handleSubdomainProxy handles proxying for subdomain-based tunnel requests.
//
// The base tunnel domain ({slug}.tunnel.nullbore.com) and the account namespace
// (*.heroapp.nullbore.com) are separate routing planes. A slug miss on the base
// domain must NOT fall back to account resolution — that would let bare global
// hostnames silently route to a user's first active tunnel and leak account
// existence.
func (s *Server) handleSubdomainProxy(w http.ResponseWriter, r *http.Request, slug string) {
	t, ok := s.cfg.Registry.GetBySlug(slug)
	if !ok {
		writeNotFound(w)
		return
	}

	// User-selected slugs are reserved for account/custom domain namespaces.
	// Do not serve non-random slugs on the global base domain (e.g. name.tunnel.nullbore.com).
	if !isGeneratedSlug(slug) && s.cfg.BaseDomain != "" {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		suffix := "." + s.cfg.BaseDomain
		if strings.HasSuffix(host, suffix) {
			left := strings.TrimSuffix(host, suffix)
			if left == slug && !strings.Contains(left, ".") {
				http.Error(w, "tunnel not found", http.StatusNotFound)
				return
			}
		}
	}

	if t.Suspended {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tunnel Suspended</title><style>body{font-family:system-ui;background:#1a1a2e;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}div{text-align:center;max-width:400px;padding:2rem}.icon{font-size:3rem;margin-bottom:1rem}h1{font-size:1.3rem;margin:0.5rem 0}p{color:#888;font-size:0.9rem}a{color:#6366f1}</style></head><body><div><div class="icon">⏸️</div><h1>Tunnel Suspended</h1><p>This tunnel has been temporarily suspended by its owner.</p><p style="margin-top:1.5rem;font-size:0.8rem;"><a href="https://nullbore.com">Powered by NullBore</a></p></div></body></html>`)
		return
	}

	if time.Now().After(t.ExpiresAt) {
		http.Error(w, "tunnel expired", http.StatusGone)
		return
	}

	// IP allowlist check — uses TrustedProxy-gated client IP
	if s.cfg.IPChecker != nil {
		allowlist := s.cfg.IPChecker.GetIPAllowlistForUser(t.ClientID)
		if !checkIPAllowed(s.clientIP(r), allowlist) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied</title><style>body{font-family:system-ui;background:#1a1a2e;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}div{text-align:center;max-width:400px;padding:2rem}.icon{font-size:3rem;margin-bottom:1rem}h1{font-size:1.3rem;margin:0.5rem 0}p{color:#888;font-size:0.9rem}a{color:#6366f1}</style></head><body><div><div class="icon">🚫</div><h1>Access Denied</h1><p>Your IP address is not permitted to access this tunnel.</p><p style="margin-top:1.5rem;font-size:0.8rem;"><a href="https://nullbore.com">Powered by NullBore</a></p></div></body></html>`)
			return
		}
	}

	// Basic auth check (if configured on this tunnel)
	if !s.checkTunnelAuth(w, r, t) {
		return
	}

	// Per-tunnel request rate limit
	if !s.checkProxyRateLimit(w, t) {
		return
	}

	// Reconstruct HTTP request — for subdomain proxy, the full path stays as-is
	reqBytes := reconstructSubdomainRequest(r, slug)

	// Tier-based body limit (falls back to global MaxBodyBytes config)
	bodyLimit := tierMaxBodyBytes(t.Tier)
	if s.cfg.MaxBodyBytes > 0 && s.cfg.MaxBodyBytes < bodyLimit {
		bodyLimit = s.cfg.MaxBodyBytes
	}
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, bodyLimit))
	}
	reqPrefix := append(reqBytes, bodyBytes...)

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

	if buf.Reader.Buffered() > 0 {
		buffered := make([]byte, buf.Reader.Buffered())
		buf.Read(buffered)
		conn = &prefixConn{Conn: conn, prefix: buffered}
	}

	if err := s.wsHub.RelayConn(t.ID, conn, reqPrefix); err != nil {
		log.Printf("relay error: tunnel=%s err=%v", t.ID, err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 24\r\n\r\ntunnel client unavailable"))
		conn.Close()
		return
	}

	t.AddRequest()
}

// reconstructSubdomainRequest rebuilds raw HTTP request bytes for subdomain proxying.
// Unlike path-based proxy, the URL path stays as-is (not stripped).
func reconstructSubdomainRequest(r *http.Request, slug string) []byte {
	var buf bytes.Buffer

	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}

	isWebSocket := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")

	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", r.Method, path)
	fmt.Fprintf(&buf, "Host: localhost\r\n")
	if isWebSocket {
		fmt.Fprintf(&buf, "Connection: Upgrade\r\n")
		fmt.Fprintf(&buf, "Upgrade: websocket\r\n")
	} else {
		fmt.Fprintf(&buf, "Connection: close\r\n")
	}

	for key, vals := range r.Header {
		lower := strings.ToLower(key)
		if lower == "host" || lower == "connection" || lower == "upgrade" {
			continue
		}
		// Strip hop-by-hop headers (but keep Sec-WebSocket-* for WS upgrades)
		if lower == "transfer-encoding" ||
			lower == "proxy-connection" || lower == "keep-alive" ||
			lower == "te" || lower == "trailer" {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, v)
		}
	}

	buf.WriteString("\r\n")
	return buf.Bytes()
}

func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%s", s.cfg.Host, s.cfg.Port)

	// Wrap with: request ID → logging → subdomain routing → mux.
	// Request ID must be outermost so the logging middleware sees it for
	// every request, and so the X-Request-ID response header is set even
	// on early-return paths inside the subdomain handler.
	handler := RequestIDMiddleware(LoggingMiddleware(s.subdomainHandler(s.mux)))

	// Wrap handler to inject version headers on all responses
	versionHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-NullBore-Version", ServerVersion)
		w.Header().Set("X-NullBore-API", APIVersion)
		handler.ServeHTTP(w, r)
	})

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      versionHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Disabled — tunnel connections are long-lived
		IdleTimeout:  60 * time.Second,
		// Disable HTTP/2 — our proxy handler requires Hijack(), which HTTP/2 doesn't support.
		// This is the same approach used by chisel and similar tunnel servers.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	srv := s.httpServer

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

// Shutdown gracefully shuts down the server, waiting for active connections to finish.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	log.Printf("shutting down server...")
	return s.httpServer.Shutdown(ctx)
}

// handleAccountSubdomainProxy handles account subdomain routing.
// Two-level: web.heroapp.nullbore.com → accountSub="heroapp", tunnelName="web"
// Single-level: heroapp.nullbore.com → accountSub="heroapp", tunnelName=""
//
// Security model: every non-match path returns the same generic 404 as
// writeNotFound, so an attacker cannot distinguish:
//   - account subdomains not configured at all
//   - unknown account
//   - real account / unknown leaf
//   - real account / no default tunnel (bare host)
// Any divergence here becomes an enumeration oracle for which accounts and
// leaf names exist.
func (s *Server) handleAccountSubdomainProxy(w http.ResponseWriter, r *http.Request, accountSub, tunnelName string) {
	if s.cfg.SubdomainResolver == nil {
		writeNotFound(w)
		return
	}

	userID, err := s.cfg.SubdomainResolver.Resolve(accountSub)
	if err != nil || userID == "" {
		writeNotFound(w)
		return
	}

	if tunnelName == "" {
		// Bare heroapp.nullbore.com. We deliberately do NOT fall back to
		// "first active tunnel" — that would silently expose whichever tunnel
		// happened to sort first under the account's bare hostname, which is
		// non-deterministic and violates the rule that named tunnels must be
		// reached via their exact named subdomain. A future opt-in default
		// tunnel field on the account can re-enable bare-host routing.
		writeNotFound(w)
		return
	}

	// {leaf}.heroapp.nullbore.com — only an exact tunnel-name match proxies.
	// Anything else is indistinguishable from "account does not exist".
	tunnels := s.cfg.Registry.GetByClient(userID)
	for _, t := range tunnels {
		if t.Slug == tunnelName {
			s.handleSubdomainProxy(w, r, t.Slug)
			return
		}
	}
	writeNotFound(w)
}

// --- API Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "ok",
		"version":     ServerVersion,
		"api_version": APIVersion,
	})
}

type createTunnelRequest struct {
	LocalPort  int    `json:"local_port"`
	Name       string `json:"name,omitempty"`
	TTL        string `json:"ttl,omitempty"`
	IdleTTL    bool   `json:"idle_ttl,omitempty"`
	DeviceName string `json:"device_name,omitempty"` // human-readable device name
	Source     string `json:"source,omitempty"`      // "cli" or "daemon"
	AuthUser   string `json:"auth_user,omitempty"`   // basic auth username
	AuthPass   string `json:"auth_pass,omitempty"`   // basic auth password
}

// tierMaxTTL returns the max TTL for a tier.
func tierMaxTTL(tier string) time.Duration {
	switch tier {
	case "pro":
		return 0 // no limit (persistent)
	case "hobby":
		return 7 * 24 * time.Hour // 7 days
	default: // free
		return 2 * time.Hour
	}
}

// checkTunnelAuth returns true if the request passes the tunnel's basic auth check.
// If the tunnel has no auth configured, all requests pass.
// On success, strips the Authorization header so the local service doesn't see it.
func (s *Server) checkTunnelAuth(w http.ResponseWriter, r *http.Request, t *tunnel.Tunnel) bool {
	if t.AuthUser == "" {
		return true // no auth configured
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != t.AuthUser || pass != t.AuthPass {
		w.Header().Set("WWW-Authenticate", `Basic realm="NullBore Tunnel"`)
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return false
	}
	// Strip tunnel auth header — don't leak it to the local service
	r.Header.Del("Authorization")
	return true
}

// checkProxyRateLimit returns true if the request is allowed through.
func (s *Server) checkProxyRateLimit(w http.ResponseWriter, t *tunnel.Tunnel) bool {
	tier := t.Tier
	if tier == "" {
		tier = "free"
	}
	limiter, ok := s.proxyLimiters[tier]
	if !ok {
		limiter = s.proxyLimiters["free"]
	}
	if !limiter.Allow(t.ID) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "429 Too Many Requests — tunnel rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}

// tierMaxBodyBytes returns the max request body size for a tier.
// Scaled to bandwidth allocation: free=25MB, hobby=100MB, pro=500MB.
func tierMaxBodyBytes(tier string) int64 {
	switch tier {
	case "pro":
		return 500 * 1024 * 1024
	case "hobby":
		return 100 * 1024 * 1024
	default: // free
		return 25 * 1024 * 1024
	}
}

// tierTunnelLimit returns the max active tunnels for a tier.
func tierTunnelLimit(tier string) int {
	switch tier {
	case "pro":
		return 20
	case "hobby":
		return 5
	default: // free or unknown
		return 1
	}
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	clientID := auth.ClientIDFrom(r.Context())

	// Rate limit by client ID
	if !s.rateLimiter.Allow(clientID) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}

	// Enforce per-tier tunnel limits
	tier := auth.TierFrom(r.Context())
	limit := tierTunnelLimit(tier)
	current := s.cfg.Registry.CountByClient(clientID)
	if current >= limit {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"error": fmt.Sprintf("tunnel limit reached (%d/%d for %s tier)", current, limit, tier),
			"limit": limit,
			"tier":  tier,
		})
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

	// Validate tunnel name — only allowed if user owns an account subdomain or custom domain
	if req.Name != "" {
		if err := validateTunnelName(req.Name); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// Allow reclaiming an existing tunnel by slug (reconnect after restart)
		isReclaim := false
		if existing, ok := s.cfg.Registry.GetBySlug(req.Name); ok && existing.ClientID == clientID {
			isReclaim = true
		}

		if !isReclaim {
			// Named tunnels require an account subdomain (Hobby+) or custom domain (Pro).
			// Without one, names would collide in the global tunnel.nullbore.com namespace.
			hasNamespace := false
			if rp := getRemoteProvider(s.cfg.Auth); rp != nil {
				token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if sub := rp.GetSubdomain(token); sub != "" {
					hasNamespace = true
				}
			}
			if !hasNamespace {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "named tunnels require an account subdomain — claim one in your dashboard (Hobby plan and up)",
				})
				return
			}
		}
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

	// TTL=0 means persistent (pro only)
	if ttl == 0 {
		if tier != "pro" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "persistent tunnels require Pro tier"})
			return
		}
		ttl = 100 * 365 * 24 * time.Hour // ~100 years
	}

	// Enforce tier-based TTL cap (0 = no limit for pro)
	if maxTTL := tierMaxTTL(tier); maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}

	// Bandwidth limit check
	if rp := getRemoteProvider(s.cfg.Auth); rp != nil {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		used, limit := rp.GetBandwidthInfo(token)
		if limit > 0 && used >= limit {
			writeJSON(w, http.StatusPaymentRequired, map[string]string{
				"error": "monthly bandwidth limit exceeded — upgrade your plan or wait until next month",
			})
			return
		}
	}

	// Build creation options. All fields are applied atomically inside
	// CreateWithOptions before the tunnel is published into the slug map,
	// so concurrent proxy requests can never race on Tier/AuthUser/etc.
	opts := tunnel.CreateOptions{
		LocalPort:  req.LocalPort,
		Name:       req.Name,
		TTL:        ttl,
		Tier:       tier,
		IdleTTL:    req.IdleTTL,
		Source:     req.Source,
		DeviceName: req.DeviceName,
	}
	if opts.AuthUser == "" && req.AuthUser != "" && req.AuthPass != "" {
		opts.AuthUser = req.AuthUser
		opts.AuthPass = req.AuthPass
	}
	// Device identity — prefer request body, fall back to header
	if opts.DeviceName == "" {
		if h := r.Header.Get("X-NullBore-Device-Hostname"); h != "" {
			opts.DeviceName = h
		}
	}

	t, err := s.cfg.Registry.CreateWithOptions(clientID, opts)
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
	}
	if s.cfg.Events != nil {
		s.cfg.Events.LogEvent(t.ID, t.ClientID, "created", fmt.Sprintf("port=%d slug=%s ttl=%s", t.LocalPort, t.Slug, ttl))
	}

	// Build response with public URL (use account subdomain if available)
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	resp := struct {
		*tunnel.Tunnel
		PublicURL string `json:"public_url"`
	}{
		Tunnel:    t,
		PublicURL: s.publicURLForClient(t.Slug, token),
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	clientID := auth.ClientIDFrom(r.Context())
	tunnels := s.cfg.Registry.List(clientID)

	type tunnelWithURL struct {
		*tunnel.Tunnel
		PublicURL string `json:"public_url"`
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	result := make([]tunnelWithURL, 0, len(tunnels))
	for _, t := range tunnels {
		result = append(result, tunnelWithURL{Tunnel: t, PublicURL: s.publicURLForClient(t.Slug, token)})
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	clientID := auth.ClientIDFrom(r.Context())
	t, ok := s.cfg.Registry.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	if t.ClientID != clientID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	resp := struct {
		*tunnel.Tunnel
		PublicURL string `json:"public_url"`
	}{Tunnel: t, PublicURL: s.publicURLForClient(t.Slug, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCloseTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	clientID := auth.ClientIDFrom(r.Context())
	t, ok := s.cfg.Registry.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	if t.ClientID != clientID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	if err := s.cfg.Registry.Close(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if s.cfg.Store != nil {
		s.cfg.Store.CloseTunnel(id)
	}
	if s.cfg.Events != nil {
		s.cfg.Events.LogEvent(id, clientID, "closed", "closed via API")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

// handleSuspendTunnel toggles a tunnel's suspended state (user-facing, ownership checked).
func (s *Server) handleSuspendTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	clientID := auth.ClientIDFrom(r.Context())
	t, ok := s.cfg.Registry.Get(id)
	if !ok || t.ClientID != clientID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}

	var req struct {
		Suspended bool `json:"suspended"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	if err := s.cfg.Registry.SetSuspended(id, req.Suspended); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	state := "resumed"
	if req.Suspended {
		state = "suspended"
	}
	if s.cfg.Events != nil {
		s.cfg.Events.LogEvent(id, clientID, state, "via API")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": state, "suspended": fmt.Sprintf("%v", req.Suspended)})
}

type extendRequest struct {
	TTL string `json:"ttl"`
}

func (s *Server) handleExtendTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	clientID := auth.ClientIDFrom(r.Context())

	// Verify ownership before parsing request
	t, ok := s.cfg.Registry.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	if t.ClientID != clientID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}

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

	t, _ = s.cfg.Registry.Get(id)
	writeJSON(w, http.StatusOK, t)
}

// --- Proxy Handler ---
//
func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	clientID := auth.ClientIDFrom(r.Context())

	t, ok := s.cfg.Registry.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	if t.ClientID != clientID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not your tunnel"})
		return
	}

	if s.cfg.Events == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	logs, err := s.cfg.Events.ListRequests(id, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list requests"})
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

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

	// IP allowlist check — uses TrustedProxy-gated client IP
	if s.cfg.IPChecker != nil {
		allowlist := s.cfg.IPChecker.GetIPAllowlistForUser(t.ClientID)
		if !checkIPAllowed(s.clientIP(r), allowlist) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied</title><style>body{font-family:system-ui;background:#1a1a2e;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}div{text-align:center;max-width:400px;padding:2rem}.icon{font-size:3rem;margin-bottom:1rem}h1{font-size:1.3rem;margin:0.5rem 0}p{color:#888;font-size:0.9rem}a{color:#6366f1}</style></head><body><div><div class="icon">🚫</div><h1>Access Denied</h1><p>Your IP address is not permitted to access this tunnel.</p><p style="margin-top:1.5rem;font-size:0.8rem;"><a href="https://nullbore.com">Powered by NullBore</a></p></div></body></html>`)
			return
		}
	}

	// Basic auth check (if configured on this tunnel)
	if !s.checkTunnelAuth(w, r, t) {
		return
	}

	// Per-tunnel request rate limit
	if !s.checkProxyRateLimit(w, t) {
		return
	}

	// Reconstruct the HTTP request as raw bytes.
	// The HTTP server has already consumed the request, so we need to rebuild it
	// so the local service on the client side receives a proper HTTP request.
	reqBytes := reconstructHTTPRequest(r)

	// Tier-based body limit (falls back to global MaxBodyBytes config)
	bodyLimit := tierMaxBodyBytes(t.Tier)
	if s.cfg.MaxBodyBytes > 0 && s.cfg.MaxBodyBytes < bodyLimit {
		bodyLimit = s.cfg.MaxBodyBytes
	}
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, bodyLimit))
	}

	reqPrefix := append(reqBytes, bodyBytes...)

	// Log request for inspection (async, non-blocking)
	if s.cfg.Store != nil {
		// Cap body passed to log (log only needs first 4KB snippet)
		logBody := bodyBytes
		if len(logBody) > 4096 {
			logBody = logBody[:4096]
		}
		go s.logRequest(t, r, logBody)
	}

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

	t.AddRequest()
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

	// WebSocket upgrades need Connection: Upgrade + Upgrade: websocket to pass through.
	// Regular requests get Connection: close (each gets its own data WebSocket / pipe).
	isWS := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if isWS {
		fmt.Fprintf(&buf, "Connection: Upgrade\r\n")
		fmt.Fprintf(&buf, "Upgrade: websocket\r\n")
	} else {
		fmt.Fprintf(&buf, "Connection: close\r\n")
	}

	// Remaining headers — skip hop-by-hop (keep Sec-WebSocket-* for WS)
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

// --- Admin API ---

// adminMiddleware verifies the X-Admin-Secret header matches the configured secret.
func (s *Server) adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminSecret == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "admin API not configured — start the server with --admin-secret or set NULLBORE_ADMIN_SECRET",
			})
			return
		}
		secret := r.Header.Get("X-Admin-Secret")
		if secret == "" {
			// Also check Authorization: Bearer <secret> for flexibility
			auth := r.Header.Get("Authorization")
			if len(auth) > 7 && auth[:7] == "Bearer " {
				secret = auth[7:]
			}
		}
		if secret == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "missing admin secret — pass it via X-Admin-Secret header or Authorization: Bearer <secret>",
			})
			return
		}
		if subtle.ConstantTimeCompare([]byte(secret), []byte(s.cfg.AdminSecret)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid admin secret"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleAdminListTunnels returns all live tunnels, optionally filtered by client_id.
func (s *Server) handleAdminListTunnels(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	tunnels := s.cfg.Registry.List(clientID) // empty clientID = all tunnels
	if tunnels == nil {
		tunnels = []*tunnel.Tunnel{}
	}

	// Enrich with connection status
	type enrichedTunnel struct {
		*tunnel.Tunnel
		Connected bool   `json:"connected"`
		URL       string `json:"url,omitempty"`
	}

	result := make([]enrichedTunnel, len(tunnels))
	for i, t := range tunnels {
		connected := false
		if conn, err := s.cfg.Registry.GetConn(t.ID); err == nil && conn != nil {
			connected = true
		}
		url := ""
		if s.cfg.BaseDomain != "" {
			url = fmt.Sprintf("https://%s.%s", t.Slug, s.cfg.BaseDomain)
		} else {
			url = fmt.Sprintf("/t/%s", t.Slug)
		}
		result[i] = enrichedTunnel{
			Tunnel:    t,
			Connected: connected,
			URL:       url,
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// handleAdminCloseTunnel force-closes any tunnel by ID.
func (s *Server) handleAdminCloseTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Registry.Close(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if s.cfg.Store != nil {
		s.cfg.Store.CloseTunnel(id)
	}
	if s.cfg.Events != nil {
		s.cfg.Events.LogEvent(id, "", "closed", "closed via admin API")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

// handleAdminSuspendTunnel toggles any tunnel's suspended state.
func (s *Server) handleAdminSuspendTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Suspended bool `json:"suspended"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	if err := s.cfg.Registry.SetSuspended(id, req.Suspended); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	state := "resumed"
	if req.Suspended {
		state = "suspended"
	}
	if s.cfg.Events != nil {
		s.cfg.Events.LogEvent(id, "", state, "via admin API")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": state})
}

// publicURL returns the public-facing URL for a tunnel slug.
// Uses subdomain routing if base_domain is set, otherwise falls back to path-based.
func (s *Server) publicURL(slug string) string {
	if s.cfg.BaseDomain != "" {
		return fmt.Sprintf("https://%s.%s", slug, s.cfg.BaseDomain)
	}
	return fmt.Sprintf("/t/%s", slug)
}

// publicURLForClient returns the URL using the user's account subdomain if they have one.
// With account subdomain: https://web.heroapp.nullbore.com
// Without: https://slug.tunnel.nullbore.com
func (s *Server) publicURLForClient(slug, token string) string {
	if rp := getRemoteProvider(s.cfg.Auth); rp != nil && token != "" {
		if sub := rp.GetSubdomain(token); sub != "" && s.cfg.AccountDomain != "" {
			return fmt.Sprintf("https://%s.%s.%s", slug, sub, s.cfg.AccountDomain)
		}
	}
	if s.cfg.BaseDomain != "" {
		return fmt.Sprintf("https://%s.%s", slug, s.cfg.BaseDomain)
	}
	return fmt.Sprintf("/t/%s", slug)
}

func getRemoteProvider(p auth.Provider) *auth.RemoteProvider {
	switch v := p.(type) {
	case *auth.RemoteProvider:
		return v
	case *auth.ComboProvider:
		if rp, ok := v.Primary.(*auth.RemoteProvider); ok {
			return rp
		}
	}
	return nil
}

// --- Helpers ---

// Tunnel name rules:
//   - 2-63 characters
//   - lowercase alphanumeric + hyphens only
//   - must start and end with alphanumeric
//   - no consecutive hyphens
//   - reserved names blocked (health, dash, ws, v1, api, etc.)
var (
	tunnelNameRe       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	tunnelNameReserved = map[string]bool{
		"health": true, "dash": true, "api": true,
		"ws": true, "v1": true, "v2": true,
		"login": true, "admin": true, "static": true,
		"t": true, "tunnel": true, "tunnels": true,
	}
)

func validateTunnelName(name string) error {
	if len(name) < 2 || len(name) > 63 {
		return fmt.Errorf("tunnel name must be 2-63 characters")
	}
	if !tunnelNameRe.MatchString(name) {
		return fmt.Errorf("tunnel name must be lowercase alphanumeric with hyphens, no leading/trailing hyphens")
	}
	if strings.Contains(name, "--") {
		return fmt.Errorf("tunnel name must not contain consecutive hyphens")
	}
	if tunnelNameReserved[name] {
		return fmt.Errorf("tunnel name %q is reserved", name)
	}
	return nil
}

// isGeneratedSlug reports whether a slug looks like an auto-generated random slug
// (12 lowercase hex chars). User-chosen slugs should not resolve on base domain.
func isGeneratedSlug(slug string) bool {
	if len(slug) != 12 {
		return false
	}
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// logRequest records request metadata for the tunnel inspection log.
func (s *Server) logRequest(t *tunnel.Tunnel, r *http.Request, body []byte) {
	// Build headers JSON (skip large/sensitive ones)
	hdrs := make(map[string]string)
	for k, vs := range r.Header {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "cookie" {
			hdrs[k] = "[redacted]"
		} else {
			hdrs[k] = strings.Join(vs, ", ")
		}
	}
	headersJSON, _ := json.Marshal(hdrs)

	// Body snippet — first 4KB
	snippet := ""
	if len(body) > 0 {
		if len(body) > 4096 {
			snippet = string(body[:4096])
		} else {
			snippet = string(body)
		}
	}

	path := "/" + r.PathValue("path")
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}

	if s.cfg.Events != nil {
		s.cfg.Events.LogRequest(t.ID, t.Slug, r.Method, path, string(headersJSON), int64(len(body)), snippet, s.clientIP(r))
	}
}

// writeNotFound returns a generic 404 with no information that could leak
// account or tunnel-name existence. Every "not found" code path under the
// account-subdomain plane MUST funnel through here so responses are byte-for-byte
// identical regardless of which condition failed (unknown account, unknown leaf,
// resolver not configured, etc.). Any branding or hostname echoback turns this
// into an enumeration oracle.
func writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404 not found\n")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode error: %v", err)
	}
}

// clientIP returns the originating client IP for a request, honoring
// X-Forwarded-For ONLY when the immediate peer is in TrustedProxies.
//
// Without this gating, anyone on the internet can spoof X-Forwarded-For
// to bypass per-tunnel IP allowlists or pollute request logs. By default
// TrustedProxies is empty, so X-F-F is ignored entirely — the safe stance
// for a server fronted by nothing or by ACME on its own listener. Set the
// flag in front-of-CDN deployments.
func (s *Server) clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if h, _, err := net.SplitHostPort(peer); err == nil {
		peer = h
	}
	if len(s.cfg.TrustedProxies) > 0 {
		if ip := net.ParseIP(peer); ip != nil && ipInCIDRs(ip, s.cfg.TrustedProxies) {
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				// Use the leftmost address (the original client per RFC 7239 §5.2)
				if first := strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0]); first != "" {
					return first
				}
			}
		}
	}
	return peer
}

func ipInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// checkIPAllowed checks if the given remote address is permitted by the CIDR allowlist.
// If the allowlist is empty, all IPs are allowed.
// remoteAddr can be "IP:port" or just "IP".
func checkIPAllowed(remoteAddr string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = host
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}
