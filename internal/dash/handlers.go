package dash

import (
	"encoding/json"
	"net/http"

	"github.com/nullbore/nullbore-server/internal/store"
)

// Handlers holds shared dashboard API handlers.
// These are auth-agnostic — the caller wraps them with whatever
// auth middleware is appropriate (passphrase, OAuth, etc.).
type Handlers struct {
	Store *store.Store
}

// NewHandlers creates shared dashboard handlers.
func NewHandlers(s *store.Store) *Handlers {
	return &Handlers{Store: s}
}

// --- Tunnel handlers ---

// ListTunnels returns tunnels, optionally filtered by status.
func (h *Handlers) ListTunnels(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	tunnels, err := h.Store.ListTunnels("", status, 100)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if tunnels == nil {
		tunnels = []store.TunnelRecord{}
	}
	writeJSON(w, 200, tunnels)
}

// CloseTunnel closes a tunnel by ID.
func (h *Handlers) CloseTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Store.CloseTunnel(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	h.Store.LogEvent(id, "closed", "closed via dashboard")
	writeJSON(w, 200, map[string]string{"status": "closed"})
}

// GetTunnelEvents returns events for a tunnel.
func (h *Handlers) GetTunnelEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	events, err := h.Store.GetEvents(id, 50)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if events == nil {
		events = []store.TunnelEvent{}
	}
	writeJSON(w, 200, events)
}

// --- API Key handlers ---

// ListAPIKeys returns API keys for a client.
func (h *Handlers) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = "default"
	}
	keys, err := h.Store.ListAPIKeys(clientID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if keys == nil {
		keys = []store.APIKey{}
	}
	writeJSON(w, 200, keys)
}

// CreateAPIKey generates a new API key.
func (h *Handlers) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		Label    string `json:"label"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.ClientID == "" {
		req.ClientID = "default"
	}

	rawKey, key, err := h.Store.CreateAPIKey(req.ClientID, req.Label)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	writeJSON(w, 201, map[string]interface{}{
		"key":     rawKey,
		"details": key,
	})
}

// RevokeAPIKey revokes an API key by ID.
func (h *Handlers) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Store.RevokeAPIKey(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "revoked"})
}

// --- Stats ---

// GetStats returns dashboard statistics.
func (h *Handlers) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.Store.GetStats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, stats)
}

// RegisterRoutes mounts all shared API handlers on the given mux.
// Each handler is wrapped with the provided auth middleware.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /dash/api/tunnels", auth(h.ListTunnels))
	mux.HandleFunc("DELETE /dash/api/tunnels/{id}", auth(h.CloseTunnel))
	mux.HandleFunc("GET /dash/api/tunnels/{id}/events", auth(h.GetTunnelEvents))
	mux.HandleFunc("GET /dash/api/keys", auth(h.ListAPIKeys))
	mux.HandleFunc("POST /dash/api/keys", auth(h.CreateAPIKey))
	mux.HandleFunc("DELETE /dash/api/keys/{id}", auth(h.RevokeAPIKey))
	mux.HandleFunc("GET /dash/api/stats", auth(h.GetStats))
}
