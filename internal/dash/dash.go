package dash

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"

	"github.com/nullbore/nullbore-server/internal/store"
)

//go:embed static/*
var staticFiles embed.FS

// Config holds dashboard configuration.
type Config struct {
	Password string
	Store    *store.Store
}

// Handler returns an HTTP handler for the dashboard.
func Handler(cfg Config) http.Handler {
	mux := http.NewServeMux()

	// Static files
	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))

	// Auth middleware
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("nb_session")
			if err != nil || !cfg.Store.ValidateSession(cookie.Value) {
				if r.Header.Get("Accept") == "application/json" {
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
				} else {
					http.Redirect(w, r, "/dash/login", http.StatusFound)
				}
				return
			}
			next(w, r)
		}
	}

	// Login page (served as static file)
	mux.Handle("GET /dash/login", fileServer)

	// Login API
	mux.HandleFunc("POST /dash/api/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if subtle.ConstantTimeCompare([]byte(req.Password), []byte(cfg.Password)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid password"})
			return
		}

		token, err := cfg.Store.CreateSession()
		if err != nil {
			log.Printf("session create error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "nb_session",
			Value:    token,
			Path:     "/dash",
			MaxAge:   86400,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Logout
	mux.HandleFunc("POST /dash/api/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "nb_session",
			Value:  "",
			Path:   "/dash",
			MaxAge: -1,
		})
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// --- Protected API endpoints ---

	// Tunnels
	mux.HandleFunc("GET /dash/api/tunnels", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		tunnels, err := cfg.Store.ListTunnels("", status, 100)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if tunnels == nil {
			tunnels = []store.TunnelRecord{}
		}
		writeJSON(w, 200, tunnels)
	}))

	mux.HandleFunc("DELETE /dash/api/tunnels/{id}", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := cfg.Store.CloseTunnel(id); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		cfg.Store.LogEvent(id, "closed", "closed via dashboard")
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}))

	mux.HandleFunc("GET /dash/api/tunnels/{id}/events", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		events, err := cfg.Store.GetEvents(id, 50)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if events == nil {
			events = []store.TunnelEvent{}
		}
		writeJSON(w, 200, events)
	}))

	// API Keys
	mux.HandleFunc("GET /dash/api/keys", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			clientID = "default"
		}
		keys, err := cfg.Store.ListAPIKeys(clientID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if keys == nil {
			keys = []store.APIKey{}
		}
		writeJSON(w, 200, keys)
	}))

	mux.HandleFunc("POST /dash/api/keys", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID string `json:"client_id"`
			Label    string `json:"label"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.ClientID == "" {
			req.ClientID = "default"
		}

		rawKey, key, err := cfg.Store.CreateAPIKey(req.ClientID, req.Label)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}

		writeJSON(w, 201, map[string]interface{}{
			"key":     rawKey, // Only shown once!
			"details": key,
		})
	}))

	mux.HandleFunc("DELETE /dash/api/keys/{id}", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := cfg.Store.RevokeAPIKey(id); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"status": "revoked"})
	}))

	// Stats
	mux.HandleFunc("GET /dash/api/stats", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		stats, err := cfg.Store.GetStats()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, stats)
	}))

	// Catch-all: serve static files for the SPA
	mux.HandleFunc("GET /dash/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	}))
	mux.HandleFunc("GET /dash", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dash/", http.StatusFound)
	}))

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
