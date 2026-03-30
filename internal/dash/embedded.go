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

// EmbeddedConfig holds configuration for the embedded (self-hosted) dashboard.
type EmbeddedConfig struct {
	Password string
	Store    *store.Store
}

// EmbeddedHandler returns an HTTP handler for the self-hosted dashboard.
// Auth is via a single passphrase — no user accounts, no billing.
func EmbeddedHandler(cfg EmbeddedConfig) http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(staticFiles, "static")
	handlers := NewHandlers(cfg.Store)

	// Passphrase auth middleware
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

	// --- Auth routes (embedded-specific) ---

	// Login page
	mux.HandleFunc("GET /dash/login", func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(staticFS, "login")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// Login API — passphrase check
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

	// --- Shared API routes (auth-wrapped) ---
	handlers.RegisterRoutes(mux, requireAuth)

	// --- Static UI ---

	// Main dashboard page
	mux.HandleFunc("GET /dash/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(staticFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}))
	mux.HandleFunc("GET /dash", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dash/", http.StatusFound)
	}))

	return mux
}
