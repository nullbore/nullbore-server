package dash

import (
	"io/fs"
	"net/http"

	"github.com/nullbore/nullbore-server/internal/store"
)

// Tier represents a subscription tier with its limits.
type Tier struct {
	Name           string `json:"name"` // free, hobby, pro
	MaxTunnels     int    `json:"max_tunnels"`
	MaxTTLHours    int    `json:"max_ttl_hours"`
	MonthlyBandwidth int64 `json:"monthly_bandwidth_bytes"`
	Webhooks       bool   `json:"webhooks"`
	CustomDomains  bool   `json:"custom_domains"`
	MaxAPIKeys     int    `json:"max_api_keys"`
}

// Predefined tiers.
var (
	TierFree = Tier{
		Name: "free", MaxTunnels: 1, MaxTTLHours: 2,
		MonthlyBandwidth: 2 * 1024 * 1024 * 1024, // 2 GB
		Webhooks: false, CustomDomains: false, MaxAPIKeys: 1,
	}
	TierHobby = Tier{
		Name: "hobby", MaxTunnels: 3, MaxTTLHours: 8,
		MonthlyBandwidth: 25 * 1024 * 1024 * 1024, // 25 GB
		Webhooks: true, CustomDomains: false, MaxAPIKeys: 3,
	}
	TierPro = Tier{
		Name: "pro", MaxTunnels: 10, MaxTTLHours: 24,
		MonthlyBandwidth: 100 * 1024 * 1024 * 1024, // 100 GB
		Webhooks: true, CustomDomains: true, MaxAPIKeys: 10,
	}
)

// HostedConfig holds configuration for the hosted (commercial) dashboard.
type HostedConfig struct {
	Store *store.Store
	// TODO: Add when implementing hosted dashboard
	// UserStore    *userstore.Store   // user accounts, sessions
	// StripeKey    string             // Stripe API key
	// OAuthConfig  *oauth2.Config     // OAuth provider config
	// WebhookSecret string           // for signing outgoing webhooks
}

// HostedHandler returns an HTTP handler for the hosted (commercial) dashboard.
// This wraps the same shared handlers as EmbeddedHandler, but adds:
//   - User account auth (OAuth / magic link) instead of passphrase
//   - Tier-based feature gating
//   - Billing / Stripe integration
//   - Account management routes
//
// NOT YET IMPLEMENTED — this is the scaffold for Phase 4.
func HostedHandler(cfg HostedConfig) http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(staticFiles, "static")
	handlers := NewHandlers(cfg.Store)

	// TODO: Replace with OAuth/magic link session validation
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Placeholder — will check user session + load tier
			http.Error(w, "hosted auth not implemented", http.StatusNotImplemented)
		}
	}

	// TODO: Tier gate middleware — checks feature access against user's plan
	// tierGate := func(feature string, next http.HandlerFunc) http.HandlerFunc { ... }

	// --- Shared API routes (same handlers, different auth) ---
	handlers.RegisterRoutes(mux, requireAuth)

	// --- Hosted-only routes ---

	// Account management
	mux.HandleFunc("GET /dash/api/account", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Return user profile, current tier, usage stats
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	}))

	// Billing
	mux.HandleFunc("GET /dash/api/billing", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Return current plan, Stripe customer portal link
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	}))

	mux.HandleFunc("POST /dash/api/billing/checkout", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Create Stripe checkout session, return redirect URL
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	}))

	// Webhook configuration (Hobby+ tier)
	mux.HandleFunc("GET /dash/api/webhooks", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// TODO: List configured webhook endpoints
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	}))

	mux.HandleFunc("POST /dash/api/webhooks", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Create webhook endpoint (tier-gated)
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	}))

	// Custom domains (Pro tier)
	mux.HandleFunc("GET /dash/api/domains", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// TODO: List custom domains
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	}))

	mux.HandleFunc("POST /dash/api/domains", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Add custom domain (tier-gated, needs DNS verification)
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	}))

	// --- Auth routes (hosted-specific) ---

	// Login page
	mux.HandleFunc("GET /dash/login", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Serve hosted login page (OAuth buttons, magic link form)
		// For now, serve the same static login page
		data, err := fs.ReadFile(staticFS, "login")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// OAuth callback
	mux.HandleFunc("GET /dash/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Handle OAuth callback, create user session
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	})

	// Registration
	mux.HandleFunc("POST /dash/api/register", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Create account (invite-only initially)
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	})

	// Stripe webhook receiver
	mux.HandleFunc("POST /dash/webhook/stripe", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Handle Stripe events (subscription created/updated/cancelled)
		writeJSON(w, 501, map[string]string{"error": "not implemented"})
	})

	// --- Static UI ---

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

// TierFor returns the tier for a given plan name.
func TierFor(name string) Tier {
	switch name {
	case "hobby":
		return TierHobby
	case "pro":
		return TierPro
	default:
		return TierFree
	}
}
