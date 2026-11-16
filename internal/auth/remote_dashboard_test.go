package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeDashboard mimics /internal/validate-key: 403 on a wrong shared secret,
// otherwise 200 {"valid":false} (no real keys exist here).
func fakeDashboard(secret string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Secret") != secret {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"valid":false}`))
	}))
}

func TestCheckDashboard(t *testing.T) {
	dash := fakeDashboard("right")
	defer dash.Close()

	if got := NewRemoteProvider(dash.URL, "right").CheckDashboard(); got != DashboardOK {
		t.Errorf("matching secret: got %q, want %q", got, DashboardOK)
	}
	p := NewRemoteProvider(dash.URL, "wrong")
	if got := p.CheckDashboard(); got != DashboardSecretMismatch {
		t.Errorf("wrong secret: got %q, want %q", got, DashboardSecretMismatch)
	}
	if got := p.DashboardStatus(); got != DashboardSecretMismatch {
		t.Errorf("DashboardStatus after check = %q", got)
	}

	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	if got := NewRemoteProvider(dead.URL, "right").CheckDashboard(); got != DashboardUnreachable {
		t.Errorf("closed server: got %q, want %q", got, DashboardUnreachable)
	}
}

func TestValidateRecordsSecretMismatch(t *testing.T) {
	dash := fakeDashboard("right")
	defer dash.Close()

	p := NewRemoteProvider(dash.URL, "wrong")
	if p.DashboardStatus() != "" {
		t.Fatalf("status before any call = %q, want empty", p.DashboardStatus())
	}
	if _, ok := p.Validate("nbk_some_user_key"); ok {
		t.Fatal("key accepted despite 403 from dashboard")
	}
	if got := p.DashboardStatus(); got != DashboardSecretMismatch {
		t.Errorf("status after 403 = %q, want %q", got, DashboardSecretMismatch)
	}
}
