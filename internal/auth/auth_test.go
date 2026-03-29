package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStaticProviderValidKey(t *testing.T) {
	p := NewStaticProvider("nbk_testclient_secret123")
	clientID, ok := p.Validate("nbk_testclient_secret123")
	if !ok {
		t.Fatal("expected valid key")
	}
	if clientID != "testclient" {
		t.Fatalf("expected clientID 'testclient', got %s", clientID)
	}
}

func TestStaticProviderInvalidKey(t *testing.T) {
	p := NewStaticProvider("nbk_testclient_secret123")
	_, ok := p.Validate("nbk_testclient_wrongsecret")
	if ok {
		t.Fatal("expected invalid key")
	}
}

func TestStaticProviderMultipleKeys(t *testing.T) {
	p := NewStaticProvider("nbk_alice_key1, nbk_bob_key2")

	id, ok := p.Validate("nbk_alice_key1")
	if !ok || id != "alice" {
		t.Fatalf("expected alice, got %s (ok=%v)", id, ok)
	}

	id, ok = p.Validate("nbk_bob_key2")
	if !ok || id != "bob" {
		t.Fatalf("expected bob, got %s (ok=%v)", id, ok)
	}

	_, ok = p.Validate("nbk_charlie_key3")
	if ok {
		t.Fatal("expected invalid for unknown key")
	}
}

func TestStaticProviderDevMode(t *testing.T) {
	// No keys = dev mode, accept everything
	p := NewStaticProvider("")
	id, ok := p.Validate("anything")
	if !ok {
		t.Fatal("dev mode should accept any key")
	}
	if id != "dev" {
		t.Fatalf("expected dev client ID, got %s", id)
	}
}

func TestMiddlewareNoAuthHeader(t *testing.T) {
	p := NewStaticProvider("nbk_test_secret")
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/v1/tunnels", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMiddlewareInvalidFormat(t *testing.T) {
	p := NewStaticProvider("nbk_test_secret")
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/v1/tunnels", nil)
	req.Header.Set("Authorization", "Basic abc123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMiddlewareValidKey(t *testing.T) {
	p := NewStaticProvider("nbk_test_secret")
	var gotClientID string
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClientID = ClientIDFrom(r.Context())
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotClientID != "test" {
		t.Fatalf("expected client ID 'test', got %s", gotClientID)
	}
}

func TestMiddlewareHealthBypass(t *testing.T) {
	p := NewStaticProvider("nbk_test_secret")
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for health (no auth), got %d", rec.Code)
	}
}

func TestMiddlewareInvalidKey(t *testing.T) {
	p := NewStaticProvider("nbk_test_secret")
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer nbk_wrong_key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
