package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTierTunnelLimit(t *testing.T) {
	tests := []struct {
		tier     string
		expected int
	}{
		{"free", 1},
		{"hobby", 5},
		{"pro", 20},
		{"", 1},
	}
	for _, tt := range tests {
		got := tierTunnelLimit(tt.tier)
		if got != tt.expected {
			t.Errorf("tierTunnelLimit(%q) = %d, want %d", tt.tier, got, tt.expected)
		}
	}
}

func TestTierMaxBodyBytes(t *testing.T) {
	tests := []struct {
		tier     string
		expected int64
	}{
		{"free", 25 * 1024 * 1024},
		{"hobby", 100 * 1024 * 1024},
		{"pro", 500 * 1024 * 1024},
		{"", 25 * 1024 * 1024},
	}
	for _, tt := range tests {
		got := tierMaxBodyBytes(tt.tier)
		if got != tt.expected {
			t.Errorf("tierMaxBodyBytes(%q) = %d, want %d", tt.tier, got, tt.expected)
		}
	}
}

func TestTierMaxTTL(t *testing.T) {
	tests := []struct {
		tier     string
		expected time.Duration
	}{
		{"free", 2 * time.Hour},
		{"hobby", 7 * 24 * time.Hour},
		{"pro", 0},
		{"", 2 * time.Hour},
	}
	for _, tt := range tests {
		got := tierMaxTTL(tt.tier)
		if got != tt.expected {
			t.Errorf("tierMaxTTL(%q) = %v, want %v", tt.tier, got, tt.expected)
		}
	}
}

func TestVersionEndpoint(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/v1/version", nil)
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("version request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("version status = %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)

	if body["api_version"] != APIVersion {
		t.Errorf("api_version = %q, want %q", body["api_version"], APIVersion)
	}
	if body["version"] == "" {
		t.Error("version should not be empty")
	}
}

func TestTunnelLimitEnforcement(t *testing.T) {
	// Static auth with no tier = free = limit of 1
	_, ts := newTestServer("nbk_clientA_secret1")
	defer ts.Close()

	createTunnel := func(port int) int {
		body := fmt.Sprintf(`{"local_port":%d}`, port)
		req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer nbk_clientA_secret1")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create tunnel failed: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// First tunnel should succeed
	if status := createTunnel(3000); status != 201 {
		t.Fatalf("first tunnel status = %d, want 201", status)
	}

	// Second tunnel should be rejected (free tier limit = 1)
	if status := createTunnel(3001); status != 403 {
		t.Errorf("second tunnel status = %d, want 403 (limit reached)", status)
	}
}

func TestTTLCapEnforcement(t *testing.T) {
	// Static auth (no tier) = free = max 2h TTL
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	body := `{"local_port":3000,"ttl":"48h"}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create tunnel failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := json.Marshal(resp.Body)
		t.Fatalf("create status = %d, want 201, body=%s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	ttlStr, ok := result["ttl"].(string)
	if !ok {
		t.Fatalf("ttl not in response: %+v", result)
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		t.Fatalf("parse ttl %q: %v", ttlStr, err)
	}
	if ttl > 2*time.Hour {
		t.Errorf("ttl = %v, want <= 2h (free tier cap)", ttl)
	}
}

func TestOwnershipCheck(t *testing.T) {
	// Two different clients
	_, ts := newTestServer("nbk_clientA_secret1,nbk_clientB_secret2")
	defer ts.Close()

	// Client A creates a tunnel
	body := `{"local_port":3000}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer nbk_clientA_secret1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create tunnel failed: %v", err)
	}
	var created map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}

	tunnelID, ok := created["id"].(string)
	if !ok || tunnelID == "" {
		t.Fatalf("no tunnel id in response: %+v", created)
	}

	// Client B tries to GET it — should get 404
	req, _ = http.NewRequest("GET", ts.URL+"/v1/tunnels/"+tunnelID, nil)
	req.Header.Set("Authorization", "Bearer nbk_clientB_secret2")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get tunnel failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("cross-user GET status = %d, want 404", resp.StatusCode)
	}

	// Client B tries to DELETE it — should get 404
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/tunnels/"+tunnelID, nil)
	req.Header.Set("Authorization", "Bearer nbk_clientB_secret2")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete tunnel failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("cross-user DELETE status = %d, want 404", resp.StatusCode)
	}

	// Client A can still GET it
	req, _ = http.NewRequest("GET", ts.URL+"/v1/tunnels/"+tunnelID, nil)
	req.Header.Set("Authorization", "Bearer nbk_clientA_secret1")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("own GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("own GET status = %d, want 200", resp.StatusCode)
	}

	// Client A can DELETE it
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/tunnels/"+tunnelID, nil)
	req.Header.Set("Authorization", "Bearer nbk_clientA_secret1")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("own DELETE failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("own DELETE status = %d, want 200", resp.StatusCode)
	}
}
