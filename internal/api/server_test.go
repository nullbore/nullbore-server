package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

func newTestServer(apiKeys string) (*Server, *httptest.Server) {
	authProvider := auth.NewStaticProvider(apiKeys)
	registry := tunnel.NewRegistry()
	go registry.StartReaper()

	srv := NewServer(Config{
		Auth:     authProvider,
		Registry: registry,
	})

	ts := httptest.NewServer(srv.mux)
	return srv, ts
}

func TestHealthEndpoint(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %s", body["status"])
	}
}

func TestCreateTunnel(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	payload := `{"local_port": 8080, "ttl": "30m"}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(body))
	}

	var tun tunnel.Tunnel
	json.NewDecoder(resp.Body).Decode(&tun)
	if tun.ID == "" {
		t.Fatal("expected non-empty tunnel ID")
	}
	if tun.LocalPort != 8080 {
		t.Fatalf("expected port 8080, got %d", tun.LocalPort)
	}
}

func TestCreateTunnelNoAuth(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	payload := `{"local_port": 8080}`
	resp, err := http.Post(ts.URL+"/v1/tunnels", "application/json", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCreateTunnelInvalidPort(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	payload := `{"local_port": 0}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestListTunnels(t *testing.T) {
	// Use two different clients since free tier limits each to 1 tunnel
	_, ts := newTestServer("nbk_clientX_key1,nbk_clientY_key2")
	defer ts.Close()

	keys := []string{"nbk_clientX_key1", "nbk_clientY_key2"}
	for i, port := range []int{8080, 9090} {
		payload := fmt.Sprintf(`{"local_port": %d}`, port)
		req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", bytes.NewBufferString(payload))
		req.Header.Set("Authorization", "Bearer "+keys[i])
		req.Header.Set("Content-Type", "application/json")
		http.DefaultClient.Do(req)
	}

	// Client X should see 1 tunnel (their own)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer nbk_clientX_key1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var tunnels []tunnel.Tunnel
	json.NewDecoder(resp.Body).Decode(&tunnels)
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel for clientX, got %d", len(tunnels))
	}
}

func TestCloseTunnel(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	payload := `{"local_port": 8080}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }

	var tun tunnel.Tunnel
	json.NewDecoder(resp.Body).Decode(&tun)
	resp.Body.Close()

	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/tunnels/"+tun.ID, nil)
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/v1/tunnels/"+tun.ID, nil)
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp2.Body.Close()

	if resp2.StatusCode != 404 {
		t.Fatalf("expected 404 after close, got %d", resp2.StatusCode)
	}
}

func TestExtendTunnel(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	payload := `{"local_port": 8080, "ttl": "10m"}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }

	var tun tunnel.Tunnel
	json.NewDecoder(resp.Body).Decode(&tun)
	resp.Body.Close()

	extPayload := `{"ttl": "30m"}`
	req, _ = http.NewRequest("POST", ts.URL+"/v1/tunnels/"+tun.ID+"/extend", bytes.NewBufferString(extPayload))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestProxyNoTunnel(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/t/nonexistent")
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// TestFullRelay tests the bore-style end-to-end relay:
// 1. Create tunnel via REST
// 2. Connect control WebSocket
// 3. Start a local HTTP service
// 4. Hit the proxy endpoint
// 5. Server hijacks conn, notifies client via control WS
// 6. Client opens data WebSocket, pipes to local service
// 7. Verify response arrives
func TestFullRelay(t *testing.T) {
	_, ts := newTestServer("nbk_test_secret")
	defer ts.Close()

	// 1. Start a local TCP service that speaks HTTP
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localListener.Close()
	localPort := localListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := localListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.Read(buf) // read the HTTP request
				response := "HTTP/1.1 200 OK\r\nContent-Length: 23\r\nX-Local: true\r\n\r\nhello from local service"
				c.Write([]byte(response))
			}(conn)
		}
	}()

	// 2. Create tunnel via API
	payload := fmt.Sprintf(`{"local_port": %d}`, localPort)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	var tun tunnel.Tunnel
	json.NewDecoder(resp.Body).Decode(&tun)
	resp.Body.Close()

	// 3. Connect control WebSocket
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/control?tunnel_id=" + tun.ID
	wsHeader := http.Header{}
	wsHeader.Set("Authorization", "Bearer nbk_test_secret")

	controlConn, _, err := websocket.DefaultDialer.Dial(wsURL, wsHeader)
	if err != nil {
		t.Fatalf("control ws dial: %v", err)
	}
	defer controlConn.Close()

	// 4. Start a goroutine to simulate the client:
	//    - Read "connection" messages from control WS
	//    - Open data WebSocket for each
	//    - Pipe to local service
	go func() {
		for {
			_, message, err := controlConn.ReadMessage()
			if err != nil {
				return
			}

			var msg controlMessage
			json.Unmarshal(message, &msg)

			if msg.Type == "connection" {
				go func(connID string) {
					// Open data WebSocket
					dataURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/data?id=" + connID
					dataWS, _, err := websocket.DefaultDialer.Dial(dataURL, nil)
					if err != nil {
						t.Logf("data ws dial error: %v", err)
						return
					}

					// Connect to local service
					localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 5*time.Second)
					if err != nil {
						dataWS.Close()
						return
					}

					// Pipe: data WS ↔ local TCP
					dataConn := NewWSNetConn(dataWS)
					pipe(localConn, dataConn)
				}(msg.ID)
			}
		}
	}()

	// Give the control connection a moment
	time.Sleep(50 * time.Millisecond)

	// 5. Hit the proxy endpoint — this triggers the whole relay chain
	proxyConn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("proxy connect: %v", err)
	}
	defer proxyConn.Close()

	// Send an HTTP request through the proxy
	httpReq := fmt.Sprintf("GET /t/%s/ HTTP/1.1\r\nHost: localhost\r\n\r\n", tun.Slug)
	proxyConn.Write([]byte(httpReq))

	// Read the response
	proxyConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 4096)
	n, err := proxyConn.Read(respBuf)
	if err != nil {
		t.Fatalf("proxy read: %v", err)
	}

	respStr := string(respBuf[:n])
	if !strings.Contains(respStr, "200 OK") {
		t.Fatalf("expected 200 OK, got: %s", respStr)
	}
	if !strings.Contains(respStr, "hello from local service") {
		t.Fatalf("expected 'hello from local service', got: %s", respStr)
	}
}

// TestAccountSubdomainRouting404s verifies the security-critical 404 paths
// for account subdomain routing. Every "not found" condition must return a
// generic 404 — not a branded page, not a 503, not a host echoback — so
// attackers cannot enumerate which accounts or leaf names exist.
//
// Covered scenarios:
//   - bare account host (heroapp.nullbore.com) with no default tunnel: 404
//   - unknown leaf under registered account (carp.heroapp.nullbore.com): 404
//   - unknown account, single-level (fake.nullbore.com): 404
//   - unknown account, leaf (leaf.fake.nullbore.com): 404
func TestAccountSubdomainRouting404s(t *testing.T) {
	// Tiny dashboard stub: only "heroapp" is registered, owned by "user-1".
	dash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/resolve-subdomain" {
			http.NotFound(w, r)
			return
		}
		name := r.URL.Query().Get("name")
		if name == "heroapp" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"user_id":"user-1"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer dash.Close()

	registry := tunnel.NewRegistry()
	// Create a named tunnel "shark" owned by user-1. We don't attach a WS
	// client — we never exercise the proxy path, only the 404 paths.
	if _, err := registry.Create("user-1", 8080, "shark", time.Hour); err != nil {
		t.Fatalf("registry.Create: %v", err)
	}

	srv := NewServer(Config{
		Auth:              auth.NewStaticProvider("nbk_test_secret"),
		Registry:          registry,
		BaseDomain:        "tunnel.nullbore.com",
		AccountDomain:     "nullbore.com",
		SubdomainResolver: NewSubdomainResolver(dash.URL, ""),
	})

	// Wrap the mux exactly as ListenAndServe does, so we exercise the
	// real subdomainHandler routing layer.
	ts := httptest.NewServer(srv.subdomainHandler(srv.mux))
	defer ts.Close()

	cases := []struct {
		name string
		host string
	}{
		{"bare registered account routes nowhere by default", "heroapp.nullbore.com"},
		{"unknown leaf under registered account is 404", "carp.heroapp.nullbore.com"},
		{"unknown bare account is 404", "fake.nullbore.com"},
		{"unknown leaf under unknown account is 404", "leaf.fake.nullbore.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", ts.URL+"/", nil)
			req.Host = tc.host
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status: got %d, want 404 (body=%q)", resp.StatusCode, string(body))
			}
			// Body must NOT echo back the hostname or account name —
			// that would defeat the indistinguishability property.
			bodyStr := string(body)
			for _, leak := range []string{"heroapp", "carp", "fake", "leaf"} {
				if strings.Contains(bodyStr, leak) {
					t.Errorf("404 body leaks %q (host=%s, body=%q)", leak, tc.host, bodyStr)
				}
			}
		})
	}
}

// stubIPChecker returns a fixed allowlist for any user.
type stubIPChecker struct{ allowlist []string }

func (s *stubIPChecker) GetIPAllowlistForUser(userID string) []string {
	return s.allowlist
}

// TestClientIP_TrustedProxyHonorsXFF verifies that X-Forwarded-For is
// honored ONLY when the immediate peer matches a configured TrustedProxies
// CIDR. Without TrustedProxies, X-F-F is ignored entirely — the safe
// default. This is the regression test for the IP-allowlist bypass bug.
func TestClientIP_TrustedProxyHonorsXFF(t *testing.T) {
	_, trustedNet, _ := net.ParseCIDR("10.0.0.0/8")

	cases := []struct {
		name           string
		trusted        []*net.IPNet
		remoteAddr     string
		xff            string
		wantClientIP   string
		wantAllowed    bool
		allowlist      []string
	}{
		{
			name:         "no trusted proxies → XFF ignored, peer used",
			trusted:      nil,
			remoteAddr:   "203.0.113.5:54321",
			xff:          "1.2.3.4",
			wantClientIP: "203.0.113.5",
		},
		{
			name:         "peer not in trusted list → XFF ignored",
			trusted:      []*net.IPNet{trustedNet},
			remoteAddr:   "203.0.113.5:54321",
			xff:          "1.2.3.4",
			wantClientIP: "203.0.113.5",
		},
		{
			name:         "peer in trusted list → XFF leftmost honored",
			trusted:      []*net.IPNet{trustedNet},
			remoteAddr:   "10.0.0.7:34123",
			xff:          "1.2.3.4, 10.0.0.7",
			wantClientIP: "1.2.3.4",
		},
		{
			name:         "peer in trusted list, no XFF → peer used",
			trusted:      []*net.IPNet{trustedNet},
			remoteAddr:   "10.0.0.7:34123",
			wantClientIP: "10.0.0.7",
		},
		{
			name:         "peer in trusted list, empty XFF → peer used",
			trusted:      []*net.IPNet{trustedNet},
			remoteAddr:   "10.0.0.7:34123",
			xff:          "",
			wantClientIP: "10.0.0.7",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(Config{
				TrustedProxies: tc.trusted,
				Auth:           auth.NewStaticProvider(""),
				Registry:       tunnel.NewRegistry(),
			})
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			got := srv.clientIP(req)
			if got != tc.wantClientIP {
				t.Errorf("clientIP = %q, want %q", got, tc.wantClientIP)
			}
		})
	}
}

// TestClientIP_AllowlistBypassPrevention is the end-to-end version of the
// bug: a malicious caller spoofs X-Forwarded-For to make their request
// appear to come from an allowlisted IP. With TrustedProxies empty (the
// safe default) the spoof must be ignored.
func TestClientIP_AllowlistBypassPrevention(t *testing.T) {
	srv := NewServer(Config{
		// Note: NO TrustedProxies. The internet-facing peer's X-F-F
		// header must NOT be honored.
		Auth:     auth.NewStaticProvider(""),
		Registry: tunnel.NewRegistry(),
	})
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.99:12345" // attacker
	req.Header.Set("X-Forwarded-For", "10.0.0.1") // claims to be the allowlisted internal IP
	got := srv.clientIP(req)
	if got != "198.51.100.99" {
		t.Errorf("untrusted peer's spoofed X-F-F was honored: clientIP = %q, want 198.51.100.99", got)
	}
	// And confirm the allowlist enforcement actually rejects the attacker
	allowed := checkIPAllowed(got, []string{"10.0.0.0/8"})
	if allowed {
		t.Error("attacker bypassed IP allowlist via X-Forwarded-For spoofing")
	}
}

// TestSuspendTunnelInvalidJSON verifies that handleSuspendTunnel returns
// 400 on malformed JSON instead of silently treating it as suspended=false.
// Regression test for the silently-swallowed decode bug.
func TestSuspendTunnelInvalidJSON(t *testing.T) {
	authProvider := auth.NewStaticProvider("nbk_default_secret")
	registry := tunnel.NewRegistry()
	srv := NewServer(Config{Auth: authProvider, Registry: registry})

	// Create a tunnel for the static "default" client
	tun, err := registry.CreateWithOptions("default", tunnel.CreateOptions{
		LocalPort: 8080,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(authProvider.Middleware(srv.mux))
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels/"+tun.ID+"/suspend",
		strings.NewReader("{not valid json"))
	req.Header.Set("Authorization", "Bearer nbk_default_secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("malformed JSON: got %d, want 400 (body=%s)", resp.StatusCode, string(body))
	}

	// And confirm the tunnel was NOT suspended (i.e. the decode failure
	// did not silently fall through to a state change)
	if tun.Suspended {
		t.Error("malformed JSON suspend request silently mutated state")
	}
}

// TestRequestIDMiddleware_GeneratesAndPropagates verifies that every
// response carries an X-Request-ID header, that an inbound ID is preserved
// when sane, and that an oversized inbound ID is replaced.
func TestRequestIDMiddleware_GeneratesAndPropagates(t *testing.T) {
	var observedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedID = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := RequestIDMiddleware(inner)

	// Case 1: no inbound ID → middleware generates one
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)
	gen := w.Header().Get("X-Request-ID")
	if gen == "" || len(gen) != 16 {
		t.Errorf("generated id wrong shape: %q", gen)
	}
	if observedID != gen {
		t.Errorf("context id %q != response header id %q", observedID, gen)
	}

	// Case 2: sane inbound ID → preserved
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-ID", "trace-abc-123")
	handler.ServeHTTP(w, r)
	if got := w.Header().Get("X-Request-ID"); got != "trace-abc-123" {
		t.Errorf("inbound id not preserved: got %q", got)
	}

	// Case 3: oversized inbound ID → replaced (anti-log-injection / memory abuse)
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-ID", strings.Repeat("a", 1024))
	handler.ServeHTTP(w, r)
	if got := w.Header().Get("X-Request-ID"); len(got) != 16 {
		t.Errorf("oversized id should be replaced with generated, got len=%d", len(got))
	}

	// Case 4: control-character inbound ID → replaced
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-ID", "evil\nlog\tinjection")
	handler.ServeHTTP(w, r)
	if got := w.Header().Get("X-Request-ID"); len(got) != 16 {
		t.Errorf("control-char id should be replaced with generated, got %q", got)
	}
}

// TestCreateWithOptionsAtomicPublication is the regression test for the
// data race: it verifies that all fields set via CreateOptions are
// readable by the time the tunnel is in the slug map. The race detector
// in `make test-race` is what would catch concurrent racing access; this
// test pins the contract.
func TestCreateWithOptionsAtomicPublication(t *testing.T) {
	r := tunnel.NewRegistry()
	opts := tunnel.CreateOptions{
		LocalPort:  8080,
		Name:       "myapp",
		TTL:        time.Hour,
		Tier:       "pro",
		DeviceName: "macbook",
		Source:     "cli",
		IdleTTL:    true,
		AuthUser:   "alice",
		AuthPass:   "s3cret",
	}
	tun, err := r.CreateWithOptions("user-1", opts)
	if err != nil {
		t.Fatalf("CreateWithOptions: %v", err)
	}

	// Look up by slug — this is exactly the path the proxy handler uses,
	// and it must observe all the fields set above.
	got, ok := r.GetBySlug("myapp")
	if !ok {
		t.Fatal("tunnel not findable by slug after CreateWithOptions")
	}
	if got.Tier != "pro" {
		t.Errorf("Tier: got %q want pro", got.Tier)
	}
	if got.DeviceName != "macbook" {
		t.Errorf("DeviceName: got %q want macbook", got.DeviceName)
	}
	if got.Source != "cli" {
		t.Errorf("Source: got %q want cli", got.Source)
	}
	if !got.IdleTTL {
		t.Error("IdleTTL: got false want true")
	}
	if got.AuthUser != "alice" || got.AuthPass != "s3cret" {
		t.Errorf("AuthUser/Pass: got %q/%q want alice/s3cret", got.AuthUser, got.AuthPass)
	}
	if got.ID != tun.ID {
		t.Errorf("ID mismatch: registry=%q created=%q", got.ID, tun.ID)
	}
}
