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

