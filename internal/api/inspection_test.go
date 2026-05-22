package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/store"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

// --- parseStatusLine ---

func TestParseStatusLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"OK", "HTTP/1.1 200 OK", 200},
		{"NotFound", "HTTP/1.1 404 Not Found", 404},
		{"SwitchProto", "HTTP/1.1 101 Switching Protocols", 101},
		{"ServerError", "HTTP/1.1 500 Internal Server Error", 500},
		{"HTTP10", "HTTP/1.0 200 OK", 200},
		{"NoReason", "HTTP/1.1 200", 200},
		{"Empty", "", 0},
		{"Garbage", "GIBBERISH", 0},
		{"MissingHTTPPrefix", "1.1 200 OK", 0},
		{"NonNumericCode", "HTTP/1.1 ABC OK", 0},
		{"OutOfRangeLow", "HTTP/1.1 99 ?", 0},
		{"OutOfRangeHigh", "HTTP/1.1 600 ?", 0},
		{"ZeroCode", "HTTP/1.1 0 ?", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseStatusLine([]byte(c.in))
			if got != c.want {
				t.Errorf("parseStatusLine(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// --- responseSniffer ---

func TestResponseSniffer_SingleWrite(t *testing.T) {
	var sink bytes.Buffer
	s := &responseSniffer{w: &sink}
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	n, err := s.Write([]byte(resp))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(resp) {
		t.Errorf("Write returned n=%d, want %d", n, len(resp))
	}
	if !s.parsed {
		t.Error("expected parsed=true")
	}
	if s.status != 200 {
		t.Errorf("status = %d, want 200", s.status)
	}
	if s.bytes != int64(len(resp)) {
		t.Errorf("bytes = %d, want %d", s.bytes, len(resp))
	}
	if sink.String() != resp {
		t.Error("passthrough write didn't match")
	}
}

func TestResponseSniffer_ByteByByte(t *testing.T) {
	var sink bytes.Buffer
	s := &responseSniffer{w: &sink}
	resp := "HTTP/1.1 404 Not Found\r\n\r\n"
	for _, b := range []byte(resp) {
		s.Write([]byte{b})
	}
	if s.status != 404 {
		t.Errorf("status = %d, want 404", s.status)
	}
	if s.bytes != int64(len(resp)) {
		t.Errorf("bytes = %d, want %d", s.bytes, len(resp))
	}
}

func TestResponseSniffer_StatusSplitAcrossWrites(t *testing.T) {
	var sink bytes.Buffer
	s := &responseSniffer{w: &sink}
	s.Write([]byte("HTTP/1.1 5"))
	s.Write([]byte("03 Service Unavailable\r\n\r\n"))
	if s.status != 503 {
		t.Errorf("status = %d, want 503", s.status)
	}
}

func TestResponseSniffer_NoStatusLineGivesUp(t *testing.T) {
	var sink bytes.Buffer
	s := &responseSniffer{w: &sink}
	// Write more than 4KB without a \r — sniffer should give up and stay
	// parsed=true with status=0, but passthrough should still work.
	junk := bytes.Repeat([]byte{'x'}, 5000)
	s.Write(junk)
	if !s.parsed {
		t.Error("expected sniffer to give up after 4KB and set parsed=true")
	}
	if s.status != 0 {
		t.Errorf("status = %d, want 0 (unparsed)", s.status)
	}
	if s.bytes != 5000 {
		t.Errorf("bytes = %d, want 5000", s.bytes)
	}
}

// --- parseReplayResponse ---

func TestParseReplayResponse(t *testing.T) {
	t.Run("WellFormed", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
		r := parseReplayResponse([]byte(raw), false, 42)
		if r.Status != 200 {
			t.Errorf("status = %d, want 200", r.Status)
		}
		if r.Body != "hello" {
			t.Errorf("body = %q, want %q", r.Body, "hello")
		}
		if !strings.Contains(r.Headers, "Content-Type") {
			t.Errorf("headers missing Content-Type: %q", r.Headers)
		}
		if r.DurationMs != 42 {
			t.Errorf("duration = %d, want 42", r.DurationMs)
		}
		if r.Err != "" {
			t.Errorf("unexpected error: %q", r.Err)
		}
	})

	t.Run("NoHeaderTerminator", func(t *testing.T) {
		r := parseReplayResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain"), false, 0)
		if r.Status != 0 || r.Body != "" {
			t.Errorf("incomplete response should not populate status/body, got status=%d body=%q", r.Status, r.Body)
		}
	})

	t.Run("EmptyBuffer", func(t *testing.T) {
		r := parseReplayResponse(nil, false, 5)
		if r.Err == "" {
			t.Error("empty buffer should set error message")
		}
	})

	t.Run("BodyTruncation", func(t *testing.T) {
		big := bytes.Repeat([]byte{'b'}, 40*1024)
		raw := append([]byte("HTTP/1.1 200 OK\r\n\r\n"), big...)
		r := parseReplayResponse(raw, false, 0)
		if !r.Truncated {
			t.Error("expected truncated=true for >32KB body")
		}
		if len(r.Body) != 32*1024 {
			t.Errorf("body length = %d, want 32768", len(r.Body))
		}
	})
}

// --- Handler tier gates ---

// tierAuthMiddleware mimics the production RemoteProvider's behavior: it
// validates the API key via the StaticProvider and additionally injects the
// configured tier into the request context. Used to exercise tier-gated
// handlers without spinning up a fake dashboard.
func tierAuthMiddleware(p *auth.StaticProvider, tier string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.WithTier(r.Context(), tier)
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
}

// newInspectableTestServer spins up a server with a real EventStore so the
// inspection code paths exercise the SQL layer too. Wraps the mux with
// auth + tier middleware — use this for handler/tier-gate tests.
func newInspectableTestServer(t *testing.T, tier string) (*Server, *httptest.Server, *store.EventStore, *auth.StaticProvider) {
	t.Helper()
	authProvider := auth.NewStaticProvider("nbk_test_secret")
	registry := tunnel.NewRegistry()

	events, err := store.NewEventStore(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(Config{
		Auth:     authProvider,
		Registry: registry,
		Events:   events,
	})

	ts := httptest.NewServer(tierAuthMiddleware(authProvider, tier)(srv.mux))
	return srv, ts, events, authProvider
}

// newRelayTestServer is like newInspectableTestServer but skips auth
// middleware — the integration tests need to send a raw HTTP request
// into the /t/{slug} proxy path without an Authorization header. Tunnels
// are created via registry.CreateWithOptions directly.
func newRelayTestServer(t *testing.T) (*Server, *httptest.Server, *store.EventStore) {
	t.Helper()
	authProvider := auth.NewStaticProvider("nbk_test_secret")
	registry := tunnel.NewRegistry()

	events, err := store.NewEventStore(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(Config{
		Auth:     authProvider,
		Registry: registry,
		Events:   events,
	})

	ts := httptest.NewServer(srv.mux)
	return srv, ts, events
}

func TestHandleSetInspection_TierGates(t *testing.T) {
	cases := []struct {
		tier     string
		wantCode int
	}{
		{"free", http.StatusPaymentRequired},
		{"", http.StatusPaymentRequired},
		{"dev", http.StatusOK},
		{"pro", http.StatusOK},
	}
	for _, c := range cases {
		t.Run("tier="+c.tier, func(t *testing.T) {
			srv, ts, _, _ := newInspectableTestServer(t, c.tier)
			defer ts.Close()

			tun, err := srv.cfg.Registry.CreateWithOptions("test", tunnel.CreateOptions{
				LocalPort: 8080,
				TTL:       time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}

			req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels/"+tun.ID+"/inspection",
				strings.NewReader(`{"enabled":true}`))
			req.Header.Set("Authorization", "Bearer nbk_test_secret")
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.wantCode {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("tier=%q: got %d, want %d (body=%s)", c.tier, resp.StatusCode, c.wantCode, body)
			}
			// On success, the flag should actually flip.
			if c.wantCode == http.StatusOK {
				after, _ := srv.cfg.Registry.Get(tun.ID)
				if !after.InspectionEnabled {
					t.Error("expected InspectionEnabled=true after 200")
				}
			}
		})
	}
}

func TestHandleSetInspection_NotYourTunnel(t *testing.T) {
	srv, ts, _, _ := newInspectableTestServer(t, "dev")
	defer ts.Close()

	// Tunnel owned by a different client.
	tun, _ := srv.cfg.Registry.CreateWithOptions("someone-else", tunnel.CreateOptions{
		LocalPort: 8080,
		TTL:       time.Hour,
	})

	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels/"+tun.ID+"/inspection",
		strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Authorization", "Bearer nbk_test_secret") // client = "test", not "someone-else"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

func TestHandleListRequests_TierGates(t *testing.T) {
	cases := []struct {
		tier     string
		wantCode int
	}{
		{"free", http.StatusPaymentRequired},
		{"dev", http.StatusOK},
		{"pro", http.StatusOK},
	}
	for _, c := range cases {
		t.Run("tier="+c.tier, func(t *testing.T) {
			srv, ts, _, _ := newInspectableTestServer(t, c.tier)
			defer ts.Close()

			tun, _ := srv.cfg.Registry.CreateWithOptions("test", tunnel.CreateOptions{
				LocalPort: 8080,
				TTL:       time.Hour,
			})

			req, _ := http.NewRequest("GET", ts.URL+"/v1/tunnels/"+tun.ID+"/requests", nil)
			req.Header.Set("Authorization", "Bearer nbk_test_secret")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.wantCode {
				t.Errorf("tier=%q: got %d, want %d", c.tier, resp.StatusCode, c.wantCode)
			}
		})
	}
}

// --- End-to-end inspection + replay through the full relay ---
//
// Mirrors TestFullRelay's scaffolding: real local TCP service, real WS
// control + data channels, real proxy hit. Confirms request_log writes
// happen only when inspection is enabled, and that response status +
// latency get attached. Then replays the same request and confirms a
// second upstream hit + JSON response.

func TestEndToEndInspection(t *testing.T) {
	srv, ts, events := newRelayTestServer(t)
	defer ts.Close()

	localPort, stopLocal := startEchoUpstream(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	defer stopLocal()

	tun, err := srv.cfg.Registry.CreateWithOptions("test", tunnel.CreateOptions{
		LocalPort: localPort,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	wireClient(t, ts, tun, localPort)

	// 1. With inspection OFF (default), hit the tunnel — no row should land.
	hitProxy(t, ts, tun.Slug, "/foo?x=1")
	logs, _ := events.ListRequests(tun.ID, 50)
	if len(logs) != 0 {
		t.Fatalf("inspection off: expected 0 logged requests, got %d", len(logs))
	}

	// 2. Turn inspection on and hit again — exactly one row, with response
	//    fields populated.
	if err := srv.cfg.Registry.SetInspectionEnabled(tun.ID, true); err != nil {
		t.Fatal(err)
	}
	hitProxy(t, ts, tun.Slug, "/inspected?yo=1")

	// Response writeback is async; give it a beat.
	deadline := time.Now().Add(2 * time.Second)
	var captured store.RequestLog
	for time.Now().Before(deadline) {
		logs, _ = events.ListRequests(tun.ID, 50)
		if len(logs) == 1 && logs[0].StatusCode != 0 {
			captured = logs[0]
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if captured.ID == "" {
		t.Fatalf("inspection on: did not get a populated row in time. logs=%+v", logs)
	}
	if captured.Method != "GET" {
		t.Errorf("method = %q, want GET", captured.Method)
	}
	if !strings.Contains(captured.Path, "/inspected") {
		t.Errorf("path = %q, want it to contain /inspected", captured.Path)
	}
	if captured.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", captured.StatusCode)
	}
	if captured.DurationMs < 0 {
		t.Errorf("duration_ms = %d, want >= 0", captured.DurationMs)
	}
	if captured.ResponseBytes == 0 {
		t.Errorf("response_bytes = 0, expected nonzero (response was %q)", "HTTP/1.1 200 OK...")
	}
}

func TestReplayRoundtrip(t *testing.T) {
	srv, ts, events := newRelayTestServer(t)
	defer ts.Close()

	// Upstream that counts hits so we can confirm the replay caused a 2nd one.
	var hits int32
	localPort, stopLocal := startCountingUpstream(t, &hits, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	defer stopLocal()

	tun, err := srv.cfg.Registry.CreateWithOptions("test", tunnel.CreateOptions{
		LocalPort: localPort,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	wireClient(t, ts, tun, localPort)

	if err := srv.cfg.Registry.SetInspectionEnabled(tun.ID, true); err != nil {
		t.Fatal(err)
	}

	hitProxy(t, ts, tun.Slug, "/replayme")

	// Wait for the log row to land.
	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := events.ListRequests(tun.ID, 50)
		if len(logs) == 1 {
			reqID = logs[0].ID
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("never saw a logged request")
	}

	// Call the admin replay endpoint directly via httptest (bypasses the
	// admin secret middleware since we hand-craft the path). Use the raw
	// admin secret on the request.
	// We construct a separate admin-only listener so we can hit it without
	// going through the user middleware that injects the tier.
	adminTS := httptest.NewServer(srv.mux)
	defer adminTS.Close()
	// Configure an admin secret on the server.
	srv.cfg.AdminSecret = "test-admin-secret"

	req, _ := http.NewRequest("POST",
		adminTS.URL+"/v1/admin/tunnels/"+tun.ID+"/requests/"+reqID+"/replay", nil)
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("replay status %d (body=%s)", resp.StatusCode, body)
	}

	var replay replayResult
	if err := json.NewDecoder(resp.Body).Decode(&replay); err != nil {
		t.Fatal(err)
	}
	if replay.Status != 200 {
		t.Errorf("replay status = %d, want 200", replay.Status)
	}
	if !strings.Contains(replay.Body, "hello") {
		t.Errorf("replay body = %q, want it to contain 'hello'", replay.Body)
	}

	// Upstream should have been hit at least twice (original + replay).
	// Race-tolerant: poll briefly.
	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if loadInt32(&hits) >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if loadInt32(&hits) < 2 {
		t.Errorf("upstream hits = %d, want >= 2 (original + replay)", loadInt32(&hits))
	}

	// Replays must not create new request_log rows.
	logs, _ := events.ListRequests(tun.ID, 50)
	if len(logs) != 1 {
		t.Errorf("expected 1 logged request after replay, got %d", len(logs))
	}
}

// --- helpers for the relay tests ---

func startEchoUpstream(t *testing.T, response string) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.Read(buf)
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return port, func() { ln.Close() }
}

func startCountingUpstream(t *testing.T, counter *int32, response string) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.Read(buf)
				addInt32(counter, 1)
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return port, func() { ln.Close() }
}

func addInt32(p *int32, v int32) { atomic.AddInt32(p, v) }
func loadInt32(p *int32) int32   { return atomic.LoadInt32(p) }

func createTunnel(t *testing.T, ts *httptest.Server, localPort int) *tunnel.Tunnel {
	t.Helper()
	payload := fmt.Sprintf(`{"local_port": %d}`, localPort)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer nbk_test_secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tun tunnel.Tunnel
	json.NewDecoder(resp.Body).Decode(&tun)
	return &tun
}

func wireClient(t *testing.T, ts *httptest.Server, tun *tunnel.Tunnel, localPort int) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/control?tunnel_id=" + tun.ID
	wsHeader := http.Header{}
	wsHeader.Set("Authorization", "Bearer nbk_test_secret")
	controlConn, _, err := websocket.DefaultDialer.Dial(wsURL, wsHeader)
	if err != nil {
		t.Fatalf("control ws dial: %v", err)
	}
	t.Cleanup(func() { controlConn.Close() })
	go func() {
		for {
			_, msg, err := controlConn.ReadMessage()
			if err != nil {
				return
			}
			var ctlMsg controlMessage
			json.Unmarshal(msg, &ctlMsg)
			if ctlMsg.Type == "connection" {
				connID := ctlMsg.ID
				go func() {
					dataURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/data?id=" + connID
					dataWS, _, err := websocket.DefaultDialer.Dial(dataURL, nil)
					if err != nil {
						return
					}
					localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 5*time.Second)
					if err != nil {
						dataWS.Close()
						return
					}
					pipe(localConn, NewWSNetConn(dataWS))
				}()
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
}

func hitProxy(t *testing.T, ts *httptest.Server, slug, path string) {
	t.Helper()
	proxyConn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer proxyConn.Close()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(proxyConn, "GET /t/%s%s HTTP/1.1\r\nHost: localhost\r\n\r\n", slug, path)
	proxyConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	proxyConn.Read(buf)
}

