package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/store"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

// ---------------------------------------------------------------------------
// ClientHello capture helpers
// ---------------------------------------------------------------------------

// captureConn records what a tls.Client writes (its ClientHello flight) and
// fails every read, so the handshake stops right after sending.
type captureConn struct {
	buf bytes.Buffer
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(p []byte) (int, error)      { return c.buf.Write(p) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// captureClientHello returns the exact bytes Go's TLS client sends as its
// first flight for the given ServerName ("" = no SNI).
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	cc := &captureConn{}
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: serverName == ""}
	_ = tls.Client(cc, cfg).Handshake() // fails on read; we only want the write
	if cc.buf.Len() == 0 {
		t.Fatal("tls client wrote nothing")
	}
	return cc.buf.Bytes()
}

// reframe re-splits the handshake bytes carried in records into new
// handshake records of at most chunk payload bytes each.
func reframe(t *testing.T, records []byte, chunk int) []byte {
	t.Helper()
	var hs []byte
	for len(records) > 0 {
		if len(records) < 5 {
			t.Fatal("short record header")
		}
		n := int(records[3])<<8 | int(records[4])
		hs = append(hs, records[5:5+n]...)
		records = records[5+n:]
	}
	var out []byte
	for len(hs) > 0 {
		n := chunk
		if n > len(hs) {
			n = len(hs)
		}
		out = append(out, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, hs[:n]...)
		hs = hs[n:]
	}
	return out
}

// ---------------------------------------------------------------------------
// SNI parser
// ---------------------------------------------------------------------------

func TestPeekClientHello_Valid(t *testing.T) {
	hello := captureClientHello(t, "abc123def456.tunnel.test")
	raw, sni, err := peekClientHello(bytes.NewReader(hello), sniPeekMaxBytes)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sni != "abc123def456.tunnel.test" {
		t.Errorf("sni = %q", sni)
	}
	if !bytes.Equal(raw, hello) {
		t.Errorf("raw (%d bytes) != ClientHello (%d bytes)", len(raw), len(hello))
	}
}

func TestPeekClientHello_UppercaseNormalised(t *testing.T) {
	hello := captureClientHello(t, "Web.HeroApp.NullBore.com")
	_, sni, err := peekClientHello(bytes.NewReader(hello), sniPeekMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if sni != "web.heroapp.nullbore.com" {
		t.Errorf("sni = %q, want lowercase", sni)
	}
}

func TestPeekClientHello_NoSNI(t *testing.T) {
	hello := captureClientHello(t, "")
	raw, sni, err := peekClientHello(bytes.NewReader(hello), sniPeekMaxBytes)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sni != "" {
		t.Errorf("sni = %q, want empty", sni)
	}
	if !bytes.Equal(raw, hello) {
		t.Error("raw != ClientHello")
	}
}

func TestPeekClientHello_FragmentedRecordsAndShortReads(t *testing.T) {
	hello := reframe(t, captureClientHello(t, "frag.tunnel.test"), 37)
	// One byte per Read, across many tiny records.
	raw, sni, err := peekClientHello(iotest.OneByteReader(bytes.NewReader(hello)), sniPeekMaxBytes)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sni != "frag.tunnel.test" {
		t.Errorf("sni = %q", sni)
	}
	if !bytes.Equal(raw, hello) {
		t.Error("raw != reframed ClientHello")
	}
}

func TestPeekClientHello_DoesNotOverRead(t *testing.T) {
	hello := captureClientHello(t, "x.tunnel.test")
	r := bytes.NewReader(append(append([]byte{}, hello...), "EXTRA"...))
	raw, _, err := peekClientHello(r, sniPeekMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, hello) {
		t.Fatalf("raw consumed %d bytes, ClientHello is %d", len(raw), len(hello))
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "EXTRA" {
		t.Errorf("bytes after ClientHello = %q, want EXTRA (peek must not over-read)", rest)
	}
}

func TestPeekClientHello_Truncated(t *testing.T) {
	hello := captureClientHello(t, "x.tunnel.test")
	for _, cut := range []int{0, 3, 5, 9, len(hello) / 2, len(hello) - 1} {
		in := hello[:cut]
		raw, sni, err := peekClientHello(bytes.NewReader(in), sniPeekMaxBytes)
		if err == nil {
			t.Errorf("cut=%d: expected error", cut)
		}
		if sni != "" {
			t.Errorf("cut=%d: sni = %q", cut, sni)
		}
		if !bytes.Equal(raw, in) {
			t.Errorf("cut=%d: raw must hold every consumed byte for replay (got %d, want %d)", cut, len(raw), len(in))
		}
	}
}

func TestPeekClientHello_Garbage(t *testing.T) {
	cases := map[string][]byte{
		"plain HTTP":       []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"SSLv2 hello":      {0x80, 0x2e, 0x01, 0x03, 0x01, 0x00},
		"alert record":     {0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28},
		"bad major ver":    {0x16, 0x02, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00},
		"zero-len record":  {0x16, 0x03, 0x01, 0x00, 0x00},
		"oversize record":  {0x16, 0x03, 0x01, 0x40, 0x01},
		"server hello":     {0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
		"empty hello body": {0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			raw, sni, err := peekClientHello(bytes.NewReader(in), sniPeekMaxBytes)
			if err == nil || sni != "" {
				t.Fatalf("expected error and no SNI, got sni=%q err=%v", sni, err)
			}
			if !bytes.HasPrefix(in, raw) {
				t.Errorf("raw %x is not a prefix of input", raw)
			}
		})
	}
	// Non-TLS input must be rejected after the 5-byte header, so plain HTTP
	// on :443 replays to http.Server exactly as before.
	raw, _, err := peekClientHello(bytes.NewReader(cases["plain HTTP"]), sniPeekMaxBytes)
	if !errors.Is(err, errNotTLSHandshake) || string(raw) != "GET /" {
		t.Errorf("plain HTTP: raw=%q err=%v, want \"GET /\" + errNotTLSHandshake", raw, err)
	}
}

func TestPeekClientHello_Oversized(t *testing.T) {
	// Handshake header claims a 16 MB ClientHello.
	in := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff}
	raw, _, err := peekClientHello(bytes.NewReader(in), sniPeekMaxBytes)
	if !errors.Is(err, errClientHelloTooLarge) {
		t.Errorf("err = %v, want errClientHelloTooLarge", err)
	}
	if !bytes.Equal(raw, in) {
		t.Errorf("raw = %x", raw)
	}

	// A real ClientHello under a tiny cap: rejected without exceeding it.
	hello := captureClientHello(t, "x.tunnel.test")
	const cap = 100
	raw, _, err = peekClientHello(bytes.NewReader(hello), cap)
	if !errors.Is(err, errClientHelloTooLarge) {
		t.Errorf("err = %v, want errClientHelloTooLarge", err)
	}
	if len(raw) > cap {
		t.Errorf("consumed %d bytes, cap %d", len(raw), cap)
	}

	// An endless stream of tiny handshake records never completing a
	// message is cut off at the cap.
	var endless []byte
	endless = append(endless, 0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x10, 0x00) // claims 4 KB
	for len(endless) < 2*cap {
		endless = append(endless, 0x16, 0x03, 0x01, 0x00, 0x01, 0x00)
	}
	raw, _, err = peekClientHello(bytes.NewReader(endless), cap)
	if !errors.Is(err, errClientHelloTooLarge) || len(raw) > cap {
		t.Errorf("endless records: consumed %d err=%v", len(raw), err)
	}
}

func TestParseClientHelloSNI_Malformed(t *testing.T) {
	for _, body := range [][]byte{
		nil,
		{0x03, 0x03},
		append(make([]byte, 34), 0xff), // session id length runs off the end
	} {
		if _, err := parseClientHelloSNI(body); err == nil {
			t.Errorf("parseClientHelloSNI(%x): expected error", body)
		}
	}
}

func TestNormalizeSNI(t *testing.T) {
	ok := map[string]string{
		"abc.tunnel.test":          "abc.tunnel.test",
		"Web.HeroApp.NullBore.Com": "web.heroapp.nullbore.com",
		"a-b_c.example":            "a-b_c.example",
		"localhost":                "localhost",
	}
	for in, want := range ok {
		got, err := normalizeSNI(in)
		if err != nil || got != want {
			t.Errorf("normalizeSNI(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", ".", "a..b", ".a.b", "a.b.", "a b.example", "a/b", "evil&domain=x",
		"café.example", strings.Repeat("a", 254),
	} {
		if got, err := normalizeSNI(in); err == nil {
			t.Errorf("normalizeSNI(%q) = %q, want error", in, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Host routing (shared by HTTP Host and TLS SNI)
// ---------------------------------------------------------------------------

func TestClassifyHost(t *testing.T) {
	const base, acct = "tunnel.nullbore.com", "nullbore.com"
	cases := []struct {
		host string
		want hostRoute
	}{
		{"abc123def456.tunnel.nullbore.com", hostRoute{Kind: routeBaseSlug, Slug: "abc123def456"}},
		{"shark.tunnel.nullbore.com", hostRoute{Kind: routeBaseSlug, Slug: "shark"}},
		{"tunnel.nullbore.com", hostRoute{}},
		{"web.heroapp.nullbore.com", hostRoute{Kind: routeAccount, Account: "heroapp", Leaf: "web"}},
		{"heroapp.nullbore.com", hostRoute{Kind: routeAccount, Account: "heroapp"}},
		{"a.b.c.nullbore.com", hostRoute{Kind: routeAccount, Account: "b.c", Leaf: "a"}},
		// End-to-end namespace: {leaf}.{account}.e2e.{AccountDomain}.
		{"web.heroapp.e2e.nullbore.com", hostRoute{Kind: routeAccount, Account: "heroapp", Leaf: "web", E2E: true}},
		// Two labels ending in e2e are an ordinary account named "e2e".
		{"web.e2e.nullbore.com", hostRoute{Kind: routeAccount, Account: "e2e", Leaf: "web"}},
		// Deeper or empty-label e2e names never get the E2E route.
		{"a.web.heroapp.e2e.nullbore.com", hostRoute{Kind: routeAccount, Account: "web.heroapp.e2e", Leaf: "a"}},
		// Multi-label under the base domain falls to the account plane
		// (account "y.tunnel" never resolves) — same as before the refactor.
		{"x.y.tunnel.nullbore.com", hostRoute{Kind: routeAccount, Account: "y.tunnel", Leaf: "x"}},
		{"www.nullbore.com", hostRoute{Kind: routeCustomDomain}},
		{"nullbore.com", hostRoute{Kind: routeCustomDomain}},
		{"books.example.org", hostRoute{Kind: routeCustomDomain}},
	}
	for _, c := range cases {
		if got := classifyHost(c.host, base, acct); got != c.want {
			t.Errorf("classifyHost(%q) = %+v, want %+v", c.host, got, c.want)
		}
	}
	// Host routing disabled without a base domain.
	if got := classifyHost("abc.tunnel.nullbore.com", "", acct); got != (hostRoute{}) {
		t.Errorf("no base domain: got %+v", got)
	}
	// No account domain: account-looking hosts become custom-domain candidates.
	if got := classifyHost("web.heroapp.nullbore.com", base, ""); got.Kind != routeCustomDomain {
		t.Errorf("no account domain: got %+v", got)
	}
}

// newDashStub serves the dashboard's subdomain + custom-domain lookups:
// account "heroapp" → user-1, custom domain books.example.org → slug "shark".
func newDashStub(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/resolve-subdomain" && r.URL.Query().Get("name") == "heroapp":
			w.Write([]byte(`{"user_id":"user-1"}`))
		case r.URL.Path == "/internal/domain-lookup" && r.URL.Query().Get("domain") == "books.example.org":
			w.Write([]byte(`{"tunnel_slug":"shark","user_id":"user-1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestResolveTunnelForHost(t *testing.T) {
	dash := newDashStub(t)
	registry := tunnel.NewRegistry()
	gen, _ := registry.CreateWithOptions("user-2", tunnel.CreateOptions{LocalPort: 1, TTL: time.Hour})
	shark, _ := registry.CreateWithOptions("user-1", tunnel.CreateOptions{LocalPort: 2, TTL: time.Hour, Name: "shark", Mode: tunnel.ModeTLSPassthrough})
	whale, _ := registry.CreateWithOptions("user-1", tunnel.CreateOptions{LocalPort: 3, TTL: time.Hour, Name: "whale"})

	srv := NewServer(Config{
		Auth:              auth.NewStaticProvider("nbk_test_secret"),
		Registry:          registry,
		BaseDomain:        "tunnel.nullbore.com",
		AccountDomain:     "nullbore.com",
		SubdomainResolver: NewSubdomainResolver(dash.URL, ""),
		DomainResolver:    NewDomainResolver(dash.URL, ""),
	})

	cases := []struct {
		host string
		want *tunnel.Tunnel
	}{
		{gen.Slug + ".tunnel.nullbore.com", gen},
		{"shark.tunnel.nullbore.com", nil}, // user-chosen slug never resolves on base domain
		{"shark.heroapp.nullbore.com", shark},
		{"heroapp.nullbore.com", nil}, // bare account host
		{"carp.heroapp.nullbore.com", nil},
		{"shark.fake.nullbore.com", nil},
		{"tunnel.nullbore.com", nil},
		{"books.example.org", shark},
		{"unknown.example.org", nil},
		{"a.b.tunnel.nullbore.com", nil},
		{"whale.heroapp.nullbore.com", whale},
		// e2e namespace: passthrough tunnels only.
		{"shark.heroapp.e2e.nullbore.com", shark},
		{"whale.heroapp.e2e.nullbore.com", nil},
		{"shark.fake.e2e.nullbore.com", nil},
	}
	for _, c := range cases {
		got, ok := srv.resolveTunnelForHost(c.host)
		if (c.want == nil) != !ok || (c.want != nil && got != c.want) {
			t.Errorf("resolveTunnelForHost(%q) = %v,%v; want %v", c.host, got, ok, c.want)
		}
	}

	if srv.passthroughFor("shark.heroapp.e2e.nullbore.com") == nil {
		t.Error("passthroughFor returned nil for a passthrough tunnel in the e2e namespace")
	}

	// Over HTTP (TLS already terminated, or plain HTTP) the e2e namespace
	// proxies nothing — not even a relay tunnel — and looks like a miss.
	h := srv.newHTTPServer("").Handler
	for _, host := range []string{"whale.heroapp.e2e.nullbore.com", "shark.heroapp.e2e.nullbore.com"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://"+host+"/", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("HTTP %s: status %d, want 404", host, rec.Code)
		}
	}

	// passthroughFor only diverts passthrough tunnels.
	if srv.passthroughFor(gen.Slug+".tunnel.nullbore.com") != nil {
		t.Error("passthroughFor returned a handler for a relay tunnel")
	}
	if srv.passthroughFor("shark.heroapp.nullbore.com") == nil {
		t.Error("passthroughFor returned nil for a passthrough tunnel")
	}
	if srv.passthroughFor("tunnel.nullbore.com") != nil {
		t.Error("passthroughFor returned a handler for the API host")
	}
}

// ---------------------------------------------------------------------------
// Create-tunnel validation
// ---------------------------------------------------------------------------

func TestValidateTunnelMode(t *testing.T) {
	cases := []struct {
		name     string
		req      createTunnelRequest
		tier     string
		self     bool
		wantMode string
		wantCode int
	}{
		{"default", createTunnelRequest{}, "free", false, tunnel.ModeRelay, 0},
		{"explicit relay", createTunnelRequest{Mode: "relay"}, "", false, tunnel.ModeRelay, 0},
		{"relay with auth", createTunnelRequest{AuthUser: "u", AuthPass: "p"}, "free", false, tunnel.ModeRelay, 0},
		{"unknown", createTunnelRequest{Mode: "direct"}, "pro", false, "", 400},
		{"wrong case", createTunnelRequest{Mode: "TLS-Passthrough"}, "pro", false, "", 400},
		{"passthrough free", createTunnelRequest{Mode: "tls-passthrough"}, "free", false, "", 403},
		{"passthrough no tier", createTunnelRequest{Mode: "tls-passthrough"}, "", false, "", 403},
		{"passthrough basic", createTunnelRequest{Mode: "tls-passthrough"}, "basic", false, tunnel.ModeTLSPassthrough, 0},
		{"passthrough plus", createTunnelRequest{Mode: "tls-passthrough"}, "plus", false, tunnel.ModeTLSPassthrough, 0},
		{"passthrough legacy dev", createTunnelRequest{Mode: "tls-passthrough"}, "dev", false, tunnel.ModeTLSPassthrough, 0},
		{"passthrough pro", createTunnelRequest{Mode: "tls-passthrough"}, "pro", false, tunnel.ModeTLSPassthrough, 0},
		{"passthrough + auth", createTunnelRequest{Mode: "tls-passthrough", AuthUser: "u", AuthPass: "p"}, "pro", false, "", 400},
		{"passthrough + user only", createTunnelRequest{Mode: "tls-passthrough", AuthUser: "u"}, "pro", false, "", 400},
		{"self-hosted passthrough, no tier", createTunnelRequest{Mode: "tls-passthrough"}, "", true, tunnel.ModeTLSPassthrough, 0},
		{"self-hosted explicit free", createTunnelRequest{Mode: "tls-passthrough"}, "free", true, "", 403},
		{"self-hosted passthrough + auth", createTunnelRequest{Mode: "tls-passthrough", AuthUser: "u"}, "", true, "", 400},
	}
	for _, c := range cases {
		mode, code, msg := validateTunnelMode(c.req, c.tier, c.self)
		if mode != c.wantMode || code != c.wantCode {
			t.Errorf("%s: got (%q, %d, %q), want (%q, %d)", c.name, mode, code, msg, c.wantMode, c.wantCode)
		}
		if code != 0 && msg == "" {
			t.Errorf("%s: rejection without an error message", c.name)
		}
	}
}

func TestCreateTunnelMode_Handler(t *testing.T) {
	cases := []struct {
		name     string
		tier     string
		body     string
		wantCode int
		wantMode string
	}{
		{"default relay", "free", `{"local_port":3000}`, 201, "relay"},
		{"passthrough pro", "pro", `{"local_port":8443,"mode":"tls-passthrough"}`, 201, "tls-passthrough"},
		{"passthrough basic", "basic", `{"local_port":8443,"mode":"tls-passthrough"}`, 201, "tls-passthrough"},
		{"passthrough free", "free", `{"local_port":8443,"mode":"tls-passthrough"}`, 403, ""},
		{"bogus mode", "pro", `{"local_port":8443,"mode":"bogus"}`, 400, ""},
		{"passthrough + auth", "pro", `{"local_port":8443,"mode":"tls-passthrough","auth_user":"a","auth_pass":"b"}`, 400, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			authProvider := auth.NewStaticProvider("nbk_test_secret")
			st, err := store.New(filepath.Join(t.TempDir(), "nb.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			srv := NewServer(Config{Auth: authProvider, Registry: tunnel.NewRegistry(), Store: st})
			ts := httptest.NewServer(tierAuthMiddleware(authProvider, c.tier)(srv.mux))
			defer ts.Close()

			req, _ := http.NewRequest("POST", ts.URL+"/v1/tunnels", strings.NewReader(c.body))
			req.Header.Set("Authorization", "Bearer nbk_test_secret")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var body map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&body)
			if resp.StatusCode != c.wantCode {
				t.Fatalf("status = %d, want %d (body=%v)", resp.StatusCode, c.wantCode, body)
			}
			if c.wantCode != 201 {
				if body["error"] == nil || body["error"] == "" {
					t.Errorf("expected JSON error, got %v", body)
				}
				if n := srv.cfg.Registry.CountByClient("test"); n != 0 {
					t.Errorf("rejected request still created %d tunnel(s)", n)
				}
				return
			}
			if body["mode"] != c.wantMode {
				t.Errorf("response mode = %v, want %q", body["mode"], c.wantMode)
			}
			id, _ := body["id"].(string)
			rec, err := st.GetTunnel(id)
			if err != nil || rec == nil {
				t.Fatalf("tunnel not persisted: %v %v", rec, err)
			}
			if rec.Mode != c.wantMode {
				t.Errorf("persisted mode = %q, want %q", rec.Mode, c.wantMode)
			}
		})
	}
}

func TestPassthrough_InspectionAndReplayRefused(t *testing.T) {
	srv, ts, _, _ := newInspectableTestServer(t, "pro")
	defer ts.Close()
	srv.cfg.AdminSecret = "admin-secret"
	pt, _ := srv.cfg.Registry.CreateWithOptions("test", tunnel.CreateOptions{LocalPort: 1, TTL: time.Hour, Tier: "pro", Mode: tunnel.ModeTLSPassthrough})

	// Admin routes sit behind the admin-secret middleware, not the user
	// auth wrapper newInspectableTestServer adds — hit the bare mux.
	adminTS := httptest.NewServer(srv.mux)
	defer adminTS.Close()

	do := func(path, secretHeader, body string) int {
		target := ts.URL
		if secretHeader != "" {
			target = adminTS.URL
		}
		req, _ := http.NewRequest("POST", target+path, strings.NewReader(body))
		if secretHeader != "" {
			req.Header.Set("X-Admin-Secret", secretHeader)
		} else {
			req.Header.Set("Authorization", "Bearer nbk_test_secret")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("/v1/tunnels/"+pt.ID+"/inspection", "", `{"enabled":true}`); code != 400 {
		t.Errorf("user enable inspection: %d, want 400", code)
	}
	if code := do("/v1/tunnels/"+pt.ID+"/inspection", "", `{"enabled":false}`); code != 200 {
		t.Errorf("user disable inspection: %d, want 200", code)
	}
	if code := do("/v1/admin/tunnels/"+pt.ID+"/inspection", "admin-secret", `{"enabled":true}`); code != 400 {
		t.Errorf("admin enable inspection: %d, want 400", code)
	}
	if code := do("/v1/admin/tunnels/"+pt.ID+"/requests/x/replay", "admin-secret", ``); code != 400 {
		t.Errorf("admin replay: %d, want 400", code)
	}
	if pt.InspectionEnabled {
		t.Error("inspection got enabled on a passthrough tunnel")
	}
}

// ---------------------------------------------------------------------------
// sniListener mechanics
// ---------------------------------------------------------------------------

func newTestSNIListener(t *testing.T, lookup func(string) passthroughHandler, timeout time.Duration) *sniListener {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newSNIListenerWithTimeout(inner, lookup, timeout)
	t.Cleanup(func() { l.Close() })
	return l
}

func acceptWithin(t *testing.T, l net.Listener, d time.Duration) net.Conn {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := l.Accept(); ch <- res{c, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		return r.c
	case <-time.After(d):
		t.Fatal("Accept did not return in time")
		return nil
	}
}

func TestSNIListener_NonTLSReplayedVerbatim(t *testing.T) {
	l := newTestSNIListener(t, func(string) passthroughHandler {
		t.Error("lookup must not be called for non-TLS input")
		return nil
	}, time.Second)

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := "GET /health HTTP/1.1\r\nHost: tunnel.test\r\n\r\n"
	c.Write([]byte(msg))

	sc := acceptWithin(t, l, 2*time.Second)
	defer sc.Close()
	sc.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Errorf("replayed %q, want %q", got, msg)
	}
}

func TestSNIListener_DivertsOnlyMatchingSNI(t *testing.T) {
	type diverted struct {
		c      net.Conn
		prefix []byte
	}
	divertedCh := make(chan diverted, 1)
	l := newTestSNIListener(t, func(sni string) passthroughHandler {
		if sni != "pt.tunnel.test" {
			return nil
		}
		return func(c net.Conn, prefix []byte) { divertedCh <- diverted{c, prefix} }
	}, time.Second)

	dialTLS := func(name string) net.Conn {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		go tls.Client(c, &tls.Config{ServerName: name}).Handshake()
		return c
	}

	// Matching SNI → diverted with the full ClientHello as prefix.
	c1 := dialTLS("pt.tunnel.test")
	defer c1.Close()
	select {
	case d := <-divertedCh:
		_, sni, err := peekClientHello(bytes.NewReader(d.prefix), sniPeekMaxBytes)
		if err != nil || sni != "pt.tunnel.test" {
			t.Errorf("diverted prefix: sni=%q err=%v", sni, err)
		}
		d.c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("passthrough conn was not diverted")
	}

	// Other SNI → delivered to Accept with the ClientHello replayed.
	c2 := dialTLS("other.tunnel.test")
	defer c2.Close()
	sc := acceptWithin(t, l, 2*time.Second)
	defer sc.Close()
	sc.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, sni, err := peekClientHello(sc, sniPeekMaxBytes)
	if err != nil || sni != "other.tunnel.test" {
		t.Errorf("accepted conn replay: sni=%q err=%v", sni, err)
	}
}

func TestSNIListener_SlowClientFallsBackWithDeadlineCleared(t *testing.T) {
	l := newTestSNIListener(t, func(string) passthroughHandler { return nil }, 50*time.Millisecond)

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x16, 0x03}) // partial record header, then stall

	sc := acceptWithin(t, l, 2*time.Second)
	defer sc.Close()

	head := make([]byte, 2)
	if _, err := io.ReadFull(sc, head); err != nil || head[0] != 0x16 || head[1] != 0x03 {
		t.Fatalf("partial peek not replayed: %x %v", head, err)
	}
	// The peek deadline must be gone: a read now blocks until the client
	// sends more, rather than failing with the expired peek deadline.
	go func() {
		time.Sleep(200 * time.Millisecond)
		c.Write([]byte("more"))
	}()
	sc.SetReadDeadline(time.Now().Add(2 * time.Second))
	rest := make([]byte, 4)
	if _, err := io.ReadFull(sc, rest); err != nil || string(rest) != "more" {
		t.Errorf("read after fallback: %q %v", rest, err)
	}
}

func TestSNIListener_PanicRecoveredPerConn(t *testing.T) {
	l := newTestSNIListener(t, func(sni string) passthroughHandler {
		if sni == "boom.tunnel.test" {
			panic("lookup exploded")
		}
		return nil
	}, time.Second)

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(captureClientHello(t, "boom.tunnel.test"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("panicking conn should be closed, got err=%v", err)
	}

	// The listener keeps serving other connections.
	c2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.Write([]byte("hello"))
	sc := acceptWithin(t, l, 2*time.Second)
	sc.Close()
}

func TestSNIListener_CloseUnblocksAcceptAndDropsUndelivered(t *testing.T) {
	l := newTestSNIListener(t, func(string) passthroughHandler { return nil }, time.Second)

	// A peeked conn nobody accepts must be closed on shutdown (no leak).
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	time.Sleep(50 * time.Millisecond)

	errCh := make(chan error, 1)
	go func() { _, err := l.Accept(); errCh <- err }()
	// Accept may legitimately take the pending conn first; drain until error.
	l.Close()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case err := <-errCh:
			if err == nil {
				go func() { _, err := l.Accept(); errCh <- err }()
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("Accept after Close: %v, want net.ErrClosed", err)
			}
			return
		case <-deadline:
			t.Fatal("Accept did not unblock after Close")
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ---------------------------------------------------------------------------
// End-to-end: the relay's real TLS front, a passthrough tunnel whose local
// service is a TLS server with its OWN certificate, a relay tunnel, and the
// API — all through one listener. This is NULLBORE-REQUIREMENTS.md §3 in
// test form: the public hostname must present the owner's certificate,
// completed by the owner's key, and the relay forwards ciphertext.
// ---------------------------------------------------------------------------

// genTestCert returns a fresh self-signed ECDSA cert valid for dnsNames.
func genTestCert(t *testing.T, dnsNames ...string) (tls.Certificate, *x509.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair, leaf, certPEM, keyPEM
}

func poolOf(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

// wireTLSClient plays the nullbore client against a TLS relay: control +
// data WebSockets over wss (SNI = the API host), local side plain TCP.
func wireTLSClient(t *testing.T, registry *tunnel.Registry, relayAddr string, wsTLS *tls.Config, tun *tunnel.Tunnel, localPort int) {
	t.Helper()
	dialer := websocket.Dialer{TLSClientConfig: wsTLS, HandshakeTimeout: 5 * time.Second}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer nbk_test_secret")
	ctl, _, err := dialer.Dial("wss://"+relayAddr+"/ws/control?tunnel_id="+tun.ID, hdr)
	if err != nil {
		t.Fatalf("control ws dial: %v", err)
	}
	t.Cleanup(func() { ctl.Close() })
	go func() {
		for {
			_, msg, err := ctl.ReadMessage()
			if err != nil {
				return
			}
			var m controlMessage
			json.Unmarshal(msg, &m)
			if m.Type != "connection" {
				continue
			}
			go func(id string) {
				data, _, err := dialer.Dial("wss://"+relayAddr+"/ws/data?id="+id, nil)
				if err != nil {
					return
				}
				local, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 5*time.Second)
				if err != nil {
					data.Close()
					return
				}
				pipe(local, NewWSNetConn(data))
			}(m.ID)
		}
	}()
	// Wait until the hub has registered the control channel.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := registry.GetConn(tun.ID); err == nil && c != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("control channel for tunnel %s never registered", tun.ID)
}

// tlsRoundTrip dials addr with cfg, sends one HTTP/1.1 request with the given
// Host, and returns the peer leaf and the response.
func tlsRoundTrip(addr string, cfg *tls.Config, host, path string) (*x509.Certificate, int, string, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	leaf := conn.ConnectionState().PeerCertificates[0]
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return leaf, 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return leaf, resp.StatusCode, string(body), nil
}

func tunnelStats(tun *tunnel.Tunnel) (in, out, reqs int64) {
	mu := tun.Mu()
	mu.Lock()
	defer mu.Unlock()
	return tun.BytesIn, tun.BytesOut, tun.Requests
}

func TestTLSPassthroughEndToEnd(t *testing.T) {
	const base = "tunnel.test"

	// Relay's own certificate (what relay-mode tunnels and the API present).
	_, relayLeaf, relayCertPEM, relayKeyPEM := genTestCert(t, base, "*."+base)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key")
	os.WriteFile(certFile, relayCertPEM, 0600)
	os.WriteFile(keyFile, relayKeyPEM, 0600)

	// Tunnel owner's certificate + key — never given to the relay.
	ownerPair, ownerLeaf, _, _ := genTestCert(t, "*."+base)
	if ownerLeaf.Equal(relayLeaf) {
		t.Fatal("test setup: owner and relay certs must differ")
	}

	// Owner's local service: TLS server with its own cert, speaking HTTP.
	var ownerHits int32
	var ownerSawHost atomic.Value
	ownerLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ownerPair}})
	if err != nil {
		t.Fatal(err)
	}
	ownerSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&ownerHits, 1)
		ownerSawHost.Store(r.Host)
		w.Write([]byte("owner says hi"))
	})}
	go ownerSrv.Serve(ownerLn)
	t.Cleanup(func() { ownerSrv.Close() })
	ownerPort := ownerLn.Addr().(*net.TCPAddr).Port

	// Plain-HTTP local service for the relay-mode tunnel.
	relayLocalPort, stopRelayLocal := startEchoUpstream(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	t.Cleanup(stopRelayLocal)

	events, err := store.NewEventStore(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { events.Close() })
	registry := tunnel.NewRegistry()
	srv := NewServer(Config{
		Auth:       auth.NewStaticProvider("nbk_test_secret"),
		Registry:   registry,
		Events:     events,
		BaseDomain: base,
		TLS:        &TLSConfig{CertFile: certFile, KeyFile: keyFile},
	})
	// Deterministic rate-limit check: tier "plus" gets a 1-token bucket.
	srv.proxyLimiters["plus"] = NewRateLimiter(1, time.Hour, 1)

	// Start the production TLS front on an ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := ln.Addr().String()
	srv.httpServer = srv.newHTTPServer(relayAddr)
	cf, kf, err := srv.configureTLS(relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.serveTLS(ln, cf, kf) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		select {
		case err := <-serveErr:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("serveTLS returned %v, want http.ErrServerClosed", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serveTLS did not return after Shutdown")
		}
	})

	apiTLS := &tls.Config{ServerName: base, RootCAs: poolOf(relayLeaf)}

	pt, _ := registry.CreateWithOptions("test", tunnel.CreateOptions{LocalPort: ownerPort, TTL: time.Hour, Tier: "pro", Mode: tunnel.ModeTLSPassthrough})
	rl, _ := registry.CreateWithOptions("test", tunnel.CreateOptions{LocalPort: relayLocalPort, TTL: time.Hour, Tier: "pro"})
	limited, _ := registry.CreateWithOptions("test", tunnel.CreateOptions{LocalPort: ownerPort, TTL: time.Hour, Tier: "plus", Mode: tunnel.ModeTLSPassthrough})
	offline, _ := registry.CreateWithOptions("test", tunnel.CreateOptions{LocalPort: ownerPort, TTL: time.Hour, Tier: "pro", Mode: tunnel.ModeTLSPassthrough})
	// Force the inspection flag on (bypassing the API gate) to prove the
	// passthrough path writes nothing to request_log regardless.
	registry.SetInspectionEnabled(pt.ID, true)

	wireTLSClient(t, registry, relayAddr, apiTLS, pt, ownerPort)
	wireTLSClient(t, registry, relayAddr, apiTLS, rl, relayLocalPort)
	wireTLSClient(t, registry, relayAddr, apiTLS, limited, ownerPort)

	ptHost := pt.Slug + "." + base
	rlHost := rl.Slug + "." + base

	t.Run("passthrough presents the owner's certificate and round-trips", func(t *testing.T) {
		// Trust ONLY the owner's cert: a successful verified handshake
		// proves the peer holds the owner's private key.
		leaf, status, body, err := tlsRoundTrip(relayAddr, &tls.Config{ServerName: ptHost, RootCAs: poolOf(ownerLeaf)}, ptHost, "/api/info")
		if err != nil {
			t.Fatalf("round trip: %v", err)
		}
		if sha256.Sum256(leaf.Raw) != sha256.Sum256(ownerLeaf.Raw) {
			t.Errorf("presented cert fingerprint %x is not the owner's %x", sha256.Sum256(leaf.Raw), sha256.Sum256(ownerLeaf.Raw))
		}
		if leaf.Equal(relayLeaf) {
			t.Error("relay presented its own certificate for a passthrough tunnel")
		}
		if status != 200 || body != "owner says hi" {
			t.Errorf("response = %d %q", status, body)
		}
		// The relay did not rewrite the request (relay mode sets Host: localhost).
		if h, _ := ownerSawHost.Load().(string); h != ptHost {
			t.Errorf("owner saw Host %q, want %q (request must arrive untouched)", h, ptHost)
		}
	})

	t.Run("passthrough accounting and no request_log", func(t *testing.T) {
		deadline := time.Now().Add(3 * time.Second)
		var in, out, reqs int64
		for time.Now().Before(deadline) {
			if in, out, reqs = tunnelStats(pt); in > 0 && out > 0 && reqs > 0 {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if in == 0 || out == 0 || reqs == 0 {
			t.Errorf("stats not recorded: in=%d out=%d requests=%d", in, out, reqs)
		}
		logs, err := events.ListRequests(pt.ID, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(logs) != 0 {
			t.Errorf("request_log has %d rows for a passthrough tunnel", len(logs))
		}
	})

	t.Run("relay tunnel through the same listener", func(t *testing.T) {
		leaf, status, body, err := tlsRoundTrip(relayAddr, &tls.Config{ServerName: rlHost, RootCAs: poolOf(relayLeaf)}, rlHost, "/")
		if err != nil {
			t.Fatalf("round trip: %v", err)
		}
		if !leaf.Equal(relayLeaf) {
			t.Error("relay-mode tunnel did not present the relay certificate")
		}
		if status != 200 || body != "hello" {
			t.Errorf("response = %d %q", status, body)
		}
	})

	t.Run("API health through the same listener", func(t *testing.T) {
		for name, cfg := range map[string]*tls.Config{
			"sni=api host": apiTLS,
			"no sni":       {InsecureSkipVerify: true}, // dialing an IP sends no SNI
		} {
			_, status, body, err := tlsRoundTrip(relayAddr, cfg, base, "/health")
			if err != nil || status != 200 || !strings.Contains(body, `"status":"ok"`) {
				t.Errorf("%s: /health = %d %q %v", name, status, body, err)
			}
		}
	})

	t.Run("unknown SNI falls back to the relay stack", func(t *testing.T) {
		host := "aaaaaaaaaaaa." + base
		leaf, status, _, err := tlsRoundTrip(relayAddr, &tls.Config{ServerName: host, RootCAs: poolOf(relayLeaf)}, host, "/")
		if err != nil {
			t.Fatalf("round trip: %v", err)
		}
		if !leaf.Equal(relayLeaf) || status != 404 {
			t.Errorf("unknown host: relay cert=%v status=%d, want relay cert + 404", leaf.Equal(relayLeaf), status)
		}
	})

	t.Run("passthrough tunnel never proxied after relay TLS termination", func(t *testing.T) {
		before := atomic.LoadInt32(&ownerHits)
		// SNI is the API host (so the relay terminates TLS) but Host names
		// the passthrough tunnel — what a TLS-terminating proxy in front
		// would produce.
		_, status, body, err := tlsRoundTrip(relayAddr, apiTLS, ptHost, "/")
		if err != nil || status != 404 || body != "404 not found\n" {
			t.Errorf("Host routing to passthrough: %d %q %v, want generic 404", status, body, err)
		}
		_, status, _, err = tlsRoundTrip(relayAddr, apiTLS, base, "/t/"+pt.Slug+"/")
		if err != nil || status != 404 {
			t.Errorf("/t/{slug} to passthrough: %d %v, want 404", status, err)
		}
		if got := atomic.LoadInt32(&ownerHits); got != before {
			t.Errorf("owner service was hit %d time(s) via the relay-terminated path", got-before)
		}
	})

	t.Run("passthrough tunnel never proxied over plain HTTP", func(t *testing.T) {
		before := atomic.LoadInt32(&ownerHits)
		plain := httptest.NewServer(srv.newHTTPServer("").Handler)
		defer plain.Close()
		req, _ := http.NewRequest("GET", plain.URL+"/", nil)
		req.Host = ptHost
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 404 || string(body) != "404 not found\n" {
			t.Errorf("plain HTTP to passthrough: %d %q, want generic 404", resp.StatusCode, body)
		}
		if got := atomic.LoadInt32(&ownerHits); got != before {
			t.Error("owner service was hit over plain HTTP")
		}
	})

	t.Run("offline passthrough tunnel closes the connection", func(t *testing.T) {
		host := offline.Slug + "." + base
		start := time.Now()
		_, _, _, err := tlsRoundTrip(relayAddr, &tls.Config{ServerName: host, RootCAs: poolOf(ownerLeaf)}, host, "/")
		if err == nil {
			t.Fatal("expected handshake failure for an offline tunnel")
		}
		if time.Since(start) > 3*time.Second {
			t.Errorf("offline tunnel took %v to close", time.Since(start))
		}
	})

	t.Run("rate-limited passthrough connection is closed", func(t *testing.T) {
		host := limited.Slug + "." + base
		cfg := &tls.Config{ServerName: host, RootCAs: poolOf(ownerLeaf)}
		if _, status, _, err := tlsRoundTrip(relayAddr, cfg, host, "/"); err != nil || status != 200 {
			t.Fatalf("first conn (token available): %d %v", status, err)
		}
		if _, _, _, err := tlsRoundTrip(relayAddr, cfg, host, "/"); err == nil {
			t.Error("second conn should have been closed by the rate limiter")
		}
	})
}

func TestIsSelfHostedAuth(t *testing.T) {
	static := auth.NewStaticProvider("k1")
	remote := auth.NewRemoteProvider("http://dash.invalid", "s")
	if !isSelfHostedAuth(static) {
		t.Error("static provider should be self-hosted")
	}
	if isSelfHostedAuth(remote) {
		t.Error("remote provider should not be self-hosted")
	}
	if isSelfHostedAuth(&auth.ComboProvider{Primary: remote, Fallback: static}) {
		t.Error("combo (dashboard + static fallback) should not be self-hosted")
	}
}
