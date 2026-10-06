package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

const testACMEValue = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0" // 43-char base64url

// --- validateACMEChallenge ---

func TestValidateACMEChallenge(t *testing.T) {
	const acct, dom = "heroapp", "nullbore.com"
	cases := []struct {
		name, fqdn, value string
		want              string // normalized fqdn on success
		err               error  // errACMEBadName / errACMEForeign / nil
	}{
		{"leaf", "_acme-challenge.web.heroapp.e2e.nullbore.com", testACMEValue, "_acme-challenge.web.heroapp.e2e.nullbore.com", nil},
		{"wildcard form", "_acme-challenge.heroapp.e2e.nullbore.com", testACMEValue, "_acme-challenge.heroapp.e2e.nullbore.com", nil},
		{"trailing dot (lego)", "_acme-challenge.web.heroapp.e2e.nullbore.com.", testACMEValue, "_acme-challenge.web.heroapp.e2e.nullbore.com", nil},
		{"mixed case", "_ACME-Challenge.Web.HeroApp.E2E.NullBore.COM.", testACMEValue, "_acme-challenge.web.heroapp.e2e.nullbore.com", nil},
		{"hyphenated leaf", "_acme-challenge.my-api-2.heroapp.e2e.nullbore.com", testACMEValue, "_acme-challenge.my-api-2.heroapp.e2e.nullbore.com", nil},
		{"short value", "_acme-challenge.heroapp.e2e.nullbore.com", "a", "_acme-challenge.heroapp.e2e.nullbore.com", nil},

		{"wrong account", "_acme-challenge.web.villain.e2e.nullbore.com", testACMEValue, "", errACMEForeign},
		{"wrong account wildcard", "_acme-challenge.villain.e2e.nullbore.com", testACMEValue, "", errACMEForeign},
		{"account as leaf of other account", "_acme-challenge.heroapp.villain.e2e.nullbore.com", testACMEValue, "", errACMEForeign},
		{"non-e2e account host", "_acme-challenge.web.heroapp.nullbore.com", testACMEValue, "", errACMEForeign},
		{"bare e2e zone", "_acme-challenge.e2e.nullbore.com", testACMEValue, "", errACMEForeign},
		{"apex", "_acme-challenge.nullbore.com", testACMEValue, "", errACMEForeign},
		{"other zone", "_acme-challenge.web.heroapp.e2e.example.com", testACMEValue, "", errACMEForeign},
		{"suffix lookalike", "_acme-challenge.web.heroapp.e2e.nullbore.com.evil.net", testACMEValue, "", errACMEForeign},
		{"zone prefix lookalike", "_acme-challenge.web.heroapp.e2e.evilnullbore.com", testACMEValue, "", errACMEForeign},

		{"deeper name", "_acme-challenge.a.b.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"missing challenge label", "web.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"challenge label not first", "web._acme-challenge.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"double challenge label", "_acme-challenge._acme-challenge.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"wildcard leaf", "_acme-challenge.*.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"underscore leaf", "_acme-challenge.we_b.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"leading hyphen leaf", "_acme-challenge.-web.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"two trailing dots", "_acme-challenge.heroapp.e2e.nullbore.com..", testACMEValue, "", errACMEBadName},
		{"empty label", "_acme-challenge..heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"empty fqdn", "", testACMEValue, "", errACMEBadName},
		{"space in fqdn", "_acme-challenge.web .heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"newline in fqdn", "_acme-challenge.web.heroapp.e2e.nullbore.com\nx", testACMEValue, "", errACMEBadName},
		{"quote in fqdn", "_acme-challenge.\"web\".heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"unicode in fqdn", "_acme-challenge.wéb.heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},
		{"too long", "_acme-challenge." + strings.Repeat("a.", 120) + "heroapp.e2e.nullbore.com", testACMEValue, "", errACMEBadName},

		{"empty value", "_acme-challenge.heroapp.e2e.nullbore.com", "", "", errACMEBadName},
		{"value with space", "_acme-challenge.heroapp.e2e.nullbore.com", "abc def", "", errACMEBadName},
		{"value with quote", "_acme-challenge.heroapp.e2e.nullbore.com", `abc"def`, "", errACMEBadName},
		{"value with newline", "_acme-challenge.heroapp.e2e.nullbore.com", "abc\ndef", "", errACMEBadName},
		{"value with padding", "_acme-challenge.heroapp.e2e.nullbore.com", "abc=", "", errACMEBadName},
		{"value too long", "_acme-challenge.heroapp.e2e.nullbore.com", strings.Repeat("a", 129), "", errACMEBadName},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := validateACMEChallenge(c.fqdn, c.value, acct, dom)
			if c.err == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != c.want {
					t.Errorf("fqdn = %q, want %q", got, c.want)
				}
				return
			}
			if !errors.Is(err, c.err) {
				t.Fatalf("err = %v, want %v", err, c.err)
			}
		})
	}
}

func TestValidateACMEChallengeNoAccount(t *testing.T) {
	if _, err := validateACMEChallenge("_acme-challenge.heroapp.e2e.nullbore.com", testACMEValue, "", "nullbore.com"); !errors.Is(err, errACMEForeign) {
		t.Errorf("empty account: err = %v, want errACMEForeign", err)
	}
	if _, err := validateACMEChallenge("_acme-challenge.heroapp.e2e.nullbore.com", testACMEValue, "heroapp", ""); !errors.Is(err, errACMEForeign) {
		t.Errorf("empty account domain: err = %v, want errACMEForeign", err)
	}
}

// --- Handler ---

// fakeACME is an in-memory ACMEDelegator.
type fakeACME struct {
	mu       sync.Mutex
	records  map[string]time.Time // fqdn|value → expiry
	calls    []ACMETXTRequest
	err      error
	presents int
}

func newFakeACME() *fakeACME { return &fakeACME{records: map[string]time.Time{}} }

func (f *fakeACME) PresentTXT(_ context.Context, req ACMETXTRequest) (*ACMETXTRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.err != nil {
		return nil, f.err
	}
	f.presents++
	k := req.FQDN + "|" + req.Value
	exp, ok := f.records[k]
	if !ok {
		exp = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
		f.records[k] = exp
	}
	return &ACMETXTRecord{FQDN: req.FQDN, Value: req.Value, ExpiresAt: exp}, nil
}

func (f *fakeACME) CleanupTXT(_ context.Context, req ACMETXTRequest) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.err != nil {
		return false, f.err
	}
	k := req.FQDN + "|" + req.Value
	_, ok := f.records[k]
	delete(f.records, k)
	return ok, nil
}

type acmeTestOpts struct {
	tier          string
	account       string
	accountDomain string
	noDelegator   bool
}

func newACMETestServer(t *testing.T, o acmeTestOpts) (*Server, *httptest.Server, *fakeACME) {
	t.Helper()
	authProvider := auth.NewStaticProvider("nbk_test_secret")
	fake := newFakeACME()
	cfg := Config{Auth: authProvider, Registry: tunnel.NewRegistry(), AccountDomain: o.accountDomain}
	if !o.noDelegator {
		cfg.ACME = fake
	}
	srv := NewServer(cfg)
	srv.accountOf = func(*http.Request) string { return o.account }
	ts := httptest.NewServer(tierAuthMiddleware(authProvider, o.tier)(srv.mux))
	t.Cleanup(ts.Close)
	return srv, ts, fake
}

func acmeCall(t *testing.T, ts *httptest.Server, method, token, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+"/v1/acme/dns-01", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func acmeBody(fqdn, value string) string {
	b, _ := json.Marshal(map[string]string{"fqdn": fqdn, "value": value})
	return string(b)
}

var paidACME = acmeTestOpts{tier: "plus", account: "heroapp", accountDomain: "nullbore.com"}

func TestACMEPresentAndCleanup(t *testing.T) {
	_, ts, fake := newACMETestServer(t, paidACME)
	body := acmeBody("_acme-challenge.Web.heroapp.e2e.nullbore.com.", testACMEValue)

	code, m := acmeCall(t, ts, "POST", "nbk_test_secret", body)
	if code != 200 {
		t.Fatalf("present: status %d, body %v", code, m)
	}
	if m["fqdn"] != "_acme-challenge.web.heroapp.e2e.nullbore.com" || m["value"] != testACMEValue {
		t.Errorf("present body = %v", m)
	}
	if _, err := time.Parse(time.RFC3339, m["expires_at"].(string)); err != nil {
		t.Errorf("expires_at not RFC3339: %v", m["expires_at"])
	}
	got := fake.calls[0]
	if got.UserID != "test" || got.Account != "heroapp" || got.FQDN != "_acme-challenge.web.heroapp.e2e.nullbore.com" {
		t.Errorf("delegated request = %+v", got)
	}

	// Idempotent: same fqdn+value → 200 with the same record.
	code, m2 := acmeCall(t, ts, "POST", "nbk_test_secret", body)
	if code != 200 || m2["expires_at"] != m["expires_at"] {
		t.Errorf("repeat present: %d %v (first %v)", code, m2, m)
	}

	code, m = acmeCall(t, ts, "DELETE", "nbk_test_secret", body)
	if code != 200 || m["deleted"] != true {
		t.Errorf("cleanup: %d %v", code, m)
	}
	// Safe to retry.
	code, m = acmeCall(t, ts, "DELETE", "nbk_test_secret", body)
	if code != 200 || m["deleted"] != false {
		t.Errorf("cleanup of missing record: %d %v", code, m)
	}
}

func TestACMEHandlerErrors(t *testing.T) {
	good := acmeBody("_acme-challenge.heroapp.e2e.nullbore.com", testACMEValue)
	cases := []struct {
		name   string
		opts   acmeTestOpts
		method string
		token  string
		body   string
		status int
		errHas string
	}{
		{"no auth", paidACME, "POST", "", good, 401, ""},
		{"bad key", paidACME, "POST", "nbk_wrong_key", good, 401, ""},
		{"free tier", acmeTestOpts{tier: "free", account: "heroapp", accountDomain: "nullbore.com"}, "POST", "nbk_test_secret", good, 403, "paid plan"},
		{"free tier delete", acmeTestOpts{tier: "free", account: "heroapp", accountDomain: "nullbore.com"}, "DELETE", "nbk_test_secret", good, 403, "paid plan"},
		{"unknown tier", acmeTestOpts{tier: "", account: "heroapp", accountDomain: "nullbore.com"}, "POST", "nbk_test_secret", good, 403, "paid plan"},
		{"no delegator", acmeTestOpts{tier: "plus", account: "heroapp", accountDomain: "nullbore.com", noDelegator: true}, "POST", "nbk_test_secret", good, 501, "not configured"},
		{"no account domain", acmeTestOpts{tier: "plus", account: "heroapp"}, "POST", "nbk_test_secret", good, 501, "not configured"},
		{"no account subdomain", acmeTestOpts{tier: "plus", accountDomain: "nullbore.com"}, "POST", "nbk_test_secret", good, 403, "account subdomain"},
		{"wrong account", paidACME, "POST", "nbk_test_secret", acmeBody("_acme-challenge.villain.e2e.nullbore.com", testACMEValue), 403, "not under your account"},
		{"wrong account delete", paidACME, "DELETE", "nbk_test_secret", acmeBody("_acme-challenge.web.villain.e2e.nullbore.com", testACMEValue), 403, "not under your account"},
		{"deeper name", paidACME, "POST", "nbk_test_secret", acmeBody("_acme-challenge.a.b.heroapp.e2e.nullbore.com", testACMEValue), 400, ""},
		{"bad value", paidACME, "POST", "nbk_test_secret", acmeBody("_acme-challenge.heroapp.e2e.nullbore.com", "x y"), 400, "value"},
		{"bad json", paidACME, "POST", "nbk_test_secret", "{not json", 400, "invalid JSON"},
		{"empty body", paidACME, "POST", "nbk_test_secret", "", 400, "invalid JSON"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ts, fake := newACMETestServer(t, c.opts)
			code, m := acmeCall(t, ts, c.method, c.token, c.body)
			if code != c.status {
				t.Fatalf("status = %d, want %d (body %v)", code, c.status, m)
			}
			if c.errHas != "" {
				if s, _ := m["error"].(string); !strings.Contains(s, c.errHas) {
					t.Errorf("error = %q, want it to contain %q", s, c.errHas)
				}
			}
			if len(fake.calls) != 0 {
				t.Errorf("delegator called on a rejected request: %+v", fake.calls)
			}
		})
	}
}

func TestACMEUpstreamErrorMapping(t *testing.T) {
	good := acmeBody("_acme-challenge.heroapp.e2e.nullbore.com", testACMEValue)
	cases := []struct {
		name   string
		err    error
		status int
		errMsg string
	}{
		{"cap passthrough", &ACMEUpstreamError{Status: 429, Message: "too many live records"}, 429, "too many live records"},
		{"ownership passthrough", &ACMEUpstreamError{Status: 403, Message: "account not owned"}, 403, "account not owned"},
		{"unconfigured passthrough", &ACMEUpstreamError{Status: 501, Message: ""}, 501, "Not Implemented"},
		{"dashboard 500", &ACMEUpstreamError{Status: 500, Message: "cloudflare: boom"}, 502, "DNS provider error"},
		{"bad secret is ours, not theirs", &ACMEUpstreamError{Status: 401, Message: "unauthorized"}, 502, "DNS provider error"},
		{"network error", errors.New("dial tcp: refused"), 502, "DNS provider error"},
	}
	for _, c := range cases {
		for _, method := range []string{"POST", "DELETE"} {
			t.Run(c.name+"/"+method, func(t *testing.T) {
				_, ts, fake := newACMETestServer(t, paidACME)
				fake.err = c.err
				code, m := acmeCall(t, ts, method, "nbk_test_secret", good)
				if msg, _ := m["error"].(string); code != c.status || !strings.HasPrefix(msg, c.errMsg) {
					t.Errorf("got %d %v, want %d %q", code, m, c.status, c.errMsg)
				}
			})
		}
	}
}

func TestACMERateLimit(t *testing.T) {
	srv, ts, _ := newACMETestServer(t, paidACME)
	srv.acmeLimiter = NewRateLimiter(1, time.Hour, 2)
	body := acmeBody("_acme-challenge.heroapp.e2e.nullbore.com", testACMEValue)
	for i := 0; i < 2; i++ {
		if code, m := acmeCall(t, ts, "POST", "nbk_test_secret", body); code != 200 {
			t.Fatalf("present %d: %d %v", i, code, m)
		}
	}
	if code, _ := acmeCall(t, ts, "POST", "nbk_test_secret", body); code != 429 {
		t.Errorf("3rd present: status %d, want 429", code)
	}
	// Cleanup is never rate limited — a stuck record must always be removable.
	if code, _ := acmeCall(t, ts, "DELETE", "nbk_test_secret", body); code != 200 {
		t.Errorf("cleanup while limited: status %d, want 200", code)
	}
}

// --- ACMEDashboardClient ---

func TestACMEDashboardClient(t *testing.T) {
	var gotSecret, gotMethod string
	var gotReq ACMETXTRequest
	dash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/acme-txt" {
			http.NotFound(w, r)
			return
		}
		gotSecret = r.Header.Get("X-Internal-Secret")
		gotMethod = r.Method
		json.NewDecoder(r.Body).Decode(&gotReq)
		if gotReq.Value == "capped" {
			w.WriteHeader(429)
			io.WriteString(w, `{"error":"too many live records"}`)
			return
		}
		if r.Method == "DELETE" {
			io.WriteString(w, `{"deleted":true}`)
			return
		}
		io.WriteString(w, `{"fqdn":"`+gotReq.FQDN+`","value":"`+gotReq.Value+`","expires_at":"2030-01-01T12:00:00Z"}`)
	}))
	defer dash.Close()

	c := NewACMEDashboardClient(dash.URL+"/", "s3cret")
	req := ACMETXTRequest{UserID: "u1", Account: "heroapp", FQDN: "_acme-challenge.heroapp.e2e.nullbore.com", Value: testACMEValue}

	rec, err := c.PresentTXT(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if gotSecret != "s3cret" || gotMethod != "POST" || gotReq != req {
		t.Errorf("dashboard saw secret=%q method=%q req=%+v", gotSecret, gotMethod, gotReq)
	}
	if rec.FQDN != req.FQDN || !rec.ExpiresAt.Equal(time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("record = %+v", rec)
	}

	deleted, err := c.CleanupTXT(context.Background(), req)
	if err != nil || !deleted || gotMethod != "DELETE" {
		t.Errorf("cleanup: deleted=%v err=%v method=%s", deleted, err, gotMethod)
	}

	req.Value = "capped"
	_, err = c.PresentTXT(context.Background(), req)
	var up *ACMEUpstreamError
	if !errors.As(err, &up) || up.Status != 429 || up.Message != "too many live records" {
		t.Errorf("capped: err = %v", err)
	}
}
