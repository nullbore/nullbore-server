package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nullbore/nullbore-server/internal/auth"
)

// ACME DNS-01 delegation.
//
// A tunnel owner running their own ACME client (lego, acme.sh, certbot) for a
// tls-passthrough hostname under {account}.e2e.{AccountDomain} cannot publish
// the _acme-challenge TXT record themselves — NullBore owns the zone. These
// endpoints publish/remove that record on their behalf. Only the challenge
// digest ever reaches us: the account key, the certificate key and the
// certificate itself stay on the owner's machine. The relay never obtains or
// holds a certificate for these names.
//
// The record is written by the dashboard (which holds the DNS provider
// credentials); this server authenticates the caller, validates the name
// against the caller's account, gates on tier, rate limits, and forwards.

const (
	acmeChallengeLabel = "_acme-challenge"
	// acmeCreatesPerHour bounds POST /v1/acme/dns-01 per user. A full
	// x + *.x order needs 2; retries and renewals fit comfortably.
	acmeCreatesPerHour = 30
	acmeMaxBodyBytes   = 4 << 10
)

var (
	// ACME key-authorization digests are 43-char base64url (RFC 8555 §8.4);
	// allow a little slack but nothing that could break out of a TXT value.
	acmeValueRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	// A single DNS label for the tunnel leaf (no underscores, no wildcard).
	acmeLeafRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

	errACMEBadName = errors.New("invalid fqdn")
	errACMEForeign = errors.New("name is not under your account's end-to-end zone")
)

// normalizeACMEFQDN lowercases a name and strips one trailing dot (lego
// passes fully-qualified names like "_acme-challenge.x.example.com.").
func normalizeACMEFQDN(fqdn string) string {
	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}

// validateACMEChallenge checks a DNS-01 request against the caller's account
// and returns the normalized fqdn. Accepted names are exactly:
//
//	_acme-challenge.{account}.e2e.{accountDomain}        (wildcard *.{account}.e2e cert)
//	_acme-challenge.{leaf}.{account}.e2e.{accountDomain} (single tunnel cert)
//
// where {leaf} is one DNS label. Errors wrap errACMEBadName (malformed name or
// value → 400) or errACMEForeign (well-formed but not the caller's zone → 403).
func validateACMEChallenge(fqdn, value, account, accountDomain string) (string, error) {
	if !acmeValueRe.MatchString(value) {
		return "", fmt.Errorf("%w: value must be 1-128 base64url characters", errACMEBadName)
	}
	name := normalizeACMEFQDN(fqdn)
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("%w: fqdn is empty or too long", errACMEBadName)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return "", fmt.Errorf("%w: fqdn contains invalid characters", errACMEBadName)
		}
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return "", fmt.Errorf("%w: fqdn has an empty label", errACMEBadName)
		}
	}
	rest, ok := strings.CutPrefix(name, acmeChallengeLabel+".")
	if !ok {
		return "", fmt.Errorf("%w: fqdn must start with %s.", errACMEBadName, acmeChallengeLabel)
	}

	zoneSuffix := "." + e2eLabel + "." + strings.ToLower(accountDomain)
	sub, ok := strings.CutSuffix(rest, zoneSuffix)
	if !ok || accountDomain == "" {
		return "", errACMEForeign
	}
	labels := strings.Split(sub, ".")
	var acct string
	switch len(labels) {
	case 1:
		acct = labels[0]
	case 2:
		if !acmeLeafRe.MatchString(labels[0]) {
			return "", fmt.Errorf("%w: %q is not a valid tunnel name label", errACMEBadName, labels[0])
		}
		acct = labels[1]
	default:
		return "", fmt.Errorf("%w: must be %s.<tunnel>.<account>%s or %s.<account>%s",
			errACMEBadName, acmeChallengeLabel, zoneSuffix, acmeChallengeLabel, zoneSuffix)
	}
	if account == "" || acct != strings.ToLower(account) {
		return "", errACMEForeign
	}
	return name, nil
}

// --- Dashboard delegation ---

// ACMETXTRequest is what this server sends the dashboard.
type ACMETXTRequest struct {
	UserID  string `json:"user_id"`
	Account string `json:"account"`
	FQDN    string `json:"fqdn"`
	Value   string `json:"value"`
}

// ACMETXTRecord is a live challenge record.
type ACMETXTRecord struct {
	FQDN      string    `json:"fqdn"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ACMEDelegator publishes/removes _acme-challenge TXT records. Implemented by
// ACMEDashboardClient; nil in Config means DNS-01 delegation is unavailable.
type ACMEDelegator interface {
	PresentTXT(ctx context.Context, req ACMETXTRequest) (*ACMETXTRecord, error)
	CleanupTXT(ctx context.Context, req ACMETXTRequest) (bool, error)
}

// ACMEUpstreamError carries a non-200 dashboard answer.
type ACMEUpstreamError struct {
	Status  int
	Message string
}

func (e *ACMEUpstreamError) Error() string {
	return fmt.Sprintf("dashboard acme-txt: %d %s", e.Status, e.Message)
}

// ACMEDashboardClient calls the dashboard's /internal/acme-txt endpoint.
type ACMEDashboardClient struct {
	dashboardURL string
	secret       string
	client       *http.Client
}

// NewACMEDashboardClient builds a delegator backed by the dashboard.
func NewACMEDashboardClient(dashboardURL, secret string) *ACMEDashboardClient {
	return &ACMEDashboardClient{
		dashboardURL: strings.TrimSuffix(dashboardURL, "/"),
		secret:       secret,
		// The dashboard makes a Cloudflare API call inside this request.
		client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *ACMEDashboardClient) do(ctx context.Context, method string, req ACMETXTRequest, out any) error {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, method, c.dashboardURL+"/internal/acme-txt", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Internal-Secret", c.secret)
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &e)
		return &ACMEUpstreamError{Status: resp.StatusCode, Message: e.Error}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("dashboard acme-txt: bad response: %w", err)
	}
	return nil
}

// PresentTXT asks the dashboard to create (or refresh) the TXT record.
func (c *ACMEDashboardClient) PresentTXT(ctx context.Context, req ACMETXTRequest) (*ACMETXTRecord, error) {
	var rec ACMETXTRecord
	if err := c.do(ctx, http.MethodPost, req, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// CleanupTXT asks the dashboard to remove the TXT record.
func (c *ACMEDashboardClient) CleanupTXT(ctx context.Context, req ACMETXTRequest) (bool, error) {
	var res struct {
		Deleted bool `json:"deleted"`
	}
	if err := c.do(ctx, http.MethodDelete, req, &res); err != nil {
		return false, err
	}
	return res.Deleted, nil
}

// --- Handler ---

// callerAccount returns the caller's account subdomain (from the dashboard's
// validate-key answer cached by the RemoteProvider).
func (s *Server) callerAccount(r *http.Request) string {
	if s.accountOf != nil {
		return s.accountOf(r)
	}
	rp := getRemoteProvider(s.cfg.Auth)
	if rp == nil {
		return ""
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return rp.GetSubdomain(token)
}

// handleACMEDNS01 serves POST (present) and DELETE (cleanup) /v1/acme/dns-01.
func (s *Server) handleACMEDNS01(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ACME == nil || s.cfg.AccountDomain == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "ACME DNS-01 delegation is not configured on this server"})
		return
	}
	clientID := auth.ClientIDFrom(r.Context())
	if !tierIsPaid(auth.TierFrom(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACME DNS-01 delegation requires a paid plan"})
		return
	}

	var body struct {
		FQDN  string `json:"fqdn"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, acmeMaxBodyBytes)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: want {\"fqdn\", \"value\"}"})
		return
	}
	account := s.callerAccount(r)
	if account == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "claim an account subdomain before requesting certificates"})
		return
	}
	fqdn, err := validateACMEChallenge(body.FQDN, body.Value, account, s.cfg.AccountDomain)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errACMEForeign) {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	req := ACMETXTRequest{UserID: clientID, Account: account, FQDN: fqdn, Value: body.Value}
	if r.Method == http.MethodDelete {
		deleted, err := s.cfg.ACME.CleanupTXT(r.Context(), req)
		if err != nil {
			s.writeACMEUpstreamError(w, "cleanup", req, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": deleted})
		return
	}

	if !s.acmeLimiter.Allow(clientID) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "ACME DNS-01 rate limit exceeded, try again later"})
		return
	}
	rec, err := s.cfg.ACME.PresentTXT(r.Context(), req)
	if err != nil {
		s.writeACMEUpstreamError(w, "present", req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"fqdn":       rec.FQDN,
		"value":      rec.Value,
		"expires_at": rec.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// writeACMEUpstreamError passes through the dashboard's client-facing
// statuses (400/403/429/501) and maps everything else to 502.
func (s *Server) writeACMEUpstreamError(w http.ResponseWriter, op string, req ACMETXTRequest, err error) {
	var up *ACMEUpstreamError
	if errors.As(err, &up) {
		switch up.Status {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusNotImplemented:
			msg := up.Message
			if msg == "" {
				msg = http.StatusText(up.Status)
			}
			writeJSON(w, up.Status, map[string]string{"error": msg})
			return
		}
	}
	slog.Warn("acme dns-01 upstream failure", "op", op, "user", req.UserID, "fqdn", req.FQDN, "error", err)
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": "DNS provider error, try again shortly"})
}
