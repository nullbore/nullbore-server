package api

import (
	"context"
	"fmt"
	"testing"
)

func TestHostPolicy(t *testing.T) {
	cfg := &TLSConfig{
		Domains:    []string{"tunnel.nullbore.com"},
		BaseDomain: "tunnel.nullbore.com",
	}

	policy := cfg.hostPolicy()
	ctx := context.Background()

	// Explicitly allowed
	if err := policy(ctx, "tunnel.nullbore.com"); err != nil {
		t.Errorf("expected tunnel.nullbore.com to be allowed: %v", err)
	}

	// Valid subdomain
	if err := policy(ctx, "my-app.tunnel.nullbore.com"); err != nil {
		t.Errorf("expected my-app.tunnel.nullbore.com to be allowed: %v", err)
	}

	// Another valid subdomain
	if err := policy(ctx, "abc123.tunnel.nullbore.com"); err != nil {
		t.Errorf("expected abc123.tunnel.nullbore.com to be allowed: %v", err)
	}

	// Reject: nested subdomain
	if err := policy(ctx, "a.b.tunnel.nullbore.com"); err == nil {
		t.Error("expected a.b.tunnel.nullbore.com to be rejected")
	}

	// Reject: completely different domain
	if err := policy(ctx, "evil.com"); err == nil {
		t.Error("expected evil.com to be rejected")
	}

	// Reject: partial match
	if err := policy(ctx, "notnullbore.com"); err == nil {
		t.Error("expected notnullbore.com to be rejected")
	}

	// Reject: empty slug
	if err := policy(ctx, ".tunnel.nullbore.com"); err == nil {
		t.Error("expected empty slug to be rejected")
	}
}

func TestHostPolicyNoBaseDomain(t *testing.T) {
	cfg := &TLSConfig{
		Domains: []string{"tunnel.nullbore.com"},
	}

	policy := cfg.hostPolicy()
	ctx := context.Background()

	// Explicitly allowed
	if err := policy(ctx, "tunnel.nullbore.com"); err != nil {
		t.Errorf("expected tunnel.nullbore.com to be allowed: %v", err)
	}

	// Subdomains not allowed without BaseDomain
	if err := policy(ctx, "my-app.tunnel.nullbore.com"); err == nil {
		t.Error("expected subdomain to be rejected without BaseDomain")
	}
}

// stubAccountChecker resolves a fixed set of account names.
type stubAccountChecker struct{ known map[string]string }

func (s *stubAccountChecker) Resolve(name string) (string, error) {
	if id, ok := s.known[name]; ok {
		return id, nil
	}
	return "", fmt.Errorf("unknown account %q", name)
}

func TestHostPolicyAccountDomain_GatedOnChecker(t *testing.T) {
	checker := &stubAccountChecker{known: map[string]string{"heroapp": "user-1"}}
	cfg := &TLSConfig{
		Domains:        []string{"nullbore.com"},
		BaseDomain:     "tunnel.nullbore.com",
		AccountDomain:  "nullbore.com",
		AccountChecker: checker,
	}
	policy := cfg.hostPolicy()
	ctx := context.Background()

	// Bare account: heroapp.nullbore.com → allowed (heroapp is registered)
	if err := policy(ctx, "heroapp.nullbore.com"); err != nil {
		t.Errorf("registered bare account should be allowed: %v", err)
	}
	// Leaf under registered account: web.heroapp.nullbore.com → allowed
	if err := policy(ctx, "web.heroapp.nullbore.com"); err != nil {
		t.Errorf("leaf under registered account should be allowed: %v", err)
	}
	// Unknown account: fake.nullbore.com → rejected
	if err := policy(ctx, "fake.nullbore.com"); err == nil {
		t.Error("unknown bare account must be rejected to prevent ACME abuse")
	}
	// Leaf under unknown account: leaf.fake.nullbore.com → rejected
	if err := policy(ctx, "leaf.fake.nullbore.com"); err == nil {
		t.Error("leaf under unknown account must be rejected to prevent ACME abuse")
	}
	// Three-level under registered account: a.b.heroapp.nullbore.com → rejected
	// (we only support {account} or {leaf}.{account}, never deeper)
	if err := policy(ctx, "a.b.heroapp.nullbore.com"); err == nil {
		t.Error("three-level account host must be rejected")
	}
	// {slug}.tunnel.nullbore.com pattern still works (BaseDomain plane is independent)
	if err := policy(ctx, "abc123.tunnel.nullbore.com"); err != nil {
		t.Errorf("base-domain slug should still be allowed: %v", err)
	}
}

func TestHostPolicyAccountDomain_NoCheckerRejectsAll(t *testing.T) {
	// AccountDomain set but no AccountChecker → all account hosts must be rejected.
	// This is the secure default: a misconfigured deployment cannot accidentally
	// mint certs for arbitrary names just because AccountChecker wasn't wired in.
	cfg := &TLSConfig{
		Domains:       []string{"nullbore.com"},
		AccountDomain: "nullbore.com",
	}
	policy := cfg.hostPolicy()
	ctx := context.Background()

	if err := policy(ctx, "heroapp.nullbore.com"); err == nil {
		t.Error("account host must be rejected when AccountChecker is nil")
	}
	if err := policy(ctx, "web.heroapp.nullbore.com"); err == nil {
		t.Error("leaf account host must be rejected when AccountChecker is nil")
	}
}

func TestAccountAllowedByChecker(t *testing.T) {
	checker := &stubAccountChecker{known: map[string]string{"heroapp": "u1"}}
	cases := []struct {
		host string
		want bool
	}{
		{"heroapp.nullbore.com", true},
		{"web.heroapp.nullbore.com", true},
		{"api.heroapp.nullbore.com", true},
		{"fake.nullbore.com", false},
		{"web.fake.nullbore.com", false},
		{"a.b.heroapp.nullbore.com", false}, // too deep
		{"nullbore.com", false},             // bare AccountDomain — caller should not pass this
		{".nullbore.com", false},            // empty left
	}
	for _, tc := range cases {
		got := accountAllowedByChecker(tc.host, "nullbore.com", checker)
		if got != tc.want {
			t.Errorf("accountAllowedByChecker(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}

	// Nil checker → always false
	if accountAllowedByChecker("heroapp.nullbore.com", "nullbore.com", nil) {
		t.Error("nil checker must return false")
	}
}
