package api

import (
	"context"
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
