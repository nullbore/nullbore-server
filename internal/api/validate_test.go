package api

import "testing"

func TestValidateTunnelName(t *testing.T) {
	valid := []string{
		"my-app", "api-v2", "gramps", "ab", "a1", "hello-world",
		"my-cool-tunnel-123", "x" + string(make([]byte, 61)), // we'll fix this below
	}
	// Fix the 63-char test case
	valid[len(valid)-1] = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0" // 63 chars

	for _, name := range valid {
		if err := validateTunnelName(name); err != nil {
			t.Errorf("expected %q to be valid, got: %v", name, err)
		}
	}

	invalid := []struct {
		name string
		desc string
	}{
		{"a", "too short"},
		{"", "empty"},
		{"A-B", "uppercase"},
		{"-abc", "leading hyphen"},
		{"abc-", "trailing hyphen"},
		{"my--tunnel", "consecutive hyphens"},
		{"my tunnel", "space"},
		{"my_tunnel", "underscore"},
		{"my.tunnel", "dot"},
		{"health", "reserved"},
		{"dash", "reserved"},
		{"v1", "reserved"},
		{"ws", "reserved"},
		{"admin", "reserved"},
		{"t", "reserved (and too short)"},
		{string(make([]byte, 64)), "too long"},
	}

	for _, tc := range invalid {
		if err := validateTunnelName(tc.name); err == nil {
			t.Errorf("expected %q (%s) to be invalid", tc.name, tc.desc)
		}
	}
}
