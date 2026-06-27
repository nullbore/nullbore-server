package api

import "testing"

func TestTierRankAndPaid(t *testing.T) {
	tests := []struct {
		tier string
		rank int
		paid bool
	}{
		{"free", 0, false},
		{"", 0, false},
		{"bogus", 0, false},
		{"basic", 1, true},
		{"plus", 2, true},
		{"dev", 2, true}, // legacy alias for plus
		{"pro", 3, true},
	}
	for _, tt := range tests {
		if got := tierRank(tt.tier); got != tt.rank {
			t.Errorf("tierRank(%q) = %d, want %d", tt.tier, got, tt.rank)
		}
		if got := tierIsPaid(tt.tier); got != tt.paid {
			t.Errorf("tierIsPaid(%q) = %v, want %v", tt.tier, got, tt.paid)
		}
	}
}

func TestTierTunnelLimitByTier(t *testing.T) {
	tests := map[string]int{
		"free":  1,
		"basic": 1,
		"plus":  5,
		"dev":   5, // legacy
		"pro":   20,
		"":      1,
	}
	for tier, want := range tests {
		if got := tierTunnelLimit(tier); got != want {
			t.Errorf("tierTunnelLimit(%q) = %d, want %d", tier, got, want)
		}
	}
}

func TestTierMaxTTLPaidPersistent(t *testing.T) {
	for _, paid := range []string{"basic", "plus", "pro", "dev"} {
		if tierMaxTTL(paid) != 0 {
			t.Errorf("tierMaxTTL(%q) should be 0 (persistent)", paid)
		}
	}
	if tierMaxTTL("free") == 0 {
		t.Error("tierMaxTTL(free) should be capped, not persistent")
	}
}
