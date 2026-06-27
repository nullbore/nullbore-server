package api

// Tier helpers mirror accounts.TierRank in the dashboard. The dashboard sends
// the tier via /internal/validate-key; the server enforces the same gates.
// "dev" is the legacy tier (migrated to "plus" in the dashboard) and is treated
// as plus here for backward compatibility during the transition.

// tierRank orders paid tiers ascending; free/unknown = 0.
func tierRank(tier string) int {
	switch tier {
	case "basic":
		return 1
	case "plus", "dev":
		return 2
	case "pro":
		return 3
	default:
		return 0
	}
}

// tierIsPaid reports whether a tier is any paid plan (Basic and up).
func tierIsPaid(tier string) bool { return tierRank(tier) >= 1 }
