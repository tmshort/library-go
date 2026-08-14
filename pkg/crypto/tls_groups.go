package crypto

import (
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
)

// FilterTLSGroups returns the subset of groups that are actually usable, in the
// same order they were given.
//
// Two independent reasons a requested group is dropped:
//
//   - Unknown to this Go build. TLSGroupToCurveID only knows the groups the
//     linked crypto/tls understands; a newer openshift/api may name groups a
//     given operand's Go toolchain cannot negotiate (forward compatibility).
//     These are always dropped.
//   - Not FIPS-approved, when fips is true. X25519 and the ML-KEM post-quantum
//     hybrids are not in the FIPS allowlist (see fips.go); they are dropped only
//     when the caller says the runtime is in FIPS mode.
//
// This lives in pkg/crypto rather than in the configobserver because the
// group-to-curve mapping and the FIPS policy are both crypto concerns; the
// observer should not have to know which groups a Go build supports or which are
// FIPS-approved. Callers decide FIPS state via IsFIPSEnabled() and pass it in,
// keeping this function pure and unit-testable without a FIPS runtime.
//
// Dropped groups are logged at V(4). The returned slice is always non-nil-safe
// for range but may be empty; callers must decide what an empty result means
// (typically: fall back to platform defaults rather than offering no curves).
func FilterTLSGroups(groups []configv1.TLSGroup, fips bool) []configv1.TLSGroup {
	filtered := make([]configv1.TLSGroup, 0, len(groups))
	for _, g := range groups {
		if _, ok := TLSGroupToCurveID(g); !ok {
			klog.V(4).Infof("Dropping TLS group %q: not supported by Go's crypto/tls", g)
			continue
		}
		if fips && !IsFIPSApprovedTLSGroup(g) {
			klog.V(4).Infof("Dropping TLS group %q: not FIPS-approved", g)
			continue
		}
		filtered = append(filtered, g)
	}
	return filtered
}
