package crypto

import (
	"crypto/fips140"

	configv1 "github.com/openshift/api/config/v1"
)

// fipsTLSGroups is the allowlist of TLSGroup values treated as FIPS-approved.
// Only the NIST P-curves qualify: their domain parameters are specified in
// NIST SP 800-186 and their use for ECDH key establishment in SP 800-56A.
// (The earlier "FIPS 186-5" citation was inaccurate: that is the Digital
// Signature Standard, which governs signatures, not TLS key-exchange groups.)
//
// An allowlist is used rather than a blocklist because new groups are non-FIPS
// by default until they complete formal NIST validation (typically years), so
// any future group absent from this set is correctly excluded without requiring
// a library-go update.
var fipsTLSGroups = map[configv1.TLSGroup]struct{}{
	configv1.TLSGroupSecP256r1: {},
	configv1.TLSGroupSecP384r1: {},
	configv1.TLSGroupSecP521r1: {},
}

// IsFIPSEnabled reports whether the Go runtime is operating in FIPS 140 mode.
func IsFIPSEnabled() bool {
	return fips140.Enabled()
}

// IsFIPSApprovedTLSGroup reports whether group is in the FIPS-approved
// allowlist. This is a pure classification — it does not check whether the
// current process is actually running in FIPS mode. Callers that need runtime
// FIPS enforcement should gate on IsFIPSEnabled().
func IsFIPSApprovedTLSGroup(group configv1.TLSGroup) bool {
	_, ok := fipsTLSGroups[group]
	return ok
}
