package crypto

import (
	"crypto/fips140"

	configv1 "github.com/openshift/api/config/v1"
)

// fipsTLSGroups is the allowlist of TLSGroup values approved under FIPS 186-5.
// Only the NIST P-curves qualify. An allowlist is used rather than a blocklist
// because new curves are non-FIPS by default until they complete formal NIST
// validation (typically years), so any future group absent from this set is
// correctly excluded without requiring a library-go update.
var fipsTLSGroups = map[configv1.TLSGroup]struct{}{
	configv1.TLSGroupSecP256r1: {},
	configv1.TLSGroupSecP384r1: {},
	configv1.TLSGroupSecP521r1: {},
}

// IsFIPSEnabled reports whether the Go runtime is operating in FIPS 140 mode.
func IsFIPSEnabled() bool {
	return fips140.Enabled()
}

// IsFIPSApprovedTLSGroup reports whether group is in the FIPS 186-5 approved
// allowlist. This is a pure classification — it does not check whether the
// current process is actually running in FIPS mode. Callers that need runtime
// FIPS enforcement should gate on IsFIPSEnabled().
func IsFIPSApprovedTLSGroup(group configv1.TLSGroup) bool {
	_, ok := fipsTLSGroups[group]
	return ok
}
