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
//
// KNOWN DIVERGENCE (revisit as part of native Go FIPS adoption, HPSTRAT-723).
// Three sources disagree about the FIPS status of some groups, and this
// allowlist deliberately takes the strictest position:
//
//		group           openshift/api godoc     this allowlist   Go native FIPS (fips140=on)
//		X25519          "keep" (only            drops            REFUSES ("no supported
//		                 X25519MLKEM768 should                     elliptic curves for ECDHE")
//		                 be ignored in FIPS)
//		X25519MLKEM768  "ignore in FIPS"        drops            NEGOTIATES it
//
//	  - On plain X25519 this allowlist matches the runtime (both exclude it); the
//	    openshift/api godoc is the outdated one (corrected in OCPBUGS-109794).
//	  - On X25519MLKEM768 this allowlist is stricter than Go: Go's module will
//	    negotiate the hybrid, but we drop it because the hybrid embeds X25519 and
//	    the FIPS status of ML-KEM hybrids is still settling (SP 800-56C key
//	    derivation guidance). Empirically confirmed with a probe under
//	    GODEBUG=fips140=on on Go 1.26; TestFIPSApprovalMatchesRuntime guards this
//	    so we notice if a toolchain bump changes it.
//
// This set is intentionally strict (P-curves only) while operands run mixed
// crypto backends (OpenSSL FIPS + Go native): it is the safe intersection and
// never offers a curve an OpenSSL-backed operand would reject. It should be
// revisited once native Go FIPS is the backend — likely deferring to the
// module's approved set for Go operands and allowing the P-curve+ML-KEM hybrids
// (SecP256r1MLKEM768, SecP384r1MLKEM1024; both halves are NIST-approved), keeping
// an explicit filter only for non-Go / OpenSSL-backed operands. X25519MLKEM768
// stays excluded even then, because its classical half is the non-NIST curve.
// Tracked in CNTRLPLANE-4107 (under HPSTRAT-723).
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
