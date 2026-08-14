package crypto

import (
	"crypto/tls"

	configv1 "github.com/openshift/api/config/v1"
)

// tls12CapableGroups are the classical named groups usable for ECDHE key
// exchange in TLS 1.2 (and 1.3). Every ML-KEM hybrid group (X25519MLKEM768,
// SecP256r1MLKEM768, SecP384r1MLKEM1024) is a TLS 1.3-ONLY key-exchange
// mechanism: it cannot complete a TLS 1.2 handshake, so none appear here.
var tls12CapableGroups = map[configv1.TLSGroup]bool{
	configv1.TLSGroupX25519:    true,
	configv1.TLSGroupSecP256r1: true,
	configv1.TLSGroupSecP384r1: true,
	configv1.TLSGroupSecP521r1: true,
}

// classicalHandshakeFallbackGroups is the fallback appended when a TLS 1.2
// handshake would otherwise be impossible. It mirrors the classical portion of
// the shipped Old/Intermediate/Modern profiles.
var classicalHandshakeFallbackGroups = []configv1.TLSGroup{
	configv1.TLSGroupX25519,
	configv1.TLSGroupSecP256r1,
	configv1.TLSGroupSecP384r1,
}

// fipsHandshakeFallbackGroups is the FIPS-mode fallback. X25519 is not
// FIPS-approved, so it is excluded; this matches the cluster-ingress-operator
// precedent of falling back to secp256r1:secp384r1:secp521r1 (see TRT-2597).
var fipsHandshakeFallbackGroups = []configv1.TLSGroup{
	configv1.TLSGroupSecP256r1,
	configv1.TLSGroupSecP384r1,
	configv1.TLSGroupSecP521r1,
}

// EnsureHandshakeCapableGroups guards against a subtle Custom TLSSecurityProfile
// footgun: a supported-groups list containing only TLS 1.3-only groups (the
// ML-KEM post-quantum hybrids) while minTLSVersion still permits TLS 1.2.
//
// Why this is dangerous, and why it is not caught elsewhere:
//
//   - ML-KEM hybrids are 1.3-only, so such a config negotiates fine with TLS 1.3
//     peers but SILENTLY fails the handshake for any peer that tops out at TLS
//     1.2 (there is no classical ECDHE curve on offer). The breakage is
//     invisible until a legacy client shows up, i.e. a latent partial outage.
//   - It cannot be rejected at admission time: the config is legitimately
//     correct in a fleet where every peer speaks TLS 1.3. minTLSVersion is a
//     floor, not a guarantee that 1.2 is ever used.
//   - It is more likely under FIPS + post-quantum intent, where the approved PQC
//     options ARE the 1.3-only hybrids.
//
// So instead of rejecting, we fail SAFE: when minVersion permits TLS 1.2 but no
// requested group can service a 1.2 handshake, we APPEND (never replace) the
// classical fallback groups. Appending preserves the administrator's
// post-quantum preference for 1.3 peers while restoring 1.2 capability.
//
// Rules:
//   - An empty list means "no opinion"; return it unchanged so the caller/Go
//     applies its own safe defaults.
//   - minVersion >= TLS 1.3 can never negotiate 1.2; return unchanged.
//   - If any requested group is already TLS 1.2-capable, return unchanged. When
//     fips is true a non-FIPS-approved classical group (e.g. X25519) does NOT
//     count as usable, because it will be dropped at negotiation.
//   - Otherwise append the fallback (FIPS-aware) and report injected=true so the
//     caller can surface an event/warning.
//
// The function is idempotent: feeding its own output back in returns
// injected=false, because the result now contains a classical group.
func EnsureHandshakeCapableGroups(groups []configv1.TLSGroup, minVersion uint16, fips bool) (result []configv1.TLSGroup, injected bool) {
	if len(groups) == 0 {
		return groups, false
	}
	if minVersion >= tls.VersionTLS13 {
		return groups, false
	}
	for _, g := range groups {
		if fips && !IsFIPSApprovedTLSGroup(g) {
			// Would be dropped under FIPS, so it cannot rescue a 1.2 handshake.
			continue
		}
		if tls12CapableGroups[g] {
			return groups, false
		}
	}

	fallback := classicalHandshakeFallbackGroups
	if fips {
		fallback = fipsHandshakeFallbackGroups
	}
	// Copy first so we never mutate the caller's backing array.
	result = append(append([]configv1.TLSGroup{}, groups...), fallback...)
	return result, true
}
