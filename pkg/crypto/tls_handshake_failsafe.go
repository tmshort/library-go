package crypto

import (
	"crypto/tls"
	"slices"

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

// classicalHandshakeFallbackGroups is the non-FIPS fallback appended when a TLS
// 1.2 handshake would otherwise be impossible. It mirrors the classical portion
// of the shipped Old/Intermediate/Modern profiles (X25519, secp256r1, secp384r1),
// which is why it deliberately does NOT include secp521r1 — those profiles do not
// list it either.
var classicalHandshakeFallbackGroups = []configv1.TLSGroup{
	configv1.TLSGroupX25519,
	configv1.TLSGroupSecP256r1,
	configv1.TLSGroupSecP384r1,
}

// fipsHandshakeFallbackGroups is the FIPS-mode fallback. It deliberately differs
// from classicalHandshakeFallbackGroups: X25519 is dropped (not FIPS-approved) and
// secp521r1 is included, matching the cluster-ingress-operator precedent of
// falling back to secp256r1:secp384r1:secp521r1 (see TRT-2597).
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
//
// Intended input, and why it is fips-aware:
//
// This operates on the groups a caller intends to OFFER; it does not itself drop
// groups for Go-support or FIPS (use FilterTLSGroups for that). Two caller shapes
// exist, which is why the fips parameter and the FIPS fallback exist:
//
//   - Pre-filtered caller (the config observer). getSecurityProfileGroups runs
//     FilterTLSGroups(fips) first, so under FIPS the survivors are already
//     P-curves (all TLS 1.2-capable) or the list is empty. There the FIPS branch
//     below is effectively a no-op; FIPS safety comes from FilterTLSGroups plus
//     the observer omitting an empty list so the operand uses its own defaults.
//
//   - Unfiltered caller (a component building a tls.Config directly, letting Go
//     apply FIPS at negotiation). There this helper is the one that must supply a
//     FIPS-safe classical fallback, so it needs the fips flag. For example:
//
//     spec, _ := GetTLSProfileSpec(profile)
//     min, _ := TLSVersion(string(spec.MinTLSVersion))
//     groups, _ := EnsureHandshakeCapableGroups(spec.Groups, min, IsFIPSEnabled())
//     curves, _ := TLSGroupsToCurveIDs(groups)
//     tlsConfig.CurvePreferences = curves // Go filters again at negotiation
//
// The returned slice is always one the caller fully owns (a distinct copy on
// every path), so it may be freely appended to or mutated.
func EnsureHandshakeCapableGroups(groups []configv1.TLSGroup, minVersion uint16, fips bool) ([]configv1.TLSGroup, bool) {
	if len(groups) == 0 {
		return nil, false
	}
	results := slices.Clone(groups)
	if minVersion >= tls.VersionTLS13 {
		return results, false
	}
	for _, g := range groups {
		if fips && !IsFIPSApprovedTLSGroup(g) {
			// Would be dropped under FIPS, so it cannot rescue a 1.2 handshake.
			continue
		}
		if tls12CapableGroups[g] {
			return results, false
		}
	}

	fallback := classicalHandshakeFallbackGroups
	if fips {
		fallback = fipsHandshakeFallbackGroups
	}
	return append(results, fallback...), true
}
