package crypto

import (
	"crypto/tls"
	"reflect"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestEnsureHandshakeCapableGroups(t *testing.T) {
	testCases := []struct {
		name         string
		groups       []configv1.TLSGroup
		minVersion   uint16
		fips         bool
		wantResult   []configv1.TLSGroup
		wantInjected bool
	}{
		{
			name:         "ML-KEM-only with TLS 1.2 floor injects classical fallback",
			groups:       []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
			minVersion:   tls.VersionTLS12,
			fips:         false,
			wantResult:   []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768, configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP384r1},
			wantInjected: true,
		},
		{
			name:         "ML-KEM-only with TLS 1.2 floor under FIPS injects FIPS-approved fallback (no X25519)",
			groups:       []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
			minVersion:   tls.VersionTLS12,
			fips:         true,
			wantResult:   []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768, configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP521r1},
			wantInjected: true,
		},
		{
			name:         "ML-KEM-only with TLS 1.3 floor is left untouched",
			groups:       []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
			minVersion:   tls.VersionTLS13,
			fips:         false,
			wantResult:   []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
			wantInjected: false,
		},
		{
			name:         "list already containing a classical group is left untouched (idempotency)",
			groups:       []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768, configv1.TLSGroupSecP256r1},
			minVersion:   tls.VersionTLS12,
			fips:         false,
			wantResult:   []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768, configv1.TLSGroupSecP256r1},
			wantInjected: false,
		},
		{
			name:         "classical group that is not FIPS-approved does not count as safe under FIPS",
			groups:       []configv1.TLSGroup{configv1.TLSGroupX25519}, // usable in 1.2 but dropped under FIPS
			minVersion:   tls.VersionTLS12,
			fips:         true,
			wantResult:   []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP521r1},
			wantInjected: true,
		},
		{
			name:         "FIPS: an already-present FIPS-approved classical group suppresses injection",
			groups:       []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768, configv1.TLSGroupSecP256r1},
			minVersion:   tls.VersionTLS12,
			fips:         true,
			wantResult:   []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768, configv1.TLSGroupSecP256r1},
			wantInjected: false,
		},
		{
			name:         "empty list means no opinion and is left untouched",
			groups:       nil,
			minVersion:   tls.VersionTLS12,
			fips:         false,
			wantResult:   nil,
			wantInjected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotResult, gotInjected := EnsureHandshakeCapableGroups(tc.groups, tc.minVersion, tc.fips)
			if gotInjected != tc.wantInjected {
				t.Errorf("injected = %v, want %v", gotInjected, tc.wantInjected)
			}
			if !reflect.DeepEqual(gotResult, tc.wantResult) {
				t.Errorf("result = %v, want %v", gotResult, tc.wantResult)
			}
		})
	}
}

// TestEnsureHandshakeCapableGroupsIsIdempotent feeds the augmented output back
// through the helper and asserts it is a no-op the second time. Idempotency is
// what lets the fail-safe be applied at more than one layer without compounding
// the fallback; today it runs only in the config observer.
func TestEnsureHandshakeCapableGroupsIsIdempotent(t *testing.T) {
	in := []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768}
	once, injected := EnsureHandshakeCapableGroups(in, tls.VersionTLS12, false)
	if !injected {
		t.Fatalf("expected first pass to inject a fallback")
	}
	twice, injectedAgain := EnsureHandshakeCapableGroups(once, tls.VersionTLS12, false)
	if injectedAgain {
		t.Errorf("second pass injected again; helper is not idempotent")
	}
	if !reflect.DeepEqual(once, twice) {
		t.Errorf("second pass changed the result: %v -> %v", once, twice)
	}
}
