package crypto

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

// TestIsFIPSApprovedTLSGroup pins the FIPS allowlist: only the three NIST
// P-curves are approved. X25519 and every ML-KEM post-quantum hybrid are not.
// This is a pure classification and needs no FIPS runtime to test.
//
// NOTE: this asserts OpenShift's *policy*, which is intentionally stricter than
// what Go's native FIPS module will negotiate (Go accepts X25519MLKEM768 under
// GODEBUG=fips140=on). See TestFIPSApprovalMatchesRuntime for the drift guard
// that watches that divergence.
func TestIsFIPSApprovedTLSGroup(t *testing.T) {
	testCases := []struct {
		name         string
		group        configv1.TLSGroup
		wantApproved bool
	}{
		{
			name:         "secp256r1 is approved",
			group:        configv1.TLSGroupSecP256r1,
			wantApproved: true,
		},
		{
			name:         "secp384r1 is approved",
			group:        configv1.TLSGroupSecP384r1,
			wantApproved: true,
		},
		{
			name:         "secp521r1 is approved",
			group:        configv1.TLSGroupSecP521r1,
			wantApproved: true,
		},
		{
			name:         "X25519 is not approved",
			group:        configv1.TLSGroupX25519,
			wantApproved: false,
		},
		{
			name:         "X25519MLKEM768 hybrid is not approved",
			group:        configv1.TLSGroupX25519MLKEM768,
			wantApproved: false,
		},
		{
			name:         "SecP256r1MLKEM768 hybrid is not approved",
			group:        configv1.TLSGroupSecP256r1MLKEM768,
			wantApproved: false,
		},
		{
			name:         "SecP384r1MLKEM1024 hybrid is not approved",
			group:        configv1.TLSGroupSecP384r1MLKEM1024,
			wantApproved: false,
		},
		{
			name:         "unknown group is not approved",
			group:        configv1.TLSGroup("UnknownFutureGroup"),
			wantApproved: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsFIPSApprovedTLSGroup(tc.group); got != tc.wantApproved {
				t.Errorf("IsFIPSApprovedTLSGroup(%q) = %v, want %v", tc.group, got, tc.wantApproved)
			}
		})
	}
}
