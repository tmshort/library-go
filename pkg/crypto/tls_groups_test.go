package crypto

import (
	"reflect"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestFilterTLSGroups(t *testing.T) {
	testCases := []struct {
		name   string
		groups []configv1.TLSGroup
		fips   bool
		want   []configv1.TLSGroup
	}{
		{
			name:   "non-FIPS drops only groups unknown to Go, order preserved",
			groups: []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1, configv1.TLSGroupX25519MLKEM768, "UnknownFutureGroup"},
			fips:   false,
			want:   []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1, configv1.TLSGroupX25519MLKEM768},
		},
		{
			name:   "FIPS drops unknown AND non-approved groups",
			groups: []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1, configv1.TLSGroupX25519MLKEM768, "UnknownFutureGroup"},
			fips:   true,
			want:   []configv1.TLSGroup{configv1.TLSGroupSecP256r1},
		},
		{
			name:   "FIPS keeps all NIST P-curves",
			groups: []configv1.TLSGroup{configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP521r1},
			fips:   true,
			want:   []configv1.TLSGroup{configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP521r1},
		},
		{
			name:   "FIPS dropping every group yields empty (caller must default)",
			groups: []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupX25519MLKEM768},
			fips:   true,
			want:   []configv1.TLSGroup{},
		},
		{
			name:   "empty input yields empty output",
			groups: nil,
			fips:   false,
			want:   []configv1.TLSGroup{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterTLSGroups(tc.groups, tc.fips)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FilterTLSGroups(%v, fips=%v) = %v, want %v", tc.groups, tc.fips, got, tc.want)
			}
		})
	}
}
