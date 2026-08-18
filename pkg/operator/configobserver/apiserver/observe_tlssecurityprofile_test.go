package apiserver

import (
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestObserveTLSSecurityProfile(t *testing.T) {
	existingTLSVersion := "VersionTLS11"
	existingCipherSuites := []interface{}{"DES-CBC3-SHA"}

	tests := []struct {
		name                  string
		config                *configv1.TLSSecurityProfile
		expectedMinTLSVersion string
		expectedSuites        []string
	}{
		{
			name:                  "NoAPIServerConfig",
			config:                nil,
			expectedMinTLSVersion: "VersionTLS12",
			expectedSuites: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			},
		},
		{
			name: "ModernCrypto",
			config: &configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileModernType,
				Modern: &configv1.ModernTLSProfile{},
			},
			expectedMinTLSVersion: "VersionTLS13",
			expectedSuites: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
			},
		},
		{
			name: "OldCrypto",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
				Old:  &configv1.OldTLSProfile{},
			},
			expectedMinTLSVersion: "VersionTLS10",
			expectedSuites: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
				"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
				"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
				"TLS_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_128_CBC_SHA256",
				"TLS_RSA_WITH_AES_128_CBC_SHA",
				"TLS_RSA_WITH_AES_256_CBC_SHA",
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, useAPIServerArgs := range []bool{false, true} {
				minTLSVersionPath := []string{"servingInfo", "minTLSVersion"}
				cipherSuitesPath := []string{"servingInfo", "cipherSuites"}
				name := "FromServingInfo"
				if useAPIServerArgs {
					minTLSVersionPath = []string{"apiServerArguments", "tls-min-version"}
					cipherSuitesPath = []string{"apiServerArguments", "tls-cipher-suites"}
					name = "FromAPIServerArguments"
				}
				t.Run(name, func(t *testing.T) {
					indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
					if tt.config != nil {
						if err := indexer.Add(&configv1.APIServer{
							ObjectMeta: metav1.ObjectMeta{
								Name: "cluster",
							},
							Spec: configv1.APIServerSpec{
								TLSSecurityProfile: tt.config,
							},
						}); err != nil {
							t.Fatal(err)
						}
					}
					listers := testLister{
						apiLister: configlistersv1.NewAPIServerLister(indexer),
					}

					existingConfig := map[string]interface{}{}
					if err := unstructured.SetNestedField(existingConfig, existingTLSVersion, minTLSVersionPath...); err != nil {
						t.Fatalf("couldn't set existing min TLS version: %v", err)
					}
					if err := unstructured.SetNestedField(existingConfig, existingCipherSuites, cipherSuitesPath...); err != nil {
						t.Fatalf("couldn't set existing cipher suites: %v", err)
					}

					var result map[string]interface{}
					var errs []error
					if useAPIServerArgs {
						result, errs = ObserveTLSSecurityProfileToArguments(listers, events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())), existingConfig)
					} else {
						result, errs = ObserveTLSSecurityProfile(listers, events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())), existingConfig)
					}
					if len(errs) > 0 {
						t.Errorf("expected 0 errors, got %v", errs)
					}

					gotMinTLSVersion, _, err := unstructured.NestedString(result, minTLSVersionPath...)
					if err != nil {
						t.Errorf("couldn't get minTLSVersion from the returned object: %v", err)
					}

					gotSuites, _, err := unstructured.NestedStringSlice(result, cipherSuitesPath...)
					if err != nil {
						t.Errorf("couldn't get cipherSuites from the returned object: %v", err)
					}

					if !reflect.DeepEqual(gotSuites, tt.expectedSuites) {
						t.Errorf("got cipherSuites = %v, expected %v", gotSuites, tt.expectedSuites)
					}
					if gotMinTLSVersion != tt.expectedMinTLSVersion {
						t.Errorf("got minTlSVersion = %v, expected %v", gotMinTLSVersion, tt.expectedMinTLSVersion)
					}
				})
			}
		})
	}
}

func TestObserveTLSSecurityProfileWithGroupPaths(t *testing.T) {
	// IMPORTANT: the set of TLS groups the observer emits depends on whether the
	// Go runtime is in FIPS mode. X25519 and every ML-KEM post-quantum hybrid
	// (X25519MLKEM768, ...) are NOT FIPS-approved and are dropped by
	// getSecurityProfileGroups when crypto.IsFIPSEnabled() is true. The original
	// version of this test hard-coded the non-FIPS expectations, so all but one
	// subtest failed under `GODEBUG=fips140=on` — i.e. red on every FIPS CI lane,
	// and the FIPS-filtering branch (the whole point of the feature) was never
	// actually exercised. We therefore key each expectation off the live FIPS
	// state so the suite is correct in both modes AND genuinely covers the FIPS
	// path when run under fips140=on.
	fips := crypto.IsFIPSEnabled()

	// pick returns the FIPS or non-FIPS expectation for the current runtime.
	pick := func(nonFIPS, fipsMode []string) []string {
		if fips {
			return fipsMode
		}
		return nonFIPS
	}

	// The default (Old/Intermediate/Modern/absent) profiles all advertise the
	// same groups; under FIPS the non-approved X25519MLKEM768 and X25519 are
	// stripped, leaving only the NIST P-curves.
	defaultGroups := pick(
		[]string{"X25519MLKEM768", "X25519", "secp256r1", "secp384r1"},
		[]string{"secp256r1", "secp384r1"},
	)

	testCases := []struct {
		name               string
		config             *configv1.TLSSecurityProfile
		expectedGroups     []string
		wantAugmentWarning bool
		wantDropWarning    bool
	}{
		{
			name:           "NoAPIServerConfig",
			config:         nil,
			expectedGroups: defaultGroups,
		},
		{
			name: "IntermediateProfile",
			config: &configv1.TLSSecurityProfile{
				Type:         configv1.TLSProfileIntermediateType,
				Intermediate: &configv1.IntermediateTLSProfile{},
			},
			expectedGroups: defaultGroups,
		},
		{
			name: "OldProfile",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
				Old:  &configv1.OldTLSProfile{},
			},
			expectedGroups: defaultGroups,
		},
		{
			name: "ModernProfile",
			config: &configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileModernType,
				Modern: &configv1.ModernTLSProfile{},
			},
			expectedGroups: defaultGroups,
		},
		{
			name: "CustomProfileNoGroups",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
					},
				},
			},
			expectedGroups: []string{},
		},
		{
			name: "CustomProfileWithGroups",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
					},
				},
			},
			// Under FIPS the non-approved X25519 is dropped, leaving secp256r1.
			expectedGroups: pick([]string{"X25519", "secp256r1"}, []string{"secp256r1"}),
		},
		{
			name: "CustomProfileWithUnknownGroup",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, "UnknownFutureGroup"},
					},
				},
			},
			// "UnknownFutureGroup" is always dropped (unknown to Go). Under FIPS
			// X25519 is dropped too, leaving nothing — so under FIPS the admin's
			// configured groups are all dropped and the observer warns.
			expectedGroups:  pick([]string{"X25519"}, []string{}),
			wantDropWarning: fips,
		},
		{
			// The footgun case: only a TLS 1.3-only ML-KEM hybrid, but the floor
			// still permits TLS 1.2. Non-FIPS: the hybrid survives filtering, so
			// the fail-safe appends classical fallback groups and warns. FIPS:
			// the hybrid is not approved and is dropped, leaving nothing (no
			// fallback, path omitted) so the operand uses its own defaults.
			name: "CustomProfileMLKEMOnlyWithTLS12FloorGetsFallback",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
					},
				},
			},
			expectedGroups:     pick([]string{"X25519MLKEM768", "X25519", "secp256r1", "secp384r1"}, []string{}),
			wantAugmentWarning: !fips,
			// Under FIPS the sole configured group is dropped, so the observer warns
			// that all configured groups were dropped instead.
			wantDropWarning: fips,
		},
	}

	minTLSVersionPath := []string{"olmTLS", "minTLSVersion"}
	cipherSuitesPath := []string{"olmTLS", "cipherSuites"}
	groupsPath := []string{"olmTLS", "curvePreferences"}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tc.config != nil {
				if err := indexer.Add(&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec:       configv1.APIServerSpec{TLSSecurityProfile: tc.config},
				}); err != nil {
					t.Fatal(err)
				}
			}
			listers := testLister{apiLister: configlistersv1.NewAPIServerLister(indexer)}

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			result, errs := ObserveTLSSecurityProfileWithGroupPaths(
				listers,
				recorder,
				map[string]interface{}{},
				minTLSVersionPath,
				cipherSuitesPath,
				groupsPath,
			)
			if len(errs) > 0 {
				t.Errorf("expected 0 errors, got %v", errs)
			}

			gotGroups, found, err := unstructured.NestedStringSlice(result, groupsPath...)
			if err != nil {
				t.Errorf("couldn't get groups from result: %v", err)
			}

			if len(tc.expectedGroups) == 0 {
				// An empty result must omit the path entirely (no explicit []),
				// so the operand falls back to platform defaults rather than
				// interpreting [] as "no curves permitted".
				if found {
					t.Errorf("expected groups path to be omitted for an empty result, but found %v", gotGroups)
				}
				// ...and omitting the path on a first reconcile must NOT emit a
				// spurious "groups changed to []" event.
				for _, ev := range recorder.Events() {
					if strings.Contains(ev.Message, "groups changed") {
						t.Errorf("unexpected groups-changed event for empty result: %q", ev.Message)
					}
				}
			} else {
				if !reflect.DeepEqual(gotGroups, tc.expectedGroups) {
					t.Errorf("got groups = %v, expected %v", gotGroups, tc.expectedGroups)
				}
				// A real (non-empty) first observation should report the change.
				sawEvent := false
				for _, ev := range recorder.Events() {
					if strings.Contains(ev.Message, "groups changed") {
						sawEvent = true
					}
				}
				if !sawEvent {
					t.Errorf("expected a groups-changed event for %v, got none", tc.expectedGroups)
				}
			}

			// The group observer must not clobber the sibling fields: minTLSVersion
			// and cipherSuites still have to be written alongside the groups.
			if _, found, _ := unstructured.NestedString(result, minTLSVersionPath...); !found {
				t.Errorf("minTLSVersion missing from result; group observation must not drop sibling fields")
			}
			if _, found, _ := unstructured.NestedStringSlice(result, cipherSuitesPath...); !found {
				t.Errorf("cipherSuites missing from result; group observation must not drop sibling fields")
			}

			// The fail-safe must warn (and only warn) when it augments the
			// admin's groups with a classical fallback.
			sawAugmentWarning := false
			for _, ev := range recorder.Events() {
				if strings.Contains(ev.Message, "appended classical fallback") {
					sawAugmentWarning = true
				}
			}
			if sawAugmentWarning != tc.wantAugmentWarning {
				t.Errorf("augment warning emitted = %v, want %v", sawAugmentWarning, tc.wantAugmentWarning)
			}

			// When the admin configured groups but all were dropped (unsupported /
			// non-FIPS), the observer must warn rather than silently fall back.
			sawDropWarning := false
			for _, ev := range recorder.Events() {
				if strings.Contains(ev.Message, "all configured TLS groups were dropped") {
					sawDropWarning = true
				}
			}
			if sawDropWarning != tc.wantDropWarning {
				t.Errorf("drop warning emitted = %v, want %v", sawDropWarning, tc.wantDropWarning)
			}

			// Verify the result is pruned to only the observed paths
			for k := range result {
				if k != "olmTLS" {
					t.Errorf("unexpected key %q in pruned result", k)
				}
			}
		})
	}
}

// TestObserveTLSSecurityProfileWithGroupPathsSteadyState verifies that a
// reconcile whose observed non-empty groups already match the persisted groups
// emits NO "groups changed" event. The table test above always starts from an
// empty existingConfig (currentGroups == nil), so it only ever exercises the
// nil-vs-empty short-circuit and the "changed from nothing" path of groupsEqual;
// the reflect.DeepEqual "equal, non-empty -> suppress" branch — the actual point
// of the change-suppression fix — is never hit there. This test feeds a prior
// observation back in to exercise exactly that branch. It is FIPS-agnostic: the
// default profile yields a non-empty group list in both modes.
func TestObserveTLSSecurityProfileWithGroupPathsSteadyState(t *testing.T) {
	minTLSVersionPath := []string{"olmTLS", "minTLSVersion"}
	cipherSuitesPath := []string{"olmTLS", "cipherSuites"}
	groupsPath := []string{"olmTLS", "curvePreferences"}

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	listers := testLister{apiLister: configlistersv1.NewAPIServerLister(indexer)}

	// First reconcile from empty establishes the observed groups (and expectedly
	// fires a change event).
	first, errs := ObserveTLSSecurityProfileWithGroupPaths(
		listers,
		events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())),
		map[string]interface{}{},
		minTLSVersionPath, cipherSuitesPath, groupsPath,
	)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors on first reconcile: %v", errs)
	}
	observed, found, err := unstructured.NestedStringSlice(first, groupsPath...)
	if err != nil || !found || len(observed) == 0 {
		t.Fatalf("expected a non-empty observed groups list, got found=%v groups=%v err=%v", found, observed, err)
	}

	// Second reconcile fed the first result back in as existingConfig: groups are
	// unchanged, so no "groups changed" event must fire (DeepEqual branch of
	// groupsEqual returning true).
	recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
	if _, errs = ObserveTLSSecurityProfileWithGroupPaths(
		listers, recorder, first, minTLSVersionPath, cipherSuitesPath, groupsPath,
	); len(errs) > 0 {
		t.Fatalf("unexpected errors on second reconcile: %v", errs)
	}
	for _, ev := range recorder.Events() {
		if strings.Contains(ev.Message, "groups changed") {
			t.Errorf("steady-state reconcile emitted a spurious groups-changed event: %q", ev.Message)
		}
	}
}
