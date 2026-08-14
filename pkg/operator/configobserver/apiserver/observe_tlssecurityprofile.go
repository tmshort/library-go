package apiserver

import (
	"fmt"
	"reflect"

	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ObserveTLSSecurityProfile observes APIServer.Spec.TLSSecurityProfile field and sets
// the ServingInfo.MinTLSVersion, ServingInfo.CipherSuites fields of observed config
func ObserveTLSSecurityProfile(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerTLSSecurityProfileObservations(genericListers, recorder, existingConfig, []string{"servingInfo", "minTLSVersion"}, []string{"servingInfo", "cipherSuites"}, nil)
}

// ObserveTLSSecurityProfileWithPaths is like ObserveTLSSecurityProfile, but accepts
// custom paths for ServingInfo.MinTLSVersion and ServingInfo.CipherSuites fields of observed config.
func ObserveTLSSecurityProfileWithPaths(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}, minTLSVersionPath, cipherSuitesPath []string) (map[string]interface{}, []error) {
	return innerTLSSecurityProfileObservations(genericListers, recorder, existingConfig, minTLSVersionPath, cipherSuitesPath, nil)
}

// ObserveTLSSecurityProfileWithGroupPaths is like ObserveTLSSecurityProfileWithPaths but also
// observes the TLS group (curve) preferences at groupsPath. Group names are stored as []string
// matching the TLSGroup constants from openshift/api and can be passed directly to operands
// that accept group names as CLI arguments.
func ObserveTLSSecurityProfileWithGroupPaths(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}, minTLSVersionPath, cipherSuitesPath, groupsPath []string) (map[string]interface{}, []error) {
	return innerTLSSecurityProfileObservations(genericListers, recorder, existingConfig, minTLSVersionPath, cipherSuitesPath, groupsPath)
}

// ObserveTLSSecurityProfileToArguments observes APIServer.Spec.TLSSecurityProfile field and sets
// the tls-min-version and tls-cipher-suites fileds of observedConfig.apiServerArguments
func ObserveTLSSecurityProfileToArguments(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerTLSSecurityProfileObservations(genericListers, recorder, existingConfig, []string{"apiServerArguments", "tls-min-version"}, []string{"apiServerArguments", "tls-cipher-suites"}, nil)
}

// innerTLSSecurityProfileObservations is the shared implementation for all Observe* functions.
// When groupsPath is non-nil, TLS group preferences are also observed and stored at that path.
func innerTLSSecurityProfileObservations(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}, minTLSVersionPath, cipherSuitesPath, groupsPath []string) (ret map[string]interface{}, _ []error) {
	defer func() {
		if len(groupsPath) > 0 {
			ret = configobserver.Pruned(ret, minTLSVersionPath, cipherSuitesPath, groupsPath)
		} else {
			ret = configobserver.Pruned(ret, minTLSVersionPath, cipherSuitesPath)
		}
	}()

	listers := genericListers.(APIServerLister)
	errs := []error{}

	currentMinTLSVersion, _, versionErr := unstructured.NestedString(existingConfig, minTLSVersionPath...)
	if versionErr != nil {
		errs = append(errs, fmt.Errorf("failed to retrieve spec.servingInfo.minTLSVersion: %v", versionErr))
		// keep going on read error from existing config
	}

	currentCipherSuites, _, suitesErr := unstructured.NestedStringSlice(existingConfig, cipherSuitesPath...)
	if suitesErr != nil {
		errs = append(errs, fmt.Errorf("failed to retrieve spec.servingInfo.cipherSuites: %v", suitesErr))
		// keep going on read error from existing config
	}

	var currentGroups []string
	if len(groupsPath) > 0 {
		var groupsErr error
		currentGroups, _, groupsErr = unstructured.NestedStringSlice(existingConfig, groupsPath...)
		if groupsErr != nil {
			errs = append(errs, fmt.Errorf("failed to retrieve groups: %v", groupsErr))
		}
	}

	apiServer, err := listers.APIServerLister().Get("cluster")
	if errors.IsNotFound(err) {
		klog.Warningf("apiserver.config.openshift.io/cluster: not found")
		apiServer = &configv1.APIServer{}
	} else if err != nil {
		return existingConfig, append(errs, err)
	}

	observedConfig := map[string]interface{}{}
	observedMinTLSVersion, observedCipherSuites := getSecurityProfileCiphers(apiServer.Spec.TLSSecurityProfile)
	if err = unstructured.SetNestedField(observedConfig, observedMinTLSVersion, minTLSVersionPath...); err != nil {
		return existingConfig, append(errs, err)
	}
	if err = unstructured.SetNestedStringSlice(observedConfig, observedCipherSuites, cipherSuitesPath...); err != nil {
		return existingConfig, append(errs, err)
	}

	if observedMinTLSVersion != currentMinTLSVersion {
		recorder.Eventf("ObserveTLSSecurityProfile", "minTLSVersion changed to %s", observedMinTLSVersion)
	}
	if !reflect.DeepEqual(observedCipherSuites, currentCipherSuites) {
		recorder.Eventf("ObserveTLSSecurityProfile", "cipherSuites changed to %q", observedCipherSuites)
	}

	if len(groupsPath) > 0 {
		observedGroups, groupsAugmented := getSecurityProfileGroups(apiServer.Spec.TLSSecurityProfile)
		// Only store the groups path when we actually have groups to set.
		//
		// An empty list must be treated as "no opinion". The openshift/api
		// contract states that an omitted groups field lets the platform choose
		// reasonable defaults, whereas persisting an explicit empty [] can be
		// misread by an operand as "no curves permitted" — which fails every TLS
		// handshake. So when filtering leaves us with nothing (e.g. a custom
		// profile with only non-FIPS groups on a FIPS cluster), we leave the path
		// unset and let the operand fall back to its own defaults.
		if len(observedGroups) > 0 {
			if err = unstructured.SetNestedStringSlice(observedConfig, observedGroups, groupsPath...); err != nil {
				return existingConfig, append(errs, err)
			}
		}
		// Emit events only on a meaningful change, gated identically for the
		// change notice and the augmentation warning so both fire on transitions
		// rather than on every resync. On the first reconcile currentGroups is nil
		// (the path does not exist yet) while observedGroups is a non-nil empty
		// slice; groupsEqual collapses that nil-vs-empty distinction so a fresh
		// cluster with no groups does not look like a change.
		groupsChanged := !groupsEqual(observedGroups, currentGroups)
		if groupsChanged {
			recorder.Eventf("ObserveTLSSecurityProfile", "groups changed to %q", observedGroups)
		}
		// A custom profile whose groups are all TLS 1.3-only (ML-KEM hybrids)
		// while minTLSVersion still permits TLS 1.2 would silently break 1.2
		// handshakes. getSecurityProfileGroups appends a classical fallback in
		// that case; surface it as a warning so the admin knows their profile was
		// augmented rather than honored verbatim. Only warn on a change, otherwise
		// every reconcile of a steady-state augmented profile would spam warnings.
		if groupsAugmented && groupsChanged {
			recorder.Warningf("ObserveTLSSecurityProfile",
				"TLS profile groups were all TLS 1.3-only but minTLSVersion permits TLS 1.2; "+
					"appended classical fallback groups so TLS 1.2 handshakes can complete: %q", observedGroups)
		}
	}

	return observedConfig, errs
}

// groupsEqual compares two TLS group-name slices treating nil and empty as
// equal. This prevents a first reconcile (currentGroups nil) against an empty
// observation from being mistaken for a change.
func groupsEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// resolveProfileSpec returns the effective TLSProfileSpec for a
// TLSSecurityProfile. Named profiles (Old/Intermediate/Modern) resolve from the
// well-known openshift/api table; a Custom profile uses its inline spec. When
// the profile is nil (e.g. APIServer/cluster not found) or is Custom-typed
// without an actual custom spec, it falls back to the Intermediate default.
//
// This was previously duplicated verbatim in getSecurityProfileCiphers and
// getSecurityProfileGroups; it is factored out so the two observers cannot drift.
func resolveProfileSpec(profile *configv1.TLSSecurityProfile) *configv1.TLSProfileSpec {
	profileType := crypto.DefaultTLSProfileType
	if profile != nil {
		profileType = profile.Type
	}

	var profileSpec *configv1.TLSProfileSpec
	if profileType == configv1.TLSProfileCustomType {
		if profile.Custom != nil {
			profileSpec = &profile.Custom.TLSProfileSpec
		}
	} else {
		profileSpec = configv1.TLSProfiles[profileType]
	}

	// nothing found / custom type set but no actual custom spec / empty type
	if profileSpec == nil {
		profileSpec = configv1.TLSProfiles[crypto.DefaultTLSProfileType]
	}
	return profileSpec
}

// Extracts the minimum TLS version and cipher suites from TLSSecurityProfile object,
// Converts the ciphers to IANA names as supported by Kube ServingInfo config.
// If profile is nil (e.g. APIServer/cluster not found), returns the Intermediate TLS Profile defaults.
func getSecurityProfileCiphers(profile *configv1.TLSSecurityProfile) (string, []string) {
	profileSpec := resolveProfileSpec(profile)
	// need to remap all Ciphers to their respective IANA names used by Go
	return string(profileSpec.MinTLSVersion), crypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers)
}

// getSecurityProfileGroups returns the TLS group preference names for the given
// TLSSecurityProfile as []string. The strings match the TLSGroup constants from
// openshift/api and can be passed directly to operands that accept group names as
// CLI arguments. If profile is nil (e.g. APIServer/cluster not found), returns the
// Intermediate TLS Profile defaults. Groups not recognised by the current Go runtime
// or not FIPS-approved (when running in FIPS mode) are silently dropped — the
// dropping policy now lives in crypto.FilterTLSGroups so it stays next to the
// group-to-curve mapping and the FIPS allowlist it depends on.
//
// It also fails safe: if the remaining groups are all TLS 1.3-only but the
// profile's minTLSVersion permits TLS 1.2, a classical fallback is appended so
// TLS 1.2 handshakes can still complete (see crypto.EnsureHandshakeCapableGroups).
// The second return value reports whether that fallback was injected, so the
// caller can emit a warning.
func getSecurityProfileGroups(profile *configv1.TLSSecurityProfile) ([]string, bool) {
	profileSpec := resolveProfileSpec(profile)
	fips := crypto.IsFIPSEnabled()

	filtered := crypto.FilterTLSGroups(profileSpec.Groups, fips)
	// Resolve minTLSVersion defensively: the API validates it as an enum and the
	// named profiles are well-formed, but an observer must never panic on config
	// input, so fall back to the default rather than using TLSVersionOrDie.
	minVersion, err := crypto.TLSVersion(string(profileSpec.MinTLSVersion))
	if err != nil {
		klog.V(2).Infof("unexpected minTLSVersion %q, using default for fail-safe curve check: %v", profileSpec.MinTLSVersion, err)
		minVersion = crypto.DefaultTLSVersion()
	}
	safe, augmented := crypto.EnsureHandshakeCapableGroups(filtered, minVersion, fips)

	groups := make([]string, 0, len(safe))
	for _, g := range safe {
		groups = append(groups, string(g))
	}
	return groups, augmented
}
