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
		observedGroups := getSecurityProfileGroups(apiServer.Spec.TLSSecurityProfile)
		if err = unstructured.SetNestedStringSlice(observedConfig, observedGroups, groupsPath...); err != nil {
			return existingConfig, append(errs, err)
		}
		if !reflect.DeepEqual(observedGroups, currentGroups) {
			recorder.Eventf("ObserveTLSSecurityProfile", "groups changed to %q", observedGroups)
		}
	}

	return observedConfig, errs
}

// Extracts the minimum TLS version and cipher suites from TLSSecurityProfile object,
// Converts the ciphers to IANA names as supported by Kube ServingInfo config.
// If profile is nil (e.g. APIServer/cluster not found), returns the Intermediate TLS Profile defaults.
func getSecurityProfileCiphers(profile *configv1.TLSSecurityProfile) (string, []string) {
	var profileType configv1.TLSProfileType
	if profile == nil {
		profileType = crypto.DefaultTLSProfileType
	} else {
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

	// nothing found / custom type set but no actual custom spec
	if profileSpec == nil {
		profileSpec = configv1.TLSProfiles[crypto.DefaultTLSProfileType]
	}

	// need to remap all Ciphers to their respective IANA names used by Go
	return string(profileSpec.MinTLSVersion), crypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers)
}

// getSecurityProfileGroups returns the TLS group preference names for the given
// TLSSecurityProfile as []string. The strings match the TLSGroup constants from
// openshift/api and can be passed directly to operands that accept group names as
// CLI arguments. If profile is nil (e.g. APIServer/cluster not found), returns the
// Intermediate TLS Profile defaults. Groups not recognised by the current Go runtime
// or not FIPS-approved (when running in FIPS mode) are silently dropped.
func getSecurityProfileGroups(profile *configv1.TLSSecurityProfile) []string {
	var profileType configv1.TLSProfileType
	if profile == nil {
		profileType = crypto.DefaultTLSProfileType
	} else {
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

	if profileSpec == nil {
		profileSpec = configv1.TLSProfiles[crypto.DefaultTLSProfileType]
	}

	fips := crypto.IsFIPSEnabled()
	groups := make([]string, 0, len(profileSpec.Groups))
	for _, g := range profileSpec.Groups {
		if _, ok := crypto.TLSGroupToCurveID(g); !ok {
			klog.V(4).Infof("Dropping TLS group %q: not supported by Go's crypto/tls", g)
			continue
		}
		if fips && !crypto.IsFIPSApprovedTLSGroup(g) {
			klog.V(4).Infof("Dropping TLS group %q: not FIPS-approved", g)
			continue
		}
		groups = append(groups, string(g))
	}
	return groups
}
