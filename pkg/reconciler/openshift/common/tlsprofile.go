/*
Copyright 2024 The Tekton Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"
	"strings"
	"sync"

	configv1 "github.com/openshift/api/config/v1"
	openshiftconfigclient "github.com/openshift/client-go/config/clientset/versioned"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"knative.dev/pkg/logging"
)

const (
	// TLS environment variable names used by Tekton components
	TLSMinVersionEnvVar       = "TLS_MIN_VERSION"
	TLSCipherSuitesEnvVar     = "TLS_CIPHER_SUITES"
	TLSCurvePreferencesEnvVar = "TLS_CURVE_PREFERENCES"
)

// TLSEnvVars holds TLS configuration as environment variable values
type TLSEnvVars struct {
	MinVersion       string
	CipherSuites     string
	CurvePreferences string
}

// APIServerListers implements the configobserver.Listers interface for accessing APIServer resources.
// This adapter enables using library-go's ObserveTLSSecurityProfile function with our informer setup.
type APIServerListers struct {
	lister configv1listers.APIServerLister
}

// APIServerLister returns the APIServer lister
func (a *APIServerListers) APIServerLister() configv1listers.APIServerLister {
	return a.lister
}

// ResourceSyncer is not used but required by the Listers interface
func (a *APIServerListers) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

// PreRunHasSynced returns nil (no pre-run sync needed)
func (a *APIServerListers) PreRunHasSynced() []cache.InformerSynced {
	return nil
}

// sharedAPIServerLister holds the singleton lister and client for APIServer resources.
// This is initialized once by the TektonConfig controller and shared across all components.
var (
	sharedAPIServerLister configv1listers.APIServerLister
	sharedConfigClient    openshiftconfigclient.Interface
	sharedListerMu        sync.RWMutex
)

// SetSharedAPIServerLister sets the shared APIServer lister and client.
// This should be called once during TektonConfig controller initialization.
func SetSharedAPIServerLister(lister configv1listers.APIServerLister, client openshiftconfigclient.Interface) {
	sharedListerMu.Lock()
	defer sharedListerMu.Unlock()
	sharedAPIServerLister = lister
	sharedConfigClient = client
}

// GetTLSEnvVarsFromAPIServer fetches the TLS security profile from the OpenShift APIServer
// resource and converts it to environment variable values that can be used by Tekton components.
// Returns nil if the APIServer has no TLS profile configured or if the shared lister is not initialized.
func GetTLSEnvVarsFromAPIServer(ctx context.Context, _ *rest.Config) (*TLSEnvVars, error) {
	logger := logging.FromContext(ctx)

	sharedListerMu.RLock()
	lister := sharedAPIServerLister
	client := sharedConfigClient
	sharedListerMu.RUnlock()

	if lister == nil {
		logger.Debug("Shared APIServer lister not initialized, TLS config not available")
		return nil, nil
	}

	// Create listers adapter for library-go
	listers := &APIServerListers{
		lister: lister,
	}

	// Use library-go's ObserveTLSSecurityProfile to extract TLS config.
	// Note: ObserveTLSSecurityProfile requires:
	// - non-nil recorder: it calls recorder.Eventf() to log changes
	// - non-nil existingConfig: it reads from it via unstructured.NestedString()
	// TODO: Once library-go is updated to a newer version (with TLS 1.3 cipher support),
	// the supplementTLS13Ciphers workaround below can be removed.
	existingConfig := map[string]interface{}{}
	recorder := events.NewLoggingEventRecorder("tekton-operator")
	observedConfig, errs := apiserver.ObserveTLSSecurityProfile(listers, recorder, existingConfig)
	if len(errs) > 0 {
		logger.Warnf("Errors observing TLS security profile: %v", errs)
	}

	// Extract servingInfo from observed config
	servingInfo, ok := observedConfig["servingInfo"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	// Extract minTLSVersion
	minVersion, _ := servingInfo["minTLSVersion"].(string)

	// Extract cipherSuites
	var cipherSuites []string
	if ciphers, ok := servingInfo["cipherSuites"].([]interface{}); ok {
		for _, c := range ciphers {
			if cs, ok := c.(string); ok {
				cipherSuites = append(cipherSuites, cs)
			}
		}
	}

	// If no TLS configuration is present, return nil
	if minVersion == "" && len(cipherSuites) == 0 {
		return nil, nil
	}

	// Supplement TLS 1.3 ciphers if needed
	// TODO: Remove this once library-go is updated with proper TLS 1.3 cipher mapping
	if client != nil {
		apiServer, err := lister.Get("cluster")
		if err == nil && apiServer.Spec.TLSSecurityProfile != nil {
			cipherSuites = supplementTLS13Ciphers(apiServer.Spec.TLSSecurityProfile, cipherSuites)
		}
	}

	return &TLSEnvVars{
		MinVersion:       convertTLSVersionToEnvFormat(minVersion),
		CipherSuites:     strings.Join(cipherSuites, ","),
		CurvePreferences: "", // Will be populated once openshift/api#2583 is merged
	}, nil
}

// convertTLSVersionToEnvFormat converts library-go TLS version format (VersionTLSxx) to
// the format expected by Go's crypto/tls (1.x)
func convertTLSVersionToEnvFormat(version string) string {
	switch version {
	case "VersionTLS10":
		return "1.0"
	case "VersionTLS11":
		return "1.1"
	case "VersionTLS12":
		return "1.2"
	case "VersionTLS13":
		return "1.3"
	default:
		return version
	}
}

// supplementTLS13Ciphers adds TLS 1.3 ciphers that the older library-go version doesn't map.
// TLS 1.3 ciphers are mandatory per RFC 8446 and are always enabled when TLS 1.3 is used,
// but we include them explicitly for completeness.
// TODO: Remove this function once library-go is updated to a version that properly maps TLS 1.3 ciphers.
func supplementTLS13Ciphers(profile *configv1.TLSSecurityProfile, observedCiphers []string) []string {
	if profile == nil {
		return observedCiphers
	}

	// Get the profile spec that defines the configured ciphers
	var profileSpec *configv1.TLSProfileSpec
	switch profile.Type {
	case configv1.TLSProfileCustomType:
		if profile.Custom != nil {
			profileSpec = &profile.Custom.TLSProfileSpec
		}
	case configv1.TLSProfileModernType:
		profileSpec = configv1.TLSProfiles[configv1.TLSProfileModernType]
	case configv1.TLSProfileIntermediateType:
		profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	case configv1.TLSProfileOldType:
		profileSpec = configv1.TLSProfiles[configv1.TLSProfileOldType]
	}

	if profileSpec == nil {
		return observedCiphers
	}

	// Build a set of already observed ciphers for quick lookup
	observedSet := make(map[string]bool)
	for _, c := range observedCiphers {
		observedSet[c] = true
	}

	// TLS 1.3 cipher suite names (IANA names)
	tls13Ciphers := map[string]bool{
		"TLS_AES_128_GCM_SHA256":       true,
		"TLS_AES_256_GCM_SHA384":       true,
		"TLS_CHACHA20_POLY1305_SHA256": true,
	}

	// Check configured ciphers for TLS 1.3 ciphers that library-go might have missed
	result := observedCiphers
	for _, cipher := range profileSpec.Ciphers {
		// If it's a TLS 1.3 cipher and not already in observed list, add it
		if tls13Ciphers[cipher] && !observedSet[cipher] {
			result = append(result, cipher)
		}
	}

	return result
}
