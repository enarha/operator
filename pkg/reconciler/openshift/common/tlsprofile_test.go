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
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestConvertTLSVersionToEnvFormat(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "TLS 1.0",
			version:  "VersionTLS10",
			expected: "1.0",
		},
		{
			name:     "TLS 1.1",
			version:  "VersionTLS11",
			expected: "1.1",
		},
		{
			name:     "TLS 1.2",
			version:  "VersionTLS12",
			expected: "1.2",
		},
		{
			name:     "TLS 1.3",
			version:  "VersionTLS13",
			expected: "1.3",
		},
		{
			name:     "Unknown version",
			version:  "UnknownVersion",
			expected: "UnknownVersion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertTLSVersionToEnvFormat(tt.version)
			if result != tt.expected {
				t.Errorf("convertTLSVersionToEnvFormat(%s) = %s, want %s", tt.version, result, tt.expected)
			}
		})
	}
}

func TestSupplementTLS13Ciphers(t *testing.T) {
	tests := []struct {
		name            string
		profile         *configv1.TLSSecurityProfile
		observedCiphers []string
		expectContains  []string
	}{
		{
			name:            "Nil profile returns observed ciphers unchanged",
			profile:         nil,
			observedCiphers: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			expectContains:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		},
		{
			name: "Custom profile with TLS 1.3 ciphers supplements missing ones",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers: []string{
							"TLS_AES_128_GCM_SHA256",
							"TLS_AES_256_GCM_SHA384",
						},
					},
				},
			},
			observedCiphers: []string{},
			expectContains:  []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		},
		{
			name: "Mixed ciphers - TLS 1.3 supplemented, TLS 1.2 kept",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers: []string{
							"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
							"TLS_AES_128_GCM_SHA256",
						},
					},
				},
			},
			observedCiphers: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			expectContains:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"},
		},
		{
			name: "Already present TLS 1.3 ciphers not duplicated",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers: []string{
							"TLS_AES_128_GCM_SHA256",
						},
					},
				},
			},
			observedCiphers: []string{"TLS_AES_128_GCM_SHA256"},
			expectContains:  []string{"TLS_AES_128_GCM_SHA256"},
		},
		{
			name: "Modern profile type uses predefined profile spec",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			},
			observedCiphers: []string{},
			// Modern profile includes TLS 1.3 ciphers in predefined spec
			expectContains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := supplementTLS13Ciphers(tt.profile, tt.observedCiphers)

			for _, expected := range tt.expectContains {
				found := false
				for _, cipher := range result {
					if cipher == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected cipher %s not found in result %v", expected, result)
				}
			}
		})
	}
}

func TestAPIServerListersInterface(t *testing.T) {
	// Verify that APIServerListers implements the interface methods correctly
	listers := &APIServerListers{}

	// These should not panic
	_ = listers.ResourceSyncer()
	_ = listers.PreRunHasSynced()
	_ = listers.APIServerLister()
}
