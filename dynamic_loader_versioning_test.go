// dynamic_loader_versioning_test.go: Comprehensive tests for dynamic loader version system
//
// Block 1: Core Version System Testing
// Tests ParsePluginVersion, Compare, SatisfiesConstraint functions with focus on:
// - Semantic versioning edge cases and malformed version strings
// - Version comparison logic bugs
// - Constraint matching vulnerabilities and edge cases
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"strings"
	"testing"
)

// TestDynamicLoader_VersionSystem_CoreFunctionality tests basic version parsing and comparison
func TestDynamicLoader_VersionSystem_CoreFunctionality(t *testing.T) {
	t.Run("ParseValidVersions_BasicFormats", func(t *testing.T) {
		testCases := []struct {
			name     string
			version  string
			expected PluginVersion
		}{
			{
				name:    "Basic_SemVer",
				version: "1.2.3",
				expected: PluginVersion{
					Major: 1, Minor: 2, Patch: 3,
					Original: "1.2.3",
				},
			},
			{
				name:    "With_Prerelease",
				version: "2.0.0-beta.1",
				expected: PluginVersion{
					Major: 2, Minor: 0, Patch: 0,
					Prerelease: "beta.1", Original: "2.0.0-beta.1",
				},
			},
			{
				name:    "With_Build_Metadata",
				version: "1.0.0+build.123",
				expected: PluginVersion{
					Major: 1, Minor: 0, Patch: 0,
					Build: "build.123", Original: "1.0.0+build.123",
				},
			},
			{
				name:    "Full_SemVer_Format",
				version: "3.1.4-alpha.2+exp.sha.5114f85",
				expected: PluginVersion{
					Major: 3, Minor: 1, Patch: 4,
					Prerelease: "alpha.2", Build: "exp.sha.5114f85",
					Original: "3.1.4-alpha.2+exp.sha.5114f85",
				},
			},
			{
				name:    "Zero_Version",
				version: "0.0.0",
				expected: PluginVersion{
					Major: 0, Minor: 0, Patch: 0,
					Original: "0.0.0",
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := ParsePluginVersion(tc.version)
				if err != nil {
					t.Fatalf("ParsePluginVersion failed for %s: %v", tc.version, err)
				}

				if result.Major != tc.expected.Major ||
					result.Minor != tc.expected.Minor ||
					result.Patch != tc.expected.Patch ||
					result.Prerelease != tc.expected.Prerelease ||
					result.Build != tc.expected.Build ||
					result.Original != tc.expected.Original {
					t.Errorf("ParsePluginVersion mismatch for %s\nExpected: %+v\nGot: %+v",
						tc.version, tc.expected, *result)
				}
			})
		}

		t.Logf("✅ Basic version parsing working correctly - tested %d formats", len(testCases))
	})

	t.Run("VersionComparison_LogicValidation", func(t *testing.T) {
		testCases := []struct {
			name     string
			version1 string
			version2 string
			expected int // -1, 0, 1
		}{
			{"Equal_Versions", "1.2.3", "1.2.3", 0},
			{"Major_Greater", "2.0.0", "1.9.9", 1},
			{"Major_Lesser", "1.0.0", "2.0.0", -1},
			{"Minor_Greater", "1.3.0", "1.2.9", 1},
			{"Minor_Lesser", "1.1.0", "1.2.0", -1},
			{"Patch_Greater", "1.2.4", "1.2.3", 1},
			{"Patch_Lesser", "1.2.2", "1.2.3", -1},

			// Prerelease comparison edge cases
			{"Release_vs_Prerelease", "1.0.0", "1.0.0-alpha", 1},
			{"Prerelease_vs_Release", "1.0.0-beta", "1.0.0", -1},
			{"Prerelease_Alphabetical", "1.0.0-alpha", "1.0.0-beta", -1},
			{"Prerelease_Equal", "1.0.0-alpha.1", "1.0.0-alpha.1", 0},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				v1, err := ParsePluginVersion(tc.version1)
				if err != nil {
					t.Fatalf("Failed to parse version1 %s: %v", tc.version1, err)
				}

				v2, err := ParsePluginVersion(tc.version2)
				if err != nil {
					t.Fatalf("Failed to parse version2 %s: %v", tc.version2, err)
				}

				result := v1.Compare(v2)
				if result != tc.expected {
					t.Errorf("Version comparison failed: %s vs %s\nExpected: %d, Got: %d",
						tc.version1, tc.version2, tc.expected, result)
				}
			})
		}

		t.Logf("✅ Version comparison logic working correctly - tested %d scenarios", len(testCases))
	})
}

// TestDynamicLoader_VersionSystem_EdgeCasesAndBugs tests malformed inputs and edge cases
func TestDynamicLoader_VersionSystem_EdgeCasesAndBugs(t *testing.T) {
	t.Run("MalformedVersions_ErrorHandling", func(t *testing.T) {
		malformedVersions := []struct {
			name    string
			version string
			reason  string
		}{
			{"Empty_String", "", "empty version string"},
			{"Single_Number", "1", "incomplete version"},
			{"Two_Numbers", "1.2", "missing patch version"},
			{"Invalid_Major", "a.2.3", "non-numeric major"},
			{"Invalid_Minor", "1.b.3", "non-numeric minor"},
			{"Invalid_Patch", "1.2.c", "non-numeric patch"},
			{"Negative_Major", "-1.2.3", "negative major version"},
			{"Float_Minor", "1.2.5.3", "too many components"},
			{"Special_Characters", "1.2@3", "invalid characters"},
			{"Leading_Zeros", "01.02.03", "leading zeros can cause issues"},
			{"Unicode_Characters", "1.2.３", "unicode numbers"},
			{"Very_Large_Numbers", "999999999999999999999.1.2", "overflow potential"},
			// Note: Mixed case prerelease and dashes in prerelease are actually valid per semver spec
			{"Invalid_Prerelease", "1.2.3-", "empty prerelease"},
			{"Invalid_Build", "1.2.3+", "empty build metadata"},
			{"Multiple_Builds", "1.2.3+build1+build2", "multiple build separators"},
		}

		var errorCount int
		for _, tc := range malformedVersions {
			t.Run(tc.name, func(t *testing.T) {
				result, err := ParsePluginVersion(tc.version)
				if err == nil {
					t.Errorf("Expected error for malformed version '%s' (%s), but got: %+v",
						tc.version, tc.reason, result)
				} else {
					errorCount++
					t.Logf("✅ Correctly rejected malformed version '%s': %v", tc.version, err)
				}
			})
		}

		if errorCount != len(malformedVersions) {
			t.Errorf("Some malformed versions were incorrectly accepted! Rejected: %d/%d",
				errorCount, len(malformedVersions))
		} else {
			t.Logf("✅ All %d malformed versions correctly rejected", errorCount)
		}
	})

	t.Run("ConstraintMatching_EdgeCases", func(t *testing.T) {
		testCases := []struct {
			name       string
			version    string
			constraint string
			expected   bool
			reason     string
		}{
			// Wildcard constraints
			{"Wildcard_Always_True", "1.2.3", "*", true, "wildcard should match any version"},
			{"Wildcard_Prerelease", "2.0.0-alpha", "*", true, "wildcard should match prerelease"},

			// Exact matching
			{"Exact_Match", "1.2.3", "1.2.3", true, "exact versions should match"},
			{"Exact_No_Match", "1.2.3", "1.2.4", false, "different versions should not match"},

			// Caret constraints (^x.y.z)
			{"Caret_Same_Version", "1.2.3", "^1.2.3", true, "same version satisfies caret"},
			{"Caret_Patch_Upgrade", "1.2.5", "^1.2.3", true, "patch upgrade satisfies caret"},
			{"Caret_Minor_Upgrade", "1.3.0", "^1.2.3", true, "minor upgrade satisfies caret"},
			{"Caret_Major_Upgrade", "2.0.0", "^1.2.3", false, "major upgrade violates caret"},
			{"Caret_Patch_Downgrade", "1.2.2", "^1.2.3", false, "patch downgrade violates caret"},
			{"Caret_Minor_Downgrade", "1.1.9", "^1.2.3", false, "minor downgrade violates caret"},

			// Tilde constraints (~x.y.z)
			{"Tilde_Same_Version", "1.2.3", "~1.2.3", true, "same version satisfies tilde"},
			{"Tilde_Patch_Upgrade", "1.2.5", "~1.2.3", true, "patch upgrade satisfies tilde"},
			{"Tilde_Minor_Upgrade", "1.3.0", "~1.2.3", false, "minor upgrade violates tilde"},
			{"Tilde_Patch_Downgrade", "1.2.2", "~1.2.3", false, "patch downgrade violates tilde"},

			// Edge cases and potential bugs
			{"Empty_Constraint", "1.2.3", "", false, "empty constraint should not match"},
			{"Invalid_Constraint", "1.2.3", "invalid", false, "invalid constraint should not match"},
			{"Caret_Without_Version", "1.2.3", "^", false, "caret without version should not match"},
			{"Tilde_Without_Version", "1.2.3", "~", false, "tilde without version should not match"},
			{"Malformed_Caret", "1.2.3", "^1.2", false, "malformed caret constraint should not match"},
			{"Malformed_Tilde", "1.2.3", "~1.2", false, "malformed tilde constraint should not match"},
		}

		var passCount int
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				version, err := ParsePluginVersion(tc.version)
				if err != nil {
					t.Fatalf("Failed to parse test version %s: %v", tc.version, err)
				}

				result := version.SatisfiesConstraint(tc.constraint)
				if result != tc.expected {
					t.Errorf("Constraint matching failed: version %s, constraint '%s'\nExpected: %t, Got: %t\nReason: %s",
						tc.version, tc.constraint, tc.expected, result, tc.reason)
				} else {
					passCount++
				}
			})
		}

		t.Logf("✅ Constraint matching working correctly - passed %d/%d test cases", passCount, len(testCases))
	})
}

// TestDynamicLoader_VersionSystem_SecurityAndPerformance tests security vulnerabilities and performance
func TestDynamicLoader_VersionSystem_SecurityAndPerformance(t *testing.T) {
	t.Run("SecurityVulnerabilities_InputValidation", func(t *testing.T) {
		// Test potential security issues with malicious version strings
		maliciousInputs := []struct {
			name  string
			input string
		}{
			{"SQL_Injection_Style", "1.2.3'; DROP TABLE versions; --"},
			{"Buffer_Overflow_Attempt", strings.Repeat("9", 1000)},
			{"Null_Bytes", "1.2.3\x00malicious"},
			{"Path_Traversal", "1.2.3/../../../etc/passwd"},
			{"Script_Injection", "1.2.3<script>alert('xss')</script>"},
			{"Command_Injection", "1.2.3`rm -rf /`"},
			{"Unicode_Normalization", "1.2.３"}, // Full-width 3
			{"Control_Characters", "1.2.3\r\n\t"},
			{"Very_Long_Prerelease", "1.2.3-" + strings.Repeat("a", 10000)},
			{"Very_Long_Build", "1.2.3+" + strings.Repeat("b", 10000)},
		}

		securityPassCount := 0
		for _, tc := range maliciousInputs {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ParsePluginVersion(tc.input)
				if err == nil {
					t.Errorf("⚠️  Security concern: malicious input '%s' was accepted", tc.name)
				} else {
					securityPassCount++
					t.Logf("✅ Security test passed: '%s' correctly rejected", tc.name)
				}
			})
		}

		if securityPassCount == len(maliciousInputs) {
			t.Logf("✅ All %d security tests passed - no malicious inputs accepted", securityPassCount)
		} else {
			t.Errorf("⚠️  Security concern: %d/%d malicious inputs were accepted",
				len(maliciousInputs)-securityPassCount, len(maliciousInputs))
		}
	})

	t.Run("PerformanceAndMemory_StressTest", func(t *testing.T) {
		// Test performance with various version formats
		testVersions := []string{
			"1.0.0",
			"99.99.99",
			"1.2.3-alpha.beta.gamma.delta.epsilon",
			"0.0.1-very.long.prerelease.identifier.with.many.dots+build.metadata.also.very.long",
			"1.0.0+20130313144700",
		}

		// Stress test parsing performance
		for i := 0; i < 1000; i++ {
			for _, version := range testVersions {
				_, err := ParsePluginVersion(version)
				if err != nil {
					t.Fatalf("Performance test failed on iteration %d with version %s: %v", i, version, err)
				}
			}
		}

		// Stress test comparison performance
		v1, err := ParsePluginVersion("1.2.3")
		if err != nil {
			t.Fatalf("Failed to parse version 1.2.3: %v", err)
		}
		v2, err := ParsePluginVersion("1.2.4")
		if err != nil {
			t.Fatalf("Failed to parse version 1.2.4: %v", err)
		}

		for i := 0; i < 10000; i++ {
			v1.Compare(v2)
			v1.SatisfiesConstraint("^1.0.0")
			v1.SatisfiesConstraint("~1.2.0")
		}

		t.Logf("✅ Performance stress test completed - no crashes or memory issues detected")
	})

	t.Run("ConcurrencyAndRaceConditions_SafetyTest", func(t *testing.T) {
		// Test concurrent version parsing to catch race conditions
		const numGoroutines = 100
		const operationsPerGoroutine = 100

		done := make(chan bool, numGoroutines)
		errors := make(chan error, numGoroutines*operationsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				defer func() { done <- true }()

				for j := 0; j < operationsPerGoroutine; j++ {
					// Test parsing different versions concurrently
					versions := []string{
						"1.0.0", "2.1.3", "0.9.1-beta", "3.0.0+build.1",
					}

					for _, version := range versions {
						v, err := ParsePluginVersion(version)
						if err != nil {
							errors <- err
							return
						}

						// Test concurrent comparison operations
						v2, err := ParsePluginVersion("1.0.0")
						if err != nil {
							errors <- err
							return
						}
						v.Compare(v2)
						v.SatisfiesConstraint("^1.0.0")
						v.SatisfiesConstraint("~1.0.0")
					}
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			<-done
		}

		// Check for errors
		close(errors)
		errorCount := 0
		for err := range errors {
			t.Errorf("Concurrency test error: %v", err)
			errorCount++
		}

		if errorCount == 0 {
			t.Logf("✅ Concurrency test passed - %d goroutines × %d operations completed safely",
				numGoroutines, operationsPerGoroutine)
		} else {
			t.Errorf("❌ Concurrency issues detected: %d errors found", errorCount)
		}
	})
}
