// dynamic_loader_compatibility_test.go: Tests for Dynamic Loader Version Compatibility Logic
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"sync"
	"testing"
	"time"
)

// TestBlock3VersionCompatibilityLogic - Tests for Version Compatibility Logic functions
//
// Block 3 Functions Under Test:
// - validateVersionCompatibility: Complex version constraint matching
// - SetMinSystemVersion: System version requirements
// - SatisfiesConstraint: Advanced constraint logic
// - satisfiesCaretConstraint: Caret constraint (^x.y.z) algorithm
// - satisfiesTildeConstraint: Tilde constraint (~x.y.z) algorithm
//
// Focus Areas:
// - Semantic versioning compliance and edge cases
// - Complex constraint combinations and boundary conditions
// - Breaking change detection scenarios
// - System compatibility validation
// - Edge cases that could cause compatibility issues

// ==============================================
// CATEGORY 1: Core Constraint Satisfaction Logic
// ==============================================

func TestSatisfiesConstraint_BasicConstraintTypes(t *testing.T) {
	testCases := []struct {
		version    string
		constraint string
		expected   bool
		name       string
	}{
		// Wildcard constraint
		{"1.0.0", "*", true, "wildcard accepts any version"},
		{"999.999.999", "*", true, "wildcard accepts very high versions"},
		{"0.0.1", "*", true, "wildcard accepts very low versions"},
		{"1.2.3-beta.1+build.456", "*", true, "wildcard accepts complex versions"},

		// Exact version matching
		{"1.0.0", "1.0.0", true, "exact match positive"},
		{"1.0.1", "1.0.0", false, "exact match negative - patch differs"},
		{"1.1.0", "1.0.0", false, "exact match negative - minor differs"},
		{"2.0.0", "1.0.0", false, "exact match negative - major differs"},
		{"1.0.0-beta", "1.0.0", false, "exact match with prerelease difference"},

		// Caret constraints (^x.y.z)
		{"1.0.0", "^1.0.0", true, "caret - exact match"},
		{"1.0.1", "^1.0.0", true, "caret - patch increment"},
		{"1.1.0", "^1.0.0", true, "caret - minor increment"},
		{"1.9.9", "^1.0.0", true, "caret - high minor/patch"},
		{"2.0.0", "^1.0.0", false, "caret - major increment rejected"},
		{"0.9.9", "^1.0.0", false, "caret - lower version rejected"},

		// Tilde constraints (~x.y.z)
		{"1.2.0", "~1.2.0", true, "tilde - exact match"},
		{"1.2.1", "~1.2.0", true, "tilde - patch increment"},
		{"1.2.99", "~1.2.0", true, "tilde - high patch"},
		{"1.3.0", "~1.2.0", false, "tilde - minor increment rejected"},
		{"1.1.9", "~1.2.0", false, "tilde - lower minor rejected"},
		{"2.2.0", "~1.2.0", false, "tilde - major increment rejected"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := ParsePluginVersion(tc.version)
			if err != nil {
				t.Fatalf("Failed to parse version %s: %v", tc.version, err)
			}

			result := version.SatisfiesConstraint(tc.constraint)
			if result != tc.expected {
				t.Errorf("Version %s constraint %s: expected %v, got %v",
					tc.version, tc.constraint, tc.expected, result)
			}
		})
	}
}

func TestSatisfiesConstraint_EdgeCasesAndBugs(t *testing.T) {
	testCases := []struct {
		version    string
		constraint string
		expected   bool
		name       string
		bug        string
	}{
		// BUG POTENTIAL: Invalid constraint handling
		{"1.0.0", "", false, "empty constraint", "Empty constraints should be rejected"},
		{"1.0.0", "invalid", false, "malformed constraint", "Invalid constraints should be rejected"},
		{"1.0.0", "^", false, "incomplete caret constraint", "Incomplete constraints should be rejected"},
		{"1.0.0", "~", false, "incomplete tilde constraint", "Incomplete constraints should be rejected"},
		{"1.0.0", "^invalid", false, "caret with invalid version", "Should handle malformed caret targets"},
		{"1.0.0", "~invalid", false, "tilde with invalid version", "Should handle malformed tilde targets"},

		// BUG POTENTIAL: Zero version edge cases
		{"0.0.0", "^0.0.0", true, "caret with zero version", "Zero versions should work with caret"},
		{"0.0.1", "^0.0.0", true, "caret patch increment from zero", "Patch increments from zero"},
		{"0.1.0", "^0.0.0", true, "caret minor increment from zero", "Minor increments from zero"},
		{"1.0.0", "^0.0.0", false, "caret major increment from zero", "Major increments should be rejected"},

		{"0.1.0", "~0.1.0", true, "tilde with zero major", "Tilde should work with zero major"},
		{"0.1.1", "~0.1.0", true, "tilde patch increment with zero major", "Zero major tilde patches"},
		{"0.2.0", "~0.1.0", false, "tilde minor increment with zero major", "Zero major minor rejected"},

		// BUG POTENTIAL: Boundary conditions
		{"1.0.0", "^1.0.0", true, "caret boundary - exact lower bound", "Lower boundary inclusion"},
		{"1.0.0", "~1.0.0", true, "tilde boundary - exact lower bound", "Lower boundary inclusion"},
		{"4294967295.4294967295.4294967295", "^1.0.0", false, "max uint64 version caret", "Very large versions"},

		// BUG POTENTIAL: Prerelease version handling
		{"1.0.0-alpha", "^1.0.0", false, "caret prerelease vs stable", "Prerelease constraint behavior unclear"},
		{"1.0.1-alpha", "^1.0.0", true, "caret prerelease higher patch", "Prerelease with higher numbers"},
		{"1.0.0-alpha", "~1.0.0", false, "tilde prerelease vs stable", "Tilde prerelease handling"},

		// BUG POTENTIAL: Case sensitivity and whitespace
		{"1.0.0", " ^1.0.0", false, "constraint with leading space", "Whitespace should not be ignored"},
		{"1.0.0", "^1.0.0 ", false, "constraint with trailing space", "Trailing whitespace handling"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := ParsePluginVersion(tc.version)
			if err != nil {
				t.Fatalf("Failed to parse version %s: %v", tc.version, err)
			}

			result := version.SatisfiesConstraint(tc.constraint)
			if result != tc.expected {
				t.Errorf("BUG FOUND (%s): Version %s constraint %s: expected %v, got %v",
					tc.bug, tc.version, tc.constraint, tc.expected, result)
			}
		})
	}
}

// ==============================================
// CATEGORY 2: System Version Compatibility Testing
// ==============================================

func TestSetMinSystemVersion_BasicFunctionality(t *testing.T) {
	manager := createTestManagerForCompatibility(t)
	loader := manager.dynamicLoader

	testCases := []struct {
		version string
		valid   bool
		name    string
	}{
		{"1.0.0", true, "basic valid version"},
		{"2.5.10", true, "higher version"},
		{"0.1.0", true, "zero major version"},
		{"10.0.0-beta.1", true, "prerelease version"},
		{"1.0.0+build.123", true, "version with build metadata"},

		// Invalid versions
		{"", false, "empty version"},
		{"invalid", false, "non-semver version"},
		{"1.0", false, "incomplete version"},
		{"1.0.0.0", false, "too many parts"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := loader.SetMinSystemVersion(tc.version)

			if tc.valid && err != nil {
				t.Errorf("Expected valid version %s to succeed, got error: %v", tc.version, err)
			}

			if !tc.valid && err == nil {
				t.Errorf("Expected invalid version %s to fail, but succeeded", tc.version)
			}
		})
	}
}

func TestValidateVersionCompatibility_SystemVersionChecking(t *testing.T) {
	manager := createTestManagerForCompatibility(t)
	loader := manager.dynamicLoader

	// Set system version
	err := loader.SetMinSystemVersion("2.0.0")
	if err != nil {
		t.Fatalf("Failed to set min system version: %v", err)
	}

	testCases := []struct {
		pluginVersion  string
		pluginMinGoVer string
		shouldAccept   bool
		name           string
	}{
		// Valid cases
		{"1.0.0", "1.5.0", true, "plugin requires lower than system version"},
		{"1.0.0", "2.0.0", true, "plugin requires exactly system version"},
		{"1.0.0", "", true, "plugin has no minimum version requirement"},

		// Invalid cases
		{"1.0.0", "2.1.0", false, "plugin requires higher than system version"},
		{"1.0.0", "3.0.0", false, "plugin requires much higher version"},
		{"1.0.0", "2.0.1", false, "plugin requires patch higher than system"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := &PluginManifest{
				Name:      "test-plugin",
				Version:   tc.pluginVersion,
				Transport: TransportGRPC,
				Endpoint:  "localhost:50051",
			}

			if tc.pluginMinGoVer != "" {
				manifest.Requirements = &PluginRequirements{
					MinGoVersion: tc.pluginMinGoVer,
				}
			}

			err := loader.validateVersionCompatibility(manifest)

			if tc.shouldAccept && err != nil {
				t.Errorf("Expected plugin with version %s (min: %s) to be accepted, got error: %v",
					tc.pluginVersion, tc.pluginMinGoVer, err)
			}

			if !tc.shouldAccept && err == nil {
				t.Errorf("Expected plugin with version %s (min: %s) to be rejected, but was accepted",
					tc.pluginVersion, tc.pluginMinGoVer)
			}
		})
	}
}

// ==============================================
// CATEGORY 3: Complex Constraint Algorithm Testing
// ==============================================

func TestCaretConstraintAlgorithm_EdgeCases(t *testing.T) {
	testCases := []struct {
		version    string
		constraint string
		expected   bool
		name       string
		algorithm  string
	}{
		// Basic caret algorithm verification
		{"1.0.0", "^1.0.0", true, "exact match", "major==target.major && (minor>target.minor || (minor==target.minor && patch>=target.patch))"},
		{"1.0.1", "^1.0.0", true, "patch increment", "patch increment allowed"},
		{"1.1.0", "^1.0.0", true, "minor increment", "minor increment allowed"},
		{"1.1.1", "^1.0.0", true, "minor and patch increment", "both increments allowed"},

		// Major version boundary
		{"2.0.0", "^1.0.0", false, "major boundary violation", "major version must match exactly"},
		{"0.9.9", "^1.0.0", false, "lower major rejected", "lower major versions rejected"},

		// Zero version edge cases
		{"0.0.0", "^0.0.0", true, "zero version exact", "zero version handling"},
		{"0.0.1", "^0.0.0", true, "zero major patch increment", "zero major allows patches"},
		{"0.1.0", "^0.0.0", true, "zero major minor increment", "zero major allows minor"},
		{"1.0.0", "^0.0.0", false, "zero major boundary", "major must match"},

		// High number edge cases
		{"999.1000.2000", "^999.0.0", true, "very high numbers", "algorithm works with large numbers"},
		{"999.0.0", "^999.1000.2000", false, "lower than high constraint", "lower versions rejected"},

		// Algorithm boundary testing
		{"1.0.0", "^1.0.1", false, "patch version too low", "patch must be >= target.patch"},
		{"1.1.0", "^1.2.0", false, "minor version too low", "minor must be >= target.minor"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := ParsePluginVersion(tc.version)
			if err != nil {
				t.Fatalf("Failed to parse version %s: %v", tc.version, err)
			}

			result := version.satisfiesCaretConstraint(tc.constraint)
			if result != tc.expected {
				t.Errorf("ALGORITHM BUG in caret constraint: Version %s constraint %s: expected %v, got %v. Algorithm: %s",
					tc.version, tc.constraint, tc.expected, result, tc.algorithm)
			}
		})
	}
}

func TestTildeConstraintAlgorithm_EdgeCases(t *testing.T) {
	testCases := []struct {
		version    string
		constraint string
		expected   bool
		name       string
		algorithm  string
	}{
		// Basic tilde algorithm verification
		{"1.2.0", "~1.2.0", true, "exact match", "major==target.major && minor==target.minor && patch>=target.patch"},
		{"1.2.1", "~1.2.0", true, "patch increment", "patch increment allowed"},
		{"1.2.99", "~1.2.0", true, "high patch increment", "high patches allowed"},

		// Minor version boundary
		{"1.3.0", "~1.2.0", false, "minor boundary violation", "minor version must match exactly"},
		{"1.1.99", "~1.2.0", false, "lower minor rejected", "lower minor versions rejected"},

		// Major version boundary
		{"2.2.0", "~1.2.0", false, "major boundary violation", "major version must match exactly"},
		{"0.2.0", "~1.2.0", false, "lower major rejected", "lower major versions rejected"},

		// Zero version edge cases
		{"0.0.0", "~0.0.0", true, "zero version exact", "zero version handling"},
		{"0.0.1", "~0.0.0", true, "zero version patch increment", "zero version patches allowed"},
		{"0.1.0", "~0.0.0", false, "zero version minor change", "minor must match"},

		// Algorithm boundary testing
		{"1.2.0", "~1.2.1", false, "patch version too low", "patch must be >= target.patch"},
		{"1.2.5", "~1.2.10", false, "patch significantly too low", "patch boundary testing"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := ParsePluginVersion(tc.version)
			if err != nil {
				t.Fatalf("Failed to parse version %s: %v", tc.version, err)
			}

			result := version.satisfiesTildeConstraint(tc.constraint)
			if result != tc.expected {
				t.Errorf("ALGORITHM BUG in tilde constraint: Version %s constraint %s: expected %v, got %v. Algorithm: %s",
					tc.version, tc.constraint, tc.expected, result, tc.algorithm)
			}
		})
	}
}

// ==============================================
// CATEGORY 4: Integration and Complex Scenarios
// ==============================================

func TestVersionCompatibility_IntegrationWithConstraints(t *testing.T) {
	manager := createTestManagerForCompatibility(t)
	loader := manager.dynamicLoader

	// Set up constraints for different plugins
	loader.SetCompatibilityRule("auth-plugin", "^1.0.0")
	loader.SetCompatibilityRule("log-plugin", "~2.1.0")
	loader.SetCompatibilityRule("critical-plugin", "1.5.3")
	loader.SetCompatibilityRule("dev-plugin", "*")

	testCases := []struct {
		pluginName    string
		pluginVersion string
		shouldAccept  bool
		name          string
	}{
		// auth-plugin with caret constraint ^1.0.0
		{"auth-plugin", "1.0.0", true, "auth exact match"},
		{"auth-plugin", "1.5.2", true, "auth compatible higher"},
		{"auth-plugin", "2.0.0", false, "auth major version jump"},
		{"auth-plugin", "0.9.0", false, "auth lower version"},

		// log-plugin with tilde constraint ~2.1.0
		{"log-plugin", "2.1.0", true, "log exact match"},
		{"log-plugin", "2.1.5", true, "log patch increment"},
		{"log-plugin", "2.2.0", false, "log minor increment"},
		{"log-plugin", "2.0.9", false, "log lower minor"},

		// critical-plugin with exact version
		{"critical-plugin", "1.5.3", true, "critical exact match"},
		{"critical-plugin", "1.5.4", false, "critical patch difference"},
		{"critical-plugin", "1.6.3", false, "critical minor difference"},

		// dev-plugin with wildcard
		{"dev-plugin", "0.0.1", true, "dev any version"},
		{"dev-plugin", "999.0.0", true, "dev very high version"},

		// Plugin without constraint (should accept any)
		{"new-plugin", "1.0.0", true, "no constraint accepts all"},
		{"new-plugin", "invalid-version", false, "but version must be valid"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := &PluginManifest{
				Name:      tc.pluginName,
				Version:   tc.pluginVersion,
				Transport: TransportGRPC,
				Endpoint:  "localhost:50051",
			}

			err := loader.validateVersionCompatibility(manifest)

			if tc.shouldAccept && err != nil {
				t.Errorf("Expected plugin %s version %s to be accepted, got error: %v",
					tc.pluginName, tc.pluginVersion, err)
			}

			if !tc.shouldAccept && err == nil {
				t.Errorf("Expected plugin %s version %s to be rejected, but was accepted",
					tc.pluginName, tc.pluginVersion)
			}
		})
	}
}

func TestVersionCompatibility_ComplexScenarios(t *testing.T) {
	manager := createTestManagerForCompatibility(t)
	loader := manager.dynamicLoader

	// Set both system version and plugin constraints
	err := loader.SetMinSystemVersion("2.0.0")
	if err != nil {
		t.Fatalf("Failed to set min system version: %v", err)
	}

	loader.SetCompatibilityRule("restricted-plugin", "^1.5.0")

	// Test complex interaction between system version and plugin constraints
	manifest := &PluginManifest{
		Name:      "restricted-plugin",
		Version:   "1.8.0", // Satisfies ^1.5.0 constraint
		Transport: TransportGRPC,
		Endpoint:  "localhost:50051",
		Requirements: &PluginRequirements{
			MinGoVersion: "2.5.0", // Higher than system version (2.0.0) - should fail
		},
	}

	err = loader.validateVersionCompatibility(manifest)
	if err == nil {
		t.Error("Expected validation to fail due to system version requirement, but it passed")
	}

	// Test successful case
	manifest.Requirements.MinGoVersion = "1.8.0" // Lower than system version
	err = loader.validateVersionCompatibility(manifest)
	if err != nil {
		t.Errorf("Expected validation to pass with compatible versions, got error: %v", err)
	}
}

// ==============================================
// CATEGORY 5: Concurrency and Performance Testing
// ==============================================

func TestVersionCompatibility_ConcurrencyStress(t *testing.T) {
	manager := createTestManagerForCompatibility(t)
	loader := manager.dynamicLoader

	// Set up various constraints
	constraints := map[string]string{
		"plugin-1": "^1.0.0",
		"plugin-2": "~2.0.0",
		"plugin-3": "3.0.0",
		"plugin-4": "*",
	}

	for name, constraint := range constraints {
		loader.SetCompatibilityRule(name, constraint)
	}

	err := loader.SetMinSystemVersion("2.0.0")
	if err != nil {
		t.Fatalf("Failed to set system version: %v", err)
	}

	// Test concurrent validation
	const numGoroutines = 20
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	errorChan := make(chan error, numGoroutines*operationsPerGoroutine)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				// Test different types of operations concurrently
				switch j % 4 {
				case 0: // Test constraint satisfaction
					version, err := ParsePluginVersion("1.5.0")
					if err != nil {
						errorChan <- err
						continue
					}
					version.SatisfiesConstraint("^1.0.0")

				case 1: // Test caret constraint
					version, err := ParsePluginVersion("2.3.1")
					if err != nil {
						errorChan <- err
						continue
					}
					version.satisfiesCaretConstraint("^2.0.0")

				case 2: // Test tilde constraint
					version, err := ParsePluginVersion("3.1.5")
					if err != nil {
						errorChan <- err
						continue
					}
					version.satisfiesTildeConstraint("~3.1.0")

				case 3: // Test version compatibility validation
					manifest := &PluginManifest{
						Name:      "concurrent-plugin",
						Version:   "1.0.0",
						Transport: TransportGRPC,
						Endpoint:  "localhost:50051",
						Requirements: &PluginRequirements{
							MinGoVersion: "1.8.0",
						},
					}

					if err := loader.validateVersionCompatibility(manifest); err != nil {
						t.Logf("Version validation failed for test %d: %v", i, err)
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorChan)

	// Check for errors
	for err := range errorChan {
		t.Errorf("Concurrency test error: %v", err)
	}
}

func TestVersionCompatibility_PerformanceBenchmark(t *testing.T) {
	manager := createTestManagerForCompatibility(t)
	loader := manager.dynamicLoader

	// Set up many constraints to test performance
	for i := 0; i < 1000; i++ {
		pluginName := "plugin-" + string(rune(i))
		constraint := "^1.0.0"
		loader.SetCompatibilityRule(pluginName, constraint)
	}

	err := loader.SetMinSystemVersion("1.0.0")
	if err != nil {
		t.Fatalf("Failed to set system version: %v", err)
	}

	// Performance test: validate many plugins quickly
	start := time.Now()

	for i := 0; i < 1000; i++ {
		manifest := &PluginManifest{
			Name:      "plugin-" + string(rune(i)),
			Version:   "1.5.0",
			Transport: TransportGRPC,
			Endpoint:  "localhost:50051",
		}

		if err := loader.validateVersionCompatibility(manifest); err != nil {
			t.Logf("Version validation failed: %v", err)
		}
	}

	elapsed := time.Since(start)

	// Should validate 1000 plugins in reasonable time (< 100ms)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Performance test too slow: took %v to validate 1000 plugins", elapsed)
	}

	t.Logf("Performance: Validated 1000 plugins in %v", elapsed)
}

// ==============================================
// Helper Functions
// ==============================================

func createTestManagerForCompatibility(_ *testing.T) *Manager[TestRequest, TestResponse] {
	logger := NewTestLogger()

	manager := NewManager[TestRequest, TestResponse](logger)

	return manager
}
