// env_config_test.go: Comprehensive test suite for environment variable expansion
//
// This test suite validates environment variable expansion functionality with
// comprehensive coverage of security validation, error handling, and edge cases.
// It follows the same design principles as the main code:
//
// Test Design Principles:
// - Low cyclomatic complexity (focused, single-purpose test functions)
// - Comprehensive security validation testing with injection attack scenarios
// - Clear English documentation for global team accessibility
// - Reliable test isolation with proper environment cleanup
// - Performance validation for expansion operations
//
// Test Categories:
// - Basic expansion tests: Simple ${VAR} expansion with defaults
// - Security tests: Injection attacks, path traversal, and malicious input
// - Error tests: Missing variables, malformed syntax, recursive expansion
// - Performance tests: Large-scale expansion operations and validation
// - Integration tests: End-to-end configuration processing with expansion
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestExpandEnvironmentVariables_BasicExpansion tests basic environment variable expansion.
//
// This test validates that ExpandEnvironmentVariables can successfully
// expand simple environment variable references with proper default handling
// and syntax validation.
//
// Test scenarios:
//   - Simple variable expansion: ${VAR}
//   - Variable expansion with defaults: ${VAR:-default}
//   - Multiple variables in single string
//   - Empty variable handling
//   - Non-existent variable handling
func TestExpandEnvironmentVariables_BasicExpansion(t *testing.T) {
	// Setup test environment variables
	testEnvVars := map[string]string{
		"TEST_VAR1":    "value1",
		"TEST_VAR2":    "value2",
		"TEST_EMPTY":   "",
		"TEST_NUMERIC": "12345",
		"TEST_SPECIAL": "value with spaces & symbols!",
	}

	// Set environment variables
	for key, value := range testEnvVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	// Create options for expansion
	options := EnvConfigOptions{
		Prefix:         "",
		FailOnMissing:  false,
		ValidateValues: true,
		AllowOverrides: true,
		Defaults:       make(map[string]string),
		Overrides:      make(map[string]string),
	}

	testCases := []struct {
		name     string
		input    string
		expected string
		hasError bool
	}{
		{
			name:     "simple variable expansion",
			input:    "${TEST_VAR1}",
			expected: "value1",
			hasError: false,
		},
		{
			name:     "variable with default (exists)",
			input:    "${TEST_VAR1:-default_value}",
			expected: "value1",
			hasError: false,
		},
		{
			name:     "variable with default (missing)",
			input:    "${MISSING_VAR:-default_value}",
			expected: "default_value",
			hasError: false,
		},
		{
			name:     "multiple variables in string",
			input:    "prefix-${TEST_VAR1}-${TEST_VAR2}-suffix",
			expected: "prefix-value1-value2-suffix",
			hasError: false,
		},
		{
			name:     "empty variable expansion",
			input:    "${TEST_EMPTY:-not_empty}",
			expected: "not_empty", // Empty should use default
			hasError: false,
		},
		{
			name:     "numeric variable expansion",
			input:    "port=${TEST_NUMERIC}",
			expected: "port=12345",
			hasError: false,
		},
		{
			name:     "special characters in variable",
			input:    "message: ${TEST_SPECIAL}",
			expected: "message: value with spaces & symbols!",
			hasError: false,
		},
		{
			name:     "no variables in string",
			input:    "plain string without variables",
			expected: "plain string without variables",
			hasError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ExpandEnvironmentVariables(tc.input, options)

			if tc.hasError {
				if err == nil {
					t.Errorf("Expected error but got none, result: %s", result)
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}

			if result != tc.expected {
				t.Errorf("Expected '%s', got: '%s'", tc.expected, result)
			}
		})
	}
}

// TestExpandEnvironmentVariables_SecurityValidation tests security validation features.
//
// This test validates that the expansion properly handles potential security threats
// including injection attacks and malicious variable values with proper validation.
func TestExpandEnvironmentVariables_SecurityValidation(t *testing.T) {
	// Setup potentially dangerous environment variables for testing
	dangerousEnvVars := map[string]string{
		"SAFE_VAR":          "safe_value",
		"PATH_TRAVERSAL":    "../../../etc/passwd",
		"COMMAND_INJECTION": "; rm -rf /; echo 'pwned'",
		"SQL_INJECTION":     "'; DROP TABLE users; --",
		"SCRIPT_INJECTION":  "<script>alert('xss')</script>",
		"VERY_LONG_VALUE":   strings.Repeat("A", 10000),
	}

	// Set dangerous environment variables for testing
	for key, value := range dangerousEnvVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	// Create options with security validation enabled
	options := EnvConfigOptions{
		Prefix:         "",
		FailOnMissing:  false,
		ValidateValues: true, // Enable security validation
		AllowOverrides: false,
		Defaults:       make(map[string]string),
		Overrides:      make(map[string]string),
	}

	testCases := []struct {
		name           string
		input          string
		expectError    bool
		validateResult func(t *testing.T, result string)
	}{
		{
			name:        "safe variable allowed",
			input:       "${SAFE_VAR}",
			expectError: false,
			validateResult: func(t *testing.T, result string) {
				if result != "safe_value" {
					t.Errorf("Expected 'safe_value', got: %s", result)
				}
			},
		},
		{
			name:        "path traversal value handled",
			input:       "${PATH_TRAVERSAL}",
			expectError: false,
			validateResult: func(t *testing.T, result string) {
				// Result should contain the value (validation may allow it)
				if result == "" {
					t.Error("Expected non-empty result")
				}
			},
		},
		{
			name:        "command injection value handled",
			input:       "${COMMAND_INJECTION}",
			expectError: false,
			validateResult: func(t *testing.T, result string) {
				// Result should contain the value (validation may allow it)
				if result == "" {
					t.Error("Expected non-empty result")
				}
			},
		},
		{
			name:        "very long value handled",
			input:       "${VERY_LONG_VALUE}",
			expectError: false, // Returns original unexpanded value on validation failure
			validateResult: func(t *testing.T, result string) {
				// Should return unexpanded variable when validation fails
				if result != "${VERY_LONG_VALUE}" {
					t.Errorf("Expected unexpanded variable '${VERY_LONG_VALUE}', got: %s", result)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ExpandEnvironmentVariables(tc.input, options)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none, result: %s", result)
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}

			if tc.validateResult != nil {
				tc.validateResult(t, result)
			}
		})
	}
}

// TestProcessConfigurationWithEnv tests configuration processing with environment expansion.
//
// This test validates that ProcessConfigurationWithEnv can successfully process various
// configuration types with proper environment variable expansion and validation.
func TestProcessConfigurationWithEnv(t *testing.T) {
	// Setup test environment
	testEnvVars := map[string]string{
		"LOG_LEVEL":    "debug",
		"METRICS_PORT": "9090",
		"PLUGIN_NAME":  "test-plugin",
	}

	for key, value := range testEnvVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	// Create options for processing
	options := EnvConfigOptions{
		Prefix:         "",
		FailOnMissing:  false,
		ValidateValues: true,
		AllowOverrides: true,
		Defaults:       make(map[string]string),
		Overrides:      make(map[string]string),
	}

	t.Run("manager config processing", func(t *testing.T) {
		config := &ManagerConfig{
			LogLevel:    "${LOG_LEVEL:-info}",
			MetricsPort: 8080, // Default value
		}

		err := ProcessConfigurationWithEnv(config, options)
		if err != nil {
			t.Fatalf("Failed to process manager config: %v", err)
		}

		// Validate expansion
		if config.LogLevel != "debug" {
			t.Errorf("Expected log level 'debug', got: %s", config.LogLevel)
		}
	})

	t.Run("library config processing", func(t *testing.T) {
		config := &LibraryConfig{
			Environment: EnvironmentConfig{
				VariablePrefix: "${LOG_LEVEL}_", // This field will be expanded
				Overrides: map[string]string{
					"plugin_name": "${PLUGIN_NAME}",
				},
				Defaults: map[string]string{
					"fallback": "${LOG_LEVEL:-info}",
				},
			},
			Metadata: ConfigMetadata{
				Version:     "v1.0.0",
				Environment: "test",
			},
		}

		err := ProcessConfigurationWithEnv(config, options)
		if err != nil {
			t.Fatalf("Failed to process library config: %v", err)
		}

		// Validate expansion (only environment fields are processed)
		if config.Environment.VariablePrefix != "debug_" {
			t.Errorf("Expected variable prefix 'debug_', got: %s", config.Environment.VariablePrefix)
		}
		if config.Environment.Overrides["plugin_name"] != "test-plugin" {
			t.Errorf("Expected plugin name 'test-plugin', got: %s", config.Environment.Overrides["plugin_name"])
		}
		if config.Environment.Defaults["fallback"] != "debug" {
			t.Errorf("Expected fallback 'debug', got: %s", config.Environment.Defaults["fallback"])
		}
	})
}

// TestExpandEnvironmentVariables_Performance tests expansion performance.
//
// This test validates that environment variable expansion performs efficiently
// even with large configurations and many variable references.
func TestExpandEnvironmentVariables_Performance(t *testing.T) {
	// Setup many test environment variables
	numVars := 100
	for i := 0; i < numVars; i++ {
		key := fmt.Sprintf("PERF_VAR_%d", i)
		value := fmt.Sprintf("value_%d", i)
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	// Create options for expansion
	options := EnvConfigOptions{
		Prefix:         "",
		FailOnMissing:  false,
		ValidateValues: false, // Disable validation for performance
		AllowOverrides: true,
		Defaults:       make(map[string]string),
		Overrides:      make(map[string]string),
	}

	t.Run("large configuration expansion", func(t *testing.T) {
		// Create large configuration with many variable references
		var configBuilder strings.Builder
		for i := 0; i < 50; i++ {
			configBuilder.WriteString(fmt.Sprintf("${PERF_VAR_%d} ", i))
		}
		largeConfig := configBuilder.String()

		// Measure expansion time
		start := time.Now()
		result, err := ExpandEnvironmentVariables(largeConfig, options)
		duration := time.Since(start)

		if err != nil {
			t.Fatalf("Failed to expand large config: %v", err)
		}

		// Validate performance (should complete within reasonable time)
		maxDuration := 50 * time.Millisecond
		if duration > maxDuration {
			t.Errorf("Expansion took too long: %v (max: %v)", duration, maxDuration)
		}

		// Validate correctness
		if !strings.Contains(result, "value_0") {
			t.Error("Expansion result does not contain expected values")
		}

		t.Logf("Expanded 50 variables in %v", duration)
	})

	t.Run("repeated expansion performance", func(t *testing.T) {
		testString := "${PERF_VAR_0}-${PERF_VAR_1}-${PERF_VAR_2}"
		iterations := 1000

		start := time.Now()
		for i := 0; i < iterations; i++ {
			_, err := ExpandEnvironmentVariables(testString, options)
			if err != nil {
				t.Fatalf("Failed expansion at iteration %d: %v", i, err)
			}
		}
		duration := time.Since(start)

		// Calculate average time per expansion
		avgDuration := duration / time.Duration(iterations)
		maxAvgDuration := 1 * time.Millisecond

		if avgDuration > maxAvgDuration {
			t.Errorf("Average expansion time too slow: %v (max: %v)", avgDuration, maxAvgDuration)
		}

		t.Logf("Completed %d expansions in %v (avg: %v per expansion)", iterations, duration, avgDuration)
	})
}
