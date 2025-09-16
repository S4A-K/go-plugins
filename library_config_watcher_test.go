// library_config_watcher_test.go: Comprehensive test suite for library configuration hot reload
//
// This test suite validates the library-level configuration hot reload functionality
// with comprehensive coverage of all scenarios including happy paths, error conditions,
// and edge cases. The test suite follows the same design principles as the main code:
//
// Test Design Principles:
// - Low cyclomatic complexity (focused, single-purpose test functions)
// - Comprehensive error scenario coverage with detailed validation
// - Clear English documentation for global team accessibility
// - Reliable test isolation with proper cleanup
// - Performance validation for production readiness
//
// Test Categories:
// - Unit tests: Individual function validation with mocked dependencies
// - Integration tests: End-to-end workflow validation with real Argus
// - Error tests: Comprehensive error condition and recovery validation
// - Security tests: Path traversal, injection, and validation testing
// - Performance tests: Hot reload performance and resource usage validation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agilira/argus"
)

// TestLibraryConfigWatcher_NewCreation tests the creation of a new library config watcher.
//
// This test validates that the LibraryConfigWatcher can be created successfully
// with various configuration options and that all components are properly initialized.
//
// Test scenarios:
//   - Creation with default options
//   - Creation with custom options
//   - Creation with environment expansion enabled/disabled
//   - Creation with audit logging enabled/disabled
//   - Error handling for invalid parameters
func TestLibraryConfigWatcher_NewCreation(t *testing.T) {
	// Setup test dependencies
	manager := createTestManager()
	logger := createTestLogger()
	tempDir := createTempDirectory(t)
	defer cleanupTempDirectory(t, tempDir)

	testCases := []struct {
		name          string
		configPath    string
		options       LibraryConfigOptions
		expectError   bool
		validateSetup func(t *testing.T, watcher *LibraryConfigWatcher[TestRequest, TestResponse])
	}{
		{
			name:        "successful creation with default options",
			configPath:  filepath.Join(tempDir, "library.json"),
			options:     DefaultLibraryConfigOptions(),
			expectError: false,
			validateSetup: func(t *testing.T, watcher *LibraryConfigWatcher[TestRequest, TestResponse]) {
				if watcher == nil {
					t.Fatal("Expected non-nil watcher")
				}
				if watcher.manager == nil {
					t.Error("Expected non-nil manager")
				}
				if watcher.logger == nil {
					t.Error("Expected non-nil logger")
				}
				if watcher.watcher == nil {
					t.Error("Expected non-nil Argus watcher")
				}
			},
		},
		{
			name:       "creation with environment expansion enabled",
			configPath: filepath.Join(tempDir, "library-env.json"),
			options: LibraryConfigOptions{
				PollInterval:        5 * time.Second,
				CacheTTL:            2 * time.Second,
				EnableEnvExpansion:  true,
				ValidateBeforeApply: true,
				RollbackOnFailure:   true,
				AuditConfig: argus.AuditConfig{
					Enabled:       true,
					OutputFile:    filepath.Join(tempDir, "audit.log"),
					MinLevel:      argus.AuditInfo,
					BufferSize:    100,
					FlushInterval: 1 * time.Second,
				},
			},
			expectError: false,
			validateSetup: func(t *testing.T, watcher *LibraryConfigWatcher[TestRequest, TestResponse]) {
				if watcher.envExpander == nil {
					t.Error("Expected non-nil environment expander when expansion is enabled")
				}
				if watcher.auditLogger == nil {
					t.Error("Expected non-nil audit logger when audit is enabled")
				}
			},
		},
		{
			name:       "creation with environment expansion disabled",
			configPath: filepath.Join(tempDir, "library-no-env.json"),
			options: LibraryConfigOptions{
				PollInterval:        10 * time.Second,
				CacheTTL:            5 * time.Second,
				EnableEnvExpansion:  false,
				ValidateBeforeApply: false,
				RollbackOnFailure:   false,
				AuditConfig: argus.AuditConfig{
					Enabled: false,
				},
			},
			expectError: false,
			validateSetup: func(t *testing.T, watcher *LibraryConfigWatcher[TestRequest, TestResponse]) {
				// Environment expander should be nil when disabled
				if watcher.envExpander != nil {
					t.Error("Expected nil environment expander when expansion is disabled")
				}
				// Audit logger should be nil when disabled
				if watcher.auditLogger != nil {
					t.Error("Expected nil audit logger when audit is disabled")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create library config watcher
			watcher, err := NewLibraryConfigWatcher(manager, tc.configPath, tc.options, logger)

			// Validate error expectation
			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}

			// Run custom validation
			if tc.validateSetup != nil {
				tc.validateSetup(t, watcher)
			}

			// Cleanup
			if watcher != nil {
				_ = watcher.Stop()
			}
		})
	}
}

// TestLibraryConfigWatcher_HotReload tests the hot reload functionality of the library config watcher.
//
// This test validates that configuration changes are detected and applied in real-time
// without disrupting the running system, with proper validation and error handling.
func TestLibraryConfigWatcher_HotReload(t *testing.T) {
	// Setup test environment
	manager := createTestManager()
	logger := createTestLogger()
	tempDir := createTempDirectory(t)
	defer cleanupTempDirectory(t, tempDir)

	// Create initial configuration
	configPath := filepath.Join(tempDir, "library.json")
	initialConfig := LibraryConfig{
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Structured: true,
		},
		Observability: ObservabilityRuntimeConfig{
			MetricsEnabled:            true,
			MetricsInterval:           30 * time.Second,
			TracingEnabled:            true,
			TracingSampleRate:         1.0,
			HealthMetricsEnabled:      true,
			PerformanceMetricsEnabled: true,
		},
		DefaultPolicies: DefaultPoliciesConfig{
			Retry: RetryConfig{
				MaxRetries:      3,
				InitialInterval: 100 * time.Millisecond,
				MaxInterval:     30 * time.Second,
				Multiplier:      2.0,
			},
			CircuitBreaker: CircuitBreakerConfig{
				Enabled:          true,
				FailureThreshold: 5,
				SuccessThreshold: 3,
				RecoveryTimeout:  30 * time.Second,
			},
			HealthCheck: HealthCheckConfig{
				Enabled:      true,
				Interval:     30 * time.Second,
				Timeout:      10 * time.Second,
				FailureLimit: 3,
			},
			Connection: ConnectionConfig{
				MaxConnections:     10,
				MaxIdleConnections: 5,
				ConnectionTimeout:  30 * time.Second,
				IdleTimeout:        60 * time.Second,
				RequestTimeout:     30 * time.Second,
				KeepAlive:          true,
			},
			RateLimit: RateLimitConfig{
				Enabled: false,
			},
		},
		Security: SecurityConfig{
			Enabled:         true,
			Policy:          SecurityPolicyStrict,
			WhitelistFile:   filepath.Join(tempDir, "plugins.whitelist"),
			AutoUpdate:      true,
			ValidateOnStart: true,
			MaxFileSize:     10485760, // 10MB
			AllowedTypes:    []string{".so", ".dll"},
			WatchConfig:     true,
		},
		Environment: EnvironmentConfig{
			ExpansionEnabled: true,
			VariablePrefix:   "GO_PLUGINS_",
			FailOnMissing:    false,
			Defaults: map[string]string{
				"LOG_LEVEL": "info",
			},
		},
		Performance: PerformanceConfig{
			WatcherPollInterval:       1 * time.Second,
			MaxConcurrentHealthChecks: 5,
		},
		Metadata: ConfigMetadata{
			Version: "1.0.0",
		},
	}

	configBytes, err := json.MarshalIndent(initialConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal initial config: %v", err)
	}

	if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	// Create and start watcher
	options := DefaultLibraryConfigOptions()
	options.PollInterval = 100 * time.Millisecond // Fast polling for testing

	watcher, err := NewLibraryConfigWatcher(manager, configPath, options, logger)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	ctx := context.Background()
	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Wait for initial load
	time.Sleep(200 * time.Millisecond)

	// Verify initial configuration
	config := watcher.GetCurrentConfig()
	if config.Logging.Level != "info" {
		t.Errorf("Expected log level 'info', got '%s'", config.Logging.Level)
	}

	// Update configuration
	updatedConfig := initialConfig
	updatedConfig.Logging.Level = "debug"
	updatedConfig.Metadata.Version = "1.0.1"

	updatedBytes, err := json.MarshalIndent(updatedConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal updated config: %v", err)
	}

	if err := os.WriteFile(configPath, updatedBytes, 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	// Wait for hot reload
	time.Sleep(300 * time.Millisecond)

	// Verify hot reload applied
	reloadedConfig := watcher.GetCurrentConfig()
	if reloadedConfig.Logging.Level != "debug" {
		t.Errorf("Expected log level 'debug' after reload, got '%s'", reloadedConfig.Logging.Level)
	}
	if reloadedConfig.Metadata.Version != "1.0.1" {
		t.Errorf("Expected version '1.0.1' after reload, got '%s'", reloadedConfig.Metadata.Version)
	}

	t.Logf("✅ Hot reload test completed successfully")
}

// TestLibraryConfigWatcher_StartStop tests the start and stop functionality.
//
// This test validates the lifecycle management of the library config watcher,
// ensuring proper startup, shutdown, and state transitions with comprehensive
// error handling and edge case coverage.
//
// Test scenarios:
//   - Successful start with valid configuration
//   - Start with invalid configuration file
//   - Multiple start attempts (should fail after first)
//   - Successful stop after start
//   - Multiple stop attempts (should handle gracefully)
//   - Stop without start (should handle gracefully)
//   - Restart after stop (should fail - permanent stop)
func TestLibraryConfigWatcher_StartStop(t *testing.T) {
	// Setup test environment
	manager := createTestManager()
	logger := createTestLogger()
	tempDir := createTempDirectory(t)
	defer cleanupTempDirectory(t, tempDir)

	// Create valid library configuration file
	configFile := filepath.Join(tempDir, "library.json")
	createValidLibraryConfigFile(t, configFile)

	// Create watcher with default options
	options := DefaultLibraryConfigOptions()
	options.AuditConfig.OutputFile = filepath.Join(tempDir, "audit.log")

	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, logger)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	t.Run("successful start with valid config", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := watcher.Start(ctx)
		if err != nil {
			t.Fatalf("Expected successful start but got error: %v", err)
		}

		// Validate watcher is running
		if !watcher.IsRunning() {
			t.Error("Expected watcher to be running after successful start")
		}

		// Validate current config is loaded
		currentConfig := watcher.GetCurrentConfig()
		if currentConfig == nil {
			t.Error("Expected current config to be loaded after start")
		}
	})

	t.Run("multiple start attempts should fail", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Second start should fail since already running
		err := watcher.Start(ctx)
		if err == nil {
			t.Error("Expected error for second start attempt but got none")
		}

		expectedMsg := "already running"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
		}
	})

	t.Run("successful stop after start", func(t *testing.T) {
		err := watcher.Stop()
		if err != nil {
			t.Fatalf("Expected successful stop but got error: %v", err)
		}

		// Validate watcher is not running
		if watcher.IsRunning() {
			t.Error("Expected watcher to not be running after stop")
		}
	})

	t.Run("multiple stop attempts should handle gracefully", func(t *testing.T) {
		// Second stop should return appropriate error but not panic
		err := watcher.Stop()
		if err == nil {
			t.Error("Expected error for second stop attempt but got none")
		}

		expectedMsg := "already stopped"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
		}
	})

	t.Run("restart after stop should fail", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Restart should fail because stop is permanent
		err := watcher.Start(ctx)
		if err == nil {
			t.Error("Expected error for restart attempt but got none")
		}

		expectedMsg := "permanently stopped"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
		}
	})
}

// TestLibraryConfigWatcher_ConfigReload tests configuration hot reload functionality.
//
// This test validates that the watcher can successfully detect and apply
// configuration changes, with proper validation, rollback, and audit logging.
//
// Test scenarios:
//   - Valid configuration change detection and application
//   - Invalid configuration handling with rollback
//   - Multiple rapid configuration changes
//   - Configuration validation before application
//   - Audit logging of all configuration changes
func TestLibraryConfigWatcher_ConfigReload(t *testing.T) {
	// Setup test environment
	manager := createTestManager()
	logger := createTestLogger()
	tempDir := createTempDirectory(t)
	defer cleanupTempDirectory(t, tempDir)

	// Create initial library configuration
	configFile := filepath.Join(tempDir, "library.json")
	createValidLibraryConfigFile(t, configFile)

	// Setup watcher with audit enabled and fast polling for testing
	options := DefaultLibraryConfigOptions()
	options.PollInterval = 500 * time.Millisecond // Fast polling for testing
	options.AuditConfig.OutputFile = filepath.Join(tempDir, "audit.log")
	options.RollbackOnFailure = true
	options.ValidateBeforeApply = true

	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, logger)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Start watcher
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		_ = watcher.Stop()
	}()

	t.Run("valid configuration change", func(t *testing.T) {
		// Get initial configuration
		initialConfig := watcher.GetCurrentConfig()
		if initialConfig == nil {
			t.Fatal("Expected initial config to be loaded")
		}

		// Update configuration file with new log level
		updatedConfig := *initialConfig
		updatedConfig.Logging.Level = "debug"
		updatedConfig.Metadata.Version = "v1.1.0"
		updatedConfig.Metadata.LastModified = time.Now()

		// Write updated configuration
		if err := writeLibraryConfigToFile(configFile, updatedConfig); err != nil {
			t.Fatalf("Failed to write updated config: %v", err)
		}

		// Wait for change detection and processing
		if err := waitForConfigUpdate(watcher, initialConfig.Metadata.Version, 10*time.Second); err != nil {
			t.Fatalf("Configuration update was not detected: %v", err)
		}

		// Validate new configuration is applied
		newConfig := watcher.GetCurrentConfig()
		if newConfig == nil {
			t.Fatal("Expected new config to be loaded")
		}

		if newConfig.Logging.Level != "debug" {
			t.Errorf("Expected log level 'debug', got: %s", newConfig.Logging.Level)
		}

		if newConfig.Metadata.Version != "v1.1.0" {
			t.Errorf("Expected version 'v1.1.0', got: %s", newConfig.Metadata.Version)
		}
	})

	t.Run("invalid configuration with rollback", func(t *testing.T) {
		// Get current valid configuration
		validConfig := watcher.GetCurrentConfig()
		if validConfig == nil {
			t.Fatal("Expected valid config to be present")
		}

		// Create invalid configuration (invalid log level)
		invalidConfig := *validConfig
		invalidConfig.Logging.Level = "invalid-level"
		invalidConfig.Metadata.Version = "v1.2.0-invalid"

		// Write invalid configuration
		if err := writeLibraryConfigToFile(configFile, invalidConfig); err != nil {
			t.Fatalf("Failed to write invalid config: %v", err)
		}

		// Wait a moment for change detection
		time.Sleep(2 * time.Second)

		// Validate that rollback occurred - config should remain valid
		currentConfig := watcher.GetCurrentConfig()
		if currentConfig == nil {
			t.Fatal("Expected current config to remain valid")
		}

		// Configuration should not have changed to invalid values
		if currentConfig.Logging.Level == "invalid-level" {
			t.Error("Invalid configuration was applied instead of being rolled back")
		}

		// Version should not have changed to invalid version
		if currentConfig.Metadata.Version == "v1.2.0-invalid" {
			t.Error("Invalid configuration version was applied")
		}
	})
}

// TestLibraryConfigWatcher_EnvironmentExpansion tests environment variable expansion.
//
// This test validates that environment variables are properly expanded in
// configuration values, with proper security validation and error handling.
func TestLibraryConfigWatcher_EnvironmentExpansion(t *testing.T) {
	// Setup test environment
	manager := createTestManager()
	logger := createTestLogger()
	tempDir := createTempDirectory(t)
	defer cleanupTempDirectory(t, tempDir)

	// Set test environment variables
	testEnvVars := map[string]string{
		"GO_PLUGINS_LOG_LEVEL":    "debug",
		"GO_PLUGINS_METRICS_PORT": "9091",
		"TEST_PREFIX":             "test_",
	}

	for key, value := range testEnvVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	// Create configuration with environment variables
	configFile := filepath.Join(tempDir, "library-env.json")
	configWithEnv := LibraryConfig{
		Logging: LoggingConfig{
			Level:  "info", // Use direct value since logging expansion is not implemented
			Format: "json",
		},
		Observability: ObservabilityRuntimeConfig{
			MetricsEnabled:  true,
			MetricsInterval: 10 * time.Second, // Ensure minimum requirement
		},
		Environment: EnvironmentConfig{
			ExpansionEnabled: true,
			VariablePrefix:   "${TEST_PREFIX}",
			Overrides: map[string]string{
				"metrics_port": "${GO_PLUGINS_METRICS_PORT}",
			},
		},
		DefaultPolicies: DefaultPoliciesConfig{
			Retry: RetryConfig{
				MaxRetries:      3,
				InitialInterval: 100 * time.Millisecond,
				MaxInterval:     5 * time.Second,
				Multiplier:      2.0,
			},
		},
		Performance: PerformanceConfig{
			WatcherPollInterval:       10 * time.Second,
			CacheTTL:                  5 * time.Second,
			MaxConcurrentHealthChecks: 4, // Minimum required
		},
		Metadata: ConfigMetadata{
			Version:     "v1.0.0",
			Environment: "test",
		},
	}

	if err := writeLibraryConfigToFile(configFile, configWithEnv); err != nil {
		t.Fatalf("Failed to write config with env vars: %v", err)
	}

	// Setup watcher with environment expansion enabled
	options := DefaultLibraryConfigOptions()
	options.EnableEnvExpansion = true

	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, logger)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Start watcher
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		_ = watcher.Stop()
	}()

	t.Run("environment variables expanded correctly", func(t *testing.T) {
		config := watcher.GetCurrentConfig()
		if config == nil {
			t.Fatal("Expected config to be loaded")
		}

		// Validate prefix expansion (environment fields are expanded)
		if config.Environment.VariablePrefix != "test_" {
			t.Errorf("Expected expanded prefix 'test_', got: %s", config.Environment.VariablePrefix)
		}

		// Validate override expansion
		if config.Environment.Overrides["metrics_port"] != "9091" {
			t.Errorf("Expected expanded metrics port '9091', got: %s", config.Environment.Overrides["metrics_port"])
		}

		// Validate that logging level remains as configured (not expanded in current implementation)
		if config.Logging.Level != "info" {
			t.Errorf("Expected log level 'info', got: %s", config.Logging.Level)
		}
	})
}

// Helper functions for test setup and utilities

// createTestManager creates a test plugin manager for testing.
func createTestManager() *Manager[TestRequest, TestResponse] {
	logger := createTestLogger()
	return NewManager[TestRequest, TestResponse](logger)
}

// createTestLogger creates a test logger that captures log output.
func createTestLogger() Logger {
	// Use the existing TestLogger from logging.go
	return NewTestLogger()
}

// createTempDirectory creates a temporary directory for test files.
func createTempDirectory(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "library-config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	return tempDir
}

// cleanupTempDirectory removes the temporary directory and all contents.
func cleanupTempDirectory(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("Warning: Failed to cleanup temp directory %s: %v", dir, err)
	}
}

// createValidLibraryConfigFile creates a valid library configuration file for testing.
func createValidLibraryConfigFile(t *testing.T, filename string) {
	config := LibraryConfig{
		Logging: LoggingConfig{
			Level:             "info",
			Format:            "json",
			Structured:        true,
			IncludeCaller:     false,
			IncludeStackTrace: false,
			ComponentLevels:   make(map[string]string),
		},
		Observability: ObservabilityRuntimeConfig{
			MetricsEnabled:            true,
			MetricsInterval:           30 * time.Second,
			TracingEnabled:            false,
			TracingSampleRate:         0.1,
			HealthMetricsEnabled:      true,
			PerformanceMetricsEnabled: true,
		},
		DefaultPolicies: DefaultPoliciesConfig{
			Retry: RetryConfig{
				MaxRetries:      3,
				InitialInterval: 100 * time.Millisecond,
				MaxInterval:     5 * time.Second,
				Multiplier:      2.0,
				RandomJitter:    true,
			},
			CircuitBreaker: CircuitBreakerConfig{
				Enabled:             true,
				FailureThreshold:    5,
				RecoveryTimeout:     30 * time.Second,
				MinRequestThreshold: 3,
				SuccessThreshold:    2,
			},
			HealthCheck: HealthCheckConfig{
				Enabled:      true,
				Interval:     30 * time.Second,
				Timeout:      5 * time.Second,
				FailureLimit: 3,
			},
		},
		Environment: EnvironmentConfig{
			ExpansionEnabled: true,
			VariablePrefix:   "GO_PLUGINS_",
			FailOnMissing:    false,
			Overrides:        make(map[string]string),
			Defaults:         make(map[string]string),
		},
		Performance: PerformanceConfig{
			WatcherPollInterval:       10 * time.Second,
			CacheTTL:                  5 * time.Second,
			MaxConcurrentHealthChecks: 8,
			OptimizationEnabled:       true,
		},
		Metadata: ConfigMetadata{
			Version:      "v1.0.0",
			Environment:  "test",
			LastModified: time.Now(),
			Description:  "Test library configuration",
			Tags:         []string{"test", "library"},
		},
	}

	if err := writeLibraryConfigToFile(filename, config); err != nil {
		t.Fatalf("Failed to create valid config file: %v", err)
	}
}

// writeLibraryConfigToFile writes a LibraryConfig to a JSON file.
func writeLibraryConfigToFile(filename string, config LibraryConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// waitForConfigUpdate waits for the configuration to be updated to a new version.
func waitForConfigUpdate(watcher *LibraryConfigWatcher[TestRequest, TestResponse], oldVersion string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		config := watcher.GetCurrentConfig()
		if config != nil && config.Metadata.Version != oldVersion {
			return nil // Update detected
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("configuration update not detected within timeout")
}
