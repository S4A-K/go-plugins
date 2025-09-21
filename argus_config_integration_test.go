// library_config_integration_test.go: Integration tests for library configuration hot reload
//
// This test suite provides end-to-end validation of the complete library configuration
// hot reload system, integrating Argus watcher, environment expansion, and configuration
// application with comprehensive scenarios and real-world use cases.
//
// Test Design Principles:
// - Low cyclomatic complexity (focused integration scenarios)
// - Comprehensive real-world workflow validation with proper cleanup
// - Clear English documentation for global team accessibility
// - Reliable test isolation with proper resource management
// - Performance validation for production readiness
//
// Test Categories:
// - End-to-end workflow tests: Complete configuration reload cycles
// - Multi-component integration: Argus + environment + validation
// - Error resilience tests: Recovery from configuration failures
// - Performance integration: Hot reload under load conditions
// - Security integration: Complete security validation workflow
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/agilira/argus"
)

// TestLibraryConfigIntegration_CompleteWorkflow tests the complete library config workflow.
//
// This test validates the entire end-to-end flow of library configuration management:
// 1. Initial configuration loading with environment expansion
// 2. Hot reload detection and processing via Argus
// 3. Configuration validation and application
// 4. Error handling and recovery scenarios
// 5. Audit logging and security validation
//
// TestLibraryConfigIntegration_InitialLoad tests initial configuration loading and environment expansion
func TestLibraryConfigIntegration_InitialLoad(t *testing.T) {
	// Setup
	tempDir, cleanup := setupIntegrationTestEnv(t)
	defer cleanup()
	cleanupEnv := setupIntegrationTestEnvironment(t)
	defer cleanupEnv()

	manager := createTestManager()
	logger := NewTestLogger()

	// Create initial configuration
	configFile := filepath.Join(tempDir, "library.json")
	initialConfig := createDefaultIntegrationConfig()
	if err := writeLibraryConfigToFile(configFile, initialConfig); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	// Setup watcher
	auditFile := filepath.Join(tempDir, "audit.log")
	options := LibraryConfigOptions{
		PollInterval:        2 * time.Second,
		CacheTTL:            1 * time.Second,
		EnableEnvExpansion:  true,
		ValidateBeforeApply: true,
		RollbackOnFailure:   true,
		AuditConfig: argus.AuditConfig{
			Enabled:       true,
			OutputFile:    auditFile,
			MinLevel:      argus.AuditInfo,
			BufferSize:    100,
			FlushInterval: 500 * time.Millisecond,
		},
	}

	// Create and start watcher
	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, logger)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Logf("Warning: Failed to stop watcher: %v", err)
		}
	}()

	// Test initial configuration loading
	time.Sleep(1 * time.Second)

	config := watcher.GetCurrentConfig()
	if config == nil {
		t.Fatal("Expected initial config to be loaded")
	}

	// Validate environment expansion occurred
	if config.Logging.Level != "info" {
		t.Errorf("Expected log level 'info', got: %s", config.Logging.Level)
	}

	if config.Environment.Overrides["metrics_port"] != "9090" {
		t.Errorf("Expected metrics port '9090', got: %s", config.Environment.Overrides["metrics_port"])
	}

	if config.Environment.Overrides["environment"] != "integration-test" {
		t.Errorf("Expected environment 'integration-test', got: %s", config.Environment.Overrides["environment"])
	}

	t.Logf("Initial configuration loaded successfully with version: %s", config.Metadata.Version)
}

// TestLibraryConfigIntegration_HotReload tests configuration hot reloading
func TestLibraryConfigIntegration_HotReload(t *testing.T) {
	// Setup
	tempDir, cleanup := setupIntegrationTestEnv(t)
	defer cleanup()
	cleanupEnv := setupIntegrationTestEnvironment(t)
	defer cleanupEnv()

	manager := createTestManager()
	logger := NewTestLogger()

	// Create initial configuration
	configFile := filepath.Join(tempDir, "library.json")
	initialConfig := createDefaultIntegrationConfig()
	if err := writeLibraryConfigToFile(configFile, initialConfig); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	// Setup watcher
	auditFile := filepath.Join(tempDir, "audit.log")
	options := LibraryConfigOptions{
		PollInterval:        2 * time.Second,
		CacheTTL:            1 * time.Second,
		EnableEnvExpansion:  true,
		ValidateBeforeApply: true,
		RollbackOnFailure:   true,
		AuditConfig: argus.AuditConfig{
			Enabled:       true,
			OutputFile:    auditFile,
			MinLevel:      argus.AuditInfo,
			BufferSize:    100,
			FlushInterval: 500 * time.Millisecond,
		},
	}

	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, logger)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Logf("Warning: Failed to stop watcher: %v", err)
		}
	}()

	// Wait for initial load
	time.Sleep(1 * time.Second)

	// Test hot reload with valid configuration changes
	// Get current config version
	originalConfig := watcher.GetCurrentConfig()
	originalVersion := originalConfig.Metadata.Version

	// Update configuration with new values
	updatedConfig := *originalConfig
	updatedConfig.Logging.Level = "debug" // Change log level
	updatedConfig.Metadata.Version = "v1.1.0"
	updatedConfig.Metadata.LastModified = time.Now()
	updatedConfig.Metadata.Description = "Updated integration test configuration"

	// Write updated configuration
	if err := writeLibraryConfigToFile(configFile, updatedConfig); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	// Wait for hot reload detection
	if err := waitForConfigVersionChange(watcher, originalVersion, 15*time.Second); err != nil {
		t.Fatalf("Configuration hot reload not detected: %v", err)
	}

	// Validate new configuration
	newConfig := watcher.GetCurrentConfig()
	if newConfig.Logging.Level != "debug" {
		t.Errorf("Expected updated log level 'debug', got: %s", newConfig.Logging.Level)
	}

	if newConfig.Metadata.Version != "v1.1.0" {
		t.Errorf("Expected updated version 'v1.1.0', got: %s", newConfig.Metadata.Version)
	}

	t.Logf("Hot reload completed successfully from %s to %s", originalVersion, newConfig.Metadata.Version)
}

// TestLibraryConfigIntegration_PerformanceUnderLoad tests performance under load
func TestLibraryConfigIntegration_PerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Use longer intervals on Windows for better file watcher performance
	updateInterval := 10 * time.Millisecond
	totalDuration := 2 * time.Second
	if runtime.GOOS == "windows" {
		updateInterval = 50 * time.Millisecond
		totalDuration = 5 * time.Second
	}

	// Setup performance test environment
	tempDir, cleanup := setupIntegrationTestEnv(t)
	defer cleanup()

	manager := createTestManager()
	logger := NewTestLogger()

	// Create configuration file
	configFile := filepath.Join(tempDir, "library.json")
	config := createMinimalLibraryConfig("v1.0.0")
	if err := writeLibraryConfigToFile(configFile, config); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Setup watcher with optimized settings for performance
	options := LibraryConfigOptions{
		PollInterval:        100 * time.Millisecond, // Fast polling
		CacheTTL:            50 * time.Millisecond,
		EnableEnvExpansion:  false, // Disable for performance
		ValidateBeforeApply: false,
		RollbackOnFailure:   false,
	}

	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, logger)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Logf("Warning: Failed to stop watcher: %v", err)
		}
	}()

	t.Run("rapid configuration changes", func(t *testing.T) {
		numChanges := 20
		startTime := time.Now()

		for i := 0; i < numChanges; i++ {
			// Update configuration
			config.Metadata.Version = fmt.Sprintf("v1.%d.0", i+1)
			config.Metadata.LastModified = time.Now()

			if err := writeLibraryConfigToFile(configFile, config); err != nil {
				t.Fatalf("Failed to write config %d: %v", i, err)
			}

			// Brief pause to allow processing
			time.Sleep(updateInterval)
		}

		elapsedTime := time.Since(startTime)
		avgDuration := elapsedTime / time.Duration(numChanges)

		t.Logf("Processed %d configuration changes in %v (avg: %v per change)",
			numChanges, elapsedTime, avgDuration)

		// Wait for final change to be processed with extended timeout
		finalVersion := fmt.Sprintf("v1.%d.0", numChanges)
		timeout := time.Duration(numChanges) * updateInterval * 3 // Give more time for race conditions
		if timeout < totalDuration {
			timeout = totalDuration // Use the minimum total duration
		}

		// Wait until we get the exact final version
		deadline := time.Now().Add(timeout)
		var finalConfig *LibraryConfig
		for time.Now().Before(deadline) {
			finalConfig = watcher.GetCurrentConfig()
			if finalConfig != nil && finalConfig.Metadata.Version == finalVersion {
				break // Got the final version
			}
			time.Sleep(100 * time.Millisecond)
		}

		// Validate final state
		if finalConfig == nil || finalConfig.Metadata.Version != finalVersion {
			t.Errorf("Expected final version %s, got: %s", finalVersion,
				func() string {
					if finalConfig == nil {
						return "nil"
					}
					return finalConfig.Metadata.Version
				}())
		}
	})

	t.Run("concurrent config access", func(t *testing.T) {
		numGoroutines := 10
		numReads := 100

		// Channel to coordinate goroutine completion
		done := make(chan bool, numGoroutines)

		// Start concurrent readers
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				for j := 0; j < numReads; j++ {
					config := watcher.GetCurrentConfig()
					if config == nil {
						t.Errorf("Goroutine %d: Got nil config at read %d", id, j)
						return
					}

					// Verify basic config integrity
					if config.Metadata.Version == "" {
						t.Errorf("Goroutine %d: Got empty version at read %d", id, j)
						return
					}

					// Small pause between reads
					time.Sleep(time.Millisecond)
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			select {
			case <-done:
				// Goroutine completed successfully
			case <-time.After(10 * time.Second):
				t.Fatalf("Goroutine did not complete within timeout")
			}
		}

		t.Logf("Completed %d concurrent goroutines with %d reads each", numGoroutines, numReads)
	})
}

// Helper functions for integration testing

// setupIntegrationTestEnv creates a temporary directory for integration tests.
func setupIntegrationTestEnv(t *testing.T) (tempDir string, cleanup func()) {
	tempDir, err := os.MkdirTemp("", "library-config-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	cleanup = func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to cleanup temp directory %s: %v", tempDir, err)
		}
	}

	return tempDir, cleanup
}

// createMinimalLibraryConfig creates a minimal library config for testing.
func createMinimalLibraryConfig(version string) LibraryConfig {
	return LibraryConfig{
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Observability: ObservabilityRuntimeConfig{
			MetricsEnabled:  true,
			MetricsInterval: 10 * time.Second, // Minimum requirement
		},
		Environment: EnvironmentConfig{
			ExpansionEnabled: false,
		},
		Performance: PerformanceConfig{
			WatcherPollInterval:       10 * time.Second,
			CacheTTL:                  5 * time.Second,
			MaxConcurrentHealthChecks: 4, // Required minimum
		},
		DefaultPolicies: DefaultPoliciesConfig{
			Retry: RetryConfig{
				MaxRetries:      3,
				InitialInterval: 100 * time.Millisecond,
				MaxInterval:     5 * time.Second,
				Multiplier:      2.0, // Must be > 0
				RandomJitter:    false,
			},
			CircuitBreaker: CircuitBreakerConfig{
				Enabled:             false,
				FailureThreshold:    5,
				RecoveryTimeout:     30 * time.Second,
				MinRequestThreshold: 3,
				SuccessThreshold:    2,
			},
			HealthCheck: HealthCheckConfig{
				Enabled:      false,
				Interval:     30 * time.Second,
				Timeout:      10 * time.Second,
				FailureLimit: 3,
			},
			Connection: ConnectionConfig{
				MaxConnections:     10,
				MaxIdleConnections: 5,
				IdleTimeout:        30 * time.Second,
				ConnectionTimeout:  10 * time.Second,
				RequestTimeout:     30 * time.Second,
			},
			RateLimit: RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 10.0,
				BurstSize:         20,
				TimeWindow:        time.Second,
			},
		},
		Metadata: ConfigMetadata{
			Version:      version,
			Environment:  "test",
			LastModified: time.Now(),
		},
	}
}

// waitForConfigVersionChange waits for the configuration version to change.
func waitForConfigVersionChange(watcher *LibraryConfigWatcher[TestRequest, TestResponse], oldVersion string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		config := watcher.GetCurrentConfig()
		if config != nil && config.Metadata.Version != oldVersion {
			return nil // Version changed
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("configuration version did not change from %s within timeout", oldVersion)
}

// setupIntegrationTestEnvironment sets up common environment variables for integration tests
func setupIntegrationTestEnvironment(t *testing.T) func() {
	testEnvVars := map[string]string{
		"GO_PLUGINS_LOG_LEVEL":     "info",
		"GO_PLUGINS_METRICS_PORT":  "9090",
		"GO_PLUGINS_POLL_INTERVAL": "5s",
		"GO_PLUGINS_ENV":           "integration-test",
	}

	for key, value := range testEnvVars {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("Failed to set %s: %v", key, err)
		}
	}

	return func() {
		for key := range testEnvVars {
			if err := os.Unsetenv(key); err != nil {
				t.Logf("Warning: failed to unset env var %s: %v", key, err)
			}
		}
	}
}

// createDefaultIntegrationConfig creates a standard configuration for integration tests
func createDefaultIntegrationConfig() LibraryConfig {
	return LibraryConfig{
		Logging: LoggingConfig{
			Level:             "info",
			Format:            "json",
			Structured:        true,
			IncludeCaller:     false,
			IncludeStackTrace: false,
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
		},
		Environment: EnvironmentConfig{
			ExpansionEnabled: true,
			VariablePrefix:   "GO_PLUGINS_",
			FailOnMissing:    false,
			Overrides: map[string]string{
				"metrics_port": "${GO_PLUGINS_METRICS_PORT}",
				"environment":  "${GO_PLUGINS_ENV}",
			},
		},
		Performance: PerformanceConfig{
			WatcherPollInterval:       10 * time.Second,
			CacheTTL:                  5 * time.Second,
			MaxConcurrentHealthChecks: 8,
			OptimizationEnabled:       true,
		},
		Metadata: ConfigMetadata{
			Version:      "v1.0.0",
			Environment:  "integration-test",
			LastModified: time.Now(),
			Description:  "Integration test library configuration",
			Tags:         []string{"test", "integration", "library"},
		},
	}
}
