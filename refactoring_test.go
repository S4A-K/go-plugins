// refactoring_test.go: Comprehensive test suite to protect behavior during business logic simplification
//
// DISCOVERY: argus_config_watcher.go already uses argus correctly (no duplication of argus).
// The real issue is over-engineered business logic (34 functions, 1,500 lines).
//
// This test suite protects functionality while we simplify the business logic:
// - Reduce from 34 functions to ~15 essential functions
// - Maintain exact same LibraryConfig functionality
// - Preserve all production features and error handling
// - Keep argus integration unchanged (it's already correct)
//
// Test Strategy:
// 1. Test current behavior as baseline (before simplification)
// 2. Test after each business logic simplification step
// 3. Ensure no regression in LibraryConfig functionality
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RefactoringTestSuite protects critical functionality during argus refactoring
type RefactoringTestSuite struct {
	tempDir       string
	configFile    string
	whitelistFile string
	manager       *Manager[TestRequest, TestResponse]
}

// Use existing TestRequest/TestResponse types defined in manager_test.go

// SetupRefactoringTest creates test environment for refactoring validation
func SetupRefactoringTest(t *testing.T) *RefactoringTestSuite {
	tempDir := t.TempDir()

	suite := &RefactoringTestSuite{
		tempDir:       tempDir,
		configFile:    filepath.Join(tempDir, "library_config.json"),
		whitelistFile: filepath.Join(tempDir, "whitelist.json"),
	}

	// Create minimal manager for testing using correct NewManager signature
	manager := NewManager[TestRequest, TestResponse](DefaultLogger())
	suite.manager = manager

	// Create test configuration files
	suite.createTestConfigFiles(t)

	return suite
}

// createTestConfigFiles creates minimal but valid config files for testing
func (rts *RefactoringTestSuite) createTestConfigFiles(t *testing.T) {
	// Create library config
	libraryConfig := LibraryConfig{
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Structured: true,
		},
		Observability: ObservabilityRuntimeConfig{
			MetricsEnabled:            true,
			MetricsInterval:           30 * time.Second,
			TracingEnabled:            false,
			TracingSampleRate:         0.1,
			HealthMetricsEnabled:      true,
			PerformanceMetricsEnabled: false,
		},
		DefaultPolicies: DefaultPoliciesConfig{
			Retry: RetryConfig{
				MaxRetries:      3,
				InitialInterval: 100 * time.Millisecond,
				MaxInterval:     5 * time.Second,
				Multiplier:      2.0,
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
		Environment: EnvironmentConfig{
			ExpansionEnabled: true,
			VariablePrefix:   "GO_PLUGINS_",
			FailOnMissing:    false,
		},
		Performance: PerformanceConfig{
			WatcherPollInterval:       5 * time.Second,
			CacheTTL:                  2 * time.Second,
			MaxConcurrentHealthChecks: 5,
			OptimizationEnabled:       true,
		},
		Metadata: ConfigMetadata{
			Version:      "1.0.0",
			Environment:  "test",
			LastModified: time.Now(),
			Description:  "Test configuration for refactoring validation",
		},
	}

	configData, err := json.MarshalIndent(libraryConfig, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(rts.configFile, configData, 0644))

	// Create security whitelist
	whitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		Description:   "Test whitelist for refactoring validation",
		DefaultPolicy: SecurityPolicyPermissive, // Permissive for testing
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins: map[string]PluginHashInfo{
			"test-plugin": {
				Name:        "test-plugin",
				Type:        "http",
				Version:     "1.0.0",
				Algorithm:   HashAlgorithmSHA256,
				Hash:        "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab",
				Description: "Test plugin for refactoring validation",
				AddedAt:     time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
	}

	whitelistData, err := json.MarshalIndent(whitelist, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(rts.whitelistFile, whitelistData, 0644))
}

// =============================================================================
// BASELINE TESTS (Current Implementation)
// =============================================================================

// TestLibraryConfigWatcher_CurrentImplementation tests current LibraryConfigWatcher
func TestLibraryConfigWatcher_CurrentImplementation(t *testing.T) {
	suite := SetupRefactoringTest(t)

	t.Run("creation_and_basic_functionality", func(t *testing.T) {
		watcher, err := createTestLibraryConfigWatcher(suite.manager, suite.configFile)
		require.NoError(t, err)
		assert.NotNil(t, watcher)

		// Test basic state
		assert.False(t, watcher.IsRunning())
		assert.Nil(t, watcher.GetCurrentConfig())

		// Start watching
		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)
		assert.True(t, watcher.IsRunning())

		// Wait for initial config load
		time.Sleep(200 * time.Millisecond)

		currentConfig := watcher.GetCurrentConfig()
		require.NotNil(t, currentConfig)
		assert.Equal(t, "info", currentConfig.Logging.Level)
		assert.Equal(t, "1.0.0", currentConfig.Metadata.Version)

		// Stop watching
		err = watcher.Stop()
		require.NoError(t, err)
		assert.False(t, watcher.IsRunning())
	})

	t.Run("config_reload_functionality", func(t *testing.T) {
		watcher, err := createTestLibraryConfigWatcher(suite.manager, suite.configFile)
		require.NoError(t, err)

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)
		defer func() {
			if err := watcher.Stop(); err != nil {
				t.Logf("Warning: failed to stop watcher: %v", err)
			}
		}()

		// Wait for initial load
		time.Sleep(200 * time.Millisecond)

		initialConfig := watcher.GetCurrentConfig()
		require.NotNil(t, initialConfig)
		assert.Equal(t, "info", initialConfig.Logging.Level)

		// Modify configuration
		modifiedConfig := *initialConfig
		modifiedConfig.Logging.Level = "debug"
		modifiedConfig.Metadata.Version = "1.0.1"
		modifiedConfig.Metadata.LastModified = time.Now()

		configData, err := json.MarshalIndent(modifiedConfig, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(suite.configFile, configData, 0644))

		// Wait for reload detection
		time.Sleep(300 * time.Millisecond)

		reloadedConfig := watcher.GetCurrentConfig()
		require.NotNil(t, reloadedConfig)
		assert.Equal(t, "debug", reloadedConfig.Logging.Level)
		assert.Equal(t, "1.0.1", reloadedConfig.Metadata.Version)
	})
}

// TestSecurityValidator_CurrentImplementation tests current SecurityValidator
func TestSecurityValidator_CurrentImplementation(t *testing.T) {
	suite := SetupRefactoringTest(t)

	t.Run("security_validation_flow", func(t *testing.T) {
		config := DefaultSecurityConfig()
		config.Enabled = true
		config.Policy = SecurityPolicyPermissive
		config.WhitelistFile = suite.whitelistFile
		config.ValidateOnStart = true

		validator, err := NewSecurityValidator(config, DefaultLogger())
		require.NoError(t, err)
		assert.NotNil(t, validator)

		// Enable validator (only if not already enabled)
		if !validator.IsEnabled() {
			err = validator.Enable()
			require.NoError(t, err)
		}
		assert.True(t, validator.IsEnabled()) // Test plugin validation
		pluginConfig := PluginConfig{
			Name:     "test-plugin",
			Type:     "http",
			Endpoint: "https://example.com",
		}

		result, err := validator.ValidatePlugin(pluginConfig, "")
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Authorized) // Should be authorized (permissive mode)

		// Test stats
		stats := validator.GetStats()
		assert.Equal(t, int64(1), stats.ValidationAttempts)
		assert.Equal(t, int64(1), stats.AuthorizedLoads)

		// Disable validator
		err = validator.Disable()
		require.NoError(t, err)
		assert.False(t, validator.IsEnabled())
	})
}

// =============================================================================
// REFACTORING VALIDATION HELPERS
// =============================================================================

// Simple validation helpers for ensuring functionality preservation

// =============================================================================
// MIGRATION CHECKPOINT TESTS
// =============================================================================

// TestRefactoringCheckpoint1_ArgusDirectUsage tests first migration step
// This will be implemented after we create the new argus-direct implementation
func TestRefactoringCheckpoint1_ArgusDirectUsage(t *testing.T) {
	t.Skip("TODO: Implement after creating argus-direct watcher")

	// Will test the same functionality but using argus.Watcher directly
	// instead of the duplicated LibraryConfigWatcher implementation
}

// TestRefactoringCheckpoint2_SecurityIntegration tests security migration
func TestRefactoringCheckpoint2_SecurityIntegration(t *testing.T) {
	t.Skip("TODO: Implement after migrating security system")

	// Will test the same security validation but using argus.AuditLogger directly
	// instead of the duplicated SecurityArgusIntegration implementation
}

// TestRefactoringFinal_CompleteCompatibility tests final compatibility
func TestRefactoringFinal_CompleteCompatibility(t *testing.T) {
	t.Skip("TODO: Implement after complete migration")

	// Will test that all original functionality still works
	// but using the new argus-direct implementation
}

// =============================================================================
// REGRESSION PROTECTION
// =============================================================================

// TestNoRegressionAfterRefactoring ensures no functionality loss
func TestNoRegressionAfterRefactoring(t *testing.T) {
	// This test should pass both before and after refactoring
	// If it fails after refactoring, we have a regression

	suite := SetupRefactoringTest(t)

	t.Run("plugin_manager_integration", func(t *testing.T) {
		// Test that the manager still works with config watching
		assert.NotNil(t, suite.manager)

		// Test manager methods work (use pointer to avoid copylock)
		metrics := suite.manager.GetMetrics()
		assert.GreaterOrEqual(t, metrics.RequestsTotal.Load(), int64(0))

		plugins := suite.manager.ListPlugins()
		assert.NotNil(t, plugins)
		assert.Equal(t, 0, len(plugins)) // No plugins registered yet
	})

	t.Run("file_format_support", func(t *testing.T) {
		// Test that we still support JSON config files
		data, err := os.ReadFile(suite.configFile)
		require.NoError(t, err)

		var config LibraryConfig
		err = json.Unmarshal(data, &config)
		require.NoError(t, err)
		assert.Equal(t, "info", config.Logging.Level)
	})

	t.Run("security_whitelist_format", func(t *testing.T) {
		// Test that we still support whitelist files
		data, err := os.ReadFile(suite.whitelistFile)
		require.NoError(t, err)

		var whitelist PluginWhitelist
		err = json.Unmarshal(data, &whitelist)
		require.NoError(t, err)
		assert.Contains(t, whitelist.Plugins, "test-plugin")
	})
}

// TestBasicFunctionalityPreservation ensures core functionality still works
func TestBasicFunctionalityPreservation(t *testing.T) {
	suite := SetupRefactoringTest(t)

	t.Run("manager_basic_operations", func(t *testing.T) {
		// Test basic manager functionality that should work before and after refactoring
		assert.NotNil(t, suite.manager)

		// Test that manager provides basic metrics
		metrics := suite.manager.GetMetrics()
		assert.GreaterOrEqual(t, metrics.RequestsTotal.Load(), int64(0))

		// Test that manager can list plugins (should be empty)
		plugins := suite.manager.ListPlugins()
		assert.NotNil(t, plugins)
		assert.Equal(t, 0, len(plugins))

		// Test health check
		health := suite.manager.Health()
		assert.NotNil(t, health)
	})
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// AssertConfigEquality compares two LibraryConfig instances for testing
func AssertConfigEquality(t *testing.T, expected, actual *LibraryConfig) {
	require.NotNil(t, expected)
	require.NotNil(t, actual)

	assert.Equal(t, expected.Logging.Level, actual.Logging.Level)
	assert.Equal(t, expected.Metadata.Version, actual.Metadata.Version)
	assert.Equal(t, expected.Environment.VariablePrefix, actual.Environment.VariablePrefix)
	// Add more assertions as needed
}

// WaitForConfigChange waits for a configuration change with timeout
func WaitForConfigChange(t *testing.T, watcher *LibraryConfigWatcher[TestRequest, TestResponse], expectedVersion string, timeout time.Duration) {
	start := time.Now()
	for time.Since(start) < timeout {
		if config := watcher.GetCurrentConfig(); config != nil && config.Metadata.Version == expectedVersion {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Config did not change to version %s within timeout %v", expectedVersion, timeout)
}

// Helper function for type-safe library config watcher creation
func createTestLibraryConfigWatcher(manager *Manager[TestRequest, TestResponse], configFile string) (*LibraryConfigWatcher[TestRequest, TestResponse], error) {
	options := DefaultLibraryConfigOptions()
	options.PollInterval = 100 * time.Millisecond // Fast for testing
	return NewLibraryConfigWatcher(manager, configFile, options, DefaultLogger())
}
