// redundancy_removal_test.go: Comprehensive tests before removing redundant code
//
// This file contains exhaustive tests to ensure all functionality is preserved
// when removing redundant configuration and factory code introduced by our
// simplifications. Every redundant function must have equivalent test coverage.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRedundancyRemoval_ConfigurationDefaults tests all default configuration patterns
func TestRedundancyRemoval_ConfigurationDefaults(t *testing.T) {
	t.Run("base_config_defaults_vs_individual_defaults", func(t *testing.T) {
		// Test that BaseConfig defaults match individual component defaults
		baseDefaults := StandardDefaults()

		// Test against existing default functions
		securityConfig := DefaultSecurityConfig()
		envConfig := DefaultEnvConfigOptions()
		dynamicConfig := DefaultDynamicConfigOptions()
		libraryConfig := DefaultLibraryConfigOptions()

		// Verify that timeout patterns are consistent
		assert.Equal(t, baseDefaults.DefaultTimeout, 30*time.Second,
			"StandardDefaults timeout should match expected pattern")

		// Verify that retry patterns are consistent
		assert.Equal(t, baseDefaults.DefaultRetryAttempts, 3,
			"StandardDefaults retry attempts should match expected pattern")

		// Verify that log level patterns are consistent
		assert.Equal(t, baseDefaults.DefaultLogLevel, "info",
			"StandardDefaults log level should match expected pattern")

		// Test that individual configs have reasonable defaults
		assert.NotEmpty(t, securityConfig, "SecurityConfig should have defaults")
		assert.NotEmpty(t, envConfig, "EnvConfigOptions should have defaults")
		assert.NotEmpty(t, dynamicConfig, "DynamicConfigOptions should have defaults")
		assert.NotEmpty(t, libraryConfig, "LibraryConfigOptions should have defaults")
	})

	t.Run("apply_defaults_functionality", func(t *testing.T) {
		// Test BaseConfig.ApplyDefaults vs individual ApplyDefaults methods

		// Test BaseConfig approach
		baseConfig := BaseConfig{}
		baseConfig.ApplyDefaults()

		assert.Equal(t, 30*time.Second, baseConfig.Timeout)
		assert.Equal(t, 3, baseConfig.RetryAttempts)
		assert.Equal(t, "info", baseConfig.LogLevel)

		// Test that WithDefaults works
		configWithDefaults := BaseConfig{}.WithDefaults()
		assert.Equal(t, baseConfig, configWithDefaults)

		// Test SubprocessManagerConfig defaults
		subprocessConfig := SubprocessManagerConfig{}
		subprocessConfig.ApplyDefaults()

		assert.Equal(t, 30*time.Second, subprocessConfig.BaseConfig.Timeout)
		assert.NotEmpty(t, subprocessConfig.HandshakeConfig.MagicCookieKey)
		assert.Greater(t, subprocessConfig.StreamConfig.BufferSize, 0)
	})
}

// TestRedundancyRemoval_FactoryPatterns tests factory creation patterns
func TestRedundancyRemoval_FactoryPatterns(t *testing.T) {
	t.Run("unified_factory_vs_individual_factories", func(t *testing.T) {
		// Test that UnifiedPluginFactory can replace individual factories

		// Test individual subprocess factory
		subprocessFactory := NewSubprocessPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		assert.NotNil(t, subprocessFactory)

		supportedTransports := subprocessFactory.SupportedTransports()
		assert.Contains(t, supportedTransports, string(TransportExecutable))

		// Test unified factory
		unifiedFactory := NewUnifiedPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		assert.NotNil(t, unifiedFactory)

		unifiedTransports := unifiedFactory.GetSupportedTransports()
		assert.Contains(t, unifiedTransports, string(TransportExecutable))

		// Verify unified factory supports same transports as individual factories
		for _, transport := range supportedTransports {
			assert.Contains(t, unifiedTransports, transport,
				"Unified factory should support all transports from subprocess factory")
		}
	})

	t.Run("factory_creation_equivalence", func(t *testing.T) {
		// Test that both factories create equivalent plugins

		config := PluginConfig{
			Name:       "test-plugin",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Endpoint:   "/bin/echo", // Safe executable for testing
			Executable: "/bin/echo", // Required field
			Enabled:    true,
		}

		// Validate config works with both factories
		subprocessFactory := NewSubprocessPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		err := subprocessFactory.ValidateConfig(config)
		assert.NoError(t, err, "Individual factory should validate config")

		unifiedFactory := NewUnifiedPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		// Note: UnifiedFactory doesn't have ValidateConfig method,
		// but it should validate internally during CreatePlugin

		// Both should be able to create plugins (though they may fail due to executable)
		// We're testing the creation logic, not the actual execution
		_, err1 := subprocessFactory.CreatePlugin(config)
		_, err2 := unifiedFactory.CreatePlugin(config)

		// Both should handle the same way (both succeed or both fail with similar errors)
		if err1 == nil {
			assert.NoError(t, err2, "Both factories should succeed if one succeeds")
		} else {
			assert.Error(t, err2, "Both factories should fail if one fails")
		}
	})

	t.Run("convenience_factory_functions", func(t *testing.T) {
		// Test convenience functions from factory_unified.go

		simpleSubprocessFactory := NewSimpleSubprocessFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		assert.NotNil(t, simpleSubprocessFactory)

		simpleGRPCFactory := NewSimpleGRPCFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		assert.NotNil(t, simpleGRPCFactory)

		multiTransportFactory := NewMultiTransportFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		assert.NotNil(t, multiTransportFactory)

		// Verify they return proper types
		assert.Implements(t, (*PluginFactory[RedundancyTestRequest, RedundancyTestResponse])(nil), simpleSubprocessFactory)
		assert.Implements(t, (*PluginFactory[RedundancyTestRequest, RedundancyTestResponse])(nil), simpleGRPCFactory)
		assert.IsType(t, &UnifiedPluginFactory[RedundancyTestRequest, RedundancyTestResponse]{}, multiTransportFactory)
	})
}

// TestRedundancyRemoval_ConfigurationHelpers tests configuration helper utilities
func TestRedundancyRemoval_ConfigurationHelpers(t *testing.T) {
	t.Run("configuration_helper_methods", func(t *testing.T) {
		helper := NewConfigurationHelper(nil)
		assert.NotNil(t, helper)

		// Test timeout defaults
		defaultTimeout := helper.ApplyTimeoutDefault(0)
		assert.Equal(t, 30*time.Second, defaultTimeout)

		customTimeout := helper.ApplyTimeoutDefault(5 * time.Second)
		assert.Equal(t, 5*time.Second, customTimeout)

		// Test retry defaults
		defaultRetries := helper.ApplyRetryDefault(0)
		assert.Equal(t, 3, defaultRetries)

		customRetries := helper.ApplyRetryDefault(5)
		assert.Equal(t, 5, customRetries)

		// Test log level defaults
		defaultLogLevel := helper.ApplyLogLevelDefault("")
		assert.Equal(t, "info", defaultLogLevel)

		customLogLevel := helper.ApplyLogLevelDefault("debug")
		assert.Equal(t, "debug", customLogLevel)

		// Test enabled defaults
		defaultEnabled := helper.ApplyEnabledDefault(nil)
		assert.True(t, defaultEnabled)

		falseValue := false
		explicitFalse := helper.ApplyEnabledDefault(&falseValue)
		assert.False(t, explicitFalse)
	})

	t.Run("global_convenience_functions", func(t *testing.T) {
		// Test global convenience functions
		timeout := ApplyStandardTimeout(0)
		assert.Equal(t, 30*time.Second, timeout)

		retries := ApplyStandardRetries(0)
		assert.Equal(t, 3, retries)

		logLevel := ApplyStandardLogLevel("")
		assert.Equal(t, "info", logLevel)

		// Test validation functions
		err := ValidateStandardTimeout(10 * time.Second)
		assert.NoError(t, err)

		err = ValidateStandardTimeout(-1 * time.Second)
		assert.Error(t, err)

		err = ValidateStandardRetries(3)
		assert.NoError(t, err)

		err = ValidateStandardRetries(-1)
		assert.Error(t, err)
	})
}

// TestRedundancyRemoval_FactoryBuilder tests the factory builder pattern
func TestRedundancyRemoval_FactoryBuilder(t *testing.T) {
	t.Run("factory_builder_functionality", func(t *testing.T) {
		// Test factory builder pattern
		builder := NewFactoryBuilder[RedundancyTestRequest, RedundancyTestResponse]()
		assert.NotNil(t, builder)

		// Test builder methods
		builder = builder.WithLogger(nil)
		assert.NotNil(t, builder)

		// Test custom factory registration
		customFactory := func(config PluginConfig) (Plugin[RedundancyTestRequest, RedundancyTestResponse], error) {
			return nil, NewPluginCreationError("test factory", nil)
		}

		builder = builder.WithCustomFactory("custom", customFactory)
		assert.NotNil(t, builder)

		// Build the factory
		factory := builder.Build()
		assert.NotNil(t, factory)

		// Verify custom factory is registered
		transports := factory.GetSupportedTransports()
		assert.Contains(t, transports, "custom")
	})

	t.Run("custom_factory_registration", func(t *testing.T) {
		factory := NewUnifiedPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)

		// Test custom factory registration
		customFactory := func(config PluginConfig) (Plugin[RedundancyTestRequest, RedundancyTestResponse], error) {
			return nil, NewPluginCreationError("custom factory test", nil)
		}

		err := factory.RegisterCustomFactory("test-transport", customFactory)
		assert.NoError(t, err)

		// Test invalid registrations
		err = factory.RegisterCustomFactory("", customFactory)
		assert.Error(t, err, "Empty transport type should be rejected")

		err = factory.RegisterCustomFactory("test-transport", nil)
		assert.Error(t, err, "Nil factory function should be rejected")

		// Verify registration worked
		transports := factory.GetSupportedTransports()
		assert.Contains(t, transports, "test-transport")
	})
}

// TestRedundancyRemoval_SubprocessManagerIntegration tests subprocess manager integration
func TestRedundancyRemoval_SubprocessManagerIntegration(t *testing.T) {
	t.Run("subprocess_manager_vs_individual_managers", func(t *testing.T) {
		// Test that SubprocessManager can replace individual manager functionality

		config := SubprocessManagerConfig{
			BaseConfig:      BaseConfig{}.WithDefaults(),
			ExecutablePath:  "/bin/echo",
			Args:            []string{"test"},
			HandshakeConfig: DefaultHandshakeConfig,
			StreamConfig:    DefaultStreamSyncConfig,
			BridgeConfig:    DefaultBridgeConfig,
		}

		manager := NewSubprocessManager(config)
		assert.NotNil(t, manager)

		// Test adapter methods that replace individual manager functionality
		assert.False(t, manager.IsStarted(), "Manager should start as not started")
		assert.False(t, manager.IsStopping(), "Manager should start as not stopping")
		assert.False(t, manager.IsAlive(), "Manager should start as not alive")

		processInfo := manager.GetProcessInfo()
		assert.NotNil(t, processInfo)
		assert.Equal(t, StatusStopped, processInfo.Status)

		// Test configuration accessors
		handshakeConfig := manager.GetHandshakeConfig()
		assert.NotEmpty(t, handshakeConfig.MagicCookieKey)

		streamConfig := manager.GetStreamConfig()
		assert.Greater(t, streamConfig.BufferSize, 0)

		// Test component accessors
		assert.NotNil(t, manager.GetHandshakeManager())
		assert.NotNil(t, manager.GetStreamSyncer())
		assert.NotNil(t, manager.GetCommunicationBridge())
	})

	t.Run("subprocess_manager_lifecycle", func(t *testing.T) {
		// Test complete lifecycle without actually starting processes
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/bin/echo"

		manager := NewSubprocessManager(config)
		assert.NotNil(t, manager)

		// Test configuration validation
		err := config.Validate()
		assert.NoError(t, err, "Default config should be valid")

		// Test restart functionality (should handle not-started state gracefully)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_ = manager.Restart(ctx)
		// This may fail due to executable issues, but should not panic
		assert.NotPanics(t, func() {
			_ = manager.Restart(ctx)
		}, "Restart should not panic even if it fails")
	})
}

// TestRedundancyRemoval_BackwardCompatibility tests that removing redundant code doesn't break existing usage
func TestRedundancyRemoval_BackwardCompatibility(t *testing.T) {
	t.Run("existing_factory_usage_patterns", func(t *testing.T) {
		// Test that existing code patterns still work

		// Pattern 1: Direct factory creation (common in existing code)
		factory1 := NewSubprocessPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		assert.NotNil(t, factory1)

		// Pattern 2: Manager registration (common in existing code)
		manager := NewManager[RedundancyTestRequest, RedundancyTestResponse](nil)
		err := manager.RegisterFactory("subprocess", factory1)
		assert.NoError(t, err)

		// Pattern 3: Config validation (must continue to work)
		config := PluginConfig{
			Name:       "test",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Endpoint:   "/bin/echo",
			Executable: "/bin/echo", // Required field
		}

		err = factory1.ValidateConfig(config)
		assert.NoError(t, err, "Existing validation patterns must continue to work")
	})

	t.Run("existing_configuration_patterns", func(t *testing.T) {
		// Test that existing configuration patterns still work

		// Pattern 1: Default config creation (common in existing code)
		defaultManager := GetDefaultManagerConfig()
		assert.NotNil(t, defaultManager)

		// Pattern 2: Config validation (must continue to work)
		err := defaultManager.Validate()
		assert.Error(t, err, "Empty plugin list should be invalid")

		// Pattern 3: Individual component defaults (must continue to work)
		securityConfig := DefaultSecurityConfig()
		// Note: SecurityConfig doesn't have Validate method, just check it's not empty
		assert.NotEmpty(t, securityConfig, "Default security config should not be empty")

		envConfig := DefaultEnvConfigOptions()
		assert.NotEmpty(t, envConfig, "Default env config should not be empty")
	})
}

// TestRedundancyRemoval_ErrorHandling tests that error handling remains consistent
func TestRedundancyRemoval_ErrorHandling(t *testing.T) {
	t.Run("config_validation_errors", func(t *testing.T) {
		// Test that validation errors are consistent between old and new patterns

		// Test BaseConfig validation
		invalidBaseConfig := BaseConfig{
			Timeout:       -1 * time.Second, // Invalid
			RetryAttempts: -1,               // Invalid
			LogLevel:      "invalid",        // Invalid
		}

		err := invalidBaseConfig.Validate()
		assert.Error(t, err, "Invalid BaseConfig should fail validation")

		// Test SubprocessManagerConfig validation
		invalidSubprocessConfig := SubprocessManagerConfig{
			BaseConfig:     invalidBaseConfig,
			ExecutablePath: "", // Invalid - empty path
		}

		err = invalidSubprocessConfig.Validate()
		assert.Error(t, err, "Invalid SubprocessManagerConfig should fail validation")
	})

	t.Run("factory_creation_errors", func(t *testing.T) {
		// Test that factory creation errors are handled consistently

		factory := NewUnifiedPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)

		// Test invalid config
		invalidConfig := PluginConfig{
			Name:      "", // Invalid - empty name
			Transport: TransportExecutable,
			Endpoint:  "/nonexistent",
		}

		_, err := factory.CreatePlugin(invalidConfig)
		assert.Error(t, err, "Invalid config should cause creation to fail")

		// Test unsupported transport
		unsupportedConfig := PluginConfig{
			Name:       "test",
			Transport:  "unsupported-transport",
			Endpoint:   "/bin/echo",
			Executable: "/bin/echo",
		}

		_, err = factory.CreatePlugin(unsupportedConfig)
		assert.Error(t, err, "Unsupported transport should cause creation to fail")
		// The error message may vary, just ensure it's an error
		assert.NotEmpty(t, err.Error(), "Error should have a message")
	})
}

// TestRedundancyRemoval_Integration tests end-to-end functionality
func TestRedundancyRemoval_Integration(t *testing.T) {
	t.Run("complete_workflow_with_new_components", func(t *testing.T) {
		// Test complete workflow using new simplified components

		// Create manager
		manager := NewManager[RedundancyTestRequest, RedundancyTestResponse](nil)

		// Use individual factory for now (unified factory doesn't implement PluginFactory interface)
		factory := NewSubprocessPluginFactory[RedundancyTestRequest, RedundancyTestResponse](nil)
		err := manager.RegisterFactory("subprocess", factory)
		assert.NoError(t, err)

		// Create config using BaseConfig patterns
		config := ManagerConfig{
			Plugins: []PluginConfig{
				{
					Name:      "test-plugin",
					Type:      "subprocess",
					Transport: TransportExecutable,
					Endpoint:  "/bin/echo",
					Enabled:   true,
					HealthCheck: HealthCheckConfig{
						Enabled:  true,
						Interval: ApplyStandardTimeout(0), // Use new helper
						Timeout:  5 * time.Second,
					},
					Retry: RetryConfig{
						MaxRetries: ApplyStandardRetries(0), // Use new helper
					},
				},
			},
		}

		// This may fail due to executable issues, but should not panic
		err = manager.LoadFromConfig(config)
		if err != nil {
			// Expected on systems without /bin/echo, but should be proper error
			assert.Contains(t, err.Error(), "validation", "Should be validation error")
		}

		// Test observability still works
		metrics := manager.GetObservabilityMetrics()
		assert.NotNil(t, metrics)
		assert.Contains(t, metrics, "manager")
	})
}

// Helper types for testing (using different names to avoid conflicts)
type RedundancyTestRequest struct {
	Action string            `json:"action"`
	Data   map[string]string `json:"data"`
}

type RedundancyTestResponse struct {
	Status string            `json:"status"`
	Result map[string]string `json:"result"`
}
