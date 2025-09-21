// config_base_test.go: Comprehensive tests for base configuration system
//
// This file provides complete test coverage for the config_base.go module,
// testing all configuration defaults, validation, and helper functions.
// Following systematic "piano piano studiando tutto" methodology.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"testing"
	"time"
)

// TestStandardDefaults tests the StandardDefaults function for correct default values
func TestStandardDefaults(t *testing.T) {
	t.Run("CorrectDefaultValues", func(t *testing.T) {
		defaults := StandardDefaults()

		if defaults.DefaultTimeout != 30*time.Second {
			t.Errorf("Expected default timeout 30s, got %v", defaults.DefaultTimeout)
		}

		if defaults.DefaultRetryAttempts != 3 {
			t.Errorf("Expected default retry attempts 3, got %d", defaults.DefaultRetryAttempts)
		}

		if defaults.DefaultLogLevel != "info" {
			t.Errorf("Expected default log level 'info', got '%s'", defaults.DefaultLogLevel)
		}

		if defaults.DefaultEnabled != true {
			t.Errorf("Expected default enabled true, got %v", defaults.DefaultEnabled)
		}
	})
}

// TestBaseConfig_ApplyDefaults tests the BaseConfig ApplyDefaults method
func TestBaseConfig_ApplyDefaults(t *testing.T) {
	t.Run("ApplyAllDefaults", func(t *testing.T) {
		config := &BaseConfig{}
		config.ApplyDefaults()

		if config.Timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", config.Timeout)
		}

		if config.RetryAttempts != 3 {
			t.Errorf("Expected retry attempts 3, got %d", config.RetryAttempts)
		}

		if config.LogLevel != "info" {
			t.Errorf("Expected log level 'info', got '%s'", config.LogLevel)
		}
	})

	t.Run("PreserveExistingValues", func(t *testing.T) {
		config := &BaseConfig{
			Timeout:       10 * time.Second,
			RetryAttempts: 5,
			LogLevel:      "debug",
		}
		config.ApplyDefaults()

		if config.Timeout != 10*time.Second {
			t.Errorf("Expected preserved timeout 10s, got %v", config.Timeout)
		}

		if config.RetryAttempts != 5 {
			t.Errorf("Expected preserved retry attempts 5, got %d", config.RetryAttempts)
		}

		if config.LogLevel != "debug" {
			t.Errorf("Expected preserved log level 'debug', got '%s'", config.LogLevel)
		}
	})
}

// TestBaseConfig_Validate tests the BaseConfig Validate method
func TestBaseConfig_Validate(t *testing.T) {
	t.Run("ValidConfiguration", func(t *testing.T) {
		config := &BaseConfig{
			Timeout:       30 * time.Second,
			RetryAttempts: 3,
			LogLevel:      "info",
			Enabled:       true,
		}

		if err := config.Validate(); err != nil {
			t.Errorf("Valid configuration should not return error, got: %v", err)
		}
	})

	t.Run("NegativeTimeout", func(t *testing.T) {
		config := &BaseConfig{
			Timeout: -5 * time.Second,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Negative timeout should return validation error")
		}

		if err != nil && err.Error() != "[CONFIG_1703]: Configuration validation error: timeout cannot be negative" {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("NegativeRetryAttempts", func(t *testing.T) {
		config := &BaseConfig{
			RetryAttempts: -1,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Negative retry attempts should return validation error")
		}

		if err != nil && err.Error() != "[CONFIG_1703]: Configuration validation error: retry_attempts cannot be negative" {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("InvalidLogLevel", func(t *testing.T) {
		config := &BaseConfig{
			LogLevel: "invalid",
		}

		err := config.Validate()
		if err == nil {
			t.Error("Invalid log level should return validation error")
		}

		expected := "[CONFIG_1703]: Configuration validation error: invalid log_level, must be one of: debug, info, warn, error, fatal"
		if err != nil && err.Error() != expected {
			t.Errorf("Expected error '%s', got '%v'", expected, err)
		}
	})

	t.Run("ValidLogLevels", func(t *testing.T) {
		validLevels := []string{"debug", "info", "warn", "error", "fatal"}

		for _, level := range validLevels {
			config := &BaseConfig{LogLevel: level}
			if err := config.Validate(); err != nil {
				t.Errorf("Valid log level '%s' should not return error, got: %v", level, err)
			}
		}
	})

	t.Run("EmptyLogLevel", func(t *testing.T) {
		config := &BaseConfig{LogLevel: ""}
		if err := config.Validate(); err != nil {
			t.Errorf("Empty log level should be valid, got error: %v", err)
		}
	})
}

// TestBaseConfig_WithDefaults tests the WithDefaults method
func TestBaseConfig_WithDefaults(t *testing.T) {
	t.Run("CreatesNewConfigWithDefaults", func(t *testing.T) {
		original := BaseConfig{
			Timeout: 10 * time.Second,
		}

		withDefaults := original.WithDefaults()

		// Original should be unchanged
		if original.RetryAttempts != 0 {
			t.Errorf("Original config should be unchanged, got RetryAttempts: %d", original.RetryAttempts)
		}

		// New config should have defaults applied
		if withDefaults.Timeout != 10*time.Second {
			t.Errorf("Expected preserved timeout 10s, got %v", withDefaults.Timeout)
		}

		if withDefaults.RetryAttempts != 3 {
			t.Errorf("Expected default retry attempts 3, got %d", withDefaults.RetryAttempts)
		}

		if withDefaults.LogLevel != "info" {
			t.Errorf("Expected default log level 'info', got '%s'", withDefaults.LogLevel)
		}
	})
}

// TestNewConfigurationHelper tests the ConfigurationHelper creation
func TestNewConfigurationHelper(t *testing.T) {
	t.Run("WithNilDefaults", func(t *testing.T) {
		helper := NewConfigurationHelper(nil)
		if helper == nil {
			t.Fatal("Helper should not be nil")
		}

		// Should use StandardDefaults
		if helper.defaults.DefaultTimeout != 30*time.Second {
			t.Errorf("Expected standard default timeout, got %v", helper.defaults.DefaultTimeout)
		}
	})

	t.Run("WithCustomDefaults", func(t *testing.T) {
		customDefaults := &ConfigDefaults{
			DefaultTimeout:       60 * time.Second,
			DefaultRetryAttempts: 5,
			DefaultLogLevel:      "debug",
			DefaultEnabled:       false,
		}

		helper := NewConfigurationHelper(customDefaults)
		if helper == nil {
			t.Fatal("Helper should not be nil")
		}

		if helper.defaults.DefaultTimeout != 60*time.Second {
			t.Errorf("Expected custom timeout 60s, got %v", helper.defaults.DefaultTimeout)
		}

		if helper.defaults.DefaultRetryAttempts != 5 {
			t.Errorf("Expected custom retry attempts 5, got %d", helper.defaults.DefaultRetryAttempts)
		}

		if helper.defaults.DefaultLogLevel != "debug" {
			t.Errorf("Expected custom log level 'debug', got '%s'", helper.defaults.DefaultLogLevel)
		}

		if helper.defaults.DefaultEnabled != false {
			t.Errorf("Expected custom enabled false, got %v", helper.defaults.DefaultEnabled)
		}
	})
}

// TestConfigurationHelper_ApplyTimeoutDefault tests timeout default application
func TestConfigurationHelper_ApplyTimeoutDefault(t *testing.T) {
	helper := NewConfigurationHelper(nil)

	t.Run("ApplyDefaultForZeroValue", func(t *testing.T) {
		result := helper.ApplyTimeoutDefault(0)
		if result != 30*time.Second {
			t.Errorf("Expected default timeout 30s, got %v", result)
		}
	})

	t.Run("PreserveNonZeroValue", func(t *testing.T) {
		custom := 45 * time.Second
		result := helper.ApplyTimeoutDefault(custom)
		if result != custom {
			t.Errorf("Expected preserved timeout %v, got %v", custom, result)
		}
	})
}

// TestConfigurationHelper_ApplyRetryDefault tests retry default application
func TestConfigurationHelper_ApplyRetryDefault(t *testing.T) {
	helper := NewConfigurationHelper(nil)

	t.Run("ApplyDefaultForZeroValue", func(t *testing.T) {
		result := helper.ApplyRetryDefault(0)
		if result != 3 {
			t.Errorf("Expected default retry attempts 3, got %d", result)
		}
	})

	t.Run("PreserveNonZeroValue", func(t *testing.T) {
		custom := 7
		result := helper.ApplyRetryDefault(custom)
		if result != custom {
			t.Errorf("Expected preserved retry attempts %d, got %d", custom, result)
		}
	})
}

// TestConfigurationHelper_ApplyLogLevelDefault tests log level default application
func TestConfigurationHelper_ApplyLogLevelDefault(t *testing.T) {
	helper := NewConfigurationHelper(nil)

	t.Run("ApplyDefaultForEmptyValue", func(t *testing.T) {
		result := helper.ApplyLogLevelDefault("")
		if result != "info" {
			t.Errorf("Expected default log level 'info', got '%s'", result)
		}
	})

	t.Run("PreserveNonEmptyValue", func(t *testing.T) {
		custom := "debug"
		result := helper.ApplyLogLevelDefault(custom)
		if result != custom {
			t.Errorf("Expected preserved log level '%s', got '%s'", custom, result)
		}
	})
}

// TestConfigurationHelper_ApplyEnabledDefault tests enabled default application
func TestConfigurationHelper_ApplyEnabledDefault(t *testing.T) {
	helper := NewConfigurationHelper(nil)

	t.Run("ApplyDefaultForNilValue", func(t *testing.T) {
		result := helper.ApplyEnabledDefault(nil)
		if result != true {
			t.Errorf("Expected default enabled true, got %v", result)
		}
	})

	t.Run("PreserveFalseValue", func(t *testing.T) {
		custom := false
		result := helper.ApplyEnabledDefault(&custom)
		if result != false {
			t.Errorf("Expected preserved enabled false, got %v", result)
		}
	})

	t.Run("PreserveTrueValue", func(t *testing.T) {
		custom := true
		result := helper.ApplyEnabledDefault(&custom)
		if result != true {
			t.Errorf("Expected preserved enabled true, got %v", result)
		}
	})
}

// TestConfigurationHelper_ValidateTimeout tests timeout validation
func TestConfigurationHelper_ValidateTimeout(t *testing.T) {
	helper := NewConfigurationHelper(nil)

	t.Run("ValidPositiveTimeout", func(t *testing.T) {
		if err := helper.ValidateTimeout(30 * time.Second); err != nil {
			t.Errorf("Valid positive timeout should not return error, got: %v", err)
		}
	})

	t.Run("ValidZeroTimeout", func(t *testing.T) {
		if err := helper.ValidateTimeout(0); err != nil {
			t.Errorf("Zero timeout should be valid, got: %v", err)
		}
	})

	t.Run("InvalidNegativeTimeout", func(t *testing.T) {
		err := helper.ValidateTimeout(-5 * time.Second)
		if err == nil {
			t.Error("Negative timeout should return validation error")
		}

		expected := "[CONFIG_1703]: Configuration validation error: timeout cannot be negative"
		if err != nil && err.Error() != expected {
			t.Errorf("Expected error '%s', got '%v'", expected, err)
		}
	})

	t.Run("VeryLongTimeoutStillValid", func(t *testing.T) {
		// Should not return error even for very long timeouts (2 hours)
		if err := helper.ValidateTimeout(2 * time.Hour); err != nil {
			t.Errorf("Very long timeout should still be valid, got: %v", err)
		}
	})
}

// TestConfigurationHelper_ValidateRetryAttempts tests retry attempts validation
func TestConfigurationHelper_ValidateRetryAttempts(t *testing.T) {
	helper := NewConfigurationHelper(nil)

	t.Run("ValidPositiveRetries", func(t *testing.T) {
		if err := helper.ValidateRetryAttempts(3); err != nil {
			t.Errorf("Valid positive retry attempts should not return error, got: %v", err)
		}
	})

	t.Run("ValidZeroRetries", func(t *testing.T) {
		if err := helper.ValidateRetryAttempts(0); err != nil {
			t.Errorf("Zero retry attempts should be valid, got: %v", err)
		}
	})

	t.Run("InvalidNegativeRetries", func(t *testing.T) {
		err := helper.ValidateRetryAttempts(-1)
		if err == nil {
			t.Error("Negative retry attempts should return validation error")
		}

		expected := "[CONFIG_1703]: Configuration validation error: retry_attempts cannot be negative"
		if err != nil && err.Error() != expected {
			t.Errorf("Expected error '%s', got '%v'", expected, err)
		}
	})

	t.Run("HighRetryCountStillValid", func(t *testing.T) {
		// Should not return error even for high retry counts (15)
		if err := helper.ValidateRetryAttempts(15); err != nil {
			t.Errorf("High retry count should still be valid, got: %v", err)
		}
	})
}

// TestGlobalHelperFunctions tests the convenience global functions
func TestGlobalHelperFunctions(t *testing.T) {
	t.Run("ApplyStandardTimeout", func(t *testing.T) {
		// Test zero value gets default
		result := ApplyStandardTimeout(0)
		if result != 30*time.Second {
			t.Errorf("Expected standard timeout 30s, got %v", result)
		}

		// Test non-zero value is preserved
		custom := 45 * time.Second
		result = ApplyStandardTimeout(custom)
		if result != custom {
			t.Errorf("Expected preserved timeout %v, got %v", custom, result)
		}
	})

	t.Run("ApplyStandardRetries", func(t *testing.T) {
		// Test zero value gets default
		result := ApplyStandardRetries(0)
		if result != 3 {
			t.Errorf("Expected standard retries 3, got %d", result)
		}

		// Test non-zero value is preserved
		custom := 7
		result = ApplyStandardRetries(custom)
		if result != custom {
			t.Errorf("Expected preserved retries %d, got %d", custom, result)
		}
	})

	t.Run("ApplyStandardLogLevel", func(t *testing.T) {
		// Test empty value gets default
		result := ApplyStandardLogLevel("")
		if result != "info" {
			t.Errorf("Expected standard log level 'info', got '%s'", result)
		}

		// Test non-empty value is preserved
		custom := "debug"
		result = ApplyStandardLogLevel(custom)
		if result != custom {
			t.Errorf("Expected preserved log level '%s', got '%s'", custom, result)
		}
	})

	t.Run("ValidateStandardTimeout", func(t *testing.T) {
		// Test valid timeout
		if err := ValidateStandardTimeout(30 * time.Second); err != nil {
			t.Errorf("Valid timeout should not return error, got: %v", err)
		}

		// Test negative timeout
		err := ValidateStandardTimeout(-5 * time.Second)
		if err == nil {
			t.Error("Negative timeout should return validation error")
		}
	})

	t.Run("ValidateStandardRetries", func(t *testing.T) {
		// Test valid retries
		if err := ValidateStandardRetries(3); err != nil {
			t.Errorf("Valid retries should not return error, got: %v", err)
		}

		// Test negative retries
		err := ValidateStandardRetries(-1)
		if err == nil {
			t.Error("Negative retries should return validation error")
		}
	})
}

// TestConfigurationHelper_CustomDefaults tests behavior with custom defaults
func TestConfigurationHelper_CustomDefaults(t *testing.T) {
	t.Run("CustomDefaultsAppliedCorrectly", func(t *testing.T) {
		customDefaults := &ConfigDefaults{
			DefaultTimeout:       90 * time.Second,
			DefaultRetryAttempts: 7,
			DefaultLogLevel:      "error",
			DefaultEnabled:       false,
		}

		helper := NewConfigurationHelper(customDefaults)

		// Test custom timeout default
		result := helper.ApplyTimeoutDefault(0)
		if result != 90*time.Second {
			t.Errorf("Expected custom timeout 90s, got %v", result)
		}

		// Test custom retry default
		retryResult := helper.ApplyRetryDefault(0)
		if retryResult != 7 {
			t.Errorf("Expected custom retries 7, got %d", retryResult)
		}

		// Test custom log level default
		levelResult := helper.ApplyLogLevelDefault("")
		if levelResult != "error" {
			t.Errorf("Expected custom log level 'error', got '%s'", levelResult)
		}

		// Test custom enabled default
		enabledResult := helper.ApplyEnabledDefault(nil)
		if enabledResult != false {
			t.Errorf("Expected custom enabled false, got %v", enabledResult)
		}
	})
}

// TestEdgeCases tests edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	t.Run("BaseConfigWithMetadata", func(t *testing.T) {
		config := &BaseConfig{
			Metadata: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		}

		// Apply defaults and validate
		config.ApplyDefaults()
		if err := config.Validate(); err != nil {
			t.Errorf("Config with metadata should be valid, got: %v", err)
		}

		// Metadata should be preserved
		if len(config.Metadata) != 2 {
			t.Errorf("Expected metadata length 2, got %d", len(config.Metadata))
		}

		if config.Metadata["key1"] != "value1" {
			t.Errorf("Expected metadata key1=value1, got %s", config.Metadata["key1"])
		}
	})

	t.Run("ExtremeTimeoutValues", func(t *testing.T) {
		helper := NewConfigurationHelper(nil)

		// Test maximum duration
		maxDuration := time.Duration(1<<63 - 1) // Maximum positive duration
		if err := helper.ValidateTimeout(maxDuration); err != nil {
			t.Errorf("Maximum duration should be valid, got: %v", err)
		}

		// Test minimum invalid duration
		minInvalidDuration := time.Duration(-1)
		if err := helper.ValidateTimeout(minInvalidDuration); err == nil {
			t.Error("Minimum negative duration should be invalid")
		}
	})

	t.Run("ExtremeRetryValues", func(t *testing.T) {
		helper := NewConfigurationHelper(nil)

		// Test maximum int value
		if err := helper.ValidateRetryAttempts(int(^uint(0) >> 1)); err != nil {
			t.Errorf("Maximum int value should be valid, got: %v", err)
		}

		// Test minimum invalid value
		if err := helper.ValidateRetryAttempts(-1); err == nil {
			t.Error("Negative retry attempts should be invalid")
		}
	})
}

// TestConfigurationIntegration tests integration scenarios
func TestConfigurationIntegration(t *testing.T) {
	t.Run("CompleteConfigurationWorkflow", func(t *testing.T) {
		// Start with empty config
		config := &BaseConfig{}

		// Apply defaults
		config.ApplyDefaults()

		// Validate
		if err := config.Validate(); err != nil {
			t.Errorf("Default configuration should be valid, got: %v", err)
		}

		// Verify all defaults were applied correctly
		if config.Timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", config.Timeout)
		}

		if config.RetryAttempts != 3 {
			t.Errorf("Expected retry attempts 3, got %d", config.RetryAttempts)
		}

		if config.LogLevel != "info" {
			t.Errorf("Expected log level 'info', got '%s'", config.LogLevel)
		}
	})

	t.Run("PartialConfigurationUpdate", func(t *testing.T) {
		// Start with partial config
		config := &BaseConfig{
			Timeout: 60 * time.Second,
			// Other fields will get defaults
		}

		config.ApplyDefaults()

		// Verify existing value preserved and defaults applied
		if config.Timeout != 60*time.Second {
			t.Errorf("Expected preserved timeout 60s, got %v", config.Timeout)
		}

		if config.RetryAttempts != 3 {
			t.Errorf("Expected default retry attempts 3, got %d", config.RetryAttempts)
		}

		if config.LogLevel != "info" {
			t.Errorf("Expected default log level 'info', got '%s'", config.LogLevel)
		}

		if err := config.Validate(); err != nil {
			t.Errorf("Partial configuration should be valid after defaults, got: %v", err)
		}
	})
}
