// config_base.go: Base configuration structures and common patterns
//
// This file consolidates common configuration patterns to reduce duplication
// and provide a consistent approach to configuration management across
// different components of the plugin system.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"time"
)

// BaseConfig provides common configuration fields used across different components.
//
// This structure contains the most frequently used configuration options
// that appear in multiple component configurations. By centralizing these
// common fields, we reduce duplication and provide consistency.
type BaseConfig struct {
	// Enabled indicates whether the component is active
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Timeout specifies the maximum duration for operations
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// RetryAttempts specifies the number of retry attempts
	RetryAttempts int `json:"retry_attempts" yaml:"retry_attempts"`

	// LogLevel specifies the logging level for this component
	LogLevel string `json:"log_level,omitempty" yaml:"log_level,omitempty"`

	// Metadata provides additional configuration data
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// ConfigDefaults provides default values for common configuration fields.
//
// This structure centralizes default values that are used across different
// configuration types, ensuring consistency and reducing the need for
// multiple DefaultXXXConfig() functions.
type ConfigDefaults struct {
	// Default timeout for operations
	DefaultTimeout time.Duration

	// Default number of retry attempts
	DefaultRetryAttempts int

	// Default log level
	DefaultLogLevel string

	// Default enabled state
	DefaultEnabled bool
}

// StandardDefaults returns the standard default values used across the system.
//
// These defaults provide sensible values for production use while being
// conservative enough for development environments.
func StandardDefaults() ConfigDefaults {
	return ConfigDefaults{
		DefaultTimeout:       30 * time.Second,
		DefaultRetryAttempts: 3,
		DefaultLogLevel:      "info",
		DefaultEnabled:       true,
	}
}

// ApplyDefaults applies default values to a BaseConfig if they are not set.
//
// This method uses the StandardDefaults() to fill in missing values,
// providing a consistent way to apply defaults across different configuration types.
func (bc *BaseConfig) ApplyDefaults() {
	defaults := StandardDefaults()

	if bc.Timeout == 0 {
		bc.Timeout = defaults.DefaultTimeout
	}

	if bc.RetryAttempts == 0 {
		bc.RetryAttempts = defaults.DefaultRetryAttempts
	}

	if bc.LogLevel == "" {
		bc.LogLevel = defaults.DefaultLogLevel
	}

	// Note: Enabled is a bool, so we only set it if it's explicitly false
	// and we want to default to true. In Go, false is the zero value.
}

// Validate performs basic validation on the BaseConfig fields.
//
// This method checks that the configuration values are within reasonable
// bounds and provides early feedback on configuration issues.
func (bc *BaseConfig) Validate() error {
	if bc.Timeout < 0 {
		return NewConfigValidationError("timeout cannot be negative", nil)
	}

	if bc.RetryAttempts < 0 {
		return NewConfigValidationError("retry_attempts cannot be negative", nil)
	}

	validLogLevels := []string{"debug", "info", "warn", "error", "fatal"}
	if bc.LogLevel != "" {
		valid := false
		for _, level := range validLogLevels {
			if bc.LogLevel == level {
				valid = true
				break
			}
		}
		if !valid {
			return NewConfigValidationError("invalid log_level, must be one of: debug, info, warn, error, fatal", nil)
		}
	}

	return nil
}

// WithDefaults creates a new BaseConfig with default values applied.
//
// This is a convenience method for creating a BaseConfig with sensible defaults
// without modifying an existing configuration.
func (bc BaseConfig) WithDefaults() BaseConfig {
	bc.ApplyDefaults()
	return bc
}

// ConfigurationHelper provides utility methods for configuration management.
//
// This helper reduces boilerplate code in configuration handling by providing
// common operations that are used across different configuration types.
type ConfigurationHelper struct {
	defaults ConfigDefaults
}

// NewConfigurationHelper creates a new configuration helper with the given defaults.
//
// If defaults is nil, StandardDefaults() will be used.
func NewConfigurationHelper(defaults *ConfigDefaults) *ConfigurationHelper {
	if defaults == nil {
		std := StandardDefaults()
		defaults = &std
	}

	return &ConfigurationHelper{
		defaults: *defaults,
	}
}

// ApplyTimeoutDefault applies a default timeout if the provided value is zero.
func (ch *ConfigurationHelper) ApplyTimeoutDefault(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return ch.defaults.DefaultTimeout
	}
	return timeout
}

// ApplyRetryDefault applies a default retry count if the provided value is zero.
func (ch *ConfigurationHelper) ApplyRetryDefault(retries int) int {
	if retries == 0 {
		return ch.defaults.DefaultRetryAttempts
	}
	return retries
}

// ApplyLogLevelDefault applies a default log level if the provided value is empty.
func (ch *ConfigurationHelper) ApplyLogLevelDefault(logLevel string) string {
	if logLevel == "" {
		return ch.defaults.DefaultLogLevel
	}
	return logLevel
}

// ApplyEnabledDefault applies a default enabled state.
//
// Since bool has a zero value of false, this method helps distinguish
// between explicitly disabled and unset values.
func (ch *ConfigurationHelper) ApplyEnabledDefault(enabled *bool) bool {
	if enabled == nil {
		return ch.defaults.DefaultEnabled
	}
	return *enabled
}

// ValidateTimeout validates that a timeout value is reasonable.
func (ch *ConfigurationHelper) ValidateTimeout(timeout time.Duration) error {
	if timeout < 0 {
		return NewConfigValidationError("timeout cannot be negative", nil)
	}

	// Warn about extremely long timeouts (more than 1 hour)
	if timeout > time.Hour {
		// This is a warning, not an error - some use cases may need long timeouts
		// The validation just ensures it's not negative
	}

	return nil
}

// ValidateRetryAttempts validates that retry attempts are reasonable.
func (ch *ConfigurationHelper) ValidateRetryAttempts(retries int) error {
	if retries < 0 {
		return NewConfigValidationError("retry_attempts cannot be negative", nil)
	}

	// Warn about excessive retry attempts (more than 10)
	if retries > 10 {
		// This is a warning, not an error - some use cases may need many retries
		// The validation just ensures it's not negative
	}

	return nil
}

// Global configuration helper instance for convenience
var defaultConfigHelper = NewConfigurationHelper(nil)

// ApplyStandardTimeout applies standard timeout defaults to a duration.
func ApplyStandardTimeout(timeout time.Duration) time.Duration {
	return defaultConfigHelper.ApplyTimeoutDefault(timeout)
}

// ApplyStandardRetries applies standard retry defaults to a retry count.
func ApplyStandardRetries(retries int) int {
	return defaultConfigHelper.ApplyRetryDefault(retries)
}

// ApplyStandardLogLevel applies standard log level defaults to a log level string.
func ApplyStandardLogLevel(logLevel string) string {
	return defaultConfigHelper.ApplyLogLevelDefault(logLevel)
}

// ValidateStandardTimeout validates a timeout using standard validation rules.
func ValidateStandardTimeout(timeout time.Duration) error {
	return defaultConfigHelper.ValidateTimeout(timeout)
}

// ValidateStandardRetries validates retry attempts using standard validation rules.
func ValidateStandardRetries(retries int) error {
	return defaultConfigHelper.ValidateRetryAttempts(retries)
}
