// config_validator_test.go: Comprehensive test suite for ConfigValidator implementation
//
// This test suite ensures proper configuration validation functionality including
// field constraints validation, business rules validation, security constraints validation,
// and error handling. Tests are designed to be deterministic and CI-friendly.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// getAbsolutePath returns an absolute path that works cross-platform
func getAbsolutePath(name string) string {
	tempDir := os.TempDir()
	return filepath.Join(tempDir, name)
}

// getSystemPath returns a system-specific path that should be forbidden
func getSystemPath() string {
	if filepath.Separator == '\\' {
		// Windows
		return "C:\\Windows\\System32\\drivers\\etc\\hosts"
	}
	// Unix-like systems
	return "/etc/passwd"
}

// TestRequest mock request type for testing
type TestValidatorRequest struct {
	TestField string `json:"test_field"`
}

// TestResponse mock response type for testing
type TestValidatorResponse struct {
	Result string `json:"result"`
}

// TestConfigValidator_Creation tests ConfigValidator creation
func TestConfigValidator_Creation(t *testing.T) {
	t.Run("NewConfigValidator_Initialization", func(t *testing.T) {
		validator := NewConfigValidator[TestValidatorRequest, TestValidatorResponse]()

		if validator == nil {
			t.Fatal("Expected validator to be initialized")
		}
	})
}

// TestConfigValidator_ValidateLibraryConfig tests the main validation orchestrator
func TestConfigValidator_ValidateLibraryConfig(t *testing.T) {
	validator := NewConfigValidator[TestValidatorRequest, TestValidatorResponse]()

	t.Run("ValidConfig_AllPhasesPass", func(t *testing.T) {
		config := LibraryConfig{
			Logging: LoggingConfig{
				Level: "info",
			},
			Observability: ObservabilityRuntimeConfig{
				TracingSampleRate: 0.5,
				MetricsInterval:   2 * time.Second,
			},
			Performance: PerformanceConfig{
				WatcherPollInterval:       5 * time.Second,
				MaxConcurrentHealthChecks: 3,
			},
			DefaultPolicies: DefaultPoliciesConfig{
				Retry: RetryConfig{
					MaxRetries:      3,
					InitialInterval: 1 * time.Second,
					MaxInterval:     10 * time.Second,
					Multiplier:      2.0,
				},
				CircuitBreaker: CircuitBreakerConfig{
					FailureThreshold:    5,
					RecoveryTimeout:     30 * time.Second,
					MinRequestThreshold: 10,
					SuccessThreshold:    3,
					Enabled:             true,
				},
				HealthCheck: HealthCheckConfig{
					Interval:     30 * time.Second,
					Timeout:      5 * time.Second,
					FailureLimit: 3,
					Enabled:      true,
				},
				Connection: ConnectionConfig{
					MaxConnections:     100,
					MaxIdleConnections: 10,
					IdleTimeout:        5 * time.Minute,
					ConnectionTimeout:  10 * time.Second,
					RequestTimeout:     30 * time.Second,
				},
				RateLimit: RateLimitConfig{
					RequestsPerSecond: 100.0,
					BurstSize:         10,
					TimeWindow:        1 * time.Minute,
					Enabled:           true,
				},
			},
			Security: SecurityConfig{
				Policy:         SecurityPolicyPermissive,
				WhitelistFile:  getAbsolutePath("whitelist.json"),
				HashAlgorithm:  HashAlgorithmSHA256,
				MaxFileSize:    1024 * 1024,
				AllowedTypes:   []string{"plugin"},
				ForbiddenPaths: []string{getSystemPath()},
				ReloadDelay:    5 * time.Second,
				AuditConfig: SecurityAuditConfig{
					Enabled:   true,
					AuditFile: getAbsolutePath("audit.log"),
				},
			},
		}

		err := validator.ValidateLibraryConfig(config)
		if err != nil {
			t.Errorf("Expected valid configuration, got error: %v", err)
		}
	})

	t.Run("InvalidLogging_FieldValidationFails", func(t *testing.T) {
		config := LibraryConfig{
			Logging: LoggingConfig{
				Level: "invalid-level", // Invalid logging level
			},
			Observability: ObservabilityRuntimeConfig{
				TracingSampleRate: 0.5,
				MetricsInterval:   2 * time.Second,
			},
			Performance: PerformanceConfig{
				WatcherPollInterval:       5 * time.Second,
				MaxConcurrentHealthChecks: 3,
			},
		}

		err := validator.ValidateLibraryConfig(config)
		if err == nil {
			t.Fatal("Expected field validation error for invalid logging level")
		}

		if !strings.Contains(err.Error(), "field validation failed") {
			t.Errorf("Expected field validation error, got: %v", err)
		}
	})

	t.Run("InvalidBusinessRules_BusinessRuleValidationFails", func(t *testing.T) {
		config := LibraryConfig{
			Logging: LoggingConfig{
				Level: "info",
			},
			Observability: ObservabilityRuntimeConfig{
				TracingSampleRate: 0.5,
				MetricsInterval:   2 * time.Second,
			},
			Performance: PerformanceConfig{
				WatcherPollInterval:       5 * time.Second,
				MaxConcurrentHealthChecks: 3,
			},
			DefaultPolicies: DefaultPoliciesConfig{
				Retry: RetryConfig{
					MaxRetries:      3,
					InitialInterval: 10 * time.Second, // Invalid: InitialInterval > MaxInterval
					MaxInterval:     5 * time.Second,
					Multiplier:      2.0,
				},
			},
		}

		err := validator.ValidateLibraryConfig(config)
		if err == nil {
			t.Fatal("Expected business rule validation error")
		}

		if !strings.Contains(err.Error(), "business rule validation failed") {
			t.Errorf("Expected business rule validation error, got: %v", err)
		}
	})

	t.Run("InvalidSecurity_SecurityValidationFails", func(t *testing.T) {
		config := LibraryConfig{
			Logging: LoggingConfig{
				Level: "info",
			},
			Observability: ObservabilityRuntimeConfig{
				TracingSampleRate: 0.5,
				MetricsInterval:   2 * time.Second,
			},
			Performance: PerformanceConfig{
				WatcherPollInterval:       5 * time.Second,
				MaxConcurrentHealthChecks: 3,
			},
			DefaultPolicies: DefaultPoliciesConfig{
				Retry: RetryConfig{
					MaxRetries:      3,
					InitialInterval: 1 * time.Second,
					MaxInterval:     10 * time.Second,
					Multiplier:      2.0,
				},
			},
			Security: SecurityConfig{
				Policy:        SecurityPolicy(99), // Invalid security policy
				WhitelistFile: getAbsolutePath("whitelist.json"),
			},
		}

		err := validator.ValidateLibraryConfig(config)
		if err == nil {
			t.Fatal("Expected security validation error")
		}

		if !strings.Contains(err.Error(), "security validation failed") {
			t.Errorf("Expected security validation error, got: %v", err)
		}
	})
}

// TestConfigValidator_FieldConstraints tests field-level validation
func TestConfigValidator_FieldConstraints(t *testing.T) {
	validator := NewConfigValidator[TestValidatorRequest, TestValidatorResponse]()

	t.Run("LoggingConstraints_ValidLevels", func(t *testing.T) {
		validLevels := []string{"debug", "info", "warn", "error"}

		for _, level := range validLevels {
			config := LoggingConfig{Level: level}
			err := validator.validateLoggingConstraints(config)
			if err != nil {
				t.Errorf("Expected level %s to be valid, got error: %v", level, err)
			}
		}
	})

	t.Run("LoggingConstraints_EmptyLevel", func(t *testing.T) {
		config := LoggingConfig{Level: ""} // Empty level should be allowed
		err := validator.validateLoggingConstraints(config)
		if err != nil {
			t.Errorf("Expected empty level to be valid, got error: %v", err)
		}
	})

	t.Run("LoggingConstraints_InvalidLevel", func(t *testing.T) {
		config := LoggingConfig{Level: "trace"} // Invalid level
		err := validator.validateLoggingConstraints(config)
		if err == nil {
			t.Error("Expected error for invalid logging level")
		}
		if !strings.Contains(err.Error(), "invalid log level") {
			t.Errorf("Expected invalid log level error, got: %v", err)
		}
	})

	t.Run("ObservabilityConstraints_ValidTracingSampleRate", func(t *testing.T) {
		validRates := []float64{0.0, 0.5, 1.0}

		for _, rate := range validRates {
			config := ObservabilityRuntimeConfig{
				TracingSampleRate: rate,
				MetricsInterval:   2 * time.Second,
			}
			err := validator.validateObservabilityConstraints(config)
			if err != nil {
				t.Errorf("Expected rate %f to be valid, got error: %v", rate, err)
			}
		}
	})

	t.Run("ObservabilityConstraints_InvalidTracingSampleRate", func(t *testing.T) {
		invalidRates := []float64{-0.1, 1.1, 2.0}

		for _, rate := range invalidRates {
			config := ObservabilityRuntimeConfig{
				TracingSampleRate: rate,
				MetricsInterval:   2 * time.Second,
			}
			err := validator.validateObservabilityConstraints(config)
			if err == nil {
				t.Errorf("Expected error for invalid rate %f", rate)
			}
			if !strings.Contains(err.Error(), "invalid tracing sample rate") {
				t.Errorf("Expected tracing sample rate error, got: %v", err)
			}
		}
	})

	t.Run("ObservabilityConstraints_InvalidMetricsInterval", func(t *testing.T) {
		config := ObservabilityRuntimeConfig{
			TracingSampleRate: 0.5,
			MetricsInterval:   500 * time.Millisecond, // Too short
		}
		err := validator.validateObservabilityConstraints(config)
		if err == nil {
			t.Error("Expected error for metrics interval too short")
		}
		if !strings.Contains(err.Error(), "metrics interval too short") {
			t.Errorf("Expected metrics interval error, got: %v", err)
		}
	})

	t.Run("PerformanceConstraints_InvalidWatcherPollInterval", func(t *testing.T) {
		config := PerformanceConfig{
			WatcherPollInterval:       500 * time.Millisecond, // Too short
			MaxConcurrentHealthChecks: 3,
		}
		err := validator.validatePerformanceConstraints(config)
		if err == nil {
			t.Error("Expected error for watcher poll interval too short")
		}
		if !strings.Contains(err.Error(), "watcher poll interval too short") {
			t.Errorf("Expected watcher poll interval error, got: %v", err)
		}
	})

	t.Run("PerformanceConstraints_InvalidMaxConcurrentHealthChecks", func(t *testing.T) {
		config := PerformanceConfig{
			WatcherPollInterval:       5 * time.Second,
			MaxConcurrentHealthChecks: 0, // Invalid: must be >= 1
		}
		err := validator.validatePerformanceConstraints(config)
		if err == nil {
			t.Error("Expected error for max concurrent health checks < 1")
		}
		if !strings.Contains(err.Error(), "max concurrent health checks must be at least 1") {
			t.Errorf("Expected max concurrent health checks error, got: %v", err)
		}
	})
}

// TestConfigValidator_BusinessRules tests business rule validation
func TestConfigValidator_BusinessRules(t *testing.T) {
	validator := NewConfigValidator[TestValidatorRequest, TestValidatorResponse]()

	t.Run("RetryRules_ValidConfiguration", func(t *testing.T) {
		config := RetryConfig{
			MaxRetries:      5,
			InitialInterval: 1 * time.Second,
			MaxInterval:     30 * time.Second,
			Multiplier:      2.0,
		}
		err := validator.validateRetryRules(config)
		if err != nil {
			t.Errorf("Expected valid retry config, got error: %v", err)
		}
	})

	t.Run("RetryRules_NegativeMaxRetries", func(t *testing.T) {
		config := RetryConfig{
			MaxRetries: -1,
		}
		err := validator.validateRetryRules(config)
		if err == nil {
			t.Error("Expected error for negative max retries")
		}
	})

	t.Run("RetryRules_ZeroMultiplier", func(t *testing.T) {
		config := RetryConfig{
			MaxRetries: 3,
			Multiplier: 0.0, // Invalid: must be > 0
		}
		err := validator.validateRetryRules(config)
		if err == nil {
			t.Error("Expected error for zero multiplier")
		}
	})

	t.Run("RetryRules_MaxIntervalLessThanInitial", func(t *testing.T) {
		config := RetryConfig{
			MaxRetries:      3,
			InitialInterval: 10 * time.Second,
			MaxInterval:     5 * time.Second, // Invalid: less than initial
			Multiplier:      2.0,
		}
		err := validator.validateRetryRules(config)
		if err == nil {
			t.Error("Expected error for max interval < initial interval")
		}
	})

	t.Run("CircuitBreakerRules_ValidConfiguration", func(t *testing.T) {
		config := CircuitBreakerConfig{
			FailureThreshold:    10,
			RecoveryTimeout:     30 * time.Second,
			MinRequestThreshold: 5,
			SuccessThreshold:    3,
			Enabled:             true,
		}
		err := validator.validateCircuitBreakerRules(config)
		if err != nil {
			t.Errorf("Expected valid circuit breaker config, got error: %v", err)
		}
	})

	t.Run("CircuitBreakerRules_NegativeFailureThreshold", func(t *testing.T) {
		config := CircuitBreakerConfig{
			FailureThreshold: -1,
		}
		err := validator.validateCircuitBreakerRules(config)
		if err == nil {
			t.Error("Expected error for negative failure threshold")
		}
	})

	t.Run("CircuitBreakerRules_ZeroSuccessThresholdWhenEnabled", func(t *testing.T) {
		config := CircuitBreakerConfig{
			FailureThreshold:    5,
			RecoveryTimeout:     30 * time.Second,
			MinRequestThreshold: 5,
			SuccessThreshold:    0, // Invalid when enabled
			Enabled:             true,
		}
		err := validator.validateCircuitBreakerRules(config)
		if err == nil {
			t.Error("Expected error for zero success threshold when enabled")
		}
	})

	t.Run("HealthCheckRules_ValidConfiguration", func(t *testing.T) {
		config := HealthCheckConfig{
			Interval:     30 * time.Second,
			Timeout:      5 * time.Second,
			FailureLimit: 3,
			Enabled:      true,
		}
		err := validator.validateHealthCheckRules(config)
		if err != nil {
			t.Errorf("Expected valid health check config, got error: %v", err)
		}
	})

	t.Run("HealthCheckRules_TimeoutGreaterThanInterval", func(t *testing.T) {
		config := HealthCheckConfig{
			Interval:     5 * time.Second,
			Timeout:      10 * time.Second, // Invalid: greater than interval
			FailureLimit: 3,
			Enabled:      true,
		}
		err := validator.validateHealthCheckRules(config)
		if err == nil {
			t.Error("Expected error for timeout >= interval")
		}
	})

	t.Run("ConnectionRules_ValidConfiguration", func(t *testing.T) {
		config := ConnectionConfig{
			MaxConnections:     100,
			MaxIdleConnections: 10,
			IdleTimeout:        5 * time.Minute,
			ConnectionTimeout:  10 * time.Second,
			RequestTimeout:     30 * time.Second,
		}
		err := validator.validateConnectionRules(config)
		if err != nil {
			t.Errorf("Expected valid connection config, got error: %v", err)
		}
	})

	t.Run("ConnectionRules_NegativeValues", func(t *testing.T) {
		configs := []ConnectionConfig{
			{MaxConnections: -1},
			{MaxIdleConnections: -1},
			{IdleTimeout: -1 * time.Second},
			{ConnectionTimeout: -1 * time.Second},
			{RequestTimeout: -1 * time.Second},
		}

		for i, config := range configs {
			err := validator.validateConnectionRules(config)
			if err == nil {
				t.Errorf("Expected error for negative value in config %d", i)
			}
		}
	})

	t.Run("RateLimitRules_ValidConfiguration", func(t *testing.T) {
		config := RateLimitConfig{
			RequestsPerSecond: 100.0,
			BurstSize:         10,
			TimeWindow:        1 * time.Minute,
			Enabled:           true,
		}
		err := validator.validateRateLimitRules(config)
		if err != nil {
			t.Errorf("Expected valid rate limit config, got error: %v", err)
		}
	})

	t.Run("RateLimitRules_NegativeRequestsPerSecond", func(t *testing.T) {
		config := RateLimitConfig{
			RequestsPerSecond: -1.0,
		}
		err := validator.validateRateLimitRules(config)
		if err == nil {
			t.Error("Expected error for negative requests per second")
		}
	})

	t.Run("RateLimitRules_ZeroTimeWindowWhenEnabled", func(t *testing.T) {
		config := RateLimitConfig{
			RequestsPerSecond: 100.0,
			BurstSize:         10,
			TimeWindow:        0, // Invalid when enabled
			Enabled:           true,
		}
		err := validator.validateRateLimitRules(config)
		if err == nil {
			t.Error("Expected error for zero time window when enabled")
		}
	})
}

// TestConfigValidator_SecurityConstraints tests security validation
func TestConfigValidator_SecurityConstraints(t *testing.T) {
	validator := NewConfigValidator[TestValidatorRequest, TestValidatorResponse]()

	t.Run("SecurityBasics_ValidConfiguration", func(t *testing.T) {
		config := SecurityConfig{
			Policy:        SecurityPolicyStrict,
			WhitelistFile: getAbsolutePath("whitelist.json"),
			HashAlgorithm: HashAlgorithmSHA256,
			MaxFileSize:   1024 * 1024,
		}
		err := validator.validateSecurityBasics(config)
		if err != nil {
			t.Errorf("Expected valid security config, got error: %v", err)
		}
	})

	t.Run("SecurityBasics_InvalidPolicy", func(t *testing.T) {
		config := SecurityConfig{
			Policy: SecurityPolicy(99), // Invalid policy value
		}
		err := validator.validateSecurityBasics(config)
		if err == nil {
			t.Error("Expected error for invalid security policy")
		}
		if !strings.Contains(err.Error(), "invalid security policy") {
			t.Errorf("Expected security policy error, got: %v", err)
		}
	})

	t.Run("SecurityBasics_RelativeWhitelistPath", func(t *testing.T) {
		config := SecurityConfig{
			Policy:        SecurityPolicyStrict,
			WhitelistFile: "relative/path.json", // Invalid: must be absolute
		}
		err := validator.validateSecurityBasics(config)
		if err == nil {
			t.Error("Expected error for relative whitelist path")
		}
	})

	t.Run("SecurityBasics_InvalidHashAlgorithm", func(t *testing.T) {
		config := SecurityConfig{
			Policy:        SecurityPolicyStrict,
			HashAlgorithm: HashAlgorithm("MD5"), // Invalid: only SHA256 supported
		}
		err := validator.validateSecurityBasics(config)
		if err == nil {
			t.Error("Expected error for invalid hash algorithm")
		}
	})

	t.Run("SecurityBasics_NegativeMaxFileSize", func(t *testing.T) {
		config := SecurityConfig{
			Policy:      SecurityPolicyStrict,
			MaxFileSize: -1, // Invalid: negative file size
		}
		err := validator.validateSecurityBasics(config)
		if err == nil {
			t.Error("Expected error for negative max file size")
		}
	})

	t.Run("SecurityLists_ValidConfiguration", func(t *testing.T) {
		config := SecurityConfig{
			AllowedTypes:   []string{"plugin", "service"},
			ForbiddenPaths: []string{getSystemPath(), getAbsolutePath("restricted")},
		}
		err := validator.validateSecurityLists(config)
		if err != nil {
			t.Errorf("Expected valid security lists, got error: %v", err)
		}
	})

	t.Run("SecurityLists_EmptyAllowedType", func(t *testing.T) {
		config := SecurityConfig{
			AllowedTypes: []string{"plugin", "", "service"}, // Empty type
		}
		err := validator.validateSecurityLists(config)
		if err == nil {
			t.Error("Expected error for empty allowed type")
		}
	})

	t.Run("SecurityLists_RelativeForbiddenPath", func(t *testing.T) {
		config := SecurityConfig{
			ForbiddenPaths: []string{getSystemPath(), "relative/path"}, // Relative path
		}
		err := validator.validateSecurityLists(config)
		if err == nil {
			t.Error("Expected error for relative forbidden path")
		}
	})

	t.Run("SecurityAuditAndTiming_ValidConfiguration", func(t *testing.T) {
		config := SecurityConfig{
			ReloadDelay: 5 * time.Second,
			AuditConfig: SecurityAuditConfig{
				Enabled:   true,
				AuditFile: getAbsolutePath("audit.log"),
			},
		}
		err := validator.validateSecurityAuditAndTiming(config)
		if err != nil {
			t.Errorf("Expected valid audit and timing config, got error: %v", err)
		}
	})

	t.Run("SecurityAuditAndTiming_NegativeReloadDelay", func(t *testing.T) {
		config := SecurityConfig{
			ReloadDelay: -1 * time.Second, // Invalid: negative delay
		}
		err := validator.validateSecurityAuditAndTiming(config)
		if err == nil {
			t.Error("Expected error for negative reload delay")
		}
	})

	t.Run("SecurityAuditAndTiming_RelativeAuditPath", func(t *testing.T) {
		config := SecurityConfig{
			AuditConfig: SecurityAuditConfig{
				Enabled:   true,
				AuditFile: "relative/audit.log", // Invalid: must be absolute
			},
		}
		err := validator.validateSecurityAuditAndTiming(config)
		if err == nil {
			t.Error("Expected error for relative audit path")
		}
	})
}

// TestConfigValidator_HelperFunctions tests individual helper validation functions
func TestConfigValidator_HelperFunctions(t *testing.T) {
	validator := NewConfigValidator[TestValidatorRequest, TestValidatorResponse]()

	t.Run("ValidateWhitelistPath_ValidAbsolutePath", func(t *testing.T) {
		err := validator.validateWhitelistPath(getAbsolutePath("whitelist.json"))
		if err != nil {
			t.Errorf("Expected valid absolute path, got error: %v", err)
		}
	})

	t.Run("ValidateWhitelistPath_EmptyPath", func(t *testing.T) {
		err := validator.validateWhitelistPath("")
		if err != nil {
			t.Errorf("Expected empty path to be allowed, got error: %v", err)
		}
	})

	t.Run("ValidateWhitelistPath_RelativePath", func(t *testing.T) {
		err := validator.validateWhitelistPath("relative/path.json")
		if err == nil {
			t.Error("Expected error for relative path")
		}
	})

	t.Run("ValidateHashAlgorithm_ValidSHA256", func(t *testing.T) {
		err := validator.validateHashAlgorithm(HashAlgorithmSHA256)
		if err != nil {
			t.Errorf("Expected SHA256 to be valid, got error: %v", err)
		}
	})

	t.Run("ValidateHashAlgorithm_EmptyAlgorithm", func(t *testing.T) {
		err := validator.validateHashAlgorithm("")
		if err != nil {
			t.Errorf("Expected empty algorithm to be allowed, got error: %v", err)
		}
	})

	t.Run("ValidateHashAlgorithm_InvalidAlgorithm", func(t *testing.T) {
		err := validator.validateHashAlgorithm("MD5")
		if err == nil {
			t.Error("Expected error for MD5 algorithm")
		}
	})

	t.Run("ValidateForbiddenPath_ValidAbsolutePath", func(t *testing.T) {
		err := validator.validateForbiddenPath(0, getSystemPath())
		if err != nil {
			t.Errorf("Expected valid absolute path, got error: %v", err)
		}
	})

	t.Run("ValidateForbiddenPath_EmptyPath", func(t *testing.T) {
		err := validator.validateForbiddenPath(0, "")
		if err != nil {
			t.Errorf("Expected empty path to be allowed, got error: %v", err)
		}
	})

	t.Run("ValidateForbiddenPath_RelativePath", func(t *testing.T) {
		err := validator.validateForbiddenPath(1, "relative/path")
		if err == nil {
			t.Error("Expected error for relative path")
		}
		if !strings.Contains(err.Error(), "index 1") {
			t.Errorf("Expected error to mention index, got: %v", err)
		}
	})

	t.Run("ValidateAuditConfig_ValidConfiguration", func(t *testing.T) {
		config := SecurityAuditConfig{
			Enabled:   true,
			AuditFile: getAbsolutePath("audit.log"),
		}
		err := validator.validateAuditConfig(config)
		if err != nil {
			t.Errorf("Expected valid audit config, got error: %v", err)
		}
	})

	t.Run("ValidateAuditConfig_DisabledWithRelativePath", func(t *testing.T) {
		config := SecurityAuditConfig{
			Enabled:   false,
			AuditFile: "relative/audit.log", // Should be ignored when disabled
		}
		err := validator.validateAuditConfig(config)
		if err != nil {
			t.Errorf("Expected relative path to be ignored when disabled, got error: %v", err)
		}
	})

	t.Run("ValidateAuditConfig_EnabledWithRelativePath", func(t *testing.T) {
		config := SecurityAuditConfig{
			Enabled:   true,
			AuditFile: "relative/audit.log", // Should cause error when enabled
		}
		err := validator.validateAuditConfig(config)
		if err == nil {
			t.Error("Expected error for relative audit path when enabled")
		}
	})
}

// TestConfigValidator_IntegratedValidation tests full validation flow
func TestConfigValidator_IntegratedValidation(t *testing.T) {
	validator := NewConfigValidator[TestValidatorRequest, TestValidatorResponse]()

	t.Run("ComplexValidConfig_AllConstraintsSatisfied", func(t *testing.T) {
		config := LibraryConfig{
			Logging: LoggingConfig{
				Level: "debug",
			},
			Observability: ObservabilityRuntimeConfig{
				TracingSampleRate: 1.0,
				MetricsInterval:   10 * time.Second,
			},
			Performance: PerformanceConfig{
				WatcherPollInterval:       30 * time.Second,
				MaxConcurrentHealthChecks: 5,
			},
			DefaultPolicies: DefaultPoliciesConfig{
				Retry: RetryConfig{
					MaxRetries:      10,
					InitialInterval: 500 * time.Millisecond,
					MaxInterval:     2 * time.Minute,
					Multiplier:      1.5,
				},
				CircuitBreaker: CircuitBreakerConfig{
					FailureThreshold:    20,
					RecoveryTimeout:     1 * time.Minute,
					MinRequestThreshold: 50,
					SuccessThreshold:    10,
					Enabled:             true,
				},
				HealthCheck: HealthCheckConfig{
					Interval:     1 * time.Minute,
					Timeout:      10 * time.Second,
					FailureLimit: 5,
					Enabled:      true,
				},
				Connection: ConnectionConfig{
					MaxConnections:     200,
					MaxIdleConnections: 20,
					IdleTimeout:        10 * time.Minute,
					ConnectionTimeout:  30 * time.Second,
					RequestTimeout:     2 * time.Minute,
				},
				RateLimit: RateLimitConfig{
					RequestsPerSecond: 500.0,
					BurstSize:         50,
					TimeWindow:        5 * time.Minute,
					Enabled:           true,
				},
			},
			Security: SecurityConfig{
				Policy:         SecurityPolicyAuditOnly,
				WhitelistFile:  getAbsolutePath("whitelist.json"),
				HashAlgorithm:  HashAlgorithmSHA256,
				MaxFileSize:    10 * 1024 * 1024,
				AllowedTypes:   []string{"service", "plugin", "extension"},
				ForbiddenPaths: []string{getSystemPath()},
				ReloadDelay:    10 * time.Second,
				AuditConfig: SecurityAuditConfig{
					Enabled:   true,
					AuditFile: getAbsolutePath("audit.log"),
				},
			},
		}

		err := validator.ValidateLibraryConfig(config)
		if err != nil {
			t.Errorf("Expected complex valid configuration to pass, got error: %v", err)
		}
	})

	t.Run("MultipleErrorSources_FirstErrorReturned", func(t *testing.T) {
		config := LibraryConfig{
			Logging: LoggingConfig{
				Level: "invalid", // First error - field validation
			},
			DefaultPolicies: DefaultPoliciesConfig{
				Retry: RetryConfig{
					MaxRetries: -1, // Would be second error - business rules
				},
			},
			Security: SecurityConfig{
				Policy: SecurityPolicy(99), // Would be third error - security validation
			},
		}

		err := validator.ValidateLibraryConfig(config)
		if err == nil {
			t.Fatal("Expected validation error")
		}

		// Should get field validation error first
		if !strings.Contains(err.Error(), "field validation failed") {
			t.Errorf("Expected field validation error first, got: %v", err)
		}
	})
}
