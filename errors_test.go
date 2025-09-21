// errors_test.go: comprehensive test coverage for structured error definitions
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
	"testing"
	"time"

	"github.com/agilira/go-errors"
)

// TestConfigurationErrorConstructors tests all configuration-related error constructors
func TestConfigurationErrorConstructors(t *testing.T) {
	t.Run("NewInvalidPluginNameError", func(t *testing.T) {
		pluginName := ""
		err := NewInvalidPluginNameError(pluginName)

		// Verify error code
		if err.ErrorCode() != errors.ErrorCode(ErrCodeInvalidPluginName) {
			t.Errorf("Expected error code %s, got %s", ErrCodeInvalidPluginName, err.ErrorCode())
		}

		// Verify context
		if err.Context["provided_name"] != pluginName {
			t.Errorf("Expected provided_name context to be %q, got %v", pluginName, err.Context["provided_name"])
		}

		// Verify severity - default is "error"
		expectedSeverity := "error"
		if err.Severity != expectedSeverity {
			t.Errorf("Expected severity %q, got %q", expectedSeverity, err.Severity)
		}

		// Verify user message
		expectedMsg := "Plugin name is required and cannot be empty"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify not retryable by default
		if err.IsRetryable() {
			t.Error("Expected error to not be retryable")
		}
	})

	t.Run("NewInvalidTransportError", func(t *testing.T) {
		err := NewInvalidTransportError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeInvalidTransport) {
			t.Errorf("Expected error code %s, got %s", ErrCodeInvalidTransport, err.ErrorCode())
		}

		expectedMsg := "Plugin transport is required"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewMissingEndpointError", func(t *testing.T) {
		transport := TransportGRPC
		err := NewMissingEndpointError(transport)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeMissingEndpoint) {
			t.Errorf("Expected error code %s, got %s", ErrCodeMissingEndpoint, err.ErrorCode())
		}

		if err.Context["transport"] != string(transport) {
			t.Errorf("Expected transport context to be %q, got %v", string(transport), err.Context["transport"])
		}

		expectedMsg := "Endpoint is required for network-based transport"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewInvalidEndpointURLError", func(t *testing.T) {
		endpoint := "invalid-url"
		cause := fmt.Errorf("parse error")

		// Test with cause
		errWithCause := NewInvalidEndpointURLError(endpoint, cause)
		if errWithCause.ErrorCode() != errors.ErrorCode(ErrCodeInvalidEndpointURL) {
			t.Errorf("Expected error code %s, got %s", ErrCodeInvalidEndpointURL, errWithCause.ErrorCode())
		}

		if errWithCause.Context["endpoint"] != endpoint {
			t.Errorf("Expected endpoint context to be %q, got %v", endpoint, errWithCause.Context["endpoint"])
		}

		// Test without cause
		errWithoutCause := NewInvalidEndpointURLError(endpoint, nil)
		if errWithoutCause.ErrorCode() != errors.ErrorCode(ErrCodeInvalidEndpointURL) {
			t.Errorf("Expected error code %s, got %s", ErrCodeInvalidEndpointURL, errWithoutCause.ErrorCode())
		}

		// Verify user message consistency
		expectedMsg := "The provided endpoint URL is malformed"
		if errWithCause.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, errWithCause.UserMessage())
		}
		if errWithoutCause.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, errWithoutCause.UserMessage())
		}
	})

	t.Run("NewInvalidEndpointFormatError", func(t *testing.T) {
		err := NewInvalidEndpointFormatError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeInvalidEndpointFormat) {
			t.Errorf("Expected error code %s, got %s", ErrCodeInvalidEndpointFormat, err.ErrorCode())
		}

		expectedMsg := "Endpoint URL must have both scheme and host"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewMissingExecutableError", func(t *testing.T) {
		err := NewMissingExecutableError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeMissingExecutable) {
			t.Errorf("Expected error code %s, got %s", ErrCodeMissingExecutable, err.ErrorCode())
		}

		expectedMsg := "Executable path is required for exec transport"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewUnsupportedTransportError", func(t *testing.T) {
		transport := TransportExecutable
		err := NewUnsupportedTransportError(transport)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeUnsupportedTransport) {
			t.Errorf("Expected error code %s, got %s", ErrCodeUnsupportedTransport, err.ErrorCode())
		}

		if err.Context["transport"] != string(transport) {
			t.Errorf("Expected transport context to be %q, got %v", string(transport), err.Context["transport"])
		}
	})

	t.Run("NewNoPluginsConfiguredError", func(t *testing.T) {
		err := NewNoPluginsConfiguredError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeNoPluginsConfigured) {
			t.Errorf("Expected error code %s, got %s", ErrCodeNoPluginsConfigured, err.ErrorCode())
		}

		expectedMsg := "At least one plugin must be configured"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewDuplicatePluginNameError", func(t *testing.T) {
		pluginName := "duplicate-plugin"
		err := NewDuplicatePluginNameError(pluginName)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeDuplicatePluginName) {
			t.Errorf("Expected error code %s, got %s", ErrCodeDuplicatePluginName, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}
	})

	t.Run("NewInvalidJSONConfigError", func(t *testing.T) {
		cause := fmt.Errorf("json: cannot unmarshal")
		err := NewInvalidJSONConfigError(cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeInvalidJSONConfig) {
			t.Errorf("Expected error code %s, got %s", ErrCodeInvalidJSONConfig, err.ErrorCode())
		}

		expectedMsg := "Failed to parse JSON configuration"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}

// TestAuthenticationErrorConstructors tests all authentication-related error constructors
func TestAuthenticationErrorConstructors(t *testing.T) {
	t.Run("NewMissingAPIKeyError", func(t *testing.T) {
		err := NewMissingAPIKeyError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeMissingAPIKey) {
			t.Errorf("Expected error code %s, got %s", ErrCodeMissingAPIKey, err.ErrorCode())
		}

		expectedMsg := "API key is required for api-key authentication method"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewMissingBearerTokenError", func(t *testing.T) {
		err := NewMissingBearerTokenError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeMissingBearerToken) {
			t.Errorf("Expected error code %s, got %s", ErrCodeMissingBearerToken, err.ErrorCode())
		}

		expectedMsg := "Token is required for bearer authentication method"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewMissingBasicCredentialsError", func(t *testing.T) {
		err := NewMissingBasicCredentialsError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeMissingBasicCredentials) {
			t.Errorf("Expected error code %s, got %s", ErrCodeMissingBasicCredentials, err.ErrorCode())
		}

		expectedMsg := "Username and password are required for basic authentication method"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewMissingMTLSCertsError", func(t *testing.T) {
		err := NewMissingMTLSCertsError()

		if err.ErrorCode() != errors.ErrorCode(ErrCodeMissingMTLSCerts) {
			t.Errorf("Expected error code %s, got %s", ErrCodeMissingMTLSCerts, err.ErrorCode())
		}

		expectedMsg := "Certificate file and key file are required for mTLS authentication method"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewUnsupportedAuthMethodError", func(t *testing.T) {
		authMethod := AuthAPIKey
		err := NewUnsupportedAuthMethodError(authMethod)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeUnsupportedAuthMethod) {
			t.Errorf("Expected error code %s, got %s", ErrCodeUnsupportedAuthMethod, err.ErrorCode())
		}

		if err.Context["auth_method"] != string(authMethod) {
			t.Errorf("Expected auth_method context to be %q, got %v", string(authMethod), err.Context["auth_method"])
		}
	})
}

// TestPluginExecutionErrorConstructors tests plugin execution error constructors
func TestPluginExecutionErrorConstructors(t *testing.T) {
	t.Run("NewPluginNotFoundError", func(t *testing.T) {
		pluginName := "missing-plugin"
		err := NewPluginNotFoundError(pluginName)

		if err.ErrorCode() != errors.ErrorCode(ErrCodePluginNotFound) {
			t.Errorf("Expected error code %s, got %s", ErrCodePluginNotFound, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		expectedMsg := "The requested plugin was not found in the configuration"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewPluginNotEnabledError", func(t *testing.T) {
		pluginName := "disabled-plugin"
		err := NewPluginNotEnabledError(pluginName)

		if err.ErrorCode() != errors.ErrorCode(ErrCodePluginNotEnabled) {
			t.Errorf("Expected error code %s, got %s", ErrCodePluginNotEnabled, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		// Verify warning severity
		if err.Severity != "warning" {
			t.Errorf("Expected severity 'warning', got %s", err.Severity)
		}
	})

	t.Run("NewPluginExecutionFailedError", func(t *testing.T) {
		pluginName := "failing-plugin"
		cause := fmt.Errorf("execution timeout")
		err := NewPluginExecutionFailedError(pluginName, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodePluginExecutionFailed) {
			t.Errorf("Expected error code %s, got %s", ErrCodePluginExecutionFailed, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		expectedMsg := "The plugin failed to execute the requested operation"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewPluginTimeoutError", func(t *testing.T) {
		pluginName := "slow-plugin"
		timeout := 30 * time.Second
		err := NewPluginTimeoutError(pluginName, timeout)

		if err.ErrorCode() != errors.ErrorCode(ErrCodePluginTimeout) {
			t.Errorf("Expected error code %s, got %s", ErrCodePluginTimeout, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		if err.Context["timeout"] != timeout {
			t.Errorf("Expected timeout context to be %v, got %v", timeout, err.Context["timeout"])
		}

		// Verify warning severity
		if err.Severity != "warning" {
			t.Errorf("Expected severity 'warning', got %s", err.Severity)
		}
	})

	t.Run("NewPluginConnectionFailedError", func(t *testing.T) {
		pluginName := "network-plugin"
		cause := fmt.Errorf("connection refused")
		err := NewPluginConnectionFailedError(pluginName, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodePluginConnectionFailed) {
			t.Errorf("Expected error code %s, got %s", ErrCodePluginConnectionFailed, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		// Verify retryable flag
		if !err.IsRetryable() {
			t.Error("Expected error to be retryable")
		}

		expectedMsg := "Failed to establish connection to the plugin"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}

// TestTransportErrorConstructors tests transport-related error constructors
func TestTransportErrorConstructors(t *testing.T) {
	t.Run("NewGRPCTransportError", func(t *testing.T) {
		cause := fmt.Errorf("grpc connection failed")
		err := NewGRPCTransportError(cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeGRPCTransportError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeGRPCTransportError, err.ErrorCode())
		}

		// Verify retryable flag
		if !err.IsRetryable() {
			t.Error("Expected error to be retryable")
		}

		expectedMsg := "gRPC transport operation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewExecTransportError", func(t *testing.T) {
		cause := fmt.Errorf("executable not found")
		err := NewExecTransportError(cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeExecTransportError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeExecTransportError, err.ErrorCode())
		}

		expectedMsg := "Executable transport operation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}

// TestCircuitBreakerErrorConstructors tests circuit breaker error constructors
func TestCircuitBreakerErrorConstructors(t *testing.T) {
	t.Run("NewCircuitBreakerOpenError", func(t *testing.T) {
		pluginName := "unstable-plugin"
		err := NewCircuitBreakerOpenError(pluginName)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeCircuitBreakerOpen) {
			t.Errorf("Expected error code %s, got %s", ErrCodeCircuitBreakerOpen, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		// Verify warning severity
		if err.Severity != "warning" {
			t.Errorf("Expected severity 'warning', got %s", err.Severity)
		}

		expectedMsg := "Circuit breaker is open, failing fast to prevent cascading failures"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewCircuitBreakerTimeoutError", func(t *testing.T) {
		pluginName := "timeout-plugin"
		timeout := 5 * time.Second
		err := NewCircuitBreakerTimeoutError(pluginName, timeout)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeCircuitBreakerTimeout) {
			t.Errorf("Expected error code %s, got %s", ErrCodeCircuitBreakerTimeout, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		if err.Context["timeout"] != timeout {
			t.Errorf("Expected timeout context to be %v, got %v", timeout, err.Context["timeout"])
		}

		// Verify warning severity
		if err.Severity != "warning" {
			t.Errorf("Expected severity 'warning', got %s", err.Severity)
		}
	})
}

// TestRateLimitingErrorConstructors tests rate limiting error constructors
func TestRateLimitingErrorConstructors(t *testing.T) {
	t.Run("NewRateLimitExceededError", func(t *testing.T) {
		pluginName := "busy-plugin"
		limit := 100
		err := NewRateLimitExceededError(pluginName, limit)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeRateLimitExceeded) {
			t.Errorf("Expected error code %s, got %s", ErrCodeRateLimitExceeded, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		if err.Context["limit"] != limit {
			t.Errorf("Expected limit context to be %v, got %v", limit, err.Context["limit"])
		}

		// Verify retryable flag
		if !err.IsRetryable() {
			t.Error("Expected error to be retryable")
		}

		// Verify warning severity
		if err.Severity != "warning" {
			t.Errorf("Expected severity 'warning', got %s", err.Severity)
		}

		expectedMsg := "Request rate limit has been exceeded"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})
}

// TestHealthCheckErrorConstructors tests health check error constructors
func TestHealthCheckErrorConstructors(t *testing.T) {
	t.Run("NewHealthCheckFailedError", func(t *testing.T) {
		pluginName := "unhealthy-plugin"
		cause := fmt.Errorf("health endpoint returned 500")
		err := NewHealthCheckFailedError(pluginName, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeHealthCheckFailed) {
			t.Errorf("Expected error code %s, got %s", ErrCodeHealthCheckFailed, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		// Verify warning severity
		if err.Severity != "warning" {
			t.Errorf("Expected severity 'warning', got %s", err.Severity)
		}

		expectedMsg := "Plugin health check failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewHealthCheckTimeoutError", func(t *testing.T) {
		pluginName := "slow-health-plugin"
		timeout := 10 * time.Second
		err := NewHealthCheckTimeoutError(pluginName, timeout)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeHealthCheckTimeout) {
			t.Errorf("Expected error code %s, got %s", ErrCodeHealthCheckTimeout, err.ErrorCode())
		}

		if err.Context["plugin_name"] != pluginName {
			t.Errorf("Expected plugin_name context to be %q, got %v", pluginName, err.Context["plugin_name"])
		}

		if err.Context["timeout"] != timeout {
			t.Errorf("Expected timeout context to be %v, got %v", timeout, err.Context["timeout"])
		}

		// Verify retryable flag
		if !err.IsRetryable() {
			t.Error("Expected error to be retryable")
		}

		// Verify warning severity
		if err.Severity != "warning" {
			t.Errorf("Expected severity 'warning', got %s", err.Severity)
		}
	})
}

// TestValidationErrorConstructors tests validation-related error constructors
func TestValidationErrorConstructors(t *testing.T) {
	t.Run("NewPluginValidationError", func(t *testing.T) {
		pluginIndex := 2
		cause := fmt.Errorf("missing required field")
		err := NewPluginValidationError(pluginIndex, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeInvalidPluginName) {
			t.Errorf("Expected error code %s, got %s", ErrCodeInvalidPluginName, err.ErrorCode())
		}

		if err.Context["plugin_index"] != pluginIndex {
			t.Errorf("Expected plugin_index context to be %v, got %v", pluginIndex, err.Context["plugin_index"])
		}

		expectedMsg := "Plugin configuration validation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewAuthConfigValidationError", func(t *testing.T) {
		cause := fmt.Errorf("invalid auth method")
		err := NewAuthConfigValidationError(cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeUnsupportedAuthMethod) {
			t.Errorf("Expected error code %s, got %s", ErrCodeUnsupportedAuthMethod, err.ErrorCode())
		}

		expectedMsg := "Invalid authentication configuration"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}

// TestConfigurationManagementErrorConstructors tests configuration management error constructors
func TestConfigurationManagementErrorConstructors(t *testing.T) {
	t.Run("NewConfigNotFoundError", func(t *testing.T) {
		configPath := "/path/to/config.json"
		err := NewConfigNotFoundError(configPath)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeConfigNotFound) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigNotFound, err.ErrorCode())
		}

		if err.Context["config_path"] != configPath {
			t.Errorf("Expected config_path context to be %q, got %v", configPath, err.Context["config_path"])
		}

		expectedMsg := "The configuration file could not be found"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewConfigParseError", func(t *testing.T) {
		configPath := "/path/to/config.json"
		cause := fmt.Errorf("invalid JSON syntax")
		err := NewConfigParseError(configPath, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeConfigParseError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigParseError, err.ErrorCode())
		}

		if err.Context["config_path"] != configPath {
			t.Errorf("Expected config_path context to be %q, got %v", configPath, err.Context["config_path"])
		}

		expectedMsg := "Failed to parse configuration file"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewConfigValidationError", func(t *testing.T) {
		message := "missing required field 'name'"
		cause := fmt.Errorf("validation failed")

		// Test with cause
		errWithCause := NewConfigValidationError(message, cause)
		if errWithCause.ErrorCode() != errors.ErrorCode(ErrCodeConfigValidationError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigValidationError, errWithCause.ErrorCode())
		}

		// Test without cause
		errWithoutCause := NewConfigValidationError(message, nil)
		if errWithoutCause.ErrorCode() != errors.ErrorCode(ErrCodeConfigValidationError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigValidationError, errWithoutCause.ErrorCode())
		}

		expectedMsg := "Configuration validation failed"
		if errWithCause.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, errWithCause.UserMessage())
		}
		if errWithoutCause.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, errWithoutCause.UserMessage())
		}
	})

	t.Run("NewConfigWatcherError", func(t *testing.T) {
		message := "file watcher failed"
		cause := fmt.Errorf("inotify error")
		err := NewConfigWatcherError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeConfigWatcherError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigWatcherError, err.ErrorCode())
		}

		expectedMsg := "Configuration monitoring failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewConfigPathError", func(t *testing.T) {
		configPath := "/invalid/path"
		message := "path does not exist"
		err := NewConfigPathError(configPath, message)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeConfigPathError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigPathError, err.ErrorCode())
		}

		if err.Context["config_path"] != configPath {
			t.Errorf("Expected config_path context to be %q, got %v", configPath, err.Context["config_path"])
		}

		expectedMsg := "Invalid configuration file path"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewConfigFileError", func(t *testing.T) {
		configPath := "/path/to/config.json"
		message := "file corrupted"
		cause := fmt.Errorf("read error")
		err := NewConfigFileError(configPath, message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeConfigFileError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigFileError, err.ErrorCode())
		}

		if err.Context["config_path"] != configPath {
			t.Errorf("Expected config_path context to be %q, got %v", configPath, err.Context["config_path"])
		}

		expectedMsg := "Configuration file access failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewConfigPermissionError", func(t *testing.T) {
		configPath := "/protected/config.json"
		cause := fmt.Errorf("permission denied")
		err := NewConfigPermissionError(configPath, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeConfigPermissionError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeConfigPermissionError, err.ErrorCode())
		}

		if err.Context["config_path"] != configPath {
			t.Errorf("Expected config_path context to be %q, got %v", configPath, err.Context["config_path"])
		}

		expectedMsg := "Insufficient permissions to access configuration file"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}

// TestSecurityErrorConstructors tests security-related error constructors
func TestSecurityErrorConstructors(t *testing.T) {
	t.Run("NewSecurityValidationError", func(t *testing.T) {
		message := "security check failed"
		cause := fmt.Errorf("permission denied")
		err := NewSecurityValidationError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeSecurityValidationError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeSecurityValidationError, err.ErrorCode())
		}

		expectedMsg := "Security validation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewWhitelistError", func(t *testing.T) {
		message := "plugin not allowed"
		cause := fmt.Errorf("policy violation")
		err := NewWhitelistError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeWhitelistError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeWhitelistError, err.ErrorCode())
		}

		expectedMsg := "Plugin whitelist validation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewHashValidationError", func(t *testing.T) {
		pluginPath := "/path/to/plugin"
		cause := fmt.Errorf("hash mismatch")
		err := NewHashValidationError(pluginPath, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeHashValidationError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeHashValidationError, err.ErrorCode())
		}

		expectedMsg := "Plugin integrity verification failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewPathTraversalError", func(t *testing.T) {
		path := "../../../etc/passwd"
		err := NewPathTraversalError(path)

		if err.ErrorCode() != errors.ErrorCode(ErrCodePathTraversalError) {
			t.Errorf("Expected error code %s, got %s", ErrCodePathTraversalError, err.ErrorCode())
		}

		if err.Context["attempted_path"] != path {
			t.Errorf("Expected attempted_path context to be %q, got %v", path, err.Context["attempted_path"])
		}

		expectedMsg := "Invalid file path detected"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}
	})

	t.Run("NewFilePermissionError", func(t *testing.T) {
		filePath := "/restricted/file"
		cause := fmt.Errorf("permission denied")
		err := NewFilePermissionError(filePath, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeFilePermissionError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeFilePermissionError, err.ErrorCode())
		}

		expectedMsg := "Insufficient permissions to access file"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewAuditError", func(t *testing.T) {
		message := "audit log failed"
		cause := fmt.Errorf("disk full")
		err := NewAuditError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeAuditError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeAuditError, err.ErrorCode())
		}

		expectedMsg := "Security audit logging failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}

// TestRegistryAndIsolationErrorConstructors tests registry and isolation error constructors
func TestRegistryAndIsolationErrorConstructors(t *testing.T) {
	t.Run("NewRegistryError", func(t *testing.T) {
		message := "registry operation failed"
		cause := fmt.Errorf("registry not available")
		err := NewRegistryError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeRegistryError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeRegistryError, err.ErrorCode())
		}

		expectedMsg := "Plugin registry operation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewIsolationError", func(t *testing.T) {
		message := "isolation setup failed"
		cause := fmt.Errorf("namespace error")
		err := NewIsolationError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeIsolationError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeIsolationError, err.ErrorCode())
		}

		expectedMsg := "Plugin isolation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewProcessError", func(t *testing.T) {
		message := "process crashed"
		cause := fmt.Errorf("segmentation fault")
		err := NewProcessError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeProcessError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeProcessError, err.ErrorCode())
		}

		expectedMsg := "Plugin process management failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewFactoryError", func(t *testing.T) {
		pluginType := "grpc"
		message := "factory creation failed"
		cause := fmt.Errorf("invalid configuration")
		err := NewFactoryError(pluginType, message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeFactoryError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeFactoryError, err.ErrorCode())
		}

		if err.Context["plugin_type"] != pluginType {
			t.Errorf("Expected plugin_type context to be %q, got %v", pluginType, err.Context["plugin_type"])
		}

		expectedMsg := "Plugin factory operation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewClientError", func(t *testing.T) {
		clientName := "grpc-client"
		message := "client initialization failed"
		cause := fmt.Errorf("connection refused")
		err := NewClientError(clientName, message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeClientError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeClientError, err.ErrorCode())
		}

		if err.Context["client_name"] != clientName {
			t.Errorf("Expected client_name context to be %q, got %v", clientName, err.Context["client_name"])
		}

		expectedMsg := "Plugin client operation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewDiscoveryError", func(t *testing.T) {
		message := "plugin discovery failed"
		cause := fmt.Errorf("directory not found")
		err := NewDiscoveryError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeDiscoveryError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeDiscoveryError, err.ErrorCode())
		}

		expectedMsg := "Plugin discovery failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}

// TestRPCAndCommunicationErrorConstructors tests RPC and communication error constructors
func TestRPCAndCommunicationErrorConstructors(t *testing.T) {
	t.Run("NewRPCError", func(t *testing.T) {
		message := "RPC call failed"
		cause := fmt.Errorf("network error")
		err := NewRPCError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeRPCError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeRPCError, err.ErrorCode())
		}

		expectedMsg := "RPC communication failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewHandshakeError", func(t *testing.T) {
		message := "handshake failed"
		cause := fmt.Errorf("protocol mismatch")
		err := NewHandshakeError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeHandshakeError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeHandshakeError, err.ErrorCode())
		}

		expectedMsg := "Plugin handshake failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewCommunicationError", func(t *testing.T) {
		message := "communication failed"
		cause := fmt.Errorf("connection lost")
		err := NewCommunicationError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeCommunicationError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeCommunicationError, err.ErrorCode())
		}

		expectedMsg := "Plugin communication failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewPluginProtocolError", func(t *testing.T) {
		message := "protocol error"
		cause := fmt.Errorf("invalid message format")
		err := NewPluginProtocolError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeProtocolError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeProtocolError, err.ErrorCode())
		}

		expectedMsg := "Protocol error occurred"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewSerializationError", func(t *testing.T) {
		message := "serialization failed"
		cause := fmt.Errorf("invalid data format")
		err := NewSerializationError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeSerializationError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeSerializationError, err.ErrorCode())
		}

		expectedMsg := "Data serialization failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewPluginCreationError", func(t *testing.T) {
		message := "plugin creation failed"
		cause := fmt.Errorf("resource allocation error")
		err := NewPluginCreationError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodePluginCreation) {
			t.Errorf("Expected error code %s, got %s", ErrCodePluginCreation, err.ErrorCode())
		}

		expectedMsg := "Failed to create plugin"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})

	t.Run("NewSubprocessError", func(t *testing.T) {
		message := "subprocess failed"
		cause := fmt.Errorf("process terminated")
		err := NewSubprocessError(message, cause)

		if err.ErrorCode() != errors.ErrorCode(ErrCodeSubprocessError) {
			t.Errorf("Expected error code %s, got %s", ErrCodeSubprocessError, err.ErrorCode())
		}

		expectedMsg := "Subprocess plugin operation failed"
		if err.UserMessage() != expectedMsg {
			t.Errorf("Expected user message %q, got %q", expectedMsg, err.UserMessage())
		}

		// Verify cause is properly wrapped
		if err.Cause == nil {
			t.Error("Expected cause to be set")
		}
	})
}
