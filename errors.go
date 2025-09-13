// errors.go: Structured error definitions for the go-plugins system
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"github.com/agilira/go-errors"
)

// Error codes for the go-plugins system
const (
	// Configuration errors (1000-1099)
	ErrCodeInvalidPluginName     = "PLUGIN_1001"
	ErrCodeInvalidTransport      = "PLUGIN_1002"
	ErrCodeMissingEndpoint       = "PLUGIN_1003"
	ErrCodeInvalidEndpointURL    = "PLUGIN_1004"
	ErrCodeInvalidEndpointFormat = "PLUGIN_1005"
	ErrCodeMissingSocketPath     = "PLUGIN_1006"
	ErrCodeMissingExecutable     = "PLUGIN_1007"
	ErrCodeUnsupportedTransport  = "PLUGIN_1008"
	ErrCodeNoPluginsConfigured   = "PLUGIN_1009"
	ErrCodeDuplicatePluginName   = "PLUGIN_1010"
	ErrCodeInvalidJSONConfig     = "PLUGIN_1011"

	// Authentication errors (1100-1199)
	ErrCodeMissingAPIKey           = "AUTH_1101"
	ErrCodeMissingBearerToken      = "AUTH_1102"
	ErrCodeMissingBasicCredentials = "AUTH_1103"
	ErrCodeMissingMTLSCerts        = "AUTH_1104"
	ErrCodeUnsupportedAuthMethod   = "AUTH_1105"

	// Plugin execution errors (1200-1299)
	ErrCodePluginNotFound         = "PLUGIN_1201"
	ErrCodePluginNotEnabled       = "PLUGIN_1202"
	ErrCodePluginExecutionFailed  = "PLUGIN_1203"
	ErrCodePluginTimeout          = "PLUGIN_1204"
	ErrCodePluginConnectionFailed = "PLUGIN_1205"

	// Transport errors (1300-1399)
	ErrCodeHTTPTransportError = "TRANSPORT_1301"
	ErrCodeGRPCTransportError = "TRANSPORT_1302"
	ErrCodeUnixTransportError = "TRANSPORT_1303"
	ErrCodeExecTransportError = "TRANSPORT_1304"

	// Circuit breaker errors (1400-1499)
	ErrCodeCircuitBreakerOpen    = "CIRCUIT_1401"
	ErrCodeCircuitBreakerTimeout = "CIRCUIT_1402"

	// Rate limiting errors (1500-1599)
	ErrCodeRateLimitExceeded = "RATELIMIT_1501"

	// Health check errors (1600-1699)
	ErrCodeHealthCheckFailed  = "HEALTH_1601"
	ErrCodeHealthCheckTimeout = "HEALTH_1602"

	// Load balancer errors (1700-1799)
	ErrCodeNoAvailablePlugins = "LOADBALANCER_1701"
	ErrCodeLoadBalancerFailed = "LOADBALANCER_1702"
)

// Configuration error constructors

func NewInvalidPluginNameError(name string) *errors.Error {
	return errors.New(ErrCodeInvalidPluginName, "Invalid plugin name").
		WithUserMessage("Plugin name is required and cannot be empty").
		WithContext("provided_name", name).
		WithSeverity("error")
}

func NewInvalidTransportError() *errors.Error {
	return errors.New(ErrCodeInvalidTransport, "Invalid transport").
		WithUserMessage("Plugin transport is required").
		WithSeverity("error")
}

func NewMissingEndpointError(transport TransportType) *errors.Error {
	return errors.New(ErrCodeMissingEndpoint, "Missing endpoint").
		WithUserMessage("Endpoint is required for network-based transport").
		WithContext("transport", string(transport)).
		WithSeverity("error")
}

func NewInvalidEndpointURLError(endpoint string, cause error) *errors.Error {
	err := errors.New(ErrCodeInvalidEndpointURL, "Invalid endpoint URL").
		WithUserMessage("The provided endpoint URL is malformed").
		WithContext("endpoint", endpoint).
		WithSeverity("error")

	if cause != nil {
		return errors.Wrap(cause, ErrCodeInvalidEndpointURL, "Invalid endpoint URL").
			WithUserMessage("The provided endpoint URL is malformed").
			WithContext("endpoint", endpoint).
			WithSeverity("error")
	}
	return err
}

func NewInvalidEndpointFormatError() *errors.Error {
	return errors.New(ErrCodeInvalidEndpointFormat, "Invalid endpoint format").
		WithUserMessage("Endpoint URL must have both scheme and host").
		WithSeverity("error")
}

func NewMissingSocketPathError() *errors.Error {
	return errors.New(ErrCodeMissingSocketPath, "Missing socket path").
		WithUserMessage("Socket path is required for unix transport").
		WithSeverity("error")
}

func NewMissingExecutableError() *errors.Error {
	return errors.New(ErrCodeMissingExecutable, "Missing executable").
		WithUserMessage("Executable path is required for exec transport").
		WithSeverity("error")
}

func NewUnsupportedTransportError(transport TransportType) *errors.Error {
	return errors.New(ErrCodeUnsupportedTransport, "Unsupported transport").
		WithUserMessage("The specified transport type is not supported").
		WithContext("transport", string(transport)).
		WithSeverity("error")
}

func NewNoPluginsConfiguredError() *errors.Error {
	return errors.New(ErrCodeNoPluginsConfigured, "No plugins configured").
		WithUserMessage("At least one plugin must be configured").
		WithSeverity("error")
}

func NewDuplicatePluginNameError(name string) *errors.Error {
	return errors.New(ErrCodeDuplicatePluginName, "Duplicate plugin name").
		WithUserMessage("Plugin names must be unique within the configuration").
		WithContext("plugin_name", name).
		WithSeverity("error")
}

func NewInvalidJSONConfigError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeInvalidJSONConfig, "Invalid JSON configuration").
		WithUserMessage("Failed to parse JSON configuration").
		WithSeverity("error")
}

// Authentication error constructors

func NewMissingAPIKeyError() *errors.Error {
	return errors.New(ErrCodeMissingAPIKey, "Missing API key").
		WithUserMessage("API key is required for api-key authentication method").
		WithSeverity("error")
}

func NewMissingBearerTokenError() *errors.Error {
	return errors.New(ErrCodeMissingBearerToken, "Missing bearer token").
		WithUserMessage("Token is required for bearer authentication method").
		WithSeverity("error")
}

func NewMissingBasicCredentialsError() *errors.Error {
	return errors.New(ErrCodeMissingBasicCredentials, "Missing basic credentials").
		WithUserMessage("Username and password are required for basic authentication method").
		WithSeverity("error")
}

func NewMissingMTLSCertsError() *errors.Error {
	return errors.New(ErrCodeMissingMTLSCerts, "Missing mTLS certificates").
		WithUserMessage("Certificate file and key file are required for mTLS authentication method").
		WithSeverity("error")
}

func NewUnsupportedAuthMethodError(method AuthMethod) *errors.Error {
	return errors.New(ErrCodeUnsupportedAuthMethod, "Unsupported authentication method").
		WithUserMessage("The specified authentication method is not supported").
		WithContext("auth_method", string(method)).
		WithSeverity("error")
}

// Plugin execution error constructors

func NewPluginNotFoundError(name string) *errors.Error {
	return errors.New(ErrCodePluginNotFound, "Plugin not found").
		WithUserMessage("The requested plugin was not found in the configuration").
		WithContext("plugin_name", name).
		WithSeverity("error")
}

func NewPluginNotEnabledError(name string) *errors.Error {
	return errors.New(ErrCodePluginNotEnabled, "Plugin not enabled").
		WithUserMessage("The requested plugin is not enabled").
		WithContext("plugin_name", name).
		WithSeverity("warning")
}

func NewPluginExecutionFailedError(name string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodePluginExecutionFailed, "Plugin execution failed").
		WithUserMessage("The plugin failed to execute the requested operation").
		WithContext("plugin_name", name).
		WithSeverity("error")
}

func NewPluginTimeoutError(name string, timeout interface{}) *errors.Error {
	return errors.New(ErrCodePluginTimeout, "Plugin timeout").
		WithUserMessage("The plugin operation exceeded the configured timeout").
		WithContext("plugin_name", name).
		WithContext("timeout", timeout).
		WithSeverity("warning")
}

func NewPluginConnectionFailedError(name string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodePluginConnectionFailed, "Plugin connection failed").
		WithUserMessage("Failed to establish connection to the plugin").
		WithContext("plugin_name", name).
		WithSeverity("error").
		AsRetryable()
}

// Transport error constructors

func NewHTTPTransportError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeHTTPTransportError, "HTTP transport error").
		WithUserMessage("HTTP transport operation failed").
		WithSeverity("error").
		AsRetryable()
}

func NewGRPCTransportError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeGRPCTransportError, "gRPC transport error").
		WithUserMessage("gRPC transport operation failed").
		WithSeverity("error").
		AsRetryable()
}

func NewUnixTransportError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeUnixTransportError, "Unix transport error").
		WithUserMessage("Unix socket transport operation failed").
		WithSeverity("error")
}

func NewExecTransportError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeExecTransportError, "Executable transport error").
		WithUserMessage("Executable transport operation failed").
		WithSeverity("error")
}

// Circuit breaker error constructors

func NewCircuitBreakerOpenError(pluginName string) *errors.Error {
	return errors.New(ErrCodeCircuitBreakerOpen, "Circuit breaker open").
		WithUserMessage("Circuit breaker is open, failing fast to prevent cascading failures").
		WithContext("plugin_name", pluginName).
		WithSeverity("warning")
}

func NewCircuitBreakerTimeoutError(pluginName string, timeout interface{}) *errors.Error {
	return errors.New(ErrCodeCircuitBreakerTimeout, "Circuit breaker timeout").
		WithUserMessage("Circuit breaker operation timeout").
		WithContext("plugin_name", pluginName).
		WithContext("timeout", timeout).
		WithSeverity("warning")
}

// Rate limiting error constructors

func NewRateLimitExceededError(pluginName string, limit interface{}) *errors.Error {
	return errors.New(ErrCodeRateLimitExceeded, "Rate limit exceeded").
		WithUserMessage("Request rate limit has been exceeded").
		WithContext("plugin_name", pluginName).
		WithContext("limit", limit).
		WithSeverity("warning").
		AsRetryable()
}

// Health check error constructors

func NewHealthCheckFailedError(pluginName string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeHealthCheckFailed, "Health check failed").
		WithUserMessage("Plugin health check failed").
		WithContext("plugin_name", pluginName).
		WithSeverity("warning")
}

func NewHealthCheckTimeoutError(pluginName string, timeout interface{}) *errors.Error {
	return errors.New(ErrCodeHealthCheckTimeout, "Health check timeout").
		WithUserMessage("Plugin health check timed out").
		WithContext("plugin_name", pluginName).
		WithContext("timeout", timeout).
		WithSeverity("warning").
		AsRetryable()
}

// Load balancer error constructors

func NewNoAvailablePluginsError(pluginType string) *errors.Error {
	return errors.New(ErrCodeNoAvailablePlugins, "No available plugins").
		WithUserMessage("No healthy plugins available for the requested type").
		WithContext("plugin_type", pluginType).
		WithSeverity("error")
}

func NewLoadBalancerFailedError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeLoadBalancerFailed, "Load balancer failed").
		WithUserMessage("Load balancer operation failed").
		WithSeverity("error").
		AsRetryable()
}

// Validation error constructor for plugin configuration with detailed validation context

func NewPluginValidationError(pluginIndex int, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeInvalidPluginName, "Plugin validation failed").
		WithUserMessage("Plugin configuration validation failed").
		WithContext("plugin_index", pluginIndex).
		WithSeverity("error")
}

// Authentication configuration validation error with context

func NewAuthConfigValidationError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeUnsupportedAuthMethod, "Authentication configuration validation failed").
		WithUserMessage("Invalid authentication configuration").
		WithSeverity("error")
}
