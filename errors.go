// errors.go: structured error definitions for the go-plugins system
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
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

	ErrCodeMissingExecutable    = "PLUGIN_1007"
	ErrCodeUnsupportedTransport = "PLUGIN_1008"
	ErrCodeNoPluginsConfigured  = "PLUGIN_1009"
	ErrCodeDuplicatePluginName  = "PLUGIN_1010"
	ErrCodeInvalidJSONConfig    = "PLUGIN_1011"

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
	ErrCodeGRPCTransportError = "TRANSPORT_1302"
	ErrCodeExecTransportError = "TRANSPORT_1304"

	// Circuit breaker errors (1400-1499)
	ErrCodeCircuitBreakerOpen    = "CIRCUIT_1401"
	ErrCodeCircuitBreakerTimeout = "CIRCUIT_1402"

	// Rate limiting errors (1500-1599)
	ErrCodeRateLimitExceeded = "RATELIMIT_1501"

	// Health check errors (1600-1699)
	ErrCodeHealthCheckFailed  = "HEALTH_1601"
	ErrCodeHealthCheckTimeout = "HEALTH_1602"

	// Configuration management errors (1700-1799)
	ErrCodeConfigNotFound        = "CONFIG_1701"
	ErrCodeConfigParseError      = "CONFIG_1702"
	ErrCodeConfigValidationError = "CONFIG_1703"
	ErrCodeConfigWatcherError    = "CONFIG_1704"
	ErrCodeConfigPathError       = "CONFIG_1705"
	ErrCodeConfigFileError       = "CONFIG_1706"
	ErrCodeConfigPermissionError = "CONFIG_1707"

	// Security errors (1800-1899)
	ErrCodeSecurityValidationError = "SECURITY_1801"
	ErrCodeWhitelistError          = "SECURITY_1802"
	ErrCodeHashValidationError     = "SECURITY_1803"
	ErrCodePathTraversalError      = "SECURITY_1804"
	ErrCodeFilePermissionError     = "SECURITY_1805"
	ErrCodeAuditError              = "SECURITY_1806"

	// Registry and isolation errors (1900-1999)
	ErrCodeRegistryError   = "REGISTRY_1901"
	ErrCodeIsolationError  = "REGISTRY_1902"
	ErrCodeProcessError    = "REGISTRY_1903"
	ErrCodeFactoryError    = "REGISTRY_1904"
	ErrCodeClientError     = "REGISTRY_1905"
	ErrCodeDiscoveryError  = "REGISTRY_1906"
	ErrCodePluginCreation  = "REGISTRY_1907"
	ErrCodeSubprocessError = "REGISTRY_1908"

	// RPC and communication errors (2000-2099)
	ErrCodeRPCError           = "RPC_2001"
	ErrCodeHandshakeError     = "RPC_2002"
	ErrCodeCommunicationError = "RPC_2003"
	ErrCodeProtocolError      = "RPC_2004"
	ErrCodeSerializationError = "RPC_2005"

	// Load balancer errors removed - using direct subprocess communication
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

func NewGRPCTransportError(cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeGRPCTransportError, "gRPC transport error").
		WithUserMessage("gRPC transport operation failed").
		WithSeverity("error").
		AsRetryable()
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

// Load balancer error constructors removed - using direct subprocess communication

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

// Configuration management error constructors

func NewConfigNotFoundError(path string) *errors.Error {
	return errors.New(ErrCodeConfigNotFound, "Configuration file not found").
		WithUserMessage("The configuration file could not be found").
		WithContext("config_path", path).
		WithSeverity("error")
}

func NewConfigParseError(path string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeConfigParseError, "Configuration parse error").
		WithUserMessage("Failed to parse configuration file").
		WithContext("config_path", path).
		WithSeverity("error")
}

func NewConfigValidationError(message string, cause error) *errors.Error {
	err := errors.New(ErrCodeConfigValidationError, "Configuration validation error: "+message).
		WithUserMessage("Configuration validation failed").
		WithSeverity("error")
	if cause != nil {
		return errors.Wrap(cause, ErrCodeConfigValidationError, "Configuration validation error: "+message).
			WithUserMessage("Configuration validation failed").
			WithSeverity("error")
	}
	return err
}

func NewConfigWatcherError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeConfigWatcherError, "Configuration watcher error: "+message).
		WithUserMessage("Configuration monitoring failed").
		WithSeverity("error")
}

func NewConfigPathError(path string, message string) *errors.Error {
	return errors.New(ErrCodeConfigPathError, "Configuration path error: "+message).
		WithUserMessage("Invalid configuration file path").
		WithContext("config_path", path).
		WithSeverity("error")
}

func NewConfigFileError(path string, message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeConfigFileError, "Configuration file error: "+message).
		WithUserMessage("Configuration file access failed").
		WithContext("config_path", path).
		WithSeverity("error")
}

func NewConfigPermissionError(path string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeConfigPermissionError, "Configuration permission error").
		WithUserMessage("Insufficient permissions to access configuration file").
		WithContext("config_path", path).
		WithSeverity("error")
}

// Security error constructors

func NewSecurityValidationError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeSecurityValidationError, "Security validation error: "+message).
		WithUserMessage("Security validation failed").
		WithSeverity("error")
}

func NewWhitelistError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeWhitelistError, "Whitelist error: "+message).
		WithUserMessage("Plugin whitelist validation failed").
		WithSeverity("error")
}

func NewHashValidationError(pluginPath string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeHashValidationError, "Hash validation error").
		WithUserMessage("Plugin integrity verification failed").
		WithContext("plugin_path", pluginPath).
		WithSeverity("error")
}

func NewPathTraversalError(path string) *errors.Error {
	return errors.New(ErrCodePathTraversalError, "Path traversal attempt detected").
		WithUserMessage("Invalid file path detected").
		WithContext("attempted_path", path).
		WithSeverity("error")
}

func NewFilePermissionError(path string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeFilePermissionError, "File permission error").
		WithUserMessage("Insufficient permissions to access file").
		WithContext("file_path", path).
		WithSeverity("error")
}

func NewAuditError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeAuditError, "Audit error: "+message).
		WithUserMessage("Security audit logging failed").
		WithSeverity("warning")
}

// Registry and isolation error constructors

func NewRegistryError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeRegistryError, "Registry error: "+message).
		WithUserMessage("Plugin registry operation failed").
		WithSeverity("error")
}

func NewIsolationError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeIsolationError, "Isolation error: "+message).
		WithUserMessage("Plugin isolation failed").
		WithSeverity("error")
}

func NewProcessError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeProcessError, "Process error: "+message).
		WithUserMessage("Plugin process management failed").
		WithSeverity("error")
}

func NewFactoryError(pluginType string, message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeFactoryError, "Factory error: "+message).
		WithUserMessage("Plugin factory operation failed").
		WithContext("plugin_type", pluginType).
		WithSeverity("error")
}

func NewClientError(clientName string, message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeClientError, "Client error: "+message).
		WithUserMessage("Plugin client operation failed").
		WithContext("client_name", clientName).
		WithSeverity("error")
}

func NewDiscoveryError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeDiscoveryError, "Discovery error: "+message).
		WithUserMessage("Plugin discovery failed").
		WithSeverity("error")
}

// RPC and communication error constructors

func NewRPCError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeRPCError, "RPC error: "+message).
		WithUserMessage("RPC communication failed").
		WithSeverity("error").
		AsRetryable()
}

func NewHandshakeError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeHandshakeError, "Handshake error: "+message).
		WithUserMessage("Plugin handshake failed").
		WithSeverity("error")
}

func NewCommunicationError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeCommunicationError, "Communication error: "+message).
		WithUserMessage("Plugin communication failed").
		WithSeverity("error").
		AsRetryable()
}

func NewPluginProtocolError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeProtocolError, "Protocol error: "+message).
		WithUserMessage("Protocol error occurred").
		WithSeverity("error")
}

func NewSerializationError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeSerializationError, "Serialization error: "+message).
		WithUserMessage("Data serialization failed").
		WithSeverity("error")
}

// Plugin creation error constructors

func NewPluginCreationError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodePluginCreation, "Plugin creation failed: "+message).
		WithUserMessage("Failed to create plugin").
		WithSeverity("error")
}

func NewSubprocessError(message string, cause error) *errors.Error {
	return errors.Wrap(cause, ErrCodeSubprocessError, "Subprocess operation failed: "+message).
		WithUserMessage("Subprocess plugin operation failed").
		WithSeverity("error")
}
