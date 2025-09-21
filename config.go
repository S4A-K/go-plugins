// config.go: Configuration system with validation and hot-reload support
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"encoding/json"
	"net/url"
	"time"
)

// TransportType represents the different transport protocols supported by the plugin system.
//
// Supported transport types:
//   - Executable: Direct execution of external processes (subprocess plugins) - Primary approach
//   - gRPC: High-performance RPC communication with optional TLS - For compatibility
//
// Example usage:
//
//	config := PluginConfig{
//	    Transport: TransportExecutable,
//	    Endpoint:  "./my-plugin",
//	}
type TransportType string

const (
	TransportGRPC       TransportType = "grpc"     // gRPC protocol support
	TransportGRPCTLS    TransportType = "grpc-tls" // gRPC with TLS
	TransportExecutable TransportType = "exec"     // Subprocess execution (recommended)
)

// AuthMethod represents different authentication methods supported by the plugin system.
//
// Available authentication methods:
//   - AuthNone: No authentication required
//   - AuthAPIKey: API key-based authentication via X-API-Key header
//   - AuthBearer: Bearer token authentication via Authorization header
//   - AuthBasic: Basic authentication with username/password
//   - AuthMTLS: Mutual TLS authentication using client certificates
//   - AuthCustom: Custom authentication method with user-defined headers
//
// Example usage:
//
//	auth := AuthConfig{
//	    Method: AuthBearer,
//	    Token:  "your-jwt-token-here",
//	}
type AuthMethod string

const (
	AuthNone   AuthMethod = "none"
	AuthAPIKey AuthMethod = "api-key"
	AuthBearer AuthMethod = "bearer"
	AuthBasic  AuthMethod = "basic"
	AuthMTLS   AuthMethod = "mtls"
	AuthCustom AuthMethod = "custom"
)

// AuthConfig contains authentication configuration for plugin connections.
//
// This structure supports multiple authentication methods and provides flexible
// configuration options for securing plugin communications. The specific fields
// used depend on the chosen authentication method.
//
// Field usage by auth method:
//   - AuthAPIKey: Uses APIKey field
//   - AuthBearer: Uses Token field
//   - AuthBasic: Uses Username and Password fields
//   - AuthMTLS: Uses CertFile, KeyFile, and optionally CAFile
//   - AuthCustom: Uses Headers field for custom authentication headers
//
// Example configurations:
//
//	// API Key authentication
//	auth := AuthConfig{
//	    Method: AuthAPIKey,
//	    APIKey: "your-api-key-here",
//	}
//
//	// mTLS authentication
//	auth := AuthConfig{
//	    Method:   AuthMTLS,
//	    CertFile: "/path/to/client.crt",
//	    KeyFile:  "/path/to/client.key",
//	    CAFile:   "/path/to/ca.crt",
//	}
type AuthConfig struct {
	Method   AuthMethod        `json:"method" yaml:"method"`
	APIKey   string            `json:"api_key,omitempty" yaml:"api_key,omitempty"`
	Token    string            `json:"token,omitempty" yaml:"token,omitempty"`
	Username string            `json:"username,omitempty" yaml:"username,omitempty"`
	Password string            `json:"password,omitempty" yaml:"password,omitempty"`
	CertFile string            `json:"cert_file,omitempty" yaml:"cert_file,omitempty"`
	KeyFile  string            `json:"key_file,omitempty" yaml:"key_file,omitempty"`
	CAFile   string            `json:"ca_file,omitempty" yaml:"ca_file,omitempty"`
	Headers  map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// RetryConfig contains retry and backoff configuration for failed plugin requests.
//
// This configuration implements an exponential backoff strategy with optional
// random jitter to prevent thundering herd problems when multiple clients
// retry simultaneously.
//
// The retry logic works as follows:
//  1. First retry after InitialInterval
//  2. Each subsequent retry multiplies the interval by Multiplier
//  3. Interval never exceeds MaxInterval
//  4. RandomJitter adds up to ±10% randomness to intervals
//  5. Stop retrying after MaxRetries attempts
//
// Example configuration:
//
//	retry := RetryConfig{
//	    MaxRetries:      3,
//	    InitialInterval: 100 * time.Millisecond,
//	    MaxInterval:     5 * time.Second,
//	    Multiplier:      2.0,
//	    RandomJitter:    true,
//	}
//	// This results in delays of ~100ms, ~200ms, ~400ms (with jitter)
type RetryConfig struct {
	MaxRetries      int           `json:"max_retries" yaml:"max_retries"`
	InitialInterval time.Duration `json:"initial_interval" yaml:"initial_interval"`
	MaxInterval     time.Duration `json:"max_interval" yaml:"max_interval"`
	Multiplier      float64       `json:"multiplier" yaml:"multiplier"`
	RandomJitter    bool          `json:"random_jitter" yaml:"random_jitter"`
}

// CircuitBreakerConfig contains circuit breaker settings for plugin resilience.
//
// The circuit breaker implements the Circuit Breaker pattern to prevent cascading
// failures by temporarily stopping requests to failing services. It has three states:
//   - Closed: Normal operation, requests flow through
//   - Open: Circuit is tripped, requests fail fast
//   - Half-Open: Testing if service has recovered
//
// State transitions:
//   - Closed → Open: When FailureThreshold consecutive failures occur
//   - Open → Half-Open: After RecoveryTimeout has elapsed
//   - Half-Open → Closed: When SuccessThreshold successes occur
//   - Half-Open → Open: When any failure occurs
//
// Example configuration:
//
//	cb := CircuitBreakerConfig{
//	    Enabled:             true,
//	    FailureThreshold:    5,    // Trip after 5 failures
//	    RecoveryTimeout:     30 * time.Second,
//	    MinRequestThreshold: 3,    // Need 3 requests before considering trip
//	    SuccessThreshold:    2,    // Need 2 successes to close circuit
//	}
type CircuitBreakerConfig struct {
	Enabled             bool          `json:"enabled" yaml:"enabled"`
	FailureThreshold    int           `json:"failure_threshold" yaml:"failure_threshold"`
	RecoveryTimeout     time.Duration `json:"recovery_timeout" yaml:"recovery_timeout"`
	MinRequestThreshold int           `json:"min_request_threshold" yaml:"min_request_threshold"`
	SuccessThreshold    int           `json:"success_threshold" yaml:"success_threshold"`
}

// HealthCheckConfig contains health check settings for monitoring plugin availability.
//
// Health checks are performed periodically to detect failed or degraded plugins
// and automatically route traffic away from unhealthy instances. The health
// checker maintains plugin status and provides early warning of issues.
//
// Configuration behavior:
//   - Interval: How often to perform health checks
//   - Timeout: Maximum time to wait for health check response
//   - FailureLimit: Number of consecutive failures before marking plugin unhealthy
//   - Endpoint: Custom endpoint for health checks (optional, defaults to plugin endpoint)
//
// Example configuration:
//
//	health := HealthCheckConfig{
//	    Enabled:      true,
//	    Interval:     30 * time.Second,  // Check every 30 seconds
//	    Timeout:      5 * time.Second,   // Fail if no response in 5 seconds
//	    FailureLimit: 3,                 // Mark unhealthy after 3 failures
//	    Endpoint:     "/health",         // Custom health endpoint
//	}
type HealthCheckConfig struct {
	Enabled      bool          `json:"enabled" yaml:"enabled"`
	Interval     time.Duration `json:"interval" yaml:"interval"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`
	FailureLimit int           `json:"failure_limit" yaml:"failure_limit"`
	Endpoint     string        `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
}

// ConnectionConfig contains connection pooling and timeout settings for plugin transports.
//
// This configuration optimizes network resource usage and performance by managing
// connection lifecycles and timeouts. Proper configuration prevents resource
// leaks and improves response times.
//
// Configuration guidelines:
//   - MaxConnections: Total connection pool size (consider server limits)
//   - MaxIdleConnections: Connections to keep alive when idle (balance memory vs latency)
//   - IdleTimeout: How long to keep idle connections (balance resource usage vs reconnect cost)
//   - ConnectionTimeout: Maximum time to establish new connections
//   - RequestTimeout: Maximum time for individual requests
//   - KeepAlive: Enable TCP keep-alive for long-lived connections
//
// Example configuration:
//
//	conn := ConnectionConfig{
//	    MaxConnections:     10,                   // Max 10 concurrent connections
//	    MaxIdleConnections: 5,                    // Keep 5 connections idle
//	    IdleTimeout:        30 * time.Second,     // Close idle connections after 30s
//	    ConnectionTimeout:  10 * time.Second,     // 10s to establish connection
//	    RequestTimeout:     30 * time.Second,     // 30s per request
//	    KeepAlive:          true,                 // Enable TCP keep-alive
//	    DisableCompression: false,               // Enable compression
//	}
type ConnectionConfig struct {
	MaxConnections     int           `json:"max_connections" yaml:"max_connections"`
	MaxIdleConnections int           `json:"max_idle_connections" yaml:"max_idle_connections"`
	IdleTimeout        time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	ConnectionTimeout  time.Duration `json:"connection_timeout" yaml:"connection_timeout"`
	RequestTimeout     time.Duration `json:"request_timeout" yaml:"request_timeout"`
	KeepAlive          bool          `json:"keep_alive" yaml:"keep_alive"`
	DisableCompression bool          `json:"disable_compression" yaml:"disable_compression"`
}

// RateLimitConfig contains rate limiting settings for controlling plugin request rates.
//
// Rate limiting protects plugins from being overwhelmed and ensures fair resource
// distribution. It implements a token bucket algorithm that allows burst traffic
// while maintaining average rate limits.
//
// Token bucket algorithm:
//   - BurstSize: Maximum tokens available (allows burst of requests)
//   - RequestsPerSecond: Rate at which tokens are replenished
//   - TimeWindow: Period over which the rate is measured
//   - Tokens are consumed for each request and replenished at the configured rate
//
// Example configuration:
//
//	rateLimit := RateLimitConfig{
//	    Enabled:           true,
//	    RequestsPerSecond: 10.0,           // Allow 10 requests per second
//	    BurstSize:         20,             // Allow bursts up to 20 requests
//	    TimeWindow:        time.Second,    // Rate window of 1 second
//	}
//	// This allows up to 20 requests immediately, then 10 per second thereafter
type RateLimitConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	RequestsPerSecond float64       `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	TimeWindow        time.Duration `json:"time_window" yaml:"time_window"`
}

// PluginConfig represents the comprehensive configuration for a single plugin instance.
//
// This is the main configuration structure that defines how a plugin connects,
// authenticates, and behaves within the plugin system. It combines transport
// configuration, security settings, resilience patterns, and operational parameters.
//
// Configuration sections:
//   - Basic: Name, type, transport, endpoint identification
//   - Executable: Process execution settings (for exec transport)
//   - Security: Authentication and authorization configuration
//   - Resilience: Retry, circuit breaker, health check settings
//   - Performance: Connection pooling, rate limiting configuration
//   - Metadata: Labels and annotations for organization and discovery
//
// Example configurations:
//
//	// Subprocess plugin with API key authentication
//	subprocessPlugin := PluginConfig{
//	    Name:      "payment-service",
//	    Type:      "subprocess",
//	    Transport: TransportExecutable,
//	    Endpoint:  "./payment-plugin",
//	    Enabled:   true,
//	    Priority:  1,
//	    Auth: AuthConfig{
//	        Method: AuthAPIKey,
//	        APIKey: "your-api-key",
//	    },
//	    Retry: RetryConfig{
//	        MaxRetries:      3,
//	        InitialInterval: 100 * time.Millisecond,
//	        MaxInterval:     5 * time.Second,
//	        Multiplier:      2.0,
//	        RandomJitter:    true,
//	    },
//	    Labels: map[string]string{
//	        "environment": "production",
//	        "version":     "v1.2.3",
//	    },
//	}
//
//	// Executable plugin with custom environment
//	execPlugin := PluginConfig{
//	    Name:       "data-processor",
//	    Type:       "processor",
//	    Transport:  TransportExecutable,
//	    Executable: "/opt/processors/data-processor",
//	    Args:       []string{"--config", "/etc/processor.conf"},
//	    Env:        []string{"LOG_LEVEL=info", "MAX_MEMORY=1GB"},
//	    WorkDir:    "/tmp/processor",
//	}
type PluginConfig struct {
	// Basic plugin information
	Name      string        `json:"name" yaml:"name"`
	Version   string        `json:"version" yaml:"version"`
	Type      string        `json:"type" yaml:"type"`
	Transport TransportType `json:"transport" yaml:"transport"`
	Endpoint  string        `json:"endpoint" yaml:"endpoint"`
	Priority  int           `json:"priority" yaml:"priority"`
	Enabled   bool          `json:"enabled" yaml:"enabled"`

	// Executable-specific configuration
	Executable string   `json:"executable,omitempty" yaml:"executable,omitempty"`
	Args       []string `json:"args,omitempty" yaml:"args,omitempty"`
	Env        []string `json:"env,omitempty" yaml:"env,omitempty"`
	WorkDir    string   `json:"work_dir,omitempty" yaml:"work_dir,omitempty"`

	// Security and authentication
	Auth AuthConfig `json:"auth" yaml:"auth"`

	// Resilience and reliability
	Retry          RetryConfig          `json:"retry" yaml:"retry"`
	CircuitBreaker CircuitBreakerConfig `json:"circuit_breaker" yaml:"circuit_breaker"`
	HealthCheck    HealthCheckConfig    `json:"health_check" yaml:"health_check"`
	Connection     ConnectionConfig     `json:"connection" yaml:"connection"`
	RateLimit      RateLimitConfig      `json:"rate_limit" yaml:"rate_limit"`

	// Plugin-specific configuration
	Options map[string]interface{} `json:"options,omitempty" yaml:"options,omitempty"`

	// Metadata
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// ManagerConfig represents the comprehensive configuration for the plugin manager.
//
// This is the top-level configuration that controls the entire plugin system,
// including global settings, default policies, and the collection of plugin
// configurations. It provides a centralized way to manage plugin behavior
// and operational parameters.
//
// Configuration structure:
//   - Global: System-wide settings like logging and metrics
//   - Defaults: Default configurations applied to all plugins
//   - Plugins: Individual plugin configurations
//   - Discovery: Automatic plugin discovery settings
//
// The manager applies default configurations to plugins that don't specify
// their own values, allowing for consistent behavior across the system while
// still permitting per-plugin customization.
//
// Example configuration:
//
//	config := ManagerConfig{
//	    LogLevel:    "info",
//	    MetricsPort: 9090,
//	    DefaultRetry: RetryConfig{
//	        MaxRetries:      3,
//	        InitialInterval: 100 * time.Millisecond,
//	        MaxInterval:     5 * time.Second,
//	        Multiplier:      2.0,
//	        RandomJitter:    true,
//	    },
//	    DefaultHealthCheck: HealthCheckConfig{
//	        Enabled:      true,
//	        Interval:     30 * time.Second,
//	        Timeout:      5 * time.Second,
//	        FailureLimit: 3,
//	    },
//	    Plugins: []PluginConfig{
//	        {
//	            Name:      "auth-service",
//	            Transport: TransportExecutable,
//	            Endpoint:  "./auth-plugin",
//	            // Inherits default retry and health check settings
//	        },
//	    },
//	}
type ManagerConfig struct {
	// Global settings
	LogLevel    string `json:"log_level" yaml:"log_level"`
	MetricsPort int    `json:"metrics_port" yaml:"metrics_port"`

	// Default configurations that apply to all plugins unless overridden
	DefaultRetry          RetryConfig          `json:"default_retry" yaml:"default_retry"`
	DefaultCircuitBreaker CircuitBreakerConfig `json:"default_circuit_breaker" yaml:"default_circuit_breaker"`
	DefaultHealthCheck    HealthCheckConfig    `json:"default_health_check" yaml:"default_health_check"`
	DefaultConnection     ConnectionConfig     `json:"default_connection" yaml:"default_connection"`
	DefaultRateLimit      RateLimitConfig      `json:"default_rate_limit" yaml:"default_rate_limit"`

	// Plugin configurations
	Plugins []PluginConfig `json:"plugins" yaml:"plugins"`

	// Plugin discovery settings
	Discovery DiscoveryConfig `json:"discovery,omitempty" yaml:"discovery,omitempty"`

	// Security configuration for plugin whitelisting
	Security SecurityConfig `json:"security,omitempty" yaml:"security,omitempty"`
}

// DiscoveryConfig contains plugin auto-discovery settings for dynamic plugin loading.
//
// The discovery system automatically finds and loads plugins from specified
// directories, enabling dynamic plugin registration without manual configuration.
// This is particularly useful for plugin ecosystems where plugins are deployed
// independently.
//
// Discovery behavior:
//   - Directories: List of paths to scan for plugins
//   - Patterns: File name patterns to match (e.g., "*.so", "plugin-*")
//   - WatchMode: Continuously monitor directories for changes
//
// Security considerations:
//   - Only scan trusted directories to prevent malicious plugin loading
//   - Use specific patterns to avoid loading unintended files
//   - Validate discovered plugins before loading
//
// Example configuration:
//
//	discovery := DiscoveryConfig{
//	    Enabled:     true,
//	    Directories: []string{
//	        "/opt/plugins",
//	        "/usr/local/lib/plugins",
//	    },
//	    Patterns: []string{
//	        "*.so",      // Shared libraries
//	        "plugin-*",  // Plugin executables
//	    },
//	    WatchMode: true,  // Hot-reload new plugins
//	}
type DiscoveryConfig struct {
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	Directories []string `json:"directories,omitempty" yaml:"directories,omitempty"`
	Patterns    []string `json:"patterns,omitempty" yaml:"patterns,omitempty"`
	WatchMode   bool     `json:"watch_mode" yaml:"watch_mode"`
}

// validateBasicConfig validates basic plugin configuration fields
func (pc *PluginConfig) validateBasicConfig() error {
	if pc.Name == "" {
		return NewInvalidPluginNameError(pc.Name)
	}
	if pc.Transport == "" {
		return NewInvalidTransportError()
	}
	return nil
}

// validateNetworkTransport validates network-based transport configuration
func (pc *PluginConfig) validateNetworkTransport() error {
	if pc.Endpoint == "" {
		return NewMissingEndpointError(pc.Transport)
	}

	// Handle gRPC endpoints differently (they use host:port format, not URLs)
	if pc.Transport == TransportGRPC || pc.Transport == TransportGRPCTLS {
		// For gRPC, validate host:port format
		// Basic validation that it's not empty (more detailed validation by gRPC factory)
		return nil
	}

	// For network transports, validate endpoint URL
	parsed, err := url.Parse(pc.Endpoint)
	if err != nil {
		return NewInvalidEndpointURLError(pc.Endpoint, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return NewInvalidEndpointFormatError()
	}
	return nil
}

// validateTransportConfig validates transport-specific configuration
func (pc *PluginConfig) validateTransportConfig() error {
	return pc.validateTransportConfigWithContext(nil)
}

// validateTransportConfigWithContext validates transport-specific configuration
// with optional context about supported custom transports
func (pc *PluginConfig) validateTransportConfigWithContext(customTransports map[string]bool) error {
	switch pc.Transport {
	case TransportGRPC, TransportGRPCTLS:
		return pc.validateNetworkTransport()
	case TransportExecutable:
		if pc.Executable == "" {
			return NewMissingExecutableError()
		}
	default:
		// Check if this is a known custom transport
		if customTransports != nil && customTransports[string(pc.Transport)] {
			// Custom transport - minimal validation (delegate to custom factory)
			return nil
		}
		return NewUnsupportedTransportError(pc.Transport)
	}
	return nil
}

// Validate validates the plugin configuration
func (pc *PluginConfig) Validate() error {
	if err := pc.validateBasicConfig(); err != nil {
		return err
	}

	if err := pc.validateTransportConfig(); err != nil {
		return err
	}

	// Validate authentication configuration
	if err := pc.Auth.Validate(); err != nil {
		return NewAuthConfigValidationError(err)
	}

	return nil
} // validateAPIKeyAuth validates API key authentication configuration
func (ac *AuthConfig) validateAPIKeyAuth() error {
	if ac.APIKey == "" {
		return NewMissingAPIKeyError()
	}
	return nil
}

// validateBearerAuth validates bearer token authentication configuration
func (ac *AuthConfig) validateBearerAuth() error {
	if ac.Token == "" {
		return NewMissingBearerTokenError()
	}
	return nil
}

// validateBasicAuth validates basic authentication configuration
func (ac *AuthConfig) validateBasicAuth() error {
	if ac.Username == "" || ac.Password == "" {
		return NewMissingBasicCredentialsError()
	}
	return nil
}

// validateMTLSAuth validates mTLS authentication configuration
func (ac *AuthConfig) validateMTLSAuth() error {
	if ac.CertFile == "" || ac.KeyFile == "" {
		return NewMissingMTLSCertsError()
	}
	return nil
}

// Validate validates the authentication configuration
func (ac *AuthConfig) Validate() error {
	switch ac.Method {
	case AuthNone:
		return nil
	case AuthAPIKey:
		return ac.validateAPIKeyAuth()
	case AuthBearer:
		return ac.validateBearerAuth()
	case AuthBasic:
		return ac.validateBasicAuth()
	case AuthMTLS:
		return ac.validateMTLSAuth()
	case AuthCustom:
		return nil // Custom auth method should be validated by the plugin implementation
	default:
		return NewUnsupportedAuthMethodError(ac.Method)
	}
}

// Validate validates the manager configuration
func (mc *ManagerConfig) Validate() error {
	if len(mc.Plugins) == 0 {
		return NewNoPluginsConfiguredError()
	}

	// Check for duplicate plugin names
	names := make(map[string]bool)
	for i, plugin := range mc.Plugins {
		if err := plugin.Validate(); err != nil {
			return NewPluginValidationError(i, err)
		}

		if names[plugin.Name] {
			return NewDuplicatePluginNameError(plugin.Name)
		}
		names[plugin.Name] = true
	}

	return nil
}

// applyDefaultAuth applies default authentication method if not specified
func (mc *ManagerConfig) applyDefaultAuth(plugin *PluginConfig) {
	if plugin.Auth.Method == "" {
		plugin.Auth.Method = AuthNone
	}
}

// applyDefaultRetry applies default retry configuration if not specified
func (mc *ManagerConfig) applyDefaultRetry(plugin *PluginConfig) {
	if plugin.Retry.MaxRetries == 0 && mc.DefaultRetry.MaxRetries > 0 {
		plugin.Retry = mc.DefaultRetry
	}
}

// applyDefaultCircuitBreaker applies default circuit breaker configuration if not specified
func (mc *ManagerConfig) applyDefaultCircuitBreaker(plugin *PluginConfig) {
	if !plugin.CircuitBreaker.Enabled && mc.DefaultCircuitBreaker.Enabled {
		plugin.CircuitBreaker = mc.DefaultCircuitBreaker
	}
}

// applyDefaultHealthCheck applies default health check configuration if not specified
func (mc *ManagerConfig) applyDefaultHealthCheck(plugin *PluginConfig) {
	if !plugin.HealthCheck.Enabled && mc.DefaultHealthCheck.Enabled {
		plugin.HealthCheck = mc.DefaultHealthCheck
	}
}

// applyDefaultConnection applies default connection configuration if not specified
func (mc *ManagerConfig) applyDefaultConnection(plugin *PluginConfig) {
	if plugin.Connection.MaxConnections == 0 && mc.DefaultConnection.MaxConnections > 0 {
		plugin.Connection = mc.DefaultConnection
	}
}

// applyDefaultRateLimit applies default rate limit configuration if not specified
func (mc *ManagerConfig) applyDefaultRateLimit(plugin *PluginConfig) {
	if !plugin.RateLimit.Enabled && mc.DefaultRateLimit.Enabled {
		plugin.RateLimit = mc.DefaultRateLimit
	}
}

// ApplyDefaults applies default configurations to plugins that don't specify them
func (mc *ManagerConfig) ApplyDefaults() {
	for i := range mc.Plugins {
		plugin := &mc.Plugins[i]

		mc.applyDefaultAuth(plugin)
		mc.applyDefaultRetry(plugin)
		mc.applyDefaultCircuitBreaker(plugin)
		mc.applyDefaultHealthCheck(plugin)
		mc.applyDefaultConnection(plugin)
		mc.applyDefaultRateLimit(plugin)
	}
} // ToJSON converts the configuration to JSON
func (mc *ManagerConfig) ToJSON() ([]byte, error) {
	return json.MarshalIndent(mc, "", "  ")
}

// FromJSON loads configuration from JSON
func (mc *ManagerConfig) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, mc); err != nil {
		return NewInvalidJSONConfigError(err)
	}
	return mc.Validate()
}

// GetDefaultManagerConfig returns a ManagerConfig with sensible production defaults.
// This function provides a complete configuration template that can be used as-is
// for most applications or customized for specific needs.
//
// Default configuration includes:
//   - Info-level logging for balanced verbosity
//   - Metrics server on port 9090
//   - Exponential backoff retry with jitter (3 attempts, 100ms to 5s)
//   - Circuit breaker with 5-failure threshold and 30s recovery
//   - Health checks every 30 seconds with 5s timeout
//   - Connection pooling with reasonable limits
//   - Rate limiting disabled by default
//
// Returns:
//
//	ManagerConfig with production-ready default values
//
// Example usage:
//
//	config := GetDefaultManagerConfig()
//	config.LogLevel = "debug"  // Customize as needed
//	config.Plugins = []PluginConfig{
//	    // Add your plugins here
//	}
//	manager := NewManager[MyRequest, MyResponse](logger)
//	err := manager.LoadFromConfig(config)
func GetDefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		LogLevel:    "info",
		MetricsPort: 9090,
		DefaultRetry: RetryConfig{
			MaxRetries:      3,
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     5 * time.Second,
			Multiplier:      2.0,
			RandomJitter:    true,
		},
		DefaultCircuitBreaker: CircuitBreakerConfig{
			Enabled:             true,
			FailureThreshold:    5,
			RecoveryTimeout:     30 * time.Second,
			MinRequestThreshold: 3,
			SuccessThreshold:    2,
		},
		DefaultHealthCheck: HealthCheckConfig{
			Enabled:      true,
			Interval:     30 * time.Second,
			Timeout:      5 * time.Second,
			FailureLimit: 3,
		},
		DefaultConnection: ConnectionConfig{
			MaxConnections:     10,
			MaxIdleConnections: 5,
			IdleTimeout:        30 * time.Second,
			ConnectionTimeout:  10 * time.Second,
			RequestTimeout:     30 * time.Second,
			KeepAlive:          true,
		},
		DefaultRateLimit: RateLimitConfig{
			Enabled:           false,
			RequestsPerSecond: 10.0,
			BurstSize:         20,
			TimeWindow:        time.Second,
		},
		Plugins: []PluginConfig{},
	}
}
