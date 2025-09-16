# Library Configuration API Reference

This document provides comprehensive API reference for the Library Configuration Hot Reload system.

## Table of Contents

1. [Core Types](#core-types)
2. [LibraryConfigWatcher](#libraryconfigwatcher)
3. [Environment Functions](#environment-functions)
4. [Configuration Structures](#configuration-structures)
5. [Options and Settings](#options-and-settings)
6. [Error Types](#error-types)
7. [Interfaces](#interfaces)

## Core Types

### LibraryConfigWatcher

Main type for managing library configuration hot reload.

```go
type LibraryConfigWatcher[Req, Resp any] struct {
    // Internal fields are not exported
}
```

#### Constructor

```go
func NewLibraryConfigWatcher[Req, Resp any](
    manager *Manager[Req, Resp],
    configPath string,
    options LibraryConfigOptions,
    logger Logger,
) (*LibraryConfigWatcher[Req, Resp], error)
```

**Parameters:**
- `manager`: Plugin manager instance to configure
- `configPath`: Path to the configuration file (JSON or YAML)
- `options`: Configuration options for the watcher
- `logger`: Logger instance for debugging and audit

**Returns:**
- `*LibraryConfigWatcher[Req, Resp]`: Configured watcher instance
- `error`: Error if initialization fails

**Example:**
```go
manager := goplugins.NewManager[MyRequest, MyResponse]()
logger := log.New(os.Stdout, "[CONFIG] ", log.LstdFlags)
options := goplugins.DefaultLibraryConfigOptions()

watcher, err := goplugins.NewLibraryConfigWatcher(
    manager,
    "config.json",
    options,
    logger,
)
```

#### Methods

##### Start

```go
func (lcw *LibraryConfigWatcher[Req, Resp]) Start(ctx context.Context) error
```

Starts the configuration watcher and begins monitoring the config file.

**Parameters:**
- `ctx`: Context for cancellation and timeout control

**Returns:**
- `error`: Error if startup fails

**Behavior:**
1. Loads initial configuration from file
2. Validates and applies configuration
3. Starts file watching with Argus
4. Creates audit trail entry

**Example:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := watcher.Start(ctx); err != nil {
    log.Fatalf("Failed to start watcher: %v", err)
}
```

##### Stop

```go
func (lcw *LibraryConfigWatcher[Req, Resp]) Stop() error
```

Gracefully stops the configuration watcher.

**Returns:**
- `error`: Error if shutdown fails

**Behavior:**
1. Stops file watching
2. Closes audit logger
3. Releases resources
4. Marks watcher as disabled

**Example:**
```go
if err := watcher.Stop(); err != nil {
    log.Printf("Warning: failed to stop watcher: %v", err)
}
```

##### GetCurrentConfig

```go
func (lcw *LibraryConfigWatcher[Req, Resp]) GetCurrentConfig() *LibraryConfig
```

Returns the currently active configuration.

**Returns:**
- `*LibraryConfig`: Current configuration (thread-safe copy)

**Thread Safety:** This method is safe for concurrent access.

**Example:**
```go
config := watcher.GetCurrentConfig()
fmt.Printf("Current log level: %s\n", config.Logging.Level)
```

##### IsEnabled

```go
func (lcw *LibraryConfigWatcher[Req, Resp]) IsEnabled() bool
```

Returns whether the watcher is currently active.

**Returns:**
- `bool`: True if watcher is running, false otherwise

**Example:**
```go
if watcher.IsEnabled() {
    fmt.Println("Configuration watcher is active")
}
```

## Environment Functions

### ExpandEnvironmentVariables

```go
func ExpandEnvironmentVariables(config interface{}, options EnvExpansionOptions) error
```

Expands environment variables in a configuration structure using `${VAR}` syntax.

**Parameters:**
- `config`: Pointer to configuration structure to process
- `options`: Options for environment expansion

**Returns:**
- `error`: Error if expansion fails

**Supported Syntax:**
- `${VAR}`: Required variable (error if missing)
- `${VAR:default}`: Optional variable with default value
- Nested structures and slices are processed recursively

**Security Features:**
- Prefix validation (only variables with allowed prefixes)
- Length limits (prevents oversized values)
- Pattern matching (validates variable names)
- Sanitization (prevents command injection)

**Example:**
```go
type Config struct {
    LogLevel string `json:"log_level"`
    Port     string `json:"port"`
}

config := &Config{
    LogLevel: "${LOG_LEVEL:info}",
    Port:     "${PORT:8080}",
}

options := EnvExpansionOptions{
    VariablePrefix: "APP_",
    FailOnMissing:  false,
    MaxValueLength: 1024,
}

err := ExpandEnvironmentVariables(config, options)
```

### ProcessConfiguration

```go
func ProcessConfiguration(configData []byte, config interface{}, options EnvExpansionOptions) error
```

Processes raw configuration data (JSON/YAML) with environment expansion.

**Parameters:**
- `configData`: Raw configuration data (JSON or YAML bytes)
- `config`: Pointer to configuration structure to populate
- `options`: Options for environment expansion

**Returns:**
- `error`: Error if processing fails

**Processing Steps:**
1. Detect format (JSON/YAML)
2. Parse configuration data
3. Expand environment variables
4. Validate structure

**Example:**
```go
configData := []byte(`{"log_level": "${LOG_LEVEL:info}"}`)
var config MyConfig

options := EnvExpansionOptions{
    VariablePrefix: "APP_",
    FailOnMissing:  false,
}

err := ProcessConfiguration(configData, &config, options)
```

## Configuration Structures

### LibraryConfig

Main configuration structure for the library.

```go
type LibraryConfig struct {
    Logging         LoggingConfig               `json:"logging" yaml:"logging"`
    Observability   ObservabilityRuntimeConfig  `json:"observability" yaml:"observability"`
    DefaultPolicies DefaultPoliciesConfig       `json:"default_policies" yaml:"default_policies"`
    Environment     EnvironmentConfig           `json:"environment" yaml:"environment"`
    Performance     PerformanceConfig           `json:"performance" yaml:"performance"`
    Metadata        ConfigMetadata              `json:"metadata" yaml:"metadata"`
}
```

### LoggingConfig

Configuration for logging behavior.

```go
type LoggingConfig struct {
    Level             string            `json:"level" yaml:"level"`
    Format            string            `json:"format" yaml:"format"`
    Structured        bool              `json:"structured" yaml:"structured"`
    IncludeCaller     bool              `json:"include_caller" yaml:"include_caller"`
    IncludeStackTrace bool              `json:"include_stack_trace" yaml:"include_stack_trace"`
    ComponentLevels   map[string]string `json:"component_levels,omitempty" yaml:"component_levels,omitempty"`
}
```

**Field Descriptions:**
- `Level`: Global log level (`debug`, `info`, `warn`, `error`)
- `Format`: Log format (`json`, `text`)
- `Structured`: Enable structured logging
- `IncludeCaller`: Include caller information in logs
- `IncludeStackTrace`: Include stack traces in error logs
- `ComponentLevels`: Per-component log level overrides

### ObservabilityRuntimeConfig

Configuration for observability features.

```go
type ObservabilityRuntimeConfig struct {
    MetricsEnabled            bool          `json:"metrics_enabled" yaml:"metrics_enabled"`
    MetricsInterval           time.Duration `json:"metrics_interval" yaml:"metrics_interval"`
    TracingEnabled            bool          `json:"tracing_enabled" yaml:"tracing_enabled"`
    TracingSampleRate         float64       `json:"tracing_sample_rate" yaml:"tracing_sample_rate"`
    HealthMetricsEnabled      bool          `json:"health_metrics_enabled" yaml:"health_metrics_enabled"`
    PerformanceMetricsEnabled bool          `json:"performance_metrics_enabled" yaml:"performance_metrics_enabled"`
}
```

**Field Descriptions:**
- `MetricsEnabled`: Enable metrics collection
- `MetricsInterval`: Interval for metrics collection (minimum 1 second)
- `TracingEnabled`: Enable distributed tracing
- `TracingSampleRate`: Tracing sample rate (0.0 to 1.0)
- `HealthMetricsEnabled`: Enable health check metrics
- `PerformanceMetricsEnabled`: Enable performance metrics

### DefaultPoliciesConfig

Default policies applied to new plugins.

```go
type DefaultPoliciesConfig struct {
    Retry          RetryConfig          `json:"retry" yaml:"retry"`
    CircuitBreaker CircuitBreakerConfig `json:"circuit_breaker" yaml:"circuit_breaker"`
    HealthCheck    HealthCheckConfig    `json:"health_check" yaml:"health_check"`
    Connection     ConnectionConfig     `json:"connection" yaml:"connection"`
    RateLimit      RateLimitConfig      `json:"rate_limit" yaml:"rate_limit"`
}
```

### EnvironmentConfig

Configuration for environment variable processing.

```go
type EnvironmentConfig struct {
    ExpansionEnabled bool              `json:"expansion_enabled" yaml:"expansion_enabled"`
    VariablePrefix   string            `json:"variable_prefix" yaml:"variable_prefix"`
    FailOnMissing    bool              `json:"fail_on_missing" yaml:"fail_on_missing"`
    Overrides        map[string]string `json:"overrides,omitempty" yaml:"overrides,omitempty"`
}
```

**Field Descriptions:**
- `ExpansionEnabled`: Enable environment variable expansion
- `VariablePrefix`: Prefix for allowed environment variables
- `FailOnMissing`: Fail if required environment variable is missing
- `Overrides`: Key-value pairs for environment expansion

### PerformanceConfig

Performance-related configuration settings.

```go
type PerformanceConfig struct {
    WatcherPollInterval       time.Duration `json:"watcher_poll_interval" yaml:"watcher_poll_interval"`
    CacheTTL                 time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
    MaxConcurrentHealthChecks int           `json:"max_concurrent_health_checks" yaml:"max_concurrent_health_checks"`
}
```

**Field Descriptions:**
- `WatcherPollInterval`: File polling interval (minimum 1 second)
- `CacheTTL`: Configuration cache TTL
- `MaxConcurrentHealthChecks`: Maximum concurrent health checks (minimum 1)

### ConfigMetadata

Metadata about the configuration.

```go
type ConfigMetadata struct {
    Version      string    `json:"version" yaml:"version"`
    Environment  string    `json:"environment" yaml:"environment"`
    LastModified time.Time `json:"last_modified" yaml:"last_modified"`
}
```

## Options and Settings

### LibraryConfigOptions

Options for configuring the LibraryConfigWatcher behavior.

```go
type LibraryConfigOptions struct {
    PollInterval        time.Duration `json:"poll_interval"`
    CacheTTL           time.Duration `json:"cache_ttl"`
    EnableEnvExpansion bool          `json:"enable_env_expansion"`
    ValidateBeforeApply bool          `json:"validate_before_apply"`
    RollbackOnFailure  bool          `json:"rollback_on_failure"`
    AuditConfig        AuditConfig   `json:"audit_config"`
}
```

**Field Descriptions:**
- `PollInterval`: How often to check for file changes (default: 10s)
- `CacheTTL`: How long to cache configuration (default: 5s)
- `EnableEnvExpansion`: Enable environment variable expansion (default: true)
- `ValidateBeforeApply`: Validate configuration before applying (default: true)
- `RollbackOnFailure`: Rollback on application failure (default: true)
- `AuditConfig`: Audit logging configuration

**Default Values:**
```go
func DefaultLibraryConfigOptions() LibraryConfigOptions {
    return LibraryConfigOptions{
        PollInterval:        10 * time.Second,
        CacheTTL:           5 * time.Second,
        EnableEnvExpansion: true,
        ValidateBeforeApply: true,
        RollbackOnFailure:  true,
        AuditConfig: AuditConfig{
            Enabled: false,
        },
    }
}
```

### EnvExpansionOptions

Options for environment variable expansion.

```go
type EnvExpansionOptions struct {
    VariablePrefix   string `json:"variable_prefix"`
    FailOnMissing    bool   `json:"fail_on_missing"`
    MaxValueLength   int    `json:"max_value_length"`
    AllowedPatterns  []string `json:"allowed_patterns"`
}
```

**Field Descriptions:**
- `VariablePrefix`: Required prefix for environment variables
- `FailOnMissing`: Fail if required variable is missing
- `MaxValueLength`: Maximum length of environment variable values
- `AllowedPatterns`: Regex patterns for allowed variable names

## Error Types

### Common Errors

```go
var (
    ErrConfigNotFound     = errors.New("configuration file not found")
    ErrInvalidConfig      = errors.New("invalid configuration")
    ErrValidationFailed   = errors.New("configuration validation failed")
    ErrEnvExpansionFailed = errors.New("environment variable expansion failed")
    ErrWatcherNotEnabled  = errors.New("configuration watcher is not enabled")
    ErrAlreadyRunning     = errors.New("configuration watcher is already running")
)
```

### Error Handling Patterns

```go
// Check for specific error types
if errors.Is(err, ErrConfigNotFound) {
    // Handle missing configuration file
}

// Configuration validation error
if strings.Contains(err.Error(), "validation failed") {
    // Handle validation error
}

// Environment expansion error
if strings.Contains(err.Error(), "environment variable expansion failed") {
    // Handle environment expansion error
}
```

## Interfaces

### Logger Interface

```go
type Logger interface {
    Debug(msg string, keysAndValues ...interface{})
    Info(msg string, keysAndValues ...interface{})
    Warn(msg string, keysAndValues ...interface{})
    Error(msg string, keysAndValues ...interface{})
}
```

**Implementation Example:**
```go
type StandardLogger struct {
    logger *log.Logger
}

func (l *StandardLogger) Info(msg string, keysAndValues ...interface{}) {
    l.logger.Printf("[INFO] %s %v", msg, keysAndValues)
}

func (l *StandardLogger) Error(msg string, keysAndValues ...interface{}) {
    l.logger.Printf("[ERROR] %s %v", msg, keysAndValues)
}
// ... implement other methods
```

---

## Usage Examples

### Basic Configuration Update

```go
// Get current configuration
config := watcher.GetCurrentConfig()

// Check if metrics are enabled
if config.Observability.MetricsEnabled {
    fmt.Println("Metrics collection is active")
}

// Check log level
fmt.Printf("Current log level: %s\n", config.Logging.Level)
```

### Environment Variable Expansion

```go
// Configuration with environment variables
configJSON := `{
  "logging": {
    "level": "${LOG_LEVEL:info}",
    "format": "${LOG_FORMAT:json}"
  },
  "observability": {
    "metrics_interval": "${METRICS_INTERVAL:30s}"
  }
}`

// Set environment variables
os.Setenv("LOG_LEVEL", "debug")
os.Setenv("METRICS_INTERVAL", "60s")

// Process configuration
var config LibraryConfig
options := EnvExpansionOptions{
    VariablePrefix: "",
    FailOnMissing:  false,
    MaxValueLength: 1024,
}

err := ProcessConfiguration([]byte(configJSON), &config, options)
```

### Custom Validation

```go
// Custom configuration validation
func validateCustomConfig(config *LibraryConfig) error {
    if config.Logging.Level == "debug" && config.Metadata.Environment == "production" {
        return fmt.Errorf("debug logging not allowed in production")
    }
    return nil
}

// Apply custom validation after standard validation
config := watcher.GetCurrentConfig()
if err := validateCustomConfig(config); err != nil {
    log.Printf("Custom validation failed: %v", err)
}
```

---

**Copyright (c) 2025 AGILira - A. Giordano**  
**SPDX-License-Identifier: MPL-2.0**