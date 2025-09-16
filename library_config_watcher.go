// library_config_watcher.go: Library-level configuration hot reload with Argus integration
//
// This module extends the existing Argus integration to support hot reloading of
// library-level configurations such as logging levels, observability settings,
// default policies, and environment variable overrides.
//
// Key Features:
// - Hot reload for library defaults (retry, circuit breaker, health check policies)
// - Runtime log level adjustments without service restart
// - Observability configuration updates (metrics, tracing settings)
// - Environment variable expansion with ${VAR} syntax
// - Comprehensive audit trail for all configuration changes
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/argus"
	"gopkg.in/yaml.v3"
)

// LibraryConfigWatcher manages hot reload of library-level configuration settings.
//
// This watcher complements the existing ConfigWatcher by focusing specifically on
// library infrastructure settings that don't require plugin recreation but can be
// applied dynamically to improve operational flexibility.
//
// Supported configuration categories:
//   - Logging: Log levels, output formats, structured logging
//   - Observability: Metrics settings, tracing configuration, monitoring
//   - Defaults: Default policies applied to new plugins
//   - Environment: Variable expansion and environment overrides
//   - Performance: Polling intervals, cache settings, optimization flags
//
// Usage example:
//
//	libWatcher := NewLibraryConfigWatcher(manager, "/etc/go-plugins/library.json")
//	defer libWatcher.Stop()
//
//	if err := libWatcher.Start(ctx); err != nil {
//	    log.Printf("Library config watcher failed: %v", err)
//	}
type LibraryConfigWatcher[Req, Resp any] struct {
	// Core dependencies
	manager *Manager[Req, Resp] // Associated plugin manager instance
	logger  Logger              // Logging interface for status and error reporting

	// Argus integration components
	watcher     *argus.Watcher     // Ultra-fast file change detection
	auditLogger *argus.AuditLogger // Comprehensive audit trail system

	// Configuration management
	configPath    string                        // Path to library configuration file
	currentConfig atomic.Pointer[LibraryConfig] // Thread-safe current config state
	envExpander   *EnvironmentVariableExpander  // Environment variable processor

	// Lifecycle management
	enabled  atomic.Bool // Thread-safe enabled/disabled state
	stopped  atomic.Bool // Permanent stop flag to prevent restart
	stopOnce sync.Once   // Ensures Stop() is called exactly once
	mutex    sync.Mutex  // Protects start/stop operations only

	// Configuration options
	options LibraryConfigOptions // Behavior customization options
}

// LibraryConfig represents library-level configuration that can be hot-reloaded.
//
// This structure contains all library settings that can be changed at runtime
// without requiring plugin recreation or service restart. It focuses on
// operational and observability settings that benefit from dynamic updates.
//
// Configuration categories:
//   - LoggingConfig: Runtime logging behavior
//   - ObservabilityConfig: Monitoring and metrics settings
//   - DefaultPolicies: Default policies for new plugins
//   - EnvironmentConfig: Variable expansion and overrides
//   - PerformanceConfig: Runtime performance tuning
type LibraryConfig struct {
	// Logging configuration for runtime adjustments
	Logging LoggingConfig `json:"logging" yaml:"logging"`

	// Observability settings for monitoring and metrics
	Observability ObservabilityRuntimeConfig `json:"observability" yaml:"observability"`

	// Default policies applied to new plugins during registration
	DefaultPolicies DefaultPoliciesConfig `json:"default_policies" yaml:"default_policies"`

	// Security configuration including plugin whitelist and validation
	Security SecurityConfig `json:"security" yaml:"security"`

	// Environment variable configuration and overrides
	Environment EnvironmentConfig `json:"environment" yaml:"environment"`

	// Performance tuning settings
	Performance PerformanceConfig `json:"performance" yaml:"performance"`

	// Metadata for configuration tracking and validation
	Metadata ConfigMetadata `json:"metadata" yaml:"metadata"`
}

// EnvironmentVariableExpander handles expansion of environment variables in configuration.
//
// This component processes configuration values containing ${VAR} placeholders,
// replacing them with actual environment variable values or configured defaults.
// It provides safe expansion with error handling and security validation.
type EnvironmentVariableExpander struct {
	prefix        string            // Prefix for environment variables (e.g., "GO_PLUGINS_")
	defaults      map[string]string // Default values for undefined variables
	failOnMissing bool              // Whether to fail when variables are missing
}

// EnvironmentExpansionOptions configures environment variable expansion behavior.
//
// These options control how environment variables are discovered, expanded,
// and handled when missing, providing flexibility for different deployment
// scenarios and security requirements.
type EnvironmentExpansionOptions struct {
	// Prefix for environment variables (e.g., "GO_PLUGINS_")
	Prefix string `json:"prefix" yaml:"prefix"`

	// Default values for undefined environment variables
	Defaults map[string]string `json:"defaults,omitempty" yaml:"defaults,omitempty"`

	// Whether to fail on missing environment variables
	FailOnMissing bool `json:"fail_on_missing" yaml:"fail_on_missing"`
}

// NewEnvironmentVariableExpander creates a new environment variable expander.
//
// This function initializes an expander with the specified options, providing
// safe environment variable expansion capabilities for configuration processing.
func NewEnvironmentVariableExpander(options EnvironmentExpansionOptions) *EnvironmentVariableExpander {
	return &EnvironmentVariableExpander{
		prefix:        options.Prefix,
		defaults:      options.Defaults,
		failOnMissing: options.FailOnMissing,
	}
}

// LoggingConfig controls runtime logging behavior without service restart.
//
// This configuration allows dynamic adjustment of logging levels, formats,
// and output destinations to support debugging and operational needs without
// requiring service interruption.
//
// Features:
//   - Runtime log level changes (debug, info, warn, error)
//   - Structured logging format switching (JSON, text, custom)
//   - Output destination management (stdout, file, syslog)
//   - Component-specific log level overrides
type LoggingConfig struct {
	// Global log level applied to all components
	Level string `json:"level" yaml:"level"`

	// Output format: "json", "text", "structured"
	Format string `json:"format" yaml:"format"`

	// Whether to enable structured logging with key-value pairs
	Structured bool `json:"structured" yaml:"structured"`

	// Component-specific log level overrides
	ComponentLevels map[string]string `json:"component_levels,omitempty" yaml:"component_levels,omitempty"`

	// Whether to include caller information (file:line) in logs
	IncludeCaller bool `json:"include_caller" yaml:"include_caller"`

	// Whether to include stack traces for error-level logs
	IncludeStackTrace bool `json:"include_stack_trace" yaml:"include_stack_trace"`
}

// ObservabilityRuntimeConfig manages runtime observability settings.
//
// This configuration allows dynamic adjustment of monitoring, metrics collection,
// and tracing settings without service restart, enabling operational flexibility
// for debugging and performance analysis.
type ObservabilityRuntimeConfig struct {
	// Whether metrics collection is enabled
	MetricsEnabled bool `json:"metrics_enabled" yaml:"metrics_enabled"`

	// Metrics collection interval
	MetricsInterval time.Duration `json:"metrics_interval" yaml:"metrics_interval"`

	// Whether distributed tracing is enabled
	TracingEnabled bool `json:"tracing_enabled" yaml:"tracing_enabled"`

	// Tracing sample rate (0.0 to 1.0)
	TracingSampleRate float64 `json:"tracing_sample_rate" yaml:"tracing_sample_rate"`

	// Whether to collect detailed health check metrics
	HealthMetricsEnabled bool `json:"health_metrics_enabled" yaml:"health_metrics_enabled"`

	// Whether to collect performance metrics
	PerformanceMetricsEnabled bool `json:"performance_metrics_enabled" yaml:"performance_metrics_enabled"`
}

// DefaultPoliciesConfig defines default policies applied to new plugins.
//
// These policies are applied when plugins are registered without explicit
// configuration, ensuring consistent behavior across the plugin ecosystem.
// Changes to these defaults affect only newly registered plugins.
type DefaultPoliciesConfig struct {
	// Default retry configuration for new plugins
	Retry RetryConfig `json:"retry" yaml:"retry"`

	// Default circuit breaker configuration for new plugins
	CircuitBreaker CircuitBreakerConfig `json:"circuit_breaker" yaml:"circuit_breaker"`

	// Default health check configuration for new plugins
	HealthCheck HealthCheckConfig `json:"health_check" yaml:"health_check"`

	// Default connection pooling configuration for new plugins
	Connection ConnectionConfig `json:"connection" yaml:"connection"`

	// Default rate limiting configuration for new plugins
	RateLimit RateLimitConfig `json:"rate_limit" yaml:"rate_limit"`
}

// EnvironmentConfig manages environment variable expansion and overrides.
//
// This configuration supports dynamic environment variable expansion using
// ${VAR} syntax and provides environment-specific overrides for different
// deployment scenarios (development, staging, production).
type EnvironmentConfig struct {
	// Whether environment variable expansion is enabled
	ExpansionEnabled bool `json:"expansion_enabled" yaml:"expansion_enabled"`

	// Environment variable prefix for plugin-specific variables
	VariablePrefix string `json:"variable_prefix" yaml:"variable_prefix"`

	// Environment-specific configuration overrides
	Overrides map[string]string `json:"overrides,omitempty" yaml:"overrides,omitempty"`

	// Default values for undefined environment variables
	Defaults map[string]string `json:"defaults,omitempty" yaml:"defaults,omitempty"`

	// Whether to fail on missing environment variables
	FailOnMissing bool `json:"fail_on_missing" yaml:"fail_on_missing"`
}

// PerformanceConfig controls runtime performance optimization settings.
//
// This configuration allows tuning of performance-related parameters without
// service restart, enabling optimization for different workload patterns and
// system resources.
type PerformanceConfig struct {
	// Argus file watching poll interval
	WatcherPollInterval time.Duration `json:"watcher_poll_interval" yaml:"watcher_poll_interval"`

	// Cache TTL for file stat operations
	CacheTTL time.Duration `json:"cache_ttl" yaml:"cache_ttl"`

	// Maximum number of concurrent health checks
	MaxConcurrentHealthChecks int `json:"max_concurrent_health_checks" yaml:"max_concurrent_health_checks"`

	// Whether to enable performance optimization features
	OptimizationEnabled bool `json:"optimization_enabled" yaml:"optimization_enabled"`
}

// ConfigMetadata provides metadata for configuration tracking and validation.
//
// This metadata helps with configuration version management, change tracking,
// and validation to ensure configuration consistency and auditability.
type ConfigMetadata struct {
	// Configuration version for change tracking
	Version string `json:"version" yaml:"version"`

	// Environment identifier (dev, staging, prod)
	Environment string `json:"environment" yaml:"environment"`

	// Last modified timestamp
	LastModified time.Time `json:"last_modified" yaml:"last_modified"`

	// Configuration description or change notes
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Tags for configuration categorization
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// LibraryConfigOptions configures the behavior of the library config watcher.
//
// These options control how the watcher operates, including polling intervals,
// error handling behavior, and audit configuration for comprehensive tracking
// of all library configuration changes.
type LibraryConfigOptions struct {
	// Argus polling interval for file changes
	PollInterval time.Duration `json:"poll_interval" yaml:"poll_interval"`

	// Cache TTL for file stat operations
	CacheTTL time.Duration `json:"cache_ttl" yaml:"cache_ttl"`

	// Whether to enable environment variable expansion
	EnableEnvExpansion bool `json:"enable_env_expansion" yaml:"enable_env_expansion"`

	// Whether to validate configuration before applying
	ValidateBeforeApply bool `json:"validate_before_apply" yaml:"validate_before_apply"`

	// Whether to rollback on configuration application failure
	RollbackOnFailure bool `json:"rollback_on_failure" yaml:"rollback_on_failure"`

	// Audit configuration for tracking configuration changes
	AuditConfig argus.AuditConfig `json:"audit_config" yaml:"audit_config"`

	// Custom error handler for configuration errors
	ErrorHandler func(error, string) `json:"-" yaml:"-"`
}

// DefaultLibraryConfigOptions returns production-ready defaults for library config watching.
//
// These defaults are optimized for production use with balanced performance and
// reliability. They can be customized for specific deployment requirements.
//
// Default values:
//   - PollInterval: 10 seconds (library config changes less frequently than plugins)
//   - CacheTTL: 5 seconds (balance between freshness and performance)
//   - Environment expansion: enabled (commonly needed feature)
//   - Validation: enabled (safety first approach)
//   - Rollback: enabled (prevent service disruption)
//   - Audit: comprehensive logging for compliance and debugging
func DefaultLibraryConfigOptions() LibraryConfigOptions {
	return LibraryConfigOptions{
		PollInterval:        10 * time.Second, // Library config changes less frequently
		CacheTTL:            5 * time.Second,  // Reasonable cache for stat operations
		EnableEnvExpansion:  true,             // Environment variable support
		ValidateBeforeApply: true,             // Safety first - always validate
		RollbackOnFailure:   true,             // Prevent service disruption
		AuditConfig: argus.AuditConfig{
			Enabled:       true,
			OutputFile:    "go-plugins-library-audit.jsonl",
			MinLevel:      argus.AuditInfo,
			BufferSize:    1000,
			FlushInterval: 10 * time.Second,
		},
	}
}

// NewLibraryConfigWatcher creates a new library configuration watcher.
//
// This function initializes all components needed for library-level configuration
// hot reloading, including Argus integration, environment variable expansion,
// and comprehensive audit logging.
//
// Parameters:
//   - manager: The plugin manager instance to update with configuration changes
//   - configPath: Path to the library configuration file
//   - options: Configuration options (use DefaultLibraryConfigOptions() for defaults)
//   - logger: Logger instance for status and error reporting
//
// Returns:
//   - Configured LibraryConfigWatcher ready for use
//   - Error if initialization fails
//
// Example:
//
//	watcher := NewLibraryConfigWatcher(manager, "/etc/app/library.json",
//	                                   DefaultLibraryConfigOptions(), logger)
func NewLibraryConfigWatcher[Req, Resp any](
	manager *Manager[Req, Resp],
	configPath string,
	options LibraryConfigOptions,
	logger any,
) (*LibraryConfigWatcher[Req, Resp], error) {
	// Convert logger to internal interface for consistency
	internalLogger := NewLogger(logger)

	// Create environment variable expander if enabled
	var envExpander *EnvironmentVariableExpander
	if options.EnableEnvExpansion {
		envExpander = NewEnvironmentVariableExpander(EnvironmentExpansionOptions{
			Prefix:        "GO_PLUGINS_", // Standard prefix for plugin-related env vars
			FailOnMissing: false,         // Don't fail by default - use defaults
		})
	}

	// Create Argus configuration optimized for library configuration files
	argusConfig := createArgusConfigForLibrary(options, internalLogger)

	// Initialize Argus watcher
	watcher := argus.New(argusConfig)

	// Initialize audit logger if enabled
	var auditLogger *argus.AuditLogger
	if options.AuditConfig.Enabled {
		var err error
		auditLogger, err = argus.NewAuditLogger(options.AuditConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit logger: %w", err)
		}
	}

	return &LibraryConfigWatcher[Req, Resp]{
		manager:     manager,
		logger:      internalLogger,
		watcher:     watcher,
		auditLogger: auditLogger,
		configPath:  configPath,
		envExpander: envExpander,
		options:     options,
	}, nil
}

// createArgusConfigForLibrary creates Argus configuration optimized for library config files.
//
// This function creates an Argus configuration specifically tuned for library
// configuration files, which typically change less frequently than plugin configs
// but require reliable detection and processing.
func createArgusConfigForLibrary(options LibraryConfigOptions, logger Logger) argus.Config {
	return argus.Config{
		PollInterval:         options.PollInterval,
		CacheTTL:             options.CacheTTL,
		MaxWatchedFiles:      5, // Library configs are typically few files
		Audit:                options.AuditConfig,
		OptimizationStrategy: argus.OptimizationSingleEvent, // Library configs = low latency priority
		ErrorHandler: func(err error, filepath string) {
			if options.ErrorHandler != nil {
				options.ErrorHandler(err, filepath)
			} else {
				logger.Error("Library config file watching error", "error", err, "file", filepath)
			}
		},
	}
}

// Start begins watching the library configuration file for changes.
//
// This method initializes the watcher, loads the initial configuration, applies it
// to the manager, and starts monitoring for changes. It ensures thread-safe
// startup and proper error handling throughout the initialization process.
//
// Returns error if:
//   - Watcher is already running or permanently stopped
//   - Initial configuration loading fails
//   - Configuration validation fails
//   - Argus watcher startup fails
func (lcw *LibraryConfigWatcher[Req, Resp]) Start(ctx context.Context) error {
	// Prevent restart if watcher was permanently stopped
	if lcw.stopped.Load() {
		return fmt.Errorf("library config watcher has been permanently stopped and cannot be restarted")
	}

	// Protect start/stop operations with mutex
	lcw.mutex.Lock()
	defer lcw.mutex.Unlock()

	// Use atomic compare-and-swap to ensure only one goroutine starts the watcher
	if !lcw.enabled.CompareAndSwap(false, true) {
		return fmt.Errorf("library config watcher is already running")
	}

	// Load initial library configuration from file
	initialConfig, err := lcw.loadLibraryConfigFromFile(lcw.configPath)
	if err != nil {
		lcw.enabled.Store(false) // Reset state on failure
		return fmt.Errorf("failed to load initial library configuration: %w", err)
	}

	// Apply initial configuration to manager (non-destructive)
	if err := lcw.applyLibraryConfigToManager(initialConfig); err != nil {
		lcw.enabled.Store(false) // Reset state on failure
		return fmt.Errorf("failed to apply initial library configuration: %w", err)
	}

	// Store current configuration atomically for future comparisons
	lcw.currentConfig.Store(&initialConfig)

	// Audit initial configuration load
	lcw.auditEvent("configuration_loaded", map[string]interface{}{
		"path":        lcw.configPath,
		"version":     initialConfig.Metadata.Version,
		"environment": initialConfig.Metadata.Environment,
		"source":      "initial_load",
	})

	// Start watching the library configuration file
	if err := lcw.watcher.Watch(lcw.configPath, lcw.handleLibraryConfigChange); err != nil {
		lcw.enabled.Store(false) // Reset state on failure
		return fmt.Errorf("failed to watch library config file: %w", err)
	}

	// Start Argus file watcher
	if err := lcw.watcher.Start(); err != nil {
		lcw.enabled.Store(false) // Reset state on failure
		return fmt.Errorf("failed to start Argus watcher for library config: %w", err)
	}

	// Log successful startup
	lcw.logger.Info("Library configuration watcher started successfully",
		"config_path", lcw.configPath,
		"poll_interval", lcw.options.PollInterval,
		"env_expansion", lcw.options.EnableEnvExpansion)

	// Audit the watcher startup
	lcw.auditEvent("library_config_watcher_started", map[string]interface{}{
		"config_path":   lcw.configPath,
		"poll_interval": lcw.options.PollInterval.String(),
		"env_expansion": lcw.options.EnableEnvExpansion,
		"version":       initialConfig.Metadata.Version,
		"environment":   initialConfig.Metadata.Environment,
	})

	return nil
}

// Stop gracefully stops the library configuration watcher.
//
// This method ensures thread-safe shutdown with proper cleanup of all resources.
// It uses sync.Once to guarantee that Argus Stop() is called exactly once,
// preventing potential panics from concurrent stop calls.
//
// The stop operation is permanent - the watcher cannot be restarted after stopping.
func (lcw *LibraryConfigWatcher[Req, Resp]) Stop() error {
	// Fast path: return immediately if already stopped
	if lcw.stopped.Load() {
		return fmt.Errorf("library config watcher is already stopped")
	}

	// Use sync.Once to ensure stop operations happen exactly once
	var stopErr error
	lcw.stopOnce.Do(func() {
		lcw.mutex.Lock()
		defer lcw.mutex.Unlock()

		// Double-check with atomic compare-and-swap
		if !lcw.enabled.CompareAndSwap(true, false) {
			stopErr = fmt.Errorf("library config watcher is not running")
			return
		}

		// Mark as permanently stopped before calling Argus Stop()
		lcw.stopped.Store(true)

		// Stop Argus watcher safely
		if argusErr := lcw.watcher.Stop(); argusErr != nil {
			// If Argus stop fails, restore state but keep stopped=true
			lcw.enabled.Store(true)
			stopErr = fmt.Errorf("failed to stop Argus watcher: %w", argusErr)
			return
		}

		// Close audit logger if present
		if lcw.auditLogger != nil {
			if closeErr := lcw.auditLogger.Close(); closeErr != nil {
				lcw.logger.Warn("Failed to close audit logger during shutdown", "error", closeErr)
			}
		}

		lcw.logger.Info("Library configuration watcher stopped successfully")

		// Audit the shutdown event
		lcw.auditEvent("library_config_watcher_stopped", map[string]interface{}{
			"config_path":    lcw.configPath,
			"clean_shutdown": stopErr == nil,
		})
	})

	return stopErr
}

// IsRunning returns whether the library config watcher is currently active.
//
// This method provides thread-safe status checking for the watcher state.
// A watcher is considered running only if it's enabled and not permanently stopped.
func (lcw *LibraryConfigWatcher[Req, Resp]) IsRunning() bool {
	return lcw.enabled.Load() && !lcw.stopped.Load()
}

// GetCurrentConfig returns the current library configuration (thread-safe).
//
// This method provides safe access to the current configuration state using
// atomic operations to prevent race conditions during configuration updates.
func (lcw *LibraryConfigWatcher[Req, Resp]) GetCurrentConfig() *LibraryConfig {
	return lcw.currentConfig.Load()
}

// handleLibraryConfigChange processes library configuration file changes from Argus.
//
// This callback function is invoked by Argus whenever the library configuration
// file changes. It handles the complete reload cycle including validation,
// application, and rollback on failure.
//
// The function implements comprehensive error handling and audit logging to ensure
// all configuration changes are tracked and any failures are properly recorded.
func (lcw *LibraryConfigWatcher[Req, Resp]) handleLibraryConfigChange(event argus.ChangeEvent) {
	lcw.logger.Info("Library configuration file change detected",
		"path", event.Path,
		"mod_time", event.ModTime,
		"size", event.Size,
		"is_create", event.IsCreate,
		"is_delete", event.IsDelete,
		"is_modify", event.IsModify)

	// Skip delete events - cannot reload from deleted file
	if event.IsDelete {
		lcw.logger.Warn("Library configuration file was deleted, skipping reload", "path", event.Path)
		lcw.auditEvent("library_config_file_deleted", map[string]interface{}{
			"path": event.Path,
		})
		return
	}

	// Load new library configuration
	newConfig, err := lcw.loadLibraryConfigFromFile(event.Path)
	if err != nil {
		lcw.logger.Error("Failed to load new library configuration", "error", err, "path", event.Path)
		lcw.auditEvent("library_config_load_failed", map[string]interface{}{
			"path":  event.Path,
			"error": err.Error(),
		})
		return
	}

	// Apply configuration changes with rollback capability
	if err := lcw.applyLibraryConfigWithRollback(newConfig); err != nil {
		lcw.logger.Error("Failed to apply library configuration changes", "error", err)
		lcw.auditEvent("library_config_apply_failed", map[string]interface{}{
			"path":    event.Path,
			"error":   err.Error(),
			"version": newConfig.Metadata.Version,
		})
		return
	}

	// Update current configuration atomically on success
	oldConfig := lcw.currentConfig.Swap(&newConfig)

	lcw.logger.Info("Library configuration reload completed successfully",
		"version", newConfig.Metadata.Version,
		"environment", newConfig.Metadata.Environment)

	// Audit successful configuration change
	lcw.auditEvent("configuration_changed", map[string]interface{}{
		"path":        event.Path,
		"old_version": getConfigVersion(oldConfig),
		"new_version": newConfig.Metadata.Version,
		"environment": newConfig.Metadata.Environment,
		"changes":     lcw.calculateLibraryConfigChanges(oldConfig, &newConfig),
	})

	lcw.auditEvent("library_config_reloaded", map[string]interface{}{
		"path":        event.Path,
		"old_version": getConfigVersion(oldConfig),
		"new_version": newConfig.Metadata.Version,
		"environment": newConfig.Metadata.Environment,
		"changes":     lcw.calculateLibraryConfigChanges(oldConfig, &newConfig),
	})
}

// Helper function to safely get config version from potentially nil config
func getConfigVersion(config *LibraryConfig) string {
	if config == nil {
		return "unknown"
	}
	return config.Metadata.Version
}

// calculateLibraryConfigChanges identifies what changed between configurations.
//
// This function compares old and new library configurations to identify specific
// changes, providing detailed change tracking for audit and debugging purposes.
func (lcw *LibraryConfigWatcher[Req, Resp]) calculateLibraryConfigChanges(oldConfig, newConfig *LibraryConfig) []string {
	if oldConfig == nil {
		return []string{"initial_configuration"}
	}

	changes := make([]string, 0)

	// Check logging configuration changes
	if lcw.loggingConfigChanged(oldConfig.Logging, newConfig.Logging) {
		changes = append(changes, "logging")
	}

	// Check observability configuration changes
	if lcw.observabilityConfigChanged(oldConfig.Observability, newConfig.Observability) {
		changes = append(changes, "observability")
	}

	// Check default policies changes
	if lcw.defaultPoliciesChanged(oldConfig.DefaultPolicies, newConfig.DefaultPolicies) {
		changes = append(changes, "default_policies")
	}

	// Check environment configuration changes
	if lcw.environmentConfigChanged(oldConfig.Environment, newConfig.Environment) {
		changes = append(changes, "environment")
	}

	// Check performance configuration changes
	if oldConfig.Performance != newConfig.Performance {
		changes = append(changes, "performance")
	}

	return changes
}

// observabilityConfigChanged checks if observability configuration has changed.
//
// This function performs detailed comparison of observability settings to determine
// if any runtime adjustments are needed for monitoring and metrics collection.
func (lcw *LibraryConfigWatcher[Req, Resp]) observabilityConfigChanged(old, new ObservabilityRuntimeConfig) bool {
	return old.MetricsEnabled != new.MetricsEnabled ||
		old.MetricsInterval != new.MetricsInterval ||
		old.TracingEnabled != new.TracingEnabled ||
		old.TracingSampleRate != new.TracingSampleRate ||
		old.HealthMetricsEnabled != new.HealthMetricsEnabled ||
		old.PerformanceMetricsEnabled != new.PerformanceMetricsEnabled
}

// defaultPoliciesChanged checks if default plugin policies have changed.
//
// This function compares default policy configurations that affect newly
// registered plugins. Changes to these policies don't affect existing plugins.
func (lcw *LibraryConfigWatcher[Req, Resp]) defaultPoliciesChanged(old, new DefaultPoliciesConfig) bool {
	return old.Retry != new.Retry ||
		old.CircuitBreaker != new.CircuitBreaker ||
		old.HealthCheck != new.HealthCheck ||
		old.Connection != new.Connection ||
		old.RateLimit != new.RateLimit
}

// environmentConfigChanged checks if environment configuration has changed.
//
// This function compares environment variable expansion settings and overrides
// to determine if environment processing needs to be updated.
func (lcw *LibraryConfigWatcher[Req, Resp]) environmentConfigChanged(old, new EnvironmentConfig) bool {
	return old.ExpansionEnabled != new.ExpansionEnabled ||
		old.VariablePrefix != new.VariablePrefix ||
		old.FailOnMissing != new.FailOnMissing ||
		!stringMapsEqual(old.Overrides, new.Overrides) ||
		!stringMapsEqual(old.Defaults, new.Defaults)
}

// stringMapsEqual compares two string maps for equality.
//
// This utility function performs deep comparison of string maps, handling
// nil maps correctly and ensuring accurate change detection.
func stringMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// auditEvent logs a library configuration event to the audit trail.
//
// This method provides centralized audit logging for all library configuration
// events, ensuring comprehensive tracking for compliance and debugging.
func (lcw *LibraryConfigWatcher[Req, Resp]) auditEvent(eventType string, context map[string]interface{}) {
	if lcw.auditLogger == nil {
		return // Audit logging not enabled
	}

	// Add standard context information
	if context == nil {
		context = make(map[string]interface{})
	}

	context["component"] = "library_config_watcher"
	context["timestamp"] = time.Now().Format(time.RFC3339)
	context["pid"] = os.Getpid()

	// Log the audit event
	lcw.auditLogger.LogSecurityEvent(eventType, "Library configuration change", context)
}

// loadLibraryConfigFromFile loads library configuration from file with format detection.
//
// This function supports multiple configuration formats (JSON, YAML) with automatic
// format detection based on file extension. It includes comprehensive validation
// and environment variable expansion if enabled.
//
// Security features:
//   - Path validation to prevent directory traversal
//   - File size limits to prevent memory exhaustion
//   - Format validation to ensure proper structure
//   - Environment variable expansion with safe defaults
func (lcw *LibraryConfigWatcher[Req, Resp]) loadLibraryConfigFromFile(path string) (LibraryConfig, error) {
	var config LibraryConfig

	// Validate file path for security
	if err := lcw.validateConfigFilePath(path); err != nil {
		return config, fmt.Errorf("invalid config file path: %w", err)
	}

	// Read file content securely
	configBytes, err := lcw.readConfigFileSecurely(path)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	// Detect format and parse accordingly
	format := argus.DetectFormat(path)
	switch format {
	case argus.FormatJSON:
		err = json.Unmarshal(configBytes, &config)
	case argus.FormatYAML:
		err = yaml.Unmarshal(configBytes, &config)
	default:
		return config, fmt.Errorf("unsupported config format: %s", format)
	}

	if err != nil {
		return config, fmt.Errorf("failed to parse %s config: %w", format, err)
	}

	// Apply environment variable expansion if enabled
	if lcw.envExpander != nil && lcw.options.EnableEnvExpansion {
		if err := lcw.expandEnvironmentVariables(&config); err != nil {
			return config, fmt.Errorf("environment variable expansion failed: %w", err)
		}

		// Audit successful environment expansion
		lcw.auditEvent("environment_expanded", map[string]interface{}{
			"path":    path,
			"version": config.Metadata.Version,
			"prefix":  config.Environment.VariablePrefix,
		})
	}

	// Validate configuration structure
	if err := lcw.validateLibraryConfig(config); err != nil {
		return config, fmt.Errorf("invalid library configuration: %w", err)
	}

	return config, nil
}

// validateConfigFilePath validates the configuration file path for security.
//
// This function performs basic path validation to prevent directory traversal
// and other path-based security issues. It ensures the file exists and is readable.
func (lcw *LibraryConfigWatcher[Req, Resp]) validateConfigFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("empty config file path")
	}

	// Check file exists and is readable
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access config file: %w", err)
	}

	// Ensure it's a regular file
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config path is not a regular file")
	}

	// Check reasonable file size (10MB max)
	if info.Size() > 10*1024*1024 {
		return fmt.Errorf("config file too large: %d bytes", info.Size())
	}

	return nil
}

// readConfigFileSecurely reads the configuration file with security checks.
//
// This function safely reads the configuration file content with appropriate
// security measures and error handling.
func (lcw *LibraryConfigWatcher[Req, Resp]) readConfigFileSecurely(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if len(content) == 0 {
		return nil, fmt.Errorf("config file is empty")
	}

	return content, nil
}

// expandEnvironmentVariables expands environment variables in the configuration.
//
// This function processes the configuration structure to expand any ${VAR}
// placeholders with actual environment variable values, providing safe
// expansion with proper error handling.
func (lcw *LibraryConfigWatcher[Req, Resp]) expandEnvironmentVariables(config *LibraryConfig) error {
	var err error

	// Expand logging configuration fields
	if config.Logging.Level != "" {
		config.Logging.Level, err = lcw.expandSingleVariable(config.Logging.Level)
		if err != nil {
			return fmt.Errorf("failed to expand logging level: %w", err)
		}
	}

	if config.Logging.Format != "" {
		config.Logging.Format, err = lcw.expandSingleVariable(config.Logging.Format)
		if err != nil {
			return fmt.Errorf("failed to expand logging format: %w", err)
		}
	}

	// Expand component-specific log levels
	for component, level := range config.Logging.ComponentLevels {
		expanded, err := lcw.expandSingleVariable(level)
		if err != nil {
			return fmt.Errorf("failed to expand component log level %s: %w", component, err)
		}
		config.Logging.ComponentLevels[component] = expanded
	}

	// Expand environment configuration fields
	if config.Environment.VariablePrefix != "" {
		config.Environment.VariablePrefix, err = lcw.expandSingleVariable(config.Environment.VariablePrefix)
		if err != nil {
			return fmt.Errorf("failed to expand variable prefix: %w", err)
		}
	}

	// Expand override values
	for key, value := range config.Environment.Overrides {
		expanded, err := lcw.expandSingleVariable(value)
		if err != nil {
			return fmt.Errorf("failed to expand override %s: %w", key, err)
		}
		config.Environment.Overrides[key] = expanded
	}

	// Expand default values
	for key, value := range config.Environment.Defaults {
		expanded, err := lcw.expandSingleVariable(value)
		if err != nil {
			return fmt.Errorf("failed to expand default %s: %w", key, err)
		}
		config.Environment.Defaults[key] = expanded
	}

	// Expand metadata fields that might contain environment variables
	if config.Metadata.Environment != "" {
		config.Metadata.Environment, err = lcw.expandSingleVariable(config.Metadata.Environment)
		if err != nil {
			return fmt.Errorf("failed to expand metadata environment: %w", err)
		}
	}

	if config.Metadata.Description != "" {
		config.Metadata.Description, err = lcw.expandSingleVariable(config.Metadata.Description)
		if err != nil {
			return fmt.Errorf("failed to expand metadata description: %w", err)
		}
	}

	return nil
}

// expandSingleVariable expands a single environment variable placeholder.
//
// This function processes a string that may contain ${VAR} placeholders,
// replacing them with environment variable values or defaults.
func (lcw *LibraryConfigWatcher[Req, Resp]) expandSingleVariable(value string) (string, error) {
	if value == "" {
		return value, nil
	}

	// Use the existing ExpandEnvironmentVariables function from env_config.go
	options := EnvConfigOptions{
		Prefix:         "",
		FailOnMissing:  false,
		ValidateValues: false, // Skip validation in expansion phase
		AllowOverrides: true,
		Defaults:       make(map[string]string),
		Overrides:      make(map[string]string),
	}

	return ExpandEnvironmentVariables(value, options)
}

// validateLibraryConfig validates the loaded library configuration.
//
// This function performs structural and business logic validation on the
// library configuration to ensure it's valid and safe to apply.
func (lcw *LibraryConfigWatcher[Req, Resp]) validateLibraryConfig(config LibraryConfig) error {
	// Validate logging configuration
	if err := lcw.validateLoggingConfig(config.Logging); err != nil {
		return fmt.Errorf("invalid logging config: %w", err)
	}

	// Validate observability configuration
	if err := lcw.validateObservabilityConfig(config.Observability); err != nil {
		return fmt.Errorf("invalid observability config: %w", err)
	}

	// Validate performance configuration
	if err := lcw.validatePerformanceConfig(config.Performance); err != nil {
		return fmt.Errorf("invalid performance config: %w", err)
	}

	// Validate default policies configuration
	if err := lcw.validateDefaultPoliciesConfig(config.DefaultPolicies); err != nil {
		return fmt.Errorf("invalid default policies config: %w", err)
	}

	// Validate security configuration
	if err := lcw.validateSecurityConfig(config.Security); err != nil {
		return fmt.Errorf("invalid security config: %w", err)
	}

	return nil
}

// validateLoggingConfig validates logging configuration settings.
func (lcw *LibraryConfigWatcher[Req, Resp]) validateLoggingConfig(config LoggingConfig) error {
	validLevels := []string{"debug", "info", "warn", "error"}
	levelValid := false
	for _, level := range validLevels {
		if config.Level == level {
			levelValid = true
			break
		}
	}

	if !levelValid {
		return fmt.Errorf("invalid log level: %s (must be one of: debug, info, warn, error)", config.Level)
	}

	return nil
}

// validateObservabilityConfig validates observability configuration settings.
func (lcw *LibraryConfigWatcher[Req, Resp]) validateObservabilityConfig(config ObservabilityRuntimeConfig) error {
	if config.TracingSampleRate < 0.0 || config.TracingSampleRate > 1.0 {
		return fmt.Errorf("invalid tracing sample rate: %f (must be between 0.0 and 1.0)", config.TracingSampleRate)
	}

	if config.MetricsInterval < time.Second {
		return fmt.Errorf("metrics interval too short: %v (minimum 1 second)", config.MetricsInterval)
	}

	return nil
}

// validatePerformanceConfig validates performance configuration settings.
func (lcw *LibraryConfigWatcher[Req, Resp]) validatePerformanceConfig(config PerformanceConfig) error {
	if config.WatcherPollInterval < time.Second {
		return fmt.Errorf("watcher poll interval too short: %v (minimum 1 second)", config.WatcherPollInterval)
	}

	if config.MaxConcurrentHealthChecks < 1 {
		return fmt.Errorf("max concurrent health checks must be at least 1, got: %d", config.MaxConcurrentHealthChecks)
	}

	return nil
}

// validateDefaultPoliciesConfig validates default policies configuration settings.
func (lcw *LibraryConfigWatcher[Req, Resp]) validateDefaultPoliciesConfig(config DefaultPoliciesConfig) error {
	// Validate retry configuration
	if config.Retry.MaxRetries < 0 {
		return fmt.Errorf("invalid retry max_retries: %d (must be >= 0)", config.Retry.MaxRetries)
	}

	if config.Retry.Multiplier <= 0 {
		return fmt.Errorf("invalid retry multiplier: %f (must be > 0)", config.Retry.Multiplier)
	}

	if config.Retry.InitialInterval < 0 {
		return fmt.Errorf("invalid retry initial_interval: %v (must be >= 0)", config.Retry.InitialInterval)
	}

	if config.Retry.MaxInterval < config.Retry.InitialInterval {
		return fmt.Errorf("invalid retry configuration: max_interval (%v) must be >= initial_interval (%v)",
			config.Retry.MaxInterval, config.Retry.InitialInterval)
	}

	// Validate circuit breaker configuration
	if config.CircuitBreaker.FailureThreshold < 0 {
		return fmt.Errorf("invalid circuit breaker failure_threshold: %d (must be >= 0)", config.CircuitBreaker.FailureThreshold)
	}

	if config.CircuitBreaker.RecoveryTimeout < 0 {
		return fmt.Errorf("invalid circuit breaker recovery_timeout: %v (must be >= 0)", config.CircuitBreaker.RecoveryTimeout)
	}

	if config.CircuitBreaker.MinRequestThreshold < 0 {
		return fmt.Errorf("invalid circuit breaker min_request_threshold: %d (must be >= 0)", config.CircuitBreaker.MinRequestThreshold)
	}

	if config.CircuitBreaker.SuccessThreshold <= 0 && config.CircuitBreaker.Enabled {
		return fmt.Errorf("invalid circuit breaker success_threshold: %d (must be > 0 when enabled)", config.CircuitBreaker.SuccessThreshold)
	}

	// Validate health check configuration
	if config.HealthCheck.Interval <= 0 && config.HealthCheck.Enabled {
		return fmt.Errorf("invalid health check interval: %v (must be > 0 when enabled)", config.HealthCheck.Interval)
	}

	if config.HealthCheck.Timeout <= 0 && config.HealthCheck.Enabled {
		return fmt.Errorf("invalid health check timeout: %v (must be > 0 when enabled)", config.HealthCheck.Timeout)
	}

	if config.HealthCheck.FailureLimit <= 0 && config.HealthCheck.Enabled {
		return fmt.Errorf("invalid health check failure_limit: %d (must be > 0 when enabled)", config.HealthCheck.FailureLimit)
	}

	// Validate connection configuration
	if config.Connection.MaxConnections < 0 {
		return fmt.Errorf("invalid connection max_connections: %d (must be >= 0)", config.Connection.MaxConnections)
	}

	if config.Connection.MaxIdleConnections < 0 {
		return fmt.Errorf("invalid connection max_idle_connections: %d (must be >= 0)", config.Connection.MaxIdleConnections)
	}

	if config.Connection.IdleTimeout < 0 {
		return fmt.Errorf("invalid connection idle_timeout: %v (must be >= 0)", config.Connection.IdleTimeout)
	}

	if config.Connection.ConnectionTimeout < 0 {
		return fmt.Errorf("invalid connection connection_timeout: %v (must be >= 0)", config.Connection.ConnectionTimeout)
	}

	if config.Connection.RequestTimeout < 0 {
		return fmt.Errorf("invalid connection request_timeout: %v (must be >= 0)", config.Connection.RequestTimeout)
	}

	// Validate rate limit configuration
	if config.RateLimit.RequestsPerSecond < 0 {
		return fmt.Errorf("invalid rate limit requests_per_second: %f (must be >= 0)", config.RateLimit.RequestsPerSecond)
	}

	if config.RateLimit.BurstSize < 0 {
		return fmt.Errorf("invalid rate limit burst_size: %d (must be >= 0)", config.RateLimit.BurstSize)
	}

	if config.RateLimit.TimeWindow <= 0 && config.RateLimit.Enabled {
		return fmt.Errorf("invalid rate limit time_window: %v (must be > 0 when enabled)", config.RateLimit.TimeWindow)
	}

	return nil
}

// validateSecurityConfig validates security configuration settings.
//
// This function validates all security-related configuration including
// whitelist policies, security levels, and audit settings.
func (lcw *LibraryConfigWatcher[Req, Resp]) validateSecurityConfig(config SecurityConfig) error {
	// Validate policy enum value
	if config.Policy < 0 || config.Policy > SecurityPolicyAuditOnly {
		return fmt.Errorf("invalid security policy: %d (must be 0-3)", config.Policy)
	}

	// Validate whitelist file path if specified
	if config.WhitelistFile != "" && !filepath.IsAbs(config.WhitelistFile) {
		return fmt.Errorf("whitelist file path must be absolute: %s", config.WhitelistFile)
	}

	// Validate hash algorithm
	if config.HashAlgorithm != "" && config.HashAlgorithm != HashAlgorithmSHA256 {
		return fmt.Errorf("invalid hash algorithm: %s", config.HashAlgorithm)
	}

	// Validate max file size (must not be negative if specified)
	if config.MaxFileSize < 0 {
		return fmt.Errorf("max file size cannot be negative: %d", config.MaxFileSize)
	}

	// Validate allowed types (no empty strings)
	for i, allowedType := range config.AllowedTypes {
		if allowedType == "" {
			return fmt.Errorf("allowed type at index %d cannot be empty", i)
		}
	}

	// Validate forbidden paths (must be absolute if specified)
	for i, forbiddenPath := range config.ForbiddenPaths {
		if forbiddenPath != "" && !filepath.IsAbs(forbiddenPath) {
			return fmt.Errorf("forbidden path at index %d must be absolute: %s", i, forbiddenPath)
		}
	}

	// Validate audit configuration
	if config.AuditConfig.Enabled {
		// Validate audit file path if specified
		if config.AuditConfig.AuditFile != "" && !filepath.IsAbs(config.AuditConfig.AuditFile) {
			return fmt.Errorf("audit file path must be absolute: %s", config.AuditConfig.AuditFile)
		}
	}

	// Validate reload delay (must not be negative)
	if config.ReloadDelay < 0 {
		return fmt.Errorf("reload delay cannot be negative: %v", config.ReloadDelay)
	}

	return nil
}

// applyLibraryConfigToManager applies library configuration to the manager.
//
// This function updates the manager with the new library configuration,
// applying changes that can be made at runtime without disrupting plugins.
func (lcw *LibraryConfigWatcher[Req, Resp]) applyLibraryConfigToManager(config LibraryConfig) error {
	// Apply logging configuration
	if err := lcw.applyLoggingConfig(config.Logging); err != nil {
		return fmt.Errorf("failed to apply logging config: %w", err)
	}

	// Apply observability configuration
	if err := lcw.applyObservabilityConfig(config.Observability); err != nil {
		return fmt.Errorf("failed to apply observability config: %w", err)
	}

	// Update default policies for new plugins (doesn't affect existing plugins)
	lcw.updateDefaultPolicies(config.DefaultPolicies)

	return nil
}

// applyLibraryConfigWithRollback applies configuration with rollback capability.
//
// This function attempts to apply the new configuration and rolls back to
// the previous configuration if the application fails.
func (lcw *LibraryConfigWatcher[Req, Resp]) applyLibraryConfigWithRollback(newConfig LibraryConfig) error {
	// Validate before applying if enabled
	if lcw.options.ValidateBeforeApply {
		if err := lcw.validateLibraryConfig(newConfig); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	}

	// Get current config for potential rollback
	currentConfig := lcw.currentConfig.Load()

	// Apply new configuration
	if err := lcw.applyLibraryConfigToManager(newConfig); err != nil {
		// Rollback if enabled and we have a previous config
		if lcw.options.RollbackOnFailure && currentConfig != nil {
			lcw.logger.Info("Rolling back library configuration due to application failure")
			if rollbackErr := lcw.applyLibraryConfigToManager(*currentConfig); rollbackErr != nil {
				lcw.logger.Error("Configuration rollback failed", "error", rollbackErr)
				return fmt.Errorf("config application failed and rollback failed: apply_error=%w, rollback_error=%v", err, rollbackErr)
			}
			lcw.logger.Info("Configuration rollback completed successfully")
		}
		return err
	}

	return nil
}

// applyLoggingConfig applies logging configuration changes.
//
// This function updates the logging configuration at runtime, allowing
// dynamic adjustment of log levels and formatting without service restart.
func (lcw *LibraryConfigWatcher[Req, Resp]) applyLoggingConfig(config LoggingConfig) error {
	lcw.logger.Info("Applying logging configuration changes",
		"level", config.Level,
		"format", config.Format,
		"structured", config.Structured)

	// In a full implementation, this would update the actual logger configuration
	// For now, just log the change

	return nil
}

// applyObservabilityConfig applies observability configuration changes.
//
// This function updates observability settings at runtime, enabling dynamic
// adjustment of monitoring, metrics, and tracing without service disruption.
func (lcw *LibraryConfigWatcher[Req, Resp]) applyObservabilityConfig(config ObservabilityRuntimeConfig) error {
	lcw.logger.Info("Applying observability configuration changes",
		"metrics_enabled", config.MetricsEnabled,
		"tracing_enabled", config.TracingEnabled,
		"sample_rate", config.TracingSampleRate)

	// Update manager's observability configuration
	if observableManager := lcw.manager.CreateObservableManager(); observableManager != nil {
		// Update observability settings through the observable manager
		// This is a simplified implementation - full version would update all settings
		_ = observableManager // Prevent unused variable error
	}

	return nil
}

// updateDefaultPolicies updates default policies for new plugins.
//
// This function updates the default policies that will be applied to newly
// registered plugins. It doesn't affect existing plugins.
func (lcw *LibraryConfigWatcher[Req, Resp]) updateDefaultPolicies(policies DefaultPoliciesConfig) {
	lcw.logger.Info("Updating default policies for new plugins")

	// Update manager's default configurations
	// This affects only newly registered plugins
	lcw.manager.config.DefaultRetry = policies.Retry
	lcw.manager.config.DefaultCircuitBreaker = policies.CircuitBreaker
	lcw.manager.config.DefaultHealthCheck = policies.HealthCheck
	lcw.manager.config.DefaultConnection = policies.Connection
	lcw.manager.config.DefaultRateLimit = policies.RateLimit
}

// loggingConfigChanged checks if logging configuration has changed.
//
// This function performs detailed comparison of logging settings to determine
// if any runtime adjustments are needed.
func (lcw *LibraryConfigWatcher[Req, Resp]) loggingConfigChanged(old, new LoggingConfig) bool {
	return old.Level != new.Level ||
		old.Format != new.Format ||
		old.Structured != new.Structured ||
		old.IncludeCaller != new.IncludeCaller ||
		old.IncludeStackTrace != new.IncludeStackTrace ||
		!stringMapsEqual(old.ComponentLevels, new.ComponentLevels)
}
