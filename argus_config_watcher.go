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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/argus"
	"gopkg.in/yaml.v3"
)

// LibraryConfigWatcher manages hot reload of library-level configuration settings.
//
// This watcher acts as the central configuration hub, unifying all plugin system
// configuration under Argus management. It provides hot reload capabilities for
// all system components while maintaining consistency and audit trails.
//
// UNIFIED CONFIGURATION APPROACH:
// Instead of having separate config systems, this watcher manages:
//   - Manager/Registry ObservabilityConfig → Applied in real-time
//   - SecurityConfig → Hot reloaded without restart
//   - Discovery/Dynamic loading settings → Updated dynamically
//   - All library infrastructure settings → Centralized management
//
// Supported configuration categories:
//   - Logging: Log levels, output formats, structured logging
//   - Observability: Metrics settings, tracing configuration, monitoring
//   - Security: Plugin validation, whitelists, audit settings
//   - Discovery: Plugin search paths, patterns, validation rules
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

	// Validation system
	validator *ConfigValidator[Req, Resp] // Centralized configuration validation

	// Application system
	applicator *ConfigApplicator[Req, Resp] // Centralized configuration application

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

	// Observability settings for monitoring and metrics (unified)
	Observability ObservabilityRuntimeConfig `json:"observability" yaml:"observability"`

	// Security configuration including plugin whitelist and validation
	Security SecurityConfig `json:"security" yaml:"security"`

	// Plugin discovery and dynamic loading configuration
	Discovery DiscoveryRuntimeConfig `json:"discovery" yaml:"discovery"`

	// Default policies applied to new plugins during registration
	DefaultPolicies DefaultPoliciesConfig `json:"default_policies" yaml:"default_policies"`

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

// DiscoveryRuntimeConfig manages plugin discovery and dynamic loading settings.
//
// This configuration allows runtime updates to plugin discovery behavior,
// search paths, and validation rules without requiring service restart.
// It unifies all discovery-related settings under Argus management.
type DiscoveryRuntimeConfig struct {
	// Whether plugin discovery is enabled
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Search directories for plugin discovery
	SearchPaths []string `json:"search_paths" yaml:"search_paths"`

	// File patterns to match during discovery (e.g., "*.so", "plugin.json")
	FilePatterns []string `json:"file_patterns" yaml:"file_patterns"`

	// Maximum directory depth for recursive search
	MaxDepth int `json:"max_depth" yaml:"max_depth"`

	// Whether to validate plugin manifests during discovery
	ValidateManifests bool `json:"validate_manifests" yaml:"validate_manifests"`

	// Allowed transport types for discovered plugins
	AllowedTransports []string `json:"allowed_transports" yaml:"allowed_transports"`

	// Required capabilities for plugin acceptance
	RequiredCapabilities []string `json:"required_capabilities" yaml:"required_capabilities"`

	// Whether to watch for new plugins (dynamic loading)
	WatchMode bool `json:"watch_mode" yaml:"watch_mode"`

	// Discovery scan interval for watch mode
	ScanInterval time.Duration `json:"scan_interval" yaml:"scan_interval"`
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
			return nil, NewConfigValidationError("failed to create audit logger", err)
		}
	}

	// Create validator and applicator using type inference from manager
	validator := NewConfigValidator[Req, Resp]()
	applicator := NewConfigApplicator(manager, internalLogger)

	return &LibraryConfigWatcher[Req, Resp]{
		manager:     manager,
		logger:      internalLogger,
		watcher:     watcher,
		auditLogger: auditLogger,
		configPath:  configPath,
		envExpander: envExpander,
		validator:   validator,  // Centralized validator with inferred types
		applicator:  applicator, // Centralized applicator with inferred types
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
		return NewConfigWatcherError("library config watcher has been permanently stopped and cannot be restarted", nil)
	}

	// Protect start/stop operations with mutex
	lcw.mutex.Lock()
	defer lcw.mutex.Unlock()

	// Use atomic compare-and-swap to ensure only one goroutine starts the watcher
	if !lcw.enabled.CompareAndSwap(false, true) {
		return NewConfigWatcherError("library config watcher is already running", nil)
	}

	// Load initial library configuration from file
	initialConfig, err := lcw.loadLibraryConfigFromFile(lcw.configPath)
	if err != nil {
		lcw.enabled.Store(false) // Reset state on failure
		return NewConfigWatcherError("failed to load initial library configuration", err)
	}

	// Apply initial configuration to manager using centralized applicator (non-destructive)
	if err := lcw.applicator.ApplyLibraryConfig(initialConfig, nil, false); err != nil {
		lcw.enabled.Store(false) // Reset state on failure
		return NewConfigWatcherError("failed to apply initial library configuration", err)
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
		return NewConfigWatcherError("failed to watch library config file", err)
	}

	// Start Argus file watcher
	if err := lcw.watcher.Start(); err != nil {
		lcw.enabled.Store(false) // Reset state on failure
		return NewConfigWatcherError("failed to start Argus watcher for library config", err)
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
		return NewConfigWatcherError("library config watcher is already stopped", nil)
	}

	// Use sync.Once to ensure stop operations happen exactly once
	var stopErr error
	lcw.stopOnce.Do(func() {
		lcw.mutex.Lock()
		defer lcw.mutex.Unlock()

		// Double-check with atomic compare-and-swap
		if !lcw.enabled.CompareAndSwap(true, false) {
			stopErr = NewConfigWatcherError("library config watcher is not running", nil)
			return
		}

		// Mark as permanently stopped before calling Argus Stop()
		lcw.stopped.Store(true)

		// Stop Argus watcher safely
		if argusErr := lcw.watcher.Stop(); argusErr != nil {
			// If Argus stop fails, restore state but keep stopped=true
			lcw.enabled.Store(true)
			stopErr = NewConfigWatcherError("failed to stop Argus watcher", argusErr)
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

	// Validate before applying if enabled using centralized validator
	if lcw.options.ValidateBeforeApply {
		if err := lcw.validator.ValidateLibraryConfig(newConfig); err != nil {
			lcw.logger.Error("Configuration validation failed", "error", err)
			lcw.auditEvent("library_config_validation_failed", map[string]interface{}{
				"path":    event.Path,
				"error":   err.Error(),
				"version": newConfig.Metadata.Version,
			})
			return
		}
	}

	// Get current config for potential rollback
	currentConfig := lcw.currentConfig.Load()

	// Apply configuration changes with rollback capability using centralized applicator
	if err := lcw.applicator.ApplyLibraryConfig(newConfig, currentConfig, lcw.options.RollbackOnFailure); err != nil {
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

// calculateLibraryConfigChanges provides basic change summary for audit purposes.
//
// Since Argus already handles change detection natively, this function provides
// a simple high-level summary for audit logs without duplicating Argus functionality.
func (lcw *LibraryConfigWatcher[Req, Resp]) calculateLibraryConfigChanges(oldConfig, newConfig *LibraryConfig) []string {
	if oldConfig == nil {
		return []string{"initial_configuration"}
	}

	// Simple high-level change detection for audit purposes
	// Argus already detected the file change - we just summarize what sections might have changed
	changes := []string{"configuration_updated"}

	// Add version change if available
	if oldConfig.Metadata.Version != newConfig.Metadata.Version {
		changes = append(changes, "version_change")
	}

	return changes
}

// REMOVED: observabilityConfigChanged - redundant with Argus native change detection

// REMOVED: defaultPoliciesChanged - redundant with Argus native change detection

// REMOVED: environmentConfigChanged - redundant with Argus native change detection

// REMOVED: stringMapsEqual utility - no longer needed

// auditEvent provides simplified audit logging for library configuration events.
func (lcw *LibraryConfigWatcher[Req, Resp]) auditEvent(eventType string, context map[string]interface{}) {
	if lcw.auditLogger != nil {
		lcw.auditLogger.LogSecurityEvent(eventType, "Library configuration change", context)
	}
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

	// Validate file path
	cleanPath, err := lcw.validateConfigPath(path)
	if err != nil {
		return config, err
	}

	// Read and validate file content
	configBytes, err := lcw.readConfigFileSecurely(cleanPath)
	if err != nil {
		return config, err
	}

	// Parse configuration based on format
	config, err = lcw.parseConfigContent(configBytes, path)
	if err != nil {
		return config, err
	}

	// Apply environment expansion and validation
	if err := lcw.processConfigPostParsing(&config, path); err != nil {
		return config, err
	}

	return config, nil
}

// validateConfigPath validates and cleans the configuration file path
func (lcw *LibraryConfigWatcher[Req, Resp]) validateConfigPath(path string) (string, error) {
	if path == "" {
		return "", NewConfigPathError(lcw.configPath, "empty config file path")
	}

	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || strings.Contains(path, "..") {
		return "", NewConfigPathError(lcw.configPath, "invalid or unsafe config file path")
	}

	return cleanPath, nil
}

// readConfigFileSecurely reads and validates the configuration file
func (lcw *LibraryConfigWatcher[Req, Resp]) readConfigFileSecurely(cleanPath string) ([]byte, error) {
	// Check file exists, is readable, and reasonable size
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, NewConfigFileError(lcw.configPath, "cannot access config file", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 10*1024*1024 {
		return nil, NewConfigFileError(lcw.configPath, "config file invalid or too large", nil)
	}

	// Read file content securely
	configBytes, err := os.ReadFile(cleanPath) // #nosec G304 -- Path validated above
	if err != nil {
		return nil, NewConfigFileError(lcw.configPath, "failed to read config file", err)
	}
	if len(configBytes) == 0 {
		return nil, NewConfigFileError(lcw.configPath, "config file is empty", nil)
	}

	return configBytes, nil
}

// parseConfigContent parses the configuration content based on format
func (lcw *LibraryConfigWatcher[Req, Resp]) parseConfigContent(configBytes []byte, path string) (LibraryConfig, error) {
	var config LibraryConfig

	format := argus.DetectFormat(path)
	var err error
	switch format {
	case argus.FormatJSON:
		err = json.Unmarshal(configBytes, &config)
	case argus.FormatYAML:
		err = yaml.Unmarshal(configBytes, &config)
	default:
		return config, NewConfigParseError(lcw.configPath, NewConfigValidationError("unsupported config format: "+format.String(), nil))
	}

	if err != nil {
		return config, NewConfigParseError(lcw.configPath, err)
	}

	return config, nil
}

// processConfigPostParsing handles environment expansion and validation
func (lcw *LibraryConfigWatcher[Req, Resp]) processConfigPostParsing(config *LibraryConfig, path string) error {
	// Apply environment variable expansion if enabled
	if lcw.envExpander != nil && lcw.options.EnableEnvExpansion {
		if err := lcw.expandEnvironmentVariables(config); err != nil {
			return NewConfigValidationError("environment variable expansion failed", err)
		}

		// Audit successful environment expansion
		lcw.auditEvent("environment_expanded", map[string]interface{}{
			"path":    path,
			"version": config.Metadata.Version,
			"prefix":  config.Environment.VariablePrefix,
		})
	}

	// Validate configuration structure using centralized validator
	if err := lcw.validator.ValidateLibraryConfig(*config); err != nil {
		return NewConfigValidationError("invalid library configuration", err)
	}

	return nil
}

// REMOVED: validateConfigFilePath - inlined into loadLibraryConfigFromFile for simplicity

// REMOVED: readConfigFileSecurely - inlined into loadLibraryConfigFromFile for simplicity

// expandEnvironmentVariables expands environment variables in the configuration.
//
// This function processes the configuration structure to expand any ${VAR}
// placeholders with actual environment variable values, providing safe
// expansion with proper error handling.
func (lcw *LibraryConfigWatcher[Req, Resp]) expandEnvironmentVariables(config *LibraryConfig) error {
	expander := &envExpander{}

	if err := expander.expandLoggingConfig(&config.Logging); err != nil {
		return err
	}

	if err := expander.expandEnvironmentConfig(&config.Environment); err != nil {
		return err
	}

	if err := expander.expandMetadataConfig(&config.Metadata); err != nil {
		return err
	}

	return nil
}

// envExpander handles environment variable expansion with consistent error handling
type envExpander struct{}

// expand is a helper for consistent environment variable expansion
func (e *envExpander) expand(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	return ExpandEnvironmentVariables(value, EnvConfigOptions{FailOnMissing: false})
}

// expandField expands a single string field with error context
func (e *envExpander) expandField(field *string, fieldName string) error {
	if *field == "" {
		return nil
	}

	expanded, err := e.expand(*field)
	if err != nil {
		return NewConfigValidationError("failed to expand "+fieldName, err)
	}

	*field = expanded
	return nil
}

// expandMap expands all values in a string map
func (e *envExpander) expandMap(m map[string]string, mapName string) error {
	for key, value := range m {
		expanded, err := e.expand(value)
		if err != nil {
			return NewConfigValidationError("failed to expand "+mapName+" "+key, err)
		}
		m[key] = expanded
	}
	return nil
}

// expandLoggingConfig expands logging configuration fields
func (e *envExpander) expandLoggingConfig(logging *LoggingConfig) error {
	if err := e.expandField(&logging.Level, "logging level"); err != nil {
		return err
	}

	if err := e.expandField(&logging.Format, "logging format"); err != nil {
		return err
	}

	return e.expandMap(logging.ComponentLevels, "component log level")
}

// expandEnvironmentConfig expands environment configuration fields
func (e *envExpander) expandEnvironmentConfig(env *EnvironmentConfig) error {
	if err := e.expandField(&env.VariablePrefix, "variable prefix"); err != nil {
		return err
	}

	if err := e.expandMap(env.Overrides, "override"); err != nil {
		return err
	}

	return e.expandMap(env.Defaults, "default")
}

// expandMetadataConfig expands metadata configuration fields
func (e *envExpander) expandMetadataConfig(metadata *ConfigMetadata) error {
	if err := e.expandField(&metadata.Environment, "metadata environment"); err != nil {
		return err
	}

	return e.expandField(&metadata.Description, "metadata description")
}

// REMOVED: expandSingleVariable - replaced with local helper function in expandEnvironmentVariables

// validateLibraryConfig validates the complete LibraryConfig structure
//
// This function orchestrates validation of all configuration sections using
// a consolidated validation system that maintains comprehensive validation
// while providing clearer error reporting and better maintainability.
//
// Validation order:
//  1. Field-level constraints (types, ranges, enums)
//  2. Business rule validation (cross-field dependencies)
//  3. Security constraint validation (paths, policies)
//
// Returns the first validation error encountered, with detailed context
// about which field and rule failed for easier debugging.
// REMOVED: validateLibraryConfig wrapper - replaced with direct lcw.validator.ValidateLibraryConfig calls

// REMOVED: applyLibraryConfigToManager wrapper - replaced with direct lcw.applicator.ApplyLibraryConfig calls

// REMOVED: applyLibraryConfigWithRollback wrapper - logic inlined in handleLibraryConfigChange for clarity

// MOVED: applyLoggingConfig → config_applicator.go (SOC principle)

// MOVED: applyObservabilityConfig + determineObservabilityLevel → config_applicator.go (SOC principle)

// MOVED: applyDiscoveryConfig → config_applicator.go (SOC principle)

// MOVED: updateDefaultPolicies → config_applicator.go (SOC principle)

// REMOVED: loggingConfigChanged - redundant with Argus native change detection
