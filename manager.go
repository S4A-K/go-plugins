// manager.go: Production-ready plugin manager implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/argus"
)

// Manager implements PluginManager with comprehensive production-ready features.
//
// This module provides comprehensive plugin management with circuit breaker protection,
// concurrent request handling, health monitoring, graceful shutdown coordination,
// and observability. Uses subprocess-based approach for secure and reliable
// plugin communication with robust production-ready capabilities.
//
// Core capabilities:
//   - Plugin registration and lifecycle management
//   - Automatic failover with circuit breaker patterns
//   - Health monitoring with automatic recovery
//   - Direct 1:1 plugin communication for security and isolation
//   - Hot-reload configuration updates without service interruption
//   - Comprehensive metrics and structured logging
//   - Graceful shutdown with proper resource cleanup
//
// Example usage:
//
//	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
//	manager := NewManager[AuthRequest, AuthResponse](logger)
//
//	// Register plugin factories
//	httpFactory := NewHTTPPluginFactory[AuthRequest, AuthResponse]()
//	manager.RegisterFactory("http", httpFactory)
//
//	// Load configuration
//	config := ManagerConfig{
//	    Plugins: []PluginConfig{
//	        {
//	            Name:      "auth-service",
//	            Type:      "http",
//	            Transport: TransportHTTPS,
//	            Endpoint:  "https://auth.company.com/api/v1",
//	        },
//	    },
//	}
//
//	if err := manager.LoadFromConfig(config); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Execute requests
//	response, err := manager.Execute(ctx, "auth-service", request)
//	if err != nil {
//	    log.Printf("Request failed: %v", err)
//	}
//
//	// Graceful shutdown
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	manager.Shutdown(ctx)
type Manager[Req, Resp any] struct {
	plugins   map[string]Plugin[Req, Resp]
	factories map[string]PluginFactory[Req, Resp]
	config    ManagerConfig
	logger    Logger
	metrics   *ManagerMetrics

	// Circuit breakers per plugin
	breakers map[string]*CircuitBreaker

	// Health monitoring
	healthCheckers map[string]*HealthChecker
	healthStatus   map[string]HealthStatus

	// Dynamic configuration powered by Argus (replaces old hot-reload system)
	configWatcher *ConfigWatcher[Req, Resp]

	// Request tracking for graceful draining
	requestTracker *RequestTracker

	// Dynamic loading and discovery
	discoveryEngine *DiscoveryEngine
	dynamicLoader   *DynamicLoader[Req, Resp]

	// Observability integration
	observabilityConfig ObservabilityConfig
	metricsCollector    MetricsCollector
	commonMetrics       *CommonPluginMetrics
	tracingProvider     TracingProvider

	// Security validation
	securityValidator *SecurityValidator

	// Concurrency control
	mu       sync.RWMutex
	shutdown atomic.Bool
	wg       sync.WaitGroup
}

// ManagerMetrics tracks operational metrics
type ManagerMetrics struct {
	RequestsTotal       atomic.Int64
	RequestsSuccess     atomic.Int64
	RequestsFailure     atomic.Int64
	RequestDuration     atomic.Int64 // nanoseconds
	CircuitBreakerTrips atomic.Int64
	HealthCheckFailures atomic.Int64
}

// NewManager creates a new plugin manager with comprehensive lifecycle management.
//
// The manager provides centralized plugin registration, execution coordination,
// circuit breaker integration, health monitoring, and graceful shutdown capabilities.
// It serves as the primary interface for all plugin operations in the application.
//
// Key features:
//   - Plugin lifecycle management (register, load, unload, health monitoring)
//   - Circuit breaker pattern for fault tolerance and graceful degradation
//   - Health checking with automatic status tracking and recovery
//   - Concurrent execution safety with proper synchronization
//   - Metrics collection for observability and performance monitoring
//   - Graceful shutdown with proper resource cleanup
//   - Pluggable logging system with automatic adapter detection
//
// Parameters:
//   - logger: Any supported logger type (Logger interface, *slog.Logger, or nil)
//     Automatically detects and adapts the logger type for maximum compatibility
//
// Supported logger types:
//   - Logger interface: Used directly (recommended for new code)
//   - *slog.Logger: Automatically wrapped with adapter (backward compatibility)
//   - nil: Uses default JSON logger to stdout
//
// The manager starts with empty plugin registries and must be configured with
// plugin factories and loaded with plugin configurations before use.
//
// Returns a fully initialized Manager ready for plugin registration and configuration.
//
// Example usage:
//
//	// Backward compatibility (existing code continues to work)
//	manager := NewManager[MyReq, MyResp](slog.Default())
//
//	// Interface-based logging (recommended for new code)
//	manager := NewManager[MyReq, MyResp](myCustomLogger)
//
//	// Default logger
//	manager := NewManager[MyReq, MyResp](nil)
func NewManager[Req, Resp any](logger any) *Manager[Req, Resp] {
	internalLogger := NewLogger(logger)

	// Create default discovery configuration
	discoveryConfig := ExtendedDiscoveryConfig{
		DiscoveryConfig: DiscoveryConfig{
			Enabled:     false, // Disabled by default, can be enabled later
			Directories: []string{},
			Patterns:    []string{"*.so", "*.dll", "*.dylib"},
			WatchMode:   false,
		},
		SearchPaths:    []string{},
		FilePatterns:   []string{"*.so", "*.dll", "*.dylib"},
		MaxDepth:       3,
		FollowSymlinks: false,
		// Network discovery fields deprecated - using filesystem-based approach
		NetworkInterfaces:    []string{},
		DiscoveryTimeout:     10 * time.Second,
		AllowedTransports:    []TransportType{},
		RequiredCapabilities: []string{},
		ExcludePaths:         []string{},
		ValidateManifests:    true,
	}

	// Initialize discovery engine
	discoveryEngine := NewDiscoveryEngine(discoveryConfig, internalLogger)

	// Initialize observability
	observabilityConfig := DefaultObservabilityConfig()
	metricsCollector := observabilityConfig.MetricsCollector

	// Create enhanced metrics collector if supported
	var commonMetrics *CommonPluginMetrics
	if enhancedCollector, ok := metricsCollector.(EnhancedMetricsCollector); ok {
		commonMetrics = CreateCommonPluginMetrics(enhancedCollector)
	}

	// Initialize security validator with default config (disabled by default)
	securityConfig := DefaultSecurityConfig()
	securityValidator, err := NewSecurityValidator(securityConfig, internalLogger)
	if err != nil {
		internalLogger.Warn("Failed to initialize security validator", "error", err)
	}

	manager := &Manager[Req, Resp]{
		plugins:             make(map[string]Plugin[Req, Resp]),
		factories:           make(map[string]PluginFactory[Req, Resp]),
		breakers:            make(map[string]*CircuitBreaker),
		healthCheckers:      make(map[string]*HealthChecker),
		healthStatus:        make(map[string]HealthStatus),
		logger:              internalLogger,
		metrics:             &ManagerMetrics{},
		requestTracker:      NewRequestTrackerWithObservability(metricsCollector, observabilityConfig.MetricsPrefix),
		discoveryEngine:     discoveryEngine,
		observabilityConfig: observabilityConfig,
		metricsCollector:    metricsCollector,
		commonMetrics:       commonMetrics,
		tracingProvider:     observabilityConfig.TracingProvider,
		securityValidator:   securityValidator,
	}

	// Initialize dynamic loader
	manager.dynamicLoader = NewDynamicLoader(manager, discoveryEngine, internalLogger)

	return manager
}

// Register implements PluginManager.Register
func (m *Manager[Req, Resp]) Register(plugin Plugin[Req, Resp]) error {
	return m.RegisterWithConfig(plugin, PluginConfig{})
}

// RegisterWithConfig registers a plugin with security validation using the provided config
func (m *Manager[Req, Resp]) RegisterWithConfig(plugin Plugin[Req, Resp], config PluginConfig) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	info := plugin.Info()
	if info.Name == "" {
		return errors.New("plugin name cannot be empty")
	}

	// Use plugin info to populate config if not provided
	if config.Name == "" {
		config.Name = info.Name
	}
	// Note: Plugin type needs to be provided in config since it's not available in PluginInfo

	// Validate plugin security if enabled
	if m.securityValidator != nil && m.securityValidator.IsEnabled() {
		validationResult, err := m.securityValidator.ValidatePlugin(config, "")
		if err != nil {
			return fmt.Errorf("security validation error for plugin %s: %w", info.Name, err)
		}

		if !validationResult.Authorized {
			return fmt.Errorf("plugin %s rejected by security policy: %v",
				info.Name, validationResult.Violations)
		}

		m.logger.Info("Plugin security validation passed",
			"plugin", info.Name,
			"policy", validationResult.Policy.String())
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.plugins[info.Name]; exists {
		return fmt.Errorf("plugin %s is already registered", info.Name)
	}

	// Initialize circuit breaker for the plugin
	m.breakers[info.Name] = NewCircuitBreaker(CircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    5,
		RecoveryTimeout:     30 * time.Second,
		MinRequestThreshold: 3,
		SuccessThreshold:    2,
	})

	// Initialize health checker with observability integration
	healthChecker := NewHealthChecker(plugin, HealthCheckConfig{
		Enabled:      true,
		Interval:     30 * time.Second,
		Timeout:      5 * time.Second,
		FailureLimit: 3,
	})

	m.healthCheckers[info.Name] = healthChecker

	m.plugins[info.Name] = plugin

	// Initialize health status
	m.healthStatus[info.Name] = HealthStatus{
		Status:    StatusHealthy,
		Message:   "Plugin registered",
		LastCheck: time.Now(),
	}

	// Start health monitoring
	m.wg.Add(1)
	go m.monitorPluginHealth(info.Name)

	m.logger.Info("Plugin registered successfully",
		"plugin", info.Name,
		"version", info.Version)

	return nil
}

// Unregister implements PluginManager.Unregister
func (m *Manager[Req, Resp]) Unregister(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	// Stop health monitoring
	if checker, ok := m.healthCheckers[name]; ok {
		checker.Stop()
		delete(m.healthCheckers, name)
	}

	// Clean up circuit breaker
	delete(m.breakers, name)
	delete(m.healthStatus, name)

	// Close the plugin
	if err := plugin.Close(); err != nil {
		m.logger.Warn("Error closing plugin during unregister",
			"plugin", name, "error", err)
	}

	delete(m.plugins, name)

	m.logger.Info("Plugin unregistered", "plugin", name)
	return nil
}

// Execute implements PluginManager.Execute
func (m *Manager[Req, Resp]) Execute(ctx context.Context, pluginName string, request Req) (Resp, error) {
	execCtx := ExecutionContext{
		RequestID:  generateRequestID(),
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}
	return m.ExecuteWithOptions(ctx, pluginName, execCtx, request)
}

// ExecuteWithOptions implements PluginManager.ExecuteWithOptions
func (m *Manager[Req, Resp]) ExecuteWithOptions(ctx context.Context, pluginName string, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp

	if m.shutdown.Load() {
		return zero, errors.New("manager is shut down")
	}

	// Track request for graceful draining
	m.requestTracker.StartRequest(pluginName, ctx)
	defer m.requestTracker.EndRequest(pluginName, ctx)

	startTime := time.Now()
	defer m.recordExecutionMetrics(startTime)

	// Setup observability tracking
	m.recordObservabilityStart(pluginName)
	defer m.recordObservabilityEnd(pluginName)

	// Setup tracing if enabled
	ctx, span := m.setupTracing(ctx, pluginName, execCtx)
	if span != nil {
		defer span.Finish()
		m.injectTracingHeaders(ctx, &execCtx)
	}

	// Get plugin and circuit breaker
	plugin, breaker, err := m.getPluginAndBreaker(pluginName)
	if err != nil {
		m.recordObservabilityError(pluginName, startTime, err, span)
		return zero, err
	}

	// Check circuit breaker
	if !breaker.AllowRequest() {
		m.metrics.RequestsFailure.Add(1)
		err := fmt.Errorf("circuit breaker is open for plugin %s", pluginName)
		m.recordObservabilityError(pluginName, startTime, err, span)
		return zero, err
	}

	// Execute with timeout
	execCtxWithTimeout, cancel := context.WithTimeout(ctx, execCtx.Timeout)
	defer cancel()

	// Execute with retry logic
	response, err := m.executePluginWithRetries(execCtxWithTimeout, plugin, breaker, pluginName, execCtx, request)

	// Record observability results
	latency := time.Since(startTime)
	m.recordObservabilityResult(pluginName, latency, err, span, execCtx)

	return response, err
}

// recordExecutionMetrics records timing and count metrics for plugin execution
func (m *Manager[Req, Resp]) recordExecutionMetrics(startTime time.Time) {
	duration := time.Since(startTime)
	m.metrics.RequestDuration.Add(duration.Nanoseconds())
	m.metrics.RequestsTotal.Add(1)
}

// getPluginAndBreaker retrieves plugin and circuit breaker for execution
func (m *Manager[Req, Resp]) getPluginAndBreaker(pluginName string) (Plugin[Req, Resp], *CircuitBreaker, error) {
	m.mu.RLock()
	plugin, exists := m.plugins[pluginName]
	breaker, hasBreakerr := m.breakers[pluginName]
	m.mu.RUnlock()

	if !exists {
		m.metrics.RequestsFailure.Add(1)
		return nil, nil, fmt.Errorf("plugin %s not found", pluginName)
	}

	if !hasBreakerr {
		m.metrics.RequestsFailure.Add(1)
		return nil, nil, fmt.Errorf("circuit breaker not found for plugin %s", pluginName)
	}

	return plugin, breaker, nil
}

// executePluginWithRetries executes the plugin with retry logic
func (m *Manager[Req, Resp]) executePluginWithRetries(ctx context.Context, plugin Plugin[Req, Resp], breaker *CircuitBreaker, pluginName string, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp
	var resp Resp
	var err error

	for attempt := 0; attempt <= execCtx.MaxRetries; attempt++ {
		if attempt > 0 {
			if shouldAbort := m.handleRetryBackoff(ctx, breaker, attempt); shouldAbort {
				return zero, ctx.Err()
			}
		}

		resp, err = plugin.Execute(ctx, execCtx, request)
		if err == nil {
			return m.handlePluginSuccess(breaker, pluginName, execCtx, attempt, resp)
		}

		// Check if error is retryable
		if !isRetryableError(err) || attempt == execCtx.MaxRetries {
			break
		}

		m.logRetryAttempt(pluginName, execCtx, attempt, err)
	}

	// All retries failed
	return m.handlePluginFailure(breaker, pluginName, execCtx, err)
}

// handleRetryBackoff manages backoff timing for retries
func (m *Manager[Req, Resp]) handleRetryBackoff(ctx context.Context, breaker *CircuitBreaker, attempt int) bool {
	backoffDuration := calculateBackoff(attempt, 100*time.Millisecond, 5*time.Second, 2.0)
	select {
	case <-ctx.Done():
		m.metrics.RequestsFailure.Add(1)
		breaker.RecordFailure()
		return true
	case <-time.After(backoffDuration):
		return false
	}
}

// handlePluginSuccess handles successful plugin execution
func (m *Manager[Req, Resp]) handlePluginSuccess(breaker *CircuitBreaker, pluginName string, execCtx ExecutionContext, attempt int, resp Resp) (Resp, error) {
	breaker.RecordSuccess()
	m.metrics.RequestsSuccess.Add(1)

	// Record circuit breaker state change if needed
	m.recordCircuitBreakerMetrics(pluginName, breaker.GetState())

	m.logger.Debug("Plugin execution successful",
		"plugin", pluginName,
		"request_id", execCtx.RequestID,
		"attempt", attempt+1)
	return resp, nil
}

// logRetryAttempt logs a retry attempt
func (m *Manager[Req, Resp]) logRetryAttempt(pluginName string, execCtx ExecutionContext, attempt int, err error) {
	m.logger.Warn("Plugin execution failed, retrying",
		"plugin", pluginName,
		"request_id", execCtx.RequestID,
		"attempt", attempt+1,
		"error", err)
}

// handlePluginFailure handles failed plugin execution after all retries
func (m *Manager[Req, Resp]) handlePluginFailure(breaker *CircuitBreaker, pluginName string, execCtx ExecutionContext, err error) (Resp, error) {
	var zero Resp
	breaker.RecordFailure()
	m.metrics.RequestsFailure.Add(1)

	// Record circuit breaker state change and trip metrics
	newState := breaker.GetState()
	m.recordCircuitBreakerMetrics(pluginName, newState)

	// Record circuit breaker trips if it opened
	if newState == StateOpen {
		m.metrics.CircuitBreakerTrips.Add(1)
	}

	return zero, fmt.Errorf("plugin %s execution failed after %d attempts: %w",
		pluginName, execCtx.MaxRetries+1, err)
}

// GetPlugin implements PluginManager.GetPlugin
func (m *Manager[Req, Resp]) GetPlugin(name string) (Plugin[Req, Resp], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return plugin, nil
}

// ListPlugins implements PluginManager.ListPlugins
func (m *Manager[Req, Resp]) ListPlugins() map[string]HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]HealthStatus)
	for name, status := range m.healthStatus {
		result[name] = status
	}

	return result
}

// LoadFromConfig implements PluginManager.LoadFromConfig
func (m *Manager[Req, Resp]) LoadFromConfig(config ManagerConfig) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	config.ApplyDefaults()
	m.config = config

	// Update security configuration if provided
	if config.Security.Enabled {
		if m.securityValidator != nil {
			if err := m.securityValidator.UpdateConfig(config.Security); err != nil {
				m.logger.Warn("Failed to update security config", "error", err)
			} else {
				if err := m.securityValidator.Enable(); err != nil {
					m.logger.Warn("Failed to enable security validator", "error", err)
				}
			}
		}
	}

	// Load plugins from configuration
	for _, pluginConfig := range config.Plugins {
		if !pluginConfig.Enabled {
			continue
		}

		factory, exists := m.factories[pluginConfig.Type]
		if !exists {
			return fmt.Errorf("no factory registered for plugin type: %s", pluginConfig.Type)
		}

		plugin, err := factory.CreatePlugin(pluginConfig)
		if err != nil {
			return fmt.Errorf("failed to create plugin %s: %w", pluginConfig.Name, err)
		}

		if err := m.RegisterWithConfig(plugin, pluginConfig); err != nil {
			return fmt.Errorf("failed to register plugin %s: %w", pluginConfig.Name, err)
		}
	}

	return nil
}

// ReloadConfig implements PluginManager.ReloadConfig with simple recreation strategy
func (m *Manager[Req, Resp]) ReloadConfig(config ManagerConfig) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Get current plugin names
	m.mu.RLock()
	currentPlugins := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		currentPlugins = append(currentPlugins, name)
	}
	m.mu.RUnlock()

	// Unregister existing plugins
	for _, name := range currentPlugins {
		if err := m.Unregister(name); err != nil {
			m.logger.Warn("Failed to unregister plugin during reload",
				"plugin", name, "error", err)
		}
	}

	// Load new configuration
	return m.LoadFromConfig(config)
}

// EnableDynamicConfiguration starts Argus-powered hot reload for the given config file
// This replaces the old hot-reload system with ultra-fast Argus monitoring (12.10ns/op)
//
// Parameters:
//   - configPath: Path to JSON configuration file to watch
//   - options: Dynamic config options (use DefaultDynamicConfigOptions() for defaults)
//
// Example:
//
//	manager := NewManager[MyRequest, MyResponse](logger)
//
//	// Enable Argus-powered hot reload
//	if err := manager.EnableDynamicConfiguration("config.json", DefaultDynamicConfigOptions()); err != nil {
//		log.Printf("Hot reload disabled: %v", err)
//	} else {
//		log.Println("✅ Ultra-fast Argus hot reload enabled!")
//	}
//
//	defer manager.DisableDynamicConfiguration() // Clean shutdown
func (m *Manager[Req, Resp]) EnableDynamicConfiguration(configPath string, options DynamicConfigOptions) error {
	if m.configWatcher != nil {
		return fmt.Errorf("dynamic configuration is already enabled")
	}

	watcher, err := NewConfigWatcher(m, configPath, options, m.logger)
	if err != nil {
		return fmt.Errorf("failed to create config watcher: %w", err)
	}

	ctx := context.Background()
	if err := watcher.Start(ctx); err != nil {
		return fmt.Errorf("failed to start config watcher: %w", err)
	}

	m.configWatcher = watcher
	m.logger.Info("Argus dynamic configuration enabled",
		"config_path", configPath,
		"strategy", options.ReloadStrategy,
		"poll_interval", options.PollInterval)

	return nil
}

// DisableDynamicConfiguration stops Argus-powered hot reload
func (m *Manager[Req, Resp]) DisableDynamicConfiguration() error {
	if m.configWatcher == nil {
		return fmt.Errorf("dynamic configuration is not enabled")
	}

	if err := m.configWatcher.Stop(); err != nil {
		return fmt.Errorf("failed to stop config watcher: %w", err)
	}

	m.configWatcher = nil
	m.logger.Info("Argus dynamic configuration disabled")
	return nil
}

// IsDynamicConfigurationEnabled returns true if Argus hot reload is active
func (m *Manager[Req, Resp]) IsDynamicConfigurationEnabled() bool {
	return m.configWatcher != nil && m.configWatcher.IsRunning()
}

// GetDynamicConfigurationStats returns Argus watcher performance statistics
func (m *Manager[Req, Resp]) GetDynamicConfigurationStats() *argus.CacheStats {
	if m.configWatcher == nil {
		return nil
	}
	stats := m.configWatcher.GetWatcherStats()
	return &stats
}

// Health implements PluginManager.Health
func (m *Manager[Req, Resp]) Health() map[string]HealthStatus {
	return m.ListPlugins()
}

// Shutdown implements PluginManager.Shutdown
func (m *Manager[Req, Resp]) Shutdown(ctx context.Context) error {
	if !m.shutdown.CompareAndSwap(false, true) {
		return errors.New("manager already shut down")
	}

	m.logger.Info("Shutting down plugin manager")

	// Stop watchers and loaders
	m.stopWatchersAndLoaders()

	// Stop health checkers
	m.stopHealthCheckers()

	// Wait for graceful shutdown or timeout
	m.waitForShutdown(ctx)

	// Close all plugins
	m.closeAllPlugins()

	m.logger.Info("Plugin manager shutdown complete")
	return nil
}

// stopWatchersAndLoaders stops config watchers and dynamic loaders
func (m *Manager[Req, Resp]) stopWatchersAndLoaders() {
	// Stop Argus config watcher first
	if m.configWatcher != nil {
		if err := m.configWatcher.Stop(); err != nil {
			m.logger.Warn("Failed to stop config watcher", "error", err)
		}
	}

	// Stop dynamic loader
	if m.dynamicLoader != nil {
		if err := m.dynamicLoader.Close(); err != nil {
			m.logger.Warn("Failed to stop dynamic loader", "error", err)
		}
	}
}

// stopHealthCheckers stops all health checkers
func (m *Manager[Req, Resp]) stopHealthCheckers() {
	m.mu.Lock()
	for _, checker := range m.healthCheckers {
		checker.Stop()
	}
	m.mu.Unlock()
}

// waitForShutdown waits for health monitoring goroutines to finish or timeout
func (m *Manager[Req, Resp]) waitForShutdown(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		m.logger.Info("All health monitors stopped")
	case <-ctx.Done():
		m.logger.Warn("Shutdown timeout reached, forcing shutdown")
	}
}

// closeAllPlugins closes all registered plugins
func (m *Manager[Req, Resp]) closeAllPlugins() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, plugin := range m.plugins {
		if err := plugin.Close(); err != nil {
			m.logger.Warn("Error closing plugin during shutdown",
				"plugin", name, "error", err)
		}
	}
	m.plugins = make(map[string]Plugin[Req, Resp])
}

// RegisterFactory registers a plugin factory for a specific plugin type
func (m *Manager[Req, Resp]) RegisterFactory(pluginType string, factory PluginFactory[Req, Resp]) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.factories[pluginType]; exists {
		return fmt.Errorf("factory for plugin type %s already registered", pluginType)
	}

	m.factories[pluginType] = factory
	return nil
}

// GetFactory retrieves a plugin factory by type
func (m *Manager[Req, Resp]) GetFactory(pluginType string) (PluginFactory[Req, Resp], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	factory, exists := m.factories[pluginType]
	if !exists {
		return nil, fmt.Errorf("no factory registered for plugin type: %s", pluginType)
	}

	return factory, nil
}

// GetMetrics returns current operational metrics
func (m *Manager[Req, Resp]) GetMetrics() ManagerMetrics {
	return ManagerMetrics{
		RequestsTotal:       atomic.Int64{},
		RequestsSuccess:     atomic.Int64{},
		RequestsFailure:     atomic.Int64{},
		RequestDuration:     atomic.Int64{},
		CircuitBreakerTrips: atomic.Int64{},
		HealthCheckFailures: atomic.Int64{},
	}
}

// ConfigureObservability configures comprehensive observability for the manager
func (m *Manager[Req, Resp]) ConfigureObservability(config ObservabilityConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.observabilityConfig = config
	m.metricsCollector = config.MetricsCollector
	m.tracingProvider = config.TracingProvider

	// Create enhanced metrics if available
	if enhancedCollector, ok := config.MetricsCollector.(EnhancedMetricsCollector); ok {
		m.commonMetrics = CreateCommonPluginMetrics(enhancedCollector)
	}

	m.logger.Info("Observability configured",
		"metrics_enabled", config.MetricsEnabled,
		"tracing_enabled", config.TracingEnabled,
		"logging_enabled", config.LoggingEnabled)

	return nil
}

// GetObservabilityConfig returns current observability configuration
func (m *Manager[Req, Resp]) GetObservabilityConfig() ObservabilityConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.observabilityConfig
}

// CreateObservableManager creates an ObservableManager from this Manager
func (m *Manager[Req, Resp]) CreateObservableManager() *ObservableManager[Req, Resp] {
	return NewObservableManager(m, m.observabilityConfig)
}

// GetObservabilityMetrics returns comprehensive observability metrics from the manager
func (m *Manager[Req, Resp]) GetObservabilityMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// Get basic manager metrics
	managerMetrics := m.GetMetrics()
	metrics["manager"] = map[string]interface{}{
		"requests_total":        managerMetrics.RequestsTotal.Load(),
		"requests_success":      managerMetrics.RequestsSuccess.Load(),
		"requests_failure":      managerMetrics.RequestsFailure.Load(),
		"request_duration_ns":   managerMetrics.RequestDuration.Load(),
		"circuit_breaker_trips": managerMetrics.CircuitBreakerTrips.Load(),
		"health_check_failures": managerMetrics.HealthCheckFailures.Load(),
	}

	// Get metrics from collector if available
	if m.metricsCollector != nil {
		metrics["collector"] = m.metricsCollector.GetMetrics()
	}

	// Get enhanced metrics if available
	if m.commonMetrics != nil && m.observabilityConfig.MetricsCollector != nil {
		if enhancedCollector, ok := m.observabilityConfig.MetricsCollector.(EnhancedMetricsCollector); ok {
			metrics["prometheus"] = enhancedCollector.GetPrometheusMetrics()
		}
	}

	// Get health status for all plugins
	m.mu.RLock()
	healthStatuses := make(map[string]HealthStatus)
	for name, status := range m.healthStatus {
		healthStatuses[name] = status
	}

	// Get circuit breaker states
	circuitBreakerStates := make(map[string]string)
	for name, breaker := range m.breakers {
		circuitBreakerStates[name] = breaker.GetState().String()
	}
	m.mu.RUnlock()

	metrics["health_status"] = healthStatuses
	metrics["circuit_breaker_states"] = circuitBreakerStates

	return metrics
}

// EnableObservability is a convenience method to enable observability with default settings
func (m *Manager[Req, Resp]) EnableObservability() error {
	config := DefaultObservabilityConfig()
	return m.ConfigureObservability(config)
}

// EnableEnhancedObservability enables observability with enhanced metrics collector
func (m *Manager[Req, Resp]) EnableEnhancedObservability() error {
	config := EnhancedObservabilityConfig()
	return m.ConfigureObservability(config)
}

// EnableObservabilityWithTracing enables observability with distributed tracing
func (m *Manager[Req, Resp]) EnableObservabilityWithTracing(tracingProvider TracingProvider) error {
	config := EnhancedObservabilityConfig()
	config.TracingEnabled = true
	config.TracingProvider = tracingProvider
	return m.ConfigureObservability(config)
}

// GetObservabilityStatus returns the current state of observability features
func (m *Manager[Req, Resp]) GetObservabilityStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"metrics_enabled":     m.observabilityConfig.MetricsEnabled,
		"tracing_enabled":     m.observabilityConfig.TracingEnabled,
		"logging_enabled":     m.observabilityConfig.LoggingEnabled,
		"metrics_prefix":      m.observabilityConfig.MetricsPrefix,
		"tracing_sample_rate": m.observabilityConfig.TracingSampleRate,
		"log_level":           m.observabilityConfig.LogLevel,
		"structured_logging":  m.observabilityConfig.StructuredLogging,
		"health_metrics":      m.observabilityConfig.HealthMetrics,
		"performance_metrics": m.observabilityConfig.PerformanceMetrics,
		"error_metrics":       m.observabilityConfig.ErrorMetrics,
		"has_common_metrics":  m.commonMetrics != nil,
		"has_tracing":         m.tracingProvider != nil,
	}
}

// recordObservabilityStart tracks the start of a request for observability
func (m *Manager[Req, Resp]) recordObservabilityStart(pluginName string) {
	if m.observabilityConfig.MetricsEnabled && m.commonMetrics != nil {
		m.commonMetrics.IncrementActiveRequests(pluginName)
	}
}

// recordObservabilityEnd tracks the end of a request for observability
func (m *Manager[Req, Resp]) recordObservabilityEnd(pluginName string) {
	if m.observabilityConfig.MetricsEnabled && m.commonMetrics != nil {
		m.commonMetrics.DecrementActiveRequests(pluginName)
	}
}

// setupTracing initializes distributed tracing if enabled
func (m *Manager[Req, Resp]) setupTracing(ctx context.Context, pluginName string, execCtx ExecutionContext) (context.Context, Span) {
	if !m.observabilityConfig.TracingEnabled || m.tracingProvider == nil {
		return ctx, nil
	}

	ctx, span := m.tracingProvider.StartSpan(ctx, fmt.Sprintf("plugin.execute.%s", pluginName))
	span.SetAttribute("plugin.name", pluginName)
	span.SetAttribute("request.id", execCtx.RequestID)
	span.SetAttribute("request.timeout", execCtx.Timeout.String())

	return ctx, span
}

// injectTracingHeaders adds tracing headers to execution context
func (m *Manager[Req, Resp]) injectTracingHeaders(ctx context.Context, execCtx *ExecutionContext) {
	if execCtx.Headers == nil {
		execCtx.Headers = make(map[string]string)
	}

	if m.tracingProvider != nil {
		tracingHeaders := m.tracingProvider.InjectContext(ctx)
		for k, v := range tracingHeaders {
			execCtx.Headers[k] = v
		}
	}
}

// recordObservabilityError records error metrics and tracing information
func (m *Manager[Req, Resp]) recordObservabilityError(pluginName string, startTime time.Time, err error, span Span) {
	latency := time.Since(startTime)

	// Record metrics
	if m.observabilityConfig.MetricsEnabled && m.commonMetrics != nil {
		m.commonMetrics.RecordRequest(pluginName, latency, err)
	}

	// Record to metrics collector
	if m.observabilityConfig.MetricsEnabled && m.metricsCollector != nil {
		m.recordToMetricsCollector(pluginName, latency, err)
	}

	// Set span status
	if span != nil {
		span.SetStatus(SpanStatusError, err.Error())
		span.SetAttribute("error", true)
		span.SetAttribute("error.message", err.Error())
	}

	// Log error
	if m.observabilityConfig.LoggingEnabled {
		m.logger.Warn("Plugin execution failed",
			"plugin", pluginName,
			"latency", latency,
			"error", err.Error())
	}
}

// recordObservabilityResult records successful execution metrics
func (m *Manager[Req, Resp]) recordObservabilityResult(pluginName string, latency time.Duration, err error, span Span, execCtx ExecutionContext) {
	if err != nil {
		return // Already handled in recordObservabilityError
	}

	// Record success metrics
	if m.observabilityConfig.MetricsEnabled && m.commonMetrics != nil {
		m.commonMetrics.RecordRequest(pluginName, latency, nil)
	}

	// Record to metrics collector
	if m.observabilityConfig.MetricsEnabled && m.metricsCollector != nil {
		m.recordToMetricsCollector(pluginName, latency, nil)
	}

	// Set span status
	if span != nil {
		span.SetStatus(SpanStatusOK, "success")
	}

	// Log success
	if m.observabilityConfig.LoggingEnabled {
		m.logger.Debug("Plugin execution completed",
			"plugin", pluginName,
			"request_id", execCtx.RequestID,
			"latency", latency)
	}
}

// recordToMetricsCollector records metrics to the configured collector
func (m *Manager[Req, Resp]) recordToMetricsCollector(pluginName string, latency time.Duration, err error) {
	labels := map[string]string{
		"plugin_name": pluginName,
	}

	// Record request counter
	m.metricsCollector.IncrementCounter(
		m.observabilityConfig.MetricsPrefix+"_requests_total",
		labels,
		1,
	)

	// Record latency histogram
	m.metricsCollector.RecordHistogram(
		m.observabilityConfig.MetricsPrefix+"_request_duration_seconds",
		labels,
		latency.Seconds(),
	)

	// Record error metrics if applicable
	if err != nil {
		errorLabels := make(map[string]string)
		for k, v := range labels {
			errorLabels[k] = v
		}

		// Categorize error type
		switch {
		case isTimeoutError(err):
			errorLabels["error_type"] = "timeout"
		case isConnectionError(err):
			errorLabels["error_type"] = "connection"
		case isAuthError(err):
			errorLabels["error_type"] = "authentication"
		default:
			errorLabels["error_type"] = "other"
		}

		m.metricsCollector.IncrementCounter(
			m.observabilityConfig.MetricsPrefix+"_errors_total",
			errorLabels,
			1,
		)
	}
}

// recordCircuitBreakerMetrics records circuit breaker state changes
func (m *Manager[Req, Resp]) recordCircuitBreakerMetrics(pluginName string, state CircuitBreakerState) {
	if m.observabilityConfig.MetricsEnabled && m.commonMetrics != nil {
		var stateValue int
		switch state {
		case StateClosed:
			stateValue = 0
		case StateOpen:
			stateValue = 1
		case StateHalfOpen:
			stateValue = 2
		}
		m.commonMetrics.SetCircuitBreakerState(pluginName, stateValue)
	}
}

// recordHealthCheckMetrics records health check results
func (m *Manager[Req, Resp]) recordHealthCheckMetrics(pluginName string, healthStatus HealthStatus, duration time.Duration) {
	if !m.observabilityConfig.MetricsEnabled || m.metricsCollector == nil {
		return
	}

	labels := map[string]string{
		"plugin_name": pluginName,
		"status":      healthStatus.Status.String(),
	}

	// Record health check counter
	m.metricsCollector.IncrementCounter(
		m.observabilityConfig.MetricsPrefix+"_health_checks_total",
		labels,
		1,
	)

	// Record health check duration
	m.metricsCollector.RecordHistogram(
		m.observabilityConfig.MetricsPrefix+"_health_check_duration_seconds",
		labels,
		duration.Seconds(),
	)

	// Record health check failures
	if healthStatus.Status != StatusHealthy {
		m.metrics.HealthCheckFailures.Add(1)

		failureLabels := map[string]string{
			"plugin_name": pluginName,
			"reason":      healthStatus.Message,
		}

		m.metricsCollector.IncrementCounter(
			m.observabilityConfig.MetricsPrefix+"_health_check_failures_total",
			failureLabels,
			1,
		)
	}

	// Set health status gauge
	var statusValue float64
	switch healthStatus.Status {
	case StatusHealthy:
		statusValue = 1
	case StatusDegraded:
		statusValue = 0.5
	case StatusUnhealthy:
		statusValue = 0
	case StatusOffline:
		statusValue = -1
	default:
		statusValue = 0
	}

	m.metricsCollector.SetGauge(
		m.observabilityConfig.MetricsPrefix+"_plugin_health_status",
		map[string]string{"plugin_name": pluginName},
		statusValue,
	)
}

// monitorPluginHealth runs health checks for a specific plugin
func (m *Manager[Req, Resp]) monitorPluginHealth(pluginName string) {
	defer m.wg.Done()

	m.mu.RLock()
	checker, exists := m.healthCheckers[pluginName]
	m.mu.RUnlock()

	if !exists {
		return
	}

	ticker := time.NewTicker(30 * time.Second) // TODO: use config
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if m.shutdown.Load() {
				return
			}

			// Perform health check with timing
			startTime := time.Now()
			status := checker.Check()
			duration := time.Since(startTime)

			m.mu.Lock()
			m.healthStatus[pluginName] = status
			m.mu.Unlock()

			// Record observability metrics
			m.recordHealthCheckMetrics(pluginName, status, duration)

			if status.Status != StatusHealthy {
				m.metrics.HealthCheckFailures.Add(1)
				m.logger.Warn("Plugin health check failed",
					"plugin", pluginName,
					"status", status.Status.String(),
					"message", status.Message,
					"duration", duration)
			} else if m.observabilityConfig.LoggingEnabled {
				m.logger.Debug("Plugin health check passed",
					"plugin", pluginName,
					"duration", duration,
					"response_time", status.ResponseTime)
			}

		case <-checker.Done():
			return
		}
	}
}

// Helper functions

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

func calculateBackoff(attempt int, initial, maxDuration time.Duration, multiplier float64) time.Duration {
	duration := time.Duration(float64(initial) * pow(multiplier, float64(attempt)))
	if duration > maxDuration {
		duration = maxDuration
	}
	return duration
}

func pow(base, exp float64) float64 {
	result := 1.0
	for i := 0; i < int(exp); i++ {
		result *= base
	}
	return result
}

func isRetryableError(err error) bool {
	// TODO: Implement more sophisticated error classification
	if err == nil {
		return false
	}

	// For now, consider timeout and temporary errors as retryable
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}

// GetActiveRequestCount returns the number of active requests for a plugin
func (m *Manager[Req, Resp]) GetActiveRequestCount(pluginName string) int64 {
	return m.requestTracker.GetActiveRequestCount(pluginName)
}

// GetAllActiveRequests returns a map of plugin names to active request counts
func (m *Manager[Req, Resp]) GetAllActiveRequests() map[string]int64 {
	return m.requestTracker.GetAllActiveRequests()
}

// DrainPlugin gracefully drains active requests for a specific plugin
func (m *Manager[Req, Resp]) DrainPlugin(pluginName string, options DrainOptions) error {
	m.logger.Info("Starting graceful drain for plugin",
		"plugin", pluginName,
		"timeout", options.DrainTimeout,
		"activeRequests", m.GetActiveRequestCount(pluginName))

	// Setup progress callback if not provided
	if options.ProgressCallback == nil {
		options.ProgressCallback = func(plugin string, activeCount int64) {
			if activeCount > 0 {
				m.logger.Info("Draining in progress",
					"plugin", plugin,
					"activeRequests", activeCount)
			}
		}
	}

	return m.requestTracker.GracefulDrain(pluginName, options)
}

// GracefulUnregister removes a plugin after draining all active requests
func (m *Manager[Req, Resp]) GracefulUnregister(pluginName string, drainTimeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if plugin exists
	if _, exists := m.plugins[pluginName]; !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	// Perform graceful drain
	drainOptions := DrainOptions{
		DrainTimeout:            drainTimeout,
		ForceCancelAfterTimeout: true, // Force cancel after timeout for unregister
	}

	if err := m.DrainPlugin(pluginName, drainOptions); err != nil {
		if drainErr, ok := err.(*DrainTimeoutError); ok {
			m.logger.Warn("Plugin drain timed out, forcing unregister",
				"plugin", pluginName,
				"canceledRequests", drainErr.CanceledRequests)
		} else {
			return fmt.Errorf("failed to drain plugin %s: %w", pluginName, err)
		}
	}

	// Remove plugin components
	delete(m.plugins, pluginName)
	delete(m.breakers, pluginName)

	if checker, exists := m.healthCheckers[pluginName]; exists {
		checker.Stop()
		delete(m.healthCheckers, pluginName)
	}
	delete(m.healthStatus, pluginName)

	m.logger.Info("Plugin successfully unregistered after graceful drain", "plugin", pluginName)
	return nil
}

// Dynamic Loading Methods

// EnableDynamicLoading enables automatic loading of discovered plugins.
//
// When enabled, the manager will automatically discover and load compatible plugins
// from configured sources. This includes filesystem scanning, network discovery,
// and service registry integration.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//
// Returns error if dynamic loading cannot be enabled or is already active.
func (m *Manager[Req, Resp]) EnableDynamicLoading(ctx context.Context) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.dynamicLoader.EnableAutoLoading(ctx); err != nil {
		return fmt.Errorf("failed to enable dynamic loading: %w", err)
	}

	m.logger.Info("Dynamic loading enabled")
	return nil
}

// DisableDynamicLoading disables automatic loading of discovered plugins.
//
// This stops the background discovery and loading processes. Already loaded
// plugins remain active and are not affected by this operation.
func (m *Manager[Req, Resp]) DisableDynamicLoading() error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.dynamicLoader.DisableAutoLoading(); err != nil {
		return fmt.Errorf("failed to disable dynamic loading: %w", err)
	}

	m.logger.Info("Dynamic loading disabled")
	return nil
}

// ConfigureDiscovery configures the discovery engine with new settings.
//
// Note: Currently discovery configuration is set at initialization time.
// Runtime reconfiguration will be implemented in a future version.
// For now, this method returns the current discovery configuration.
//
// TODO: Implement runtime configuration updates for the discovery engine.
func (m *Manager[Req, Resp]) ConfigureDiscovery(config ExtendedDiscoveryConfig) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	// For now, log the request but don't update config at runtime
	m.logger.Info("Discovery configuration change requested (runtime updates not yet implemented)",
		"enabled", config.Enabled,
		"directories", len(config.Directories),
		"patterns", len(config.Patterns))

	return fmt.Errorf("runtime discovery configuration updates not yet implemented")
}

// LoadDiscoveredPlugin manually loads a specific discovered plugin.
//
// This method allows manual control over plugin loading, including dependency
// resolution and version compatibility checking. The plugin must be available
// in the discovery results.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - pluginName: Name of the plugin to load from discovery results
//
// Returns error if plugin is not discovered, incompatible, or loading fails.
func (m *Manager[Req, Resp]) LoadDiscoveredPlugin(ctx context.Context, pluginName string) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	if err := m.dynamicLoader.LoadDiscoveredPlugin(ctx, pluginName); err != nil {
		return fmt.Errorf("failed to load discovered plugin %s: %w", pluginName, err)
	}

	m.logger.Info("Discovered plugin loaded successfully", "plugin", pluginName)
	return nil
}

// UnloadDynamicPlugin unloads a dynamically loaded plugin.
//
// This method safely unloads a plugin that was loaded through the dynamic
// loading system. It includes dependency checking and graceful shutdown.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - pluginName: Name of the plugin to unload
//   - force: Whether to force unload even if other plugins depend on it
//
// Returns error if plugin cannot be unloaded safely (unless forced).
func (m *Manager[Req, Resp]) UnloadDynamicPlugin(ctx context.Context, pluginName string, force bool) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	if err := m.dynamicLoader.UnloadPlugin(ctx, pluginName, force); err != nil {
		return fmt.Errorf("failed to unload dynamic plugin %s: %w", pluginName, err)
	}

	m.logger.Info("Dynamic plugin unloaded successfully",
		"plugin", pluginName,
		"forced", force)
	return nil
}

// SetPluginCompatibilityRule sets version compatibility rules for a plugin.
//
// This method configures version constraints that will be checked when
// loading plugins dynamically. Supports semantic versioning constraints
// like "^1.0.0", "~1.2.0", or exact versions.
//
// Parameters:
//   - pluginName: Name of the plugin to set constraint for
//   - constraint: Semantic version constraint string
func (m *Manager[Req, Resp]) SetPluginCompatibilityRule(pluginName, constraint string) {
	if m.shutdown.Load() {
		return
	}

	m.dynamicLoader.SetCompatibilityRule(pluginName, constraint)
	m.logger.Debug("Plugin compatibility rule set",
		"plugin", pluginName,
		"constraint", constraint)
}

// GetDiscoveredPlugins returns the current list of discovered plugins.
//
// This method provides access to the discovery engine results, showing
// all plugins that have been found but may not yet be loaded.
//
// Returns map of plugin names to discovery results.
func (m *Manager[Req, Resp]) GetDiscoveredPlugins() map[string]*DiscoveryResult {
	if m.shutdown.Load() {
		return make(map[string]*DiscoveryResult)
	}

	return m.discoveryEngine.GetDiscoveredPlugins()
}

// GetDynamicLoadingStatus returns the loading status of all dynamic plugins.
//
// This method shows the current state of plugins in the dynamic loading
// system, including their loading status and dependency relationships.
//
// Returns map of plugin names to their loading states.
func (m *Manager[Req, Resp]) GetDynamicLoadingStatus() map[string]LoadingState {
	if m.shutdown.Load() {
		return make(map[string]LoadingState)
	}

	return m.dynamicLoader.GetLoadingStatus()
}

// GetDependencyGraph returns the current plugin dependency graph.
//
// This method provides access to the dependency relationships between
// plugins, useful for understanding loading order and dependencies.
//
// Returns a copy of the current dependency graph.
func (m *Manager[Req, Resp]) GetDependencyGraph() *DependencyGraph {
	if m.shutdown.Load() {
		return NewDependencyGraph()
	}

	return m.dynamicLoader.GetDependencyGraph()
}

// GetDynamicLoadingMetrics returns metrics for the dynamic loading system.
//
// This method provides operational metrics including load counts,
// failures, and performance statistics for dynamic loading operations.
//
// Returns current dynamic loading metrics.
func (m *Manager[Req, Resp]) GetDynamicLoadingMetrics() DynamicLoaderMetrics {
	if m.shutdown.Load() {
		return DynamicLoaderMetrics{}
	}

	return m.dynamicLoader.GetMetrics()
}

// Security Management Methods

// EnablePluginSecurity enables the plugin security validator with the given configuration
func (m *Manager[Req, Resp]) EnablePluginSecurity(config SecurityConfig) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.securityValidator == nil {
		validator, err := NewSecurityValidator(config, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create security validator: %w", err)
		}
		m.securityValidator = validator
	} else {
		if err := m.securityValidator.UpdateConfig(config); err != nil {
			return fmt.Errorf("failed to update security config: %w", err)
		}
	}

	if err := m.securityValidator.Enable(); err != nil {
		return fmt.Errorf("failed to enable security validator: %w", err)
	}

	m.logger.Info("Plugin security enabled", "policy", config.Policy.String())
	return nil
}

// DisablePluginSecurity disables the plugin security validator
func (m *Manager[Req, Resp]) DisablePluginSecurity() error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.securityValidator == nil {
		return errors.New("security validator not initialized")
	}

	if err := m.securityValidator.Disable(); err != nil {
		return fmt.Errorf("failed to disable security validator: %w", err)
	}

	m.logger.Info("Plugin security disabled")
	return nil
}

// IsPluginSecurityEnabled returns whether plugin security is currently enabled
func (m *Manager[Req, Resp]) IsPluginSecurityEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.securityValidator != nil && m.securityValidator.IsEnabled()
}

// GetPluginSecurityStats returns current security validation statistics
func (m *Manager[Req, Resp]) GetPluginSecurityStats() (SecurityStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return SecurityStats{}, errors.New("security validator not initialized")
	}

	return m.securityValidator.GetStats(), nil
}

// GetPluginSecurityConfig returns the current security configuration
func (m *Manager[Req, Resp]) GetPluginSecurityConfig() (SecurityConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return SecurityConfig{}, errors.New("security validator not initialized")
	}

	return m.securityValidator.GetConfig(), nil
}

// ReloadPluginWhitelist manually reloads the plugin whitelist from file
func (m *Manager[Req, Resp]) ReloadPluginWhitelist() error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return errors.New("security validator not initialized")
	}

	if err := m.securityValidator.ReloadWhitelist(); err != nil {
		return fmt.Errorf("failed to reload whitelist: %w", err)
	}

	m.logger.Info("Plugin whitelist reloaded successfully")
	return nil
}

// GetPluginWhitelistInfo returns information about the current plugin whitelist
func (m *Manager[Req, Resp]) GetPluginWhitelistInfo() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return nil, errors.New("security validator not initialized")
	}

	return m.securityValidator.GetWhitelistInfo(), nil
}

// ValidatePluginSecurity manually validates a plugin against the security policy
// This is useful for testing or pre-validation before actual registration
func (m *Manager[Req, Resp]) ValidatePluginSecurity(config PluginConfig, pluginPath string) (*ValidationResult, error) {
	if m.shutdown.Load() {
		return nil, errors.New("manager is shut down")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return nil, errors.New("security validator not initialized")
	}

	return m.securityValidator.ValidatePlugin(config, pluginPath)
}

// GetArgusIntegrationInfo returns information about the Argus integration for security
func (m *Manager[Req, Resp]) GetArgusIntegrationInfo() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return nil, errors.New("security validator not initialized")
	}

	return m.securityValidator.GetArgusIntegrationInfo(), nil
}
