// manager.go: Production-ready plugin manager implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
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
//	subprocessFactory := NewSubprocessPluginFactory[AuthRequest, AuthResponse]()
//	manager.RegisterFactory("subprocess", subprocessFactory)
//
//	// Load configuration
//	config := ManagerConfig{
//	    Plugins: []PluginConfig{
//	        {
//	            Name:      "auth-service",
//	            Type:      "subprocess",
//	            Transport: TransportExecutable,
//	            Endpoint:  "./auth-plugin",
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

	// Observability management (refactored)
	observabilityManager *ObservabilityManager

	// Compatibility accessors (temporary during refactoring)
	observabilityConfig ObservabilityConfig
	metricsCollector    MetricsCollector
	commonMetrics       *CommonPluginMetrics
	tracingProvider     TracingProvider

	// Runtime observability metrics (compatibility)
	startTime      time.Time
	totalRequests  *atomic.Int64
	totalErrors    *atomic.Int64
	activeRequests *atomic.Int64

	// Plugin-specific detailed metrics (compatibility)
	pluginMetrics map[string]*PluginObservabilityMetrics
	metricsMu     sync.RWMutex

	// Security validation
	securityValidator *SecurityValidator

	// Concurrency control
	mu       sync.RWMutex
	shutdown atomic.Bool
	wg       sync.WaitGroup
}

// PluginObservabilityMetrics contains detailed metrics for a single plugin
// (integrated from ObservableManager)
type PluginObservabilityMetrics struct {
	// Request metrics
	TotalRequests      *atomic.Int64
	SuccessfulRequests *atomic.Int64
	FailedRequests     *atomic.Int64
	ActiveRequests     *atomic.Int64

	// Timing metrics
	TotalLatency *atomic.Int64 // Total latency in nanoseconds
	MinLatency   *atomic.Int64
	MaxLatency   *atomic.Int64
	AvgLatency   *atomic.Int64

	// Error metrics
	TimeoutErrors    *atomic.Int64
	ConnectionErrors *atomic.Int64
	AuthErrors       *atomic.Int64
	OtherErrors      *atomic.Int64

	// Circuit breaker metrics
	CircuitBreakerTrips *atomic.Int64
	CircuitBreakerState *atomic.Value // stores string

	// Health metrics
	HealthCheckTotal  *atomic.Int64
	HealthCheckFailed *atomic.Int64
	LastHealthCheck   *atomic.Int64 // Unix timestamp
	HealthStatus      *atomic.Value // stores string
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

	// Initialize observability manager (refactored)
	observabilityConfig := DefaultObservabilityConfig()
	observabilityManager := NewObservabilityManager(observabilityConfig, internalLogger)

	// Initialize security validator with default config (disabled by default)
	securityConfig := DefaultSecurityConfig()
	securityValidator, err := NewSecurityValidator(securityConfig, internalLogger)
	if err != nil {
		internalLogger.Warn("Failed to initialize security validator", "error", err)
		securityValidator = nil // Ensure nil on failure
	}

	manager := &Manager[Req, Resp]{
		plugins:              make(map[string]Plugin[Req, Resp]),
		factories:            make(map[string]PluginFactory[Req, Resp]),
		breakers:             make(map[string]*CircuitBreaker),
		healthCheckers:       make(map[string]*HealthChecker),
		healthStatus:         make(map[string]HealthStatus),
		logger:               internalLogger,
		metrics:              &ManagerMetrics{},
		requestTracker:       NewRequestTrackerWithObservability(observabilityManager.metricsCollector, observabilityConfig.MetricsPrefix),
		discoveryEngine:      discoveryEngine,
		observabilityManager: observabilityManager,
		securityValidator:    securityValidator,

		// Compatibility fields (temporary during refactoring)
		observabilityConfig: observabilityConfig,
		metricsCollector:    observabilityManager.metricsCollector,
		commonMetrics:       observabilityManager.commonMetrics,
		tracingProvider:     observabilityManager.tracingProvider,
		startTime:           observabilityManager.startTime,
		totalRequests:       observabilityManager.totalRequests,
		totalErrors:         observabilityManager.totalErrors,
		activeRequests:      observabilityManager.activeRequests,
		pluginMetrics:       observabilityManager.pluginMetrics,
	}

	// Initialize dynamic loader
	manager.dynamicLoader = NewDynamicLoader(manager, discoveryEngine, internalLogger)

	return manager
}

// recordObservabilityStart records the start of a request for observability tracking
func (m *Manager[Req, Resp]) recordObservabilityStart(pluginName string) {
	// Use the refactored ObservabilityManager
	m.observabilityManager.RecordObservabilityStart(pluginName)
}

// recordObservabilityEnd records the end of a request for observability tracking
func (m *Manager[Req, Resp]) recordObservabilityEnd(pluginName string, duration time.Duration, err error) {
	// Use the refactored ObservabilityManager
	m.observabilityManager.RecordObservabilityEnd(pluginName, duration, err)
}

// recordObservabilityError records error metrics and tracing information
func (m *Manager[Req, Resp]) recordObservabilityError(pluginName string, startTime time.Time, err error, span Span) {
	latency := time.Since(startTime)

	// Use the refactored ObservabilityManager for error recording
	m.observabilityManager.RecordObservabilityEnd(pluginName, latency, err)

	// Set span error status (keep tracing logic)
	if span != nil {
		span.SetStatus(SpanStatusError, err.Error())
		span.SetAttribute("error", true)
		span.SetAttribute("error.message", err.Error())
	}

	// Log error if enabled
	if m.observabilityManager.IsLoggingEnabled() {
		m.logger.Error("Plugin execution failed",
			"plugin", pluginName,
			"latency", latency,
			"error", err)
	}
}

// recordObservabilityResult records success metrics and tracing information
func (m *Manager[Req, Resp]) recordObservabilityResult(pluginName string, latency time.Duration, err error, span Span, execCtx ExecutionContext) {
	if err != nil {
		// Error case is already handled by recordObservabilityError
		return
	}

	// Metrics are now handled by ObservabilityManager in recordObservabilityEnd

	// Set span success status (keep tracing logic)
	if span != nil {
		span.SetStatus(SpanStatusOK, "success")
		span.SetAttribute("success", true)
		span.SetAttribute("latency_ns", latency.Nanoseconds())
	}

	// Log success if enabled
	if m.observabilityManager.IsLoggingEnabled() {
		m.logger.Debug("Plugin execution succeeded",
			"plugin", pluginName,
			"latency", latency,
			"request_id", execCtx.RequestID)
	}
}

// Configuration Management Methods are now implemented in manager_config.go
// Health Monitoring Methods are now implemented in manager_health.go
// Plugin Registry Management Methods are now implemented in manager_registry.go
// Plugin Execution Methods are now implemented in manager_execution.go
// Lifecycle Management Methods are now implemented in manager_lifecycle.go

// GetObservabilityConfig returns current observability configuration
func (m *Manager[Req, Resp]) GetObservabilityConfig() ObservabilityConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.observabilityConfig
}

// GetObservabilityMetrics returns comprehensive observability metrics from the manager
func (m *Manager[Req, Resp]) GetObservabilityMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// Get basic manager metrics
	m.addManagerMetrics(metrics)

	// Add runtime observability metrics
	m.addGlobalMetrics(metrics)

	// Add plugin-specific detailed metrics
	m.addPluginMetrics(metrics)

	// Get metrics from external collectors
	m.addExternalCollectorMetrics(metrics)

	// Add system status information
	m.addSystemStatusMetrics(metrics)

	return metrics
}

// addManagerMetrics adds basic manager metrics
func (m *Manager[Req, Resp]) addManagerMetrics(metrics map[string]interface{}) {
	managerMetrics := m.GetMetrics()

	// Get registered plugins count
	m.mu.RLock()
	pluginsCount := len(m.plugins)
	m.mu.RUnlock()

	metrics["manager"] = map[string]interface{}{
		"requests_total":        managerMetrics.RequestsTotal.Load(),
		"requests_success":      managerMetrics.RequestsSuccess.Load(),
		"requests_failure":      managerMetrics.RequestsFailure.Load(),
		"request_duration_ns":   managerMetrics.RequestDuration.Load(),
		"circuit_breaker_trips": managerMetrics.CircuitBreakerTrips.Load(),
		"health_check_failures": managerMetrics.HealthCheckFailures.Load(),
	}

	// Add the missing metric that tests expect
	metrics["registered_plugins_count"] = pluginsCount
}

// addGlobalMetrics adds runtime observability metrics
func (m *Manager[Req, Resp]) addGlobalMetrics(metrics map[string]interface{}) {
	metrics["global"] = map[string]interface{}{
		"total_requests":  m.totalRequests.Load(),
		"total_errors":    m.totalErrors.Load(),
		"active_requests": m.activeRequests.Load(),
		"start_time":      m.startTime,
		"uptime_seconds":  time.Since(m.startTime).Seconds(),
	}
}

// addPluginMetrics adds plugin-specific detailed metrics
func (m *Manager[Req, Resp]) addPluginMetrics(metrics map[string]interface{}) {
	m.metricsMu.RLock()
	defer m.metricsMu.RUnlock()

	pluginMetrics := make(map[string]interface{})
	for pluginName, pluginMetric := range m.pluginMetrics {
		pluginMetrics[pluginName] = m.buildPluginMetricData(pluginMetric)
	}
	metrics["plugins"] = pluginMetrics
}

// buildPluginMetricData builds metric data for a single plugin
func (m *Manager[Req, Resp]) buildPluginMetricData(pluginMetric *PluginObservabilityMetrics) map[string]interface{} {
	totalRequests := pluginMetric.TotalRequests.Load()
	successfulRequests := pluginMetric.SuccessfulRequests.Load()
	failedRequests := pluginMetric.FailedRequests.Load()

	var successRate float64
	if totalRequests > 0 {
		successRate = float64(successfulRequests) / float64(totalRequests) * 100.0
	}

	return map[string]interface{}{
		"total_requests":        totalRequests,
		"successful_requests":   successfulRequests,
		"failed_requests":       failedRequests,
		"active_requests":       pluginMetric.ActiveRequests.Load(),
		"success_rate":          successRate,
		"total_latency_ns":      pluginMetric.TotalLatency.Load(),
		"min_latency_ns":        pluginMetric.MinLatency.Load(),
		"max_latency_ns":        pluginMetric.MaxLatency.Load(),
		"avg_latency_ns":        pluginMetric.AvgLatency.Load(),
		"timeout_errors":        pluginMetric.TimeoutErrors.Load(),
		"connection_errors":     pluginMetric.ConnectionErrors.Load(),
		"auth_errors":           pluginMetric.AuthErrors.Load(),
		"other_errors":          pluginMetric.OtherErrors.Load(),
		"circuit_breaker_trips": pluginMetric.CircuitBreakerTrips.Load(),
		"circuit_breaker_state": m.getCircuitBreakerState(pluginMetric.CircuitBreakerState),
		"health_check_total":    pluginMetric.HealthCheckTotal.Load(),
		"health_check_failed":   pluginMetric.HealthCheckFailed.Load(),
		"last_health_check":     pluginMetric.LastHealthCheck.Load(),
		"health_status":         m.getHealthStatus(pluginMetric.HealthStatus),
	}
}

// getCircuitBreakerState safely extracts circuit breaker state
func (m *Manager[Req, Resp]) getCircuitBreakerState(state *atomic.Value) string {
	if state != nil {
		if val := state.Load(); val != nil {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return "unknown"
}

// getHealthStatus safely extracts health status
func (m *Manager[Req, Resp]) getHealthStatus(status *atomic.Value) string {
	if status != nil {
		if val := status.Load(); val != nil {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return "unknown"
}

// addExternalCollectorMetrics adds metrics from external collectors
func (m *Manager[Req, Resp]) addExternalCollectorMetrics(metrics map[string]interface{}) {
	// Get metrics from collector if available
	if m.metricsCollector != nil {
		metrics["collector"] = m.metricsCollector.GetMetrics()
	}

	// Get Prometheus metrics if available
	if m.commonMetrics != nil && m.observabilityConfig.MetricsCollector != nil {
		if prometheusMetrics := m.observabilityConfig.MetricsCollector.GetPrometheusMetrics(); prometheusMetrics != nil {
			metrics["prometheus"] = prometheusMetrics
		}
	}
}

// addSystemStatusMetrics adds health and circuit breaker status information
func (m *Manager[Req, Resp]) addSystemStatusMetrics(metrics map[string]interface{}) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get health status for all plugins
	healthStatuses := make(map[string]HealthStatus)
	for name, status := range m.healthStatus {
		healthStatuses[name] = status
	}

	// Get circuit breaker states
	circuitBreakerStates := make(map[string]string)
	for name, breaker := range m.breakers {
		circuitBreakerStates[name] = breaker.GetState().String()
	}

	metrics["health_status"] = healthStatuses
	metrics["circuit_breaker_states"] = circuitBreakerStates
}

// EnableObservability is a convenience method to enable observability with default settings
func (m *Manager[Req, Resp]) EnableObservability() error {
	config := DefaultObservabilityConfig()
	return m.ConfigureObservability(config)
}

// EnableObservabilityWithTracing enables observability with distributed tracing
func (m *Manager[Req, Resp]) EnableObservabilityWithTracing(tracingProvider TracingProvider) error {
	config := DefaultObservabilityConfig()
	config.Level = ObservabilityStandard // Enable tracing
	config.TracingProvider = tracingProvider
	return m.ConfigureObservability(config)
}

// GetObservabilityStatus returns the current state of observability features
func (m *Manager[Req, Resp]) GetObservabilityStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"observability_level": string(m.observabilityConfig.Level),
		"metrics_enabled":     m.observabilityConfig.IsMetricsEnabled(),
		"tracing_enabled":     m.observabilityConfig.IsTracingEnabled(),
		"logging_enabled":     m.observabilityConfig.IsLoggingEnabled(),
		"metrics_prefix":      m.observabilityConfig.MetricsPrefix,
		"tracing_sample_rate": m.observabilityConfig.TracingSampleRate,
		"log_level":           m.observabilityConfig.LogLevel,
		"structured_logging":  m.observabilityConfig.IsStructuredLoggingEnabled(),
		"health_metrics":      m.observabilityConfig.IsHealthMetricsEnabled(),
		"performance_metrics": m.observabilityConfig.IsPerformanceMetricsEnabled(),
		"error_metrics":       m.observabilityConfig.IsErrorMetricsEnabled(),
		"has_common_metrics":  m.commonMetrics != nil,
		"has_tracing":         m.tracingProvider != nil,
	}
}

// setupTracing initializes distributed tracing if enabled
func (m *Manager[Req, Resp]) setupTracing(ctx context.Context, pluginName string, execCtx ExecutionContext) (context.Context, Span) {
	if !m.observabilityConfig.IsTracingEnabled() || m.tracingProvider == nil {
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

// Dynamic Loading Methods are now implemented in manager_dynamic_loading.go

// Security Management Methods are now implemented in manager_security.go
