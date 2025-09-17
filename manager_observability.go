// manager_observability.go: Observability management for plugin manager
//
// This file contains all observability-related functionality extracted from
// the main manager.go file to improve code organization and maintainability.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"sync"
	"sync/atomic"
	"time"
)

// ObservabilityManager handles all observability concerns for the plugin manager.
//
// This manager centralizes metrics collection, tracing, health status tracking,
// and provides a clean interface for observability operations without cluttering
// the main manager logic.
//
// Key responsibilities:
//   - Plugin-specific metrics collection and aggregation
//   - Global manager metrics tracking
//   - Health status monitoring and reporting
//   - Circuit breaker state tracking
//   - Performance metrics (latency, throughput, error rates)
//   - Integration with external monitoring systems (Prometheus, etc.)
type ObservabilityManager struct {
	// Configuration
	config           ObservabilityConfig
	metricsCollector MetricsCollector
	commonMetrics    *CommonPluginMetrics
	tracingProvider  TracingProvider
	logger           Logger

	// Global metrics (integrated from ObservableManager)
	startTime      time.Time
	totalRequests  *atomic.Int64
	totalErrors    *atomic.Int64
	activeRequests *atomic.Int64

	// Plugin-specific detailed metrics
	pluginMetrics map[string]*PluginObservabilityMetrics
	metricsMu     sync.RWMutex

	// Manager-level operational metrics
	managerMetrics *ManagerMetrics
}

// NewObservabilityManager creates a new observability manager with the given configuration
func NewObservabilityManager(config ObservabilityConfig, logger Logger) *ObservabilityManager {
	// Create common metrics if advanced features are available
	var commonMetrics *CommonPluginMetrics
	if config.MetricsCollector != nil && config.MetricsCollector.CounterWithLabels("test", "test") != nil {
		commonMetrics = CreateCommonPluginMetrics(config.MetricsCollector)
	}

	return &ObservabilityManager{
		config:           config,
		metricsCollector: config.MetricsCollector,
		commonMetrics:    commonMetrics,
		tracingProvider:  config.TracingProvider,
		logger:           logger,
		startTime:        time.Now(),
		totalRequests:    &atomic.Int64{},
		totalErrors:      &atomic.Int64{},
		activeRequests:   &atomic.Int64{},
		pluginMetrics:    make(map[string]*PluginObservabilityMetrics),
		managerMetrics:   &ManagerMetrics{},
	}
}

// Note: PluginObservabilityMetrics, ManagerMetrics, and CommonPluginMetrics
// are defined in manager.go and observability_impl.go to avoid redeclaration.
// This manager uses those existing types.

// ConfigureObservability updates the observability configuration.
func (om *ObservabilityManager) ConfigureObservability(config ObservabilityConfig) error {
	om.config = config
	om.metricsCollector = config.MetricsCollector
	om.tracingProvider = config.TracingProvider

	// Create common plugin metrics if advanced features are supported
	if om.metricsCollector != nil && om.metricsCollector.CounterWithLabels("test", "test") != nil {
		om.commonMetrics = CreateCommonPluginMetrics(om.metricsCollector)
	} else {
		om.commonMetrics = nil
	}

	om.logger.Info("Observability configuration updated",
		"level", config.Level,
		"metrics_enabled", config.IsMetricsEnabled(),
		"tracing_enabled", config.IsTracingEnabled(),
		"logging_enabled", config.IsLoggingEnabled())

	return nil
}

// EnsurePluginMetrics ensures metrics exist for a plugin.
func (om *ObservabilityManager) EnsurePluginMetrics(pluginName string) {
	om.metricsMu.Lock()
	defer om.metricsMu.Unlock()

	if _, exists := om.pluginMetrics[pluginName]; !exists {
		circuitBreakerState := &atomic.Value{}
		circuitBreakerState.Store("closed")
		healthStatus := &atomic.Value{}
		healthStatus.Store("unknown")

		om.pluginMetrics[pluginName] = &PluginObservabilityMetrics{
			TotalRequests:       &atomic.Int64{},
			SuccessfulRequests:  &atomic.Int64{},
			FailedRequests:      &atomic.Int64{},
			ActiveRequests:      &atomic.Int64{},
			TotalLatency:        &atomic.Int64{},
			MinLatency:          &atomic.Int64{},
			MaxLatency:          &atomic.Int64{},
			AvgLatency:          &atomic.Int64{},
			TimeoutErrors:       &atomic.Int64{},
			ConnectionErrors:    &atomic.Int64{},
			AuthErrors:          &atomic.Int64{},
			OtherErrors:         &atomic.Int64{},
			CircuitBreakerTrips: &atomic.Int64{},
			CircuitBreakerState: circuitBreakerState,
			HealthCheckTotal:    &atomic.Int64{},
			HealthCheckFailed:   &atomic.Int64{},
			LastHealthCheck:     &atomic.Int64{},
			HealthStatus:        healthStatus,
		}
	}
}

// GetPluginMetrics returns metrics for a specific plugin.
func (om *ObservabilityManager) GetPluginMetrics(pluginName string) *PluginObservabilityMetrics {
	om.metricsMu.RLock()
	defer om.metricsMu.RUnlock()

	return om.pluginMetrics[pluginName]
}

// RecordObservabilityStart records the start of a plugin operation.
func (om *ObservabilityManager) RecordObservabilityStart(pluginName string) {
	if !om.config.IsMetricsEnabled() {
		return
	}

	om.EnsurePluginMetrics(pluginName)

	// Increment global counters
	om.totalRequests.Add(1)
	om.activeRequests.Add(1)

	// Increment plugin-specific counters
	if metrics := om.GetPluginMetrics(pluginName); metrics != nil {
		metrics.TotalRequests.Add(1)
		metrics.ActiveRequests.Add(1)
	}

	// Record in common metrics if available
	if om.commonMetrics != nil {
		om.commonMetrics.IncrementActiveRequests(pluginName)
	}

	// Record in manager metrics
	om.managerMetrics.RequestsTotal.Add(1)
}

// RecordObservabilityEnd records the end of a plugin operation.
func (om *ObservabilityManager) RecordObservabilityEnd(pluginName string, duration time.Duration, err error) {
	if !om.config.IsMetricsEnabled() {
		return
	}

	// Decrement active requests
	om.activeRequests.Add(-1)

	if metrics := om.GetPluginMetrics(pluginName); metrics != nil {
		metrics.ActiveRequests.Add(-1)
	}

	// Record success/failure
	success := err == nil
	if success {
		om.managerMetrics.RequestsSuccess.Add(1)
		if metrics := om.GetPluginMetrics(pluginName); metrics != nil {
			metrics.SuccessfulRequests.Add(1)
		}
	} else {
		om.totalErrors.Add(1)
		om.managerMetrics.RequestsFailure.Add(1)
		if metrics := om.GetPluginMetrics(pluginName); metrics != nil {
			metrics.FailedRequests.Add(1)
			// Classify the error and increment appropriate counter
			ClassifyError(err, metrics)
		}
	}

	// Record in common metrics (advanced collector)
	if om.commonMetrics != nil {
		om.commonMetrics.RecordRequest(pluginName, duration, success)
		om.commonMetrics.DecrementActiveRequests(pluginName)
	}

	// Also record in basic collector for compatibility
	if om.metricsCollector != nil {
		labels := map[string]string{"plugin_name": pluginName}
		om.metricsCollector.IncrementCounter("plugin_requests_total", labels, 1)

		if success {
			om.metricsCollector.IncrementCounter("plugin_requests_success_total", labels, 1)
		} else {
			om.metricsCollector.IncrementCounter("plugin_requests_failure_total", labels, 1)
		}

		om.metricsCollector.RecordHistogram("plugin_request_duration_seconds", labels, duration.Seconds())
	}

	// Record duration
	durationNs := duration.Nanoseconds()
	om.managerMetrics.RequestDuration.Store(durationNs)

	if metrics := om.GetPluginMetrics(pluginName); metrics != nil {
		metrics.TotalLatency.Add(durationNs)

		// Update min/max latency
		for {
			current := metrics.MinLatency.Load()
			if current == 0 || durationNs < current {
				if metrics.MinLatency.CompareAndSwap(current, durationNs) {
					break
				}
			} else {
				break
			}
		}

		for {
			current := metrics.MaxLatency.Load()
			if durationNs > current {
				if metrics.MaxLatency.CompareAndSwap(current, durationNs) {
					break
				}
			} else {
				break
			}
		}
	}

	// Record in common metrics if available
	if om.commonMetrics != nil {
		if om.commonMetrics.ActiveRequests != nil {
			om.commonMetrics.ActiveRequests.Add(-1, pluginName)
		}

		if om.commonMetrics.RequestDuration != nil {
			om.commonMetrics.RequestDuration.Observe(duration.Seconds(), pluginName)
		}
	}
}

// RecordCircuitBreakerMetrics records circuit breaker state changes.
func (om *ObservabilityManager) RecordCircuitBreakerMetrics(pluginName string, state CircuitBreakerState) {
	if !om.config.IsMetricsEnabled() {
		return
	}

	om.EnsurePluginMetrics(pluginName)

	if metrics := om.GetPluginMetrics(pluginName); metrics != nil {
		metrics.CircuitBreakerState.Store(state.String())

		// Record trip if state changed to open
		if state == StateOpen {
			metrics.CircuitBreakerTrips.Add(1)
			om.managerMetrics.CircuitBreakerTrips.Add(1)
		}
	}

	// Record in common metrics if available
	if om.commonMetrics != nil && om.commonMetrics.CircuitBreakerState != nil {
		stateValue := float64(state) // Convert state to numeric value
		om.commonMetrics.CircuitBreakerState.Set(stateValue, pluginName)
	}
}

// GetObservabilityMetrics returns comprehensive observability metrics.
func (om *ObservabilityManager) GetObservabilityMetrics() map[string]interface{} {
	om.metricsMu.RLock()
	defer om.metricsMu.RUnlock()

	// Global metrics
	uptime := time.Since(om.startTime)
	globalMetrics := map[string]interface{}{
		"start_time":      om.startTime,
		"uptime_seconds":  uptime.Seconds(),
		"total_requests":  om.totalRequests.Load(),
		"total_errors":    om.totalErrors.Load(),
		"active_requests": om.activeRequests.Load(),
	}

	// Manager metrics
	managerMetrics := map[string]interface{}{
		"requests_total":        om.managerMetrics.RequestsTotal.Load(),
		"requests_success":      om.managerMetrics.RequestsSuccess.Load(),
		"requests_failure":      om.managerMetrics.RequestsFailure.Load(),
		"request_duration_ns":   om.managerMetrics.RequestDuration.Load(),
		"circuit_breaker_trips": om.managerMetrics.CircuitBreakerTrips.Load(),
		"health_check_failures": om.managerMetrics.HealthCheckFailures.Load(),
	}

	// Plugin-specific metrics
	pluginMetricsMap := make(map[string]interface{})
	for pluginName, metrics := range om.pluginMetrics {
		pluginMetricsMap[pluginName] = map[string]interface{}{
			"total_requests":        metrics.TotalRequests.Load(),
			"successful_requests":   metrics.SuccessfulRequests.Load(),
			"failed_requests":       metrics.FailedRequests.Load(),
			"active_requests":       metrics.ActiveRequests.Load(),
			"total_latency_ns":      metrics.TotalLatency.Load(),
			"min_latency_ns":        metrics.MinLatency.Load(),
			"max_latency_ns":        metrics.MaxLatency.Load(),
			"avg_latency_ns":        metrics.AvgLatency.Load(),
			"timeout_errors":        metrics.TimeoutErrors.Load(),
			"connection_errors":     metrics.ConnectionErrors.Load(),
			"auth_errors":           metrics.AuthErrors.Load(),
			"other_errors":          metrics.OtherErrors.Load(),
			"circuit_breaker_trips": metrics.CircuitBreakerTrips.Load(),
			"circuit_breaker_state": metrics.CircuitBreakerState.Load().(string),
			"health_check_total":    metrics.HealthCheckTotal.Load(),
			"health_check_failed":   metrics.HealthCheckFailed.Load(),
			"last_health_check":     metrics.LastHealthCheck.Load(),
			"health_status":         metrics.HealthStatus.Load().(string),
			"success_rate":          om.calculateSuccessRate(metrics),
		}
	}

	// Collector metrics (Prometheus-style)
	var collectorMetrics map[string]interface{}
	var prometheusMetrics []interface{}

	if om.metricsCollector != nil {
		collectorMetrics = om.metricsCollector.GetMetrics()

		// Generate Prometheus-style metrics if supported
		if om.commonMetrics != nil {
			prometheusMetrics = om.generatePrometheusMetrics()
		}
	}

	return map[string]interface{}{
		"global":                 globalMetrics,
		"manager":                managerMetrics,
		"plugins":                pluginMetricsMap,
		"collector":              collectorMetrics,
		"prometheus":             prometheusMetrics,
		"circuit_breaker_states": om.getCircuitBreakerStates(),
		"health_status":          om.getHealthStatuses(),
	}
}

// calculateSuccessRate calculates success rate for a plugin.
func (om *ObservabilityManager) calculateSuccessRate(metrics *PluginObservabilityMetrics) float64 {
	total := metrics.TotalRequests.Load()
	if total == 0 {
		return 0
	}

	successful := metrics.SuccessfulRequests.Load()
	return float64(successful) / float64(total) * 100
}

// getCircuitBreakerStates returns current circuit breaker states.
func (om *ObservabilityManager) getCircuitBreakerStates() map[string]string {
	states := make(map[string]string)

	for pluginName, metrics := range om.pluginMetrics {
		states[pluginName] = metrics.CircuitBreakerState.Load().(string)
	}

	return states
}

// getHealthStatuses returns current health statuses.
func (om *ObservabilityManager) getHealthStatuses() map[string]interface{} {
	statuses := make(map[string]interface{})

	for pluginName, metrics := range om.pluginMetrics {
		statuses[pluginName] = map[string]interface{}{
			"status":       metrics.HealthStatus.Load().(string),
			"last_check":   time.Unix(0, metrics.LastHealthCheck.Load()),
			"check_total":  metrics.HealthCheckTotal.Load(),
			"check_failed": metrics.HealthCheckFailed.Load(),
		}
	}

	return statuses
}

// generatePrometheusMetrics generates Prometheus-compatible metrics.
func (om *ObservabilityManager) generatePrometheusMetrics() []interface{} {
	var metrics []interface{}

	// Generate basic metric information without trying to access metric values
	// since the metric interfaces don't provide direct access to current values
	for pluginName := range om.pluginMetrics {
		labels := map[string]string{"plugin_name": pluginName}

		// Counter metrics
		if om.commonMetrics != nil && om.commonMetrics.RequestsTotal != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "goplugins_requests_total",
				"Type":        "counter",
				"Description": "Counter metric for goplugins_requests_total",
				"Value":       float64(0), // Placeholder - actual value managed internally
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}

		// Histogram metrics
		if om.commonMetrics != nil && om.commonMetrics.RequestDuration != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "goplugins_request_duration_seconds",
				"Type":        "histogram",
				"Description": "Histogram metric for goplugins_request_duration_seconds",
				"Value":       float64(0), // Placeholder - actual value managed internally
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}

		// Gauge metrics
		if om.commonMetrics != nil && om.commonMetrics.ActiveRequests != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "plugin_active_requests",
				"Type":        "gauge",
				"Description": "Gauge metric for plugin_active_requests",
				"Value":       float64(0), // Placeholder - actual value managed internally
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}

		if om.commonMetrics != nil && om.commonMetrics.CircuitBreakerState != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "plugin_circuit_breaker_state",
				"Type":        "gauge",
				"Description": "Gauge metric for plugin_circuit_breaker_state",
				"Value":       float64(0), // Placeholder - actual value managed internally
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}
	}

	return metrics
}

// GetObservabilityConfig returns the current observability configuration.
func (om *ObservabilityManager) GetObservabilityConfig() ObservabilityConfig {
	return om.config
}

// IsMetricsEnabled returns whether metrics collection is enabled.
func (om *ObservabilityManager) IsMetricsEnabled() bool {
	return om.config.IsMetricsEnabled()
}

// IsTracingEnabled returns whether tracing is enabled.
func (om *ObservabilityManager) IsTracingEnabled() bool {
	return om.config.IsTracingEnabled()
}

// IsLoggingEnabled returns whether observability logging is enabled.
func (om *ObservabilityManager) IsLoggingEnabled() bool {
	return om.config.IsLoggingEnabled()
}
