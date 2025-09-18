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

	success := err == nil

	// Update request counters
	om.updateRequestCounters(pluginName, success, err)

	// Record in collectors
	om.recordInCollectors(pluginName, duration, success)

	// Record latency metrics
	om.recordLatencyMetrics(pluginName, duration)
}

// updateRequestCounters updates active request counts and success/failure metrics
func (om *ObservabilityManager) updateRequestCounters(pluginName string, success bool, err error) {
	// Decrement active requests
	om.activeRequests.Add(-1)

	if metrics := om.GetPluginMetrics(pluginName); metrics != nil {
		metrics.ActiveRequests.Add(-1)

		if success {
			metrics.SuccessfulRequests.Add(1)
		} else {
			metrics.FailedRequests.Add(1)
			ClassifyError(err, metrics)
		}
	}

	// Update manager-level counters
	if success {
		om.managerMetrics.RequestsSuccess.Add(1)
	} else {
		om.totalErrors.Add(1)
		om.managerMetrics.RequestsFailure.Add(1)
	}
}

// recordInCollectors records metrics in various collectors
func (om *ObservabilityManager) recordInCollectors(pluginName string, duration time.Duration, success bool) {
	// Record in common metrics (advanced collector)
	if om.commonMetrics != nil {
		om.commonMetrics.RecordRequest(pluginName, duration, success)
		om.commonMetrics.DecrementActiveRequests(pluginName)

		if om.commonMetrics.ActiveRequests != nil {
			om.commonMetrics.ActiveRequests.Add(-1, pluginName)
		}

		if om.commonMetrics.RequestDuration != nil {
			om.commonMetrics.RequestDuration.Observe(duration.Seconds(), pluginName)
		}
	}

	// Record in basic collector for compatibility
	om.recordInBasicCollector(pluginName, duration, success)
}

// recordInBasicCollector records metrics in the basic metrics collector
func (om *ObservabilityManager) recordInBasicCollector(pluginName string, duration time.Duration, success bool) {
	if om.metricsCollector == nil {
		return
	}

	labels := map[string]string{"plugin_name": pluginName}
	om.metricsCollector.IncrementCounter("plugin_requests_total", labels, 1)

	if success {
		om.metricsCollector.IncrementCounter("plugin_requests_success_total", labels, 1)
	} else {
		om.metricsCollector.IncrementCounter("plugin_requests_failure_total", labels, 1)
	}

	om.metricsCollector.RecordHistogram("plugin_request_duration_seconds", labels, duration.Seconds())
}

// recordLatencyMetrics records duration and latency statistics
func (om *ObservabilityManager) recordLatencyMetrics(pluginName string, duration time.Duration) {
	durationNs := duration.Nanoseconds()
	om.managerMetrics.RequestDuration.Store(durationNs)

	metrics := om.GetPluginMetrics(pluginName)
	if metrics == nil {
		return
	}

	metrics.TotalLatency.Add(durationNs)
	om.updateMinLatency(metrics, durationNs)
	om.updateMaxLatency(metrics, durationNs)
}

// updateMinLatency atomically updates minimum latency
func (om *ObservabilityManager) updateMinLatency(metrics *PluginObservabilityMetrics, durationNs int64) {
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
}

// updateMaxLatency atomically updates maximum latency
func (om *ObservabilityManager) updateMaxLatency(metrics *PluginObservabilityMetrics, durationNs int64) {
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
			"circuit_breaker_state": func() string {
				if val := metrics.CircuitBreakerState.Load(); val != nil {
					if str, ok := val.(string); ok {
						return str
					}
				}
				return "unknown"
			}(),
			"health_check_total":  metrics.HealthCheckTotal.Load(),
			"health_check_failed": metrics.HealthCheckFailed.Load(),
			"last_health_check":   metrics.LastHealthCheck.Load(),
			"health_status": func() string {
				if val := metrics.HealthStatus.Load(); val != nil {
					if str, ok := val.(string); ok {
						return str
					}
				}
				return "unknown"
			}(),
			"success_rate": om.calculateSuccessRate(metrics),
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
		if val := metrics.CircuitBreakerState.Load(); val != nil {
			if str, ok := val.(string); ok {
				states[pluginName] = str
			} else {
				states[pluginName] = "unknown"
			}
		} else {
			states[pluginName] = "unknown"
		}
	}

	return states
}

// getHealthStatuses returns current health statuses.
func (om *ObservabilityManager) getHealthStatuses() map[string]interface{} {
	statuses := make(map[string]interface{})

	for pluginName, metrics := range om.pluginMetrics {
		healthStatus := "unknown"
		if val := metrics.HealthStatus.Load(); val != nil {
			if str, ok := val.(string); ok {
				healthStatus = str
			}
		}

		statuses[pluginName] = map[string]interface{}{
			"status":       healthStatus,
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

	// Generate metric information with actual values from internal plugin metrics
	om.metricsMu.RLock()
	defer om.metricsMu.RUnlock()

	for pluginName, pluginMetric := range om.pluginMetrics {
		labels := map[string]string{"plugin_name": pluginName}

		// Counter metrics - total requests
		if om.commonMetrics != nil && om.commonMetrics.RequestsTotal != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "goplugins_requests_total",
				"Type":        "counter",
				"Description": "Counter metric for goplugins_requests_total",
				"Value":       float64(pluginMetric.TotalRequests.Load()),
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}

		// Counter metrics - successful requests
		if om.commonMetrics != nil && om.commonMetrics.RequestsSuccess != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "goplugins_requests_success_total",
				"Type":        "counter",
				"Description": "Counter metric for successful plugin requests",
				"Value":       float64(pluginMetric.SuccessfulRequests.Load()),
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}

		// Counter metrics - failed requests
		if om.commonMetrics != nil && om.commonMetrics.RequestsFailure != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "goplugins_requests_failure_total",
				"Type":        "counter",
				"Description": "Counter metric for failed plugin requests",
				"Value":       float64(pluginMetric.FailedRequests.Load()),
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}

		// Histogram metrics - request duration (use average from internal metrics)
		if om.commonMetrics != nil && om.commonMetrics.RequestDuration != nil {
			avgLatencyNs := pluginMetric.AvgLatency.Load()
			avgLatencySeconds := float64(avgLatencyNs) / 1e9 // Convert nanoseconds to seconds

			metrics = append(metrics, map[string]interface{}{
				"Name":        "goplugins_request_duration_seconds",
				"Type":        "histogram",
				"Description": "Histogram metric for goplugins_request_duration_seconds",
				"Value":       avgLatencySeconds,
				"Labels":      labels,
				"Buckets":     []interface{}{}, // Bucket data managed by histogram implementation
			})
		}

		// Gauge metrics - active requests
		if om.commonMetrics != nil && om.commonMetrics.ActiveRequests != nil {
			metrics = append(metrics, map[string]interface{}{
				"Name":        "plugin_active_requests",
				"Type":        "gauge",
				"Description": "Gauge metric for plugin_active_requests",
				"Value":       float64(pluginMetric.ActiveRequests.Load()),
				"Labels":      labels,
				"Buckets":     []interface{}{},
			})
		}

		// Gauge metrics - circuit breaker state
		if om.commonMetrics != nil && om.commonMetrics.CircuitBreakerState != nil {
			// Convert circuit breaker state string to numeric value
			var stateValue float64
			if state := pluginMetric.CircuitBreakerState.Load(); state != nil {
				switch state.(string) {
				case "closed":
					stateValue = 0
				case "open":
					stateValue = 1
				case "half-open":
					stateValue = 2
				default:
					stateValue = 0 // Default to closed
				}
			}

			metrics = append(metrics, map[string]interface{}{
				"Name":        "plugin_circuit_breaker_state",
				"Type":        "gauge",
				"Description": "Gauge metric for plugin_circuit_breaker_state (0=closed, 1=open, 2=half-open)",
				"Value":       stateValue,
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

// RecordHealthCheckMetrics records health check metrics for a plugin.
//
// This method tracks health check results, durations, and status changes
// providing comprehensive observability for plugin health monitoring.
//
// Parameters:
//   - pluginName: Name of the plugin being health checked
//   - status: Current health status result
//   - duration: Time taken for the health check operation
func (om *ObservabilityManager) RecordHealthCheckMetrics(pluginName string, status HealthStatus, duration time.Duration) {
	if !om.IsMetricsEnabled() {
		return
	}

	// Record health check execution time
	om.recordLatencyMetrics(pluginName+"_health", duration)

	// Record health check result in common metrics
	if om.commonMetrics != nil {
		isHealthy := status.Status == StatusHealthy
		om.commonMetrics.RecordRequest(pluginName+"_health", duration, isHealthy)
	}

	// Record in basic collector for compatibility
	om.recordInBasicCollector(pluginName+"_health", duration, status.Status == StatusHealthy)

	// Update plugin-specific health check metrics if available
	if pluginMetrics, exists := om.pluginMetrics[pluginName]; exists {
		pluginMetrics.HealthCheckTotal.Add(1)
		if status.Status != StatusHealthy {
			pluginMetrics.HealthCheckFailed.Add(1)
		}
		pluginMetrics.LastHealthCheck.Store(status.LastCheck.UnixNano())
		pluginMetrics.HealthStatus.Store(status.Status.String())
	}

	// Log health status change for observability
	if om.config.IsLoggingEnabled() {
		om.logger.Debug("Health check completed",
			"plugin", pluginName,
			"status", status.Status.String(),
			"duration_ms", duration.Milliseconds(),
			"message", status.Message)
	}
}

// IsLoggingEnabled returns whether observability logging is enabled.
func (om *ObservabilityManager) IsLoggingEnabled() bool {
	return om.config.IsLoggingEnabled()
}
