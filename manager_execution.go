// manager_execution.go: Plugin execution methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Plugin Execution Methods

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
		err := NewCircuitBreakerOpenError(pluginName)
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

	// Record observability end
	m.recordObservabilityEnd(pluginName, latency, err)

	return response, err
}

// recordExecutionMetrics records timing and count metrics for plugin execution
func (m *Manager[Req, Resp]) recordExecutionMetrics(startTime time.Time) {
	duration := time.Since(startTime)
	m.metrics.RequestDuration.Add(duration.Nanoseconds())
	m.metrics.RequestsTotal.Add(1)

	// Also record in common metrics if available
	if m.commonMetrics != nil {
		m.commonMetrics.RequestsTotal.Add(1)
		m.commonMetrics.RequestDuration.Observe(duration.Seconds())
	}

	// Record in metrics collector if available
	if m.metricsCollector != nil {
		labels := make(map[string]string)
		m.metricsCollector.IncrementCounter("plugin_requests_total", labels, 1)
		m.metricsCollector.RecordHistogram("plugin_request_duration_seconds", labels, duration.Seconds())
	}

	// Update global totals for observability
	if m.totalRequests != nil {
		m.totalRequests.Add(1)
	}
}

// getPluginAndBreaker retrieves plugin and circuit breaker for execution
func (m *Manager[Req, Resp]) getPluginAndBreaker(pluginName string) (Plugin[Req, Resp], *CircuitBreaker, error) {
	m.mu.RLock()
	plugin, exists := m.plugins[pluginName]
	breaker, hasBreakerr := m.breakers[pluginName]
	m.mu.RUnlock()

	if !exists {
		m.metrics.RequestsFailure.Add(1)
		return nil, nil, NewPluginNotFoundError(pluginName)
	}

	if !hasBreakerr {
		m.metrics.RequestsFailure.Add(1)
		return nil, nil, NewRegistryError(fmt.Sprintf("circuit breaker not found for plugin %s", pluginName), nil)
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

	// Record in common metrics if available
	if m.commonMetrics != nil {
		m.commonMetrics.RequestsSuccess.Add(1)
	}

	// Record in metrics collector if available
	if m.metricsCollector != nil {
		labels := make(map[string]string)
		m.metricsCollector.IncrementCounter("plugin_requests_success_total", labels, 1)
	}

	// Record circuit breaker state change if needed
	m.observabilityManager.RecordCircuitBreakerMetrics(pluginName, breaker.GetState())

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

	// Record in common metrics if available
	if m.commonMetrics != nil {
		m.commonMetrics.RequestsFailure.Add(1)
	}

	// Record in metrics collector if available
	if m.metricsCollector != nil {
		labels := make(map[string]string)
		m.metricsCollector.IncrementCounter("plugin_requests_failure_total", labels, 1)
	}

	// Update global error count
	if m.totalErrors != nil {
		m.totalErrors.Add(1)
	}

	// Record circuit breaker state change and trip metrics
	newState := breaker.GetState()
	m.observabilityManager.RecordCircuitBreakerMetrics(pluginName, newState)

	// Record circuit breaker trips if it opened
	if newState == StateOpen {
		m.metrics.CircuitBreakerTrips.Add(1)
	}

	// Create detailed error with execution context
	pluginErr := NewPluginExecutionFailedError(pluginName, err).
		WithContext("max_retries", execCtx.MaxRetries).
		WithContext("request_id", execCtx.RequestID).
		WithContext("timeout", execCtx.Timeout.String()).
		WithContext("circuit_breaker_state", newState.String())

	return zero, pluginErr
}

// isRetryableError determines if an error should trigger a retry
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// For now, consider timeout and temporary errors as retryable
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}
