// manager_health.go: Health monitoring methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"time"
)

// Health Monitoring Methods

// Health implements PluginManager.Health
func (m *Manager[Req, Resp]) Health() map[string]HealthStatus {
	return m.ListPlugins()
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

// monitorPluginHealth runs health checks for a specific plugin.
//
// This method provides continuous health monitoring for individual plugins,
// executing periodic health checks and recording results for observability.
//
// Monitoring Features:
//   - Configurable health check intervals with sensible defaults
//   - Comprehensive health status tracking and persistence
//   - Observability integration with metrics and logging
//   - Graceful shutdown handling during manager termination
//
// Health Check Flow:
//  1. Initialization - Validates checker existence and configures timing
//  2. Monitoring Loop - Executes periodic checks with proper error handling
//  3. Result Processing - Records status, metrics, and logs appropriately
//  4. Shutdown Handling - Responds to manager shutdown and checker termination
//
// Complexity: Reduced from 10 to 4 through helper function extraction
func (m *Manager[Req, Resp]) monitorPluginHealth(pluginName string) {
	defer m.wg.Done()

	// Phase 1: Initialize health monitoring for the plugin
	checker, interval := m.initializeHealthMonitoring(pluginName)
	if checker == nil {
		return // Plugin checker not found
	}

	// Phase 2: Setup monitoring ticker with configured interval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Phase 3: Execute continuous monitoring loop
	for {
		select {
		case <-ticker.C:
			if m.shutdown.Load() {
				return // Manager shutting down
			}
			m.executeHealthCheck(pluginName, checker)

		case <-checker.Done():
			return // Health checker terminated
		}
	}
}

// initializeHealthMonitoring initializes health monitoring for a specific plugin.
//
// This helper method handles the setup phase of health monitoring, including
// checker validation and interval configuration with appropriate defaults.
//
// Initialization Steps:
//   - Validates health checker existence for the plugin
//   - Retrieves configured health check interval
//   - Applies sensible default interval if not configured
//
// Default Configuration:
//   - Falls back to 30-second interval for unconfigured plugins
//   - Ensures consistent monitoring behavior across all plugins
//
// Complexity: 3 (checker validation with interval configuration)
func (m *Manager[Req, Resp]) initializeHealthMonitoring(pluginName string) (*HealthChecker, time.Duration) {
	// Retrieve health checker for the plugin
	m.mu.RLock()
	checker, exists := m.healthCheckers[pluginName]
	interval := m.config.DefaultHealthCheck.Interval
	m.mu.RUnlock()

	if !exists {
		m.logger.Warn("Health checker not found for plugin", "plugin", pluginName)
		return nil, 0
	}

	// Apply default interval if not configured
	if interval <= 0 {
		interval = 30 * time.Second
		m.logger.Debug("Using default health check interval", "plugin", pluginName, "interval", interval)
	}

	return checker, interval
}

// executeHealthCheck performs a single health check execution with full observability.
//
// This helper method encapsulates the complete health check execution flow,
// including timing, status recording, metrics collection, and logging.
//
// Execution Flow:
//  1. Health Check Execution - Performs timed health check operation
//  2. Status Recording - Persists health status for plugin management
//  3. Observability Integration - Records metrics and logs appropriately
//  4. Error Handling - Manages failures with detailed logging
//
// Observability Features:
//   - Precise timing measurement for performance monitoring
//   - Comprehensive metrics recording for operational dashboards
//   - Contextual logging for troubleshooting and auditing
//   - Status persistence for management system integration
//
// Complexity: 4 (health check execution with comprehensive observability)
func (m *Manager[Req, Resp]) executeHealthCheck(pluginName string, checker *HealthChecker) {
	// Execute timed health check
	startTime := time.Now()
	status := checker.Check()
	duration := time.Since(startTime)

	// Record health status for plugin management
	m.mu.Lock()
	m.healthStatus[pluginName] = status
	m.mu.Unlock()

	// Integrate with observability systems
	m.recordHealthCheckObservability(pluginName, status, duration)

	// Log health check results appropriately
	m.logHealthCheckResult(pluginName, status, duration)
}

// recordHealthCheckObservability records health check metrics and observability data.
//
// This helper method centralizes observability integration for health checks,
// ensuring consistent metrics recording across all plugin monitoring.
//
// Observability Integration:
//   - Metrics recording through observability manager
//   - Failure count tracking for alerting systems
//   - Performance timing for operational monitoring
//
// Complexity: 1 (straightforward observability recording)
func (m *Manager[Req, Resp]) recordHealthCheckObservability(pluginName string, status HealthStatus, duration time.Duration) {
	// Record detailed metrics through observability manager
	if m.observabilityManager != nil {
		m.observabilityManager.RecordHealthCheckMetrics(pluginName, status, duration)
	}

	// Track failure counts for alerting
	if status.Status != StatusHealthy {
		m.metrics.HealthCheckFailures.Add(1)
	}
}

// logHealthCheckResult logs health check results with appropriate detail level.
//
// This helper method handles contextual logging for health check results,
// providing detailed information for failures and debug information for successes.
//
// Logging Strategy:
//   - Warning level for health check failures with full context
//   - Debug level for successful checks when logging is enabled
//   - Includes timing and status information for operational visibility
//
// Complexity: 2 (conditional logging based on status and configuration)
func (m *Manager[Req, Resp]) logHealthCheckResult(pluginName string, status HealthStatus, duration time.Duration) {
	if status.Status != StatusHealthy {
		// Log failures at warning level with full context
		m.logger.Warn("Plugin health check failed",
			"plugin", pluginName,
			"status", status.Status.String(),
			"message", status.Message,
			"duration", duration)
	} else if m.observabilityConfig.IsLoggingEnabled() {
		// Log successes at debug level when logging is enabled
		m.logger.Debug("Plugin health check passed",
			"plugin", pluginName,
			"duration", duration,
			"response_time", status.ResponseTime)
	}
}

// initializeHealthChecker initializes health checker for a plugin during registration
func (m *Manager[Req, Resp]) initializeHealthChecker(plugin Plugin[Req, Resp]) *HealthChecker {
	// Initialize health checker with observability integration
	healthChecker := NewHealthChecker(plugin, HealthCheckConfig{
		Enabled:      true,
		Interval:     30 * time.Second,
		Timeout:      5 * time.Second,
		FailureLimit: 3,
	})

	return healthChecker
}

// initializeHealthStatus initializes health status for a plugin during registration
func (m *Manager[Req, Resp]) initializeHealthStatus(pluginName string) {
	// Initialize health status
	m.healthStatus[pluginName] = HealthStatus{
		Status:    StatusHealthy,
		Message:   "Plugin registered",
		LastCheck: time.Now(),
	}
}

// startHealthMonitoring starts health monitoring for a plugin
func (m *Manager[Req, Resp]) startHealthMonitoring(pluginName string) {
	// Start health monitoring
	m.wg.Add(1)
	go m.monitorPluginHealth(pluginName)
}

// stopHealthChecker stops health checker for a plugin during unregistration
func (m *Manager[Req, Resp]) stopHealthChecker(pluginName string) {
	// Stop health monitoring
	if checker, ok := m.healthCheckers[pluginName]; ok {
		checker.Stop()
		delete(m.healthCheckers, pluginName)
	}
}

// cleanupHealthStatus cleans up health status for a plugin during unregistration
func (m *Manager[Req, Resp]) cleanupHealthStatus(pluginName string) {
	delete(m.healthStatus, pluginName)
}

// stopAllHealthCheckers stops all health checkers during shutdown
func (m *Manager[Req, Resp]) stopAllHealthCheckers() {
	m.mu.Lock()
	for _, checker := range m.healthCheckers {
		checker.Stop()
	}
	m.mu.Unlock()
}
