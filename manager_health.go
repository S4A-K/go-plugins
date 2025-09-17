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
			// TODO: Add health check metrics to ObservabilityManager
			// m.recordHealthCheckMetrics(pluginName, status, duration)

			if status.Status != StatusHealthy {
				m.metrics.HealthCheckFailures.Add(1)
				m.logger.Warn("Plugin health check failed",
					"plugin", pluginName,
					"status", status.Status.String(),
					"message", status.Message,
					"duration", duration)
			} else if m.observabilityConfig.IsLoggingEnabled() {
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
