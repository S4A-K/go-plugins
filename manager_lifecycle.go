// manager_lifecycle.go: Lifecycle management methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"sync/atomic"
)

// Lifecycle Management Methods

// Shutdown implements PluginManager.Shutdown
func (m *Manager[Req, Resp]) Shutdown(ctx context.Context) error {
	if !m.shutdown.CompareAndSwap(false, true) {
		return errors.New("manager already shut down")
	}

	m.logger.Info("Shutting down plugin manager")

	// Stop watchers and loaders
	m.stopWatchersAndLoaders()

	// Stop health checkers
	m.stopAllHealthCheckers()

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

	// Initialize observability manager if not already done
	if m.observabilityManager == nil {
		m.observabilityManager = NewObservabilityManager(config, m.logger)
	}

	// Initialize common metrics if provided and available
	if config.MetricsCollector != nil {
		// Try to create common metrics - this may not work in all configurations
		// so we handle it gracefully
		m.commonMetrics = CreateCommonPluginMetrics(config.MetricsCollector)
	}

	m.logger.Info("Observability configured",
		"level", config.Level,
		"metrics_prefix", config.MetricsPrefix,
		"tracing_sample_rate", config.TracingSampleRate)

	return nil
}

// EnableEnhancedObservability enables advanced observability features
func (m *Manager[Req, Resp]) EnableEnhancedObservability() error {
	config := DefaultObservabilityConfig()
	config.Level = ObservabilityAdvanced
	return m.ConfigureObservability(config)
}

// GetActiveRequestCount returns the number of active requests for a plugin
func (m *Manager[Req, Resp]) GetActiveRequestCount(pluginName string) int64 {
	return m.requestTracker.GetActiveRequestCount(pluginName)
}

// GetAllActiveRequests returns a map of plugin names to active request counts
func (m *Manager[Req, Resp]) GetAllActiveRequests() map[string]int64 {
	return m.requestTracker.GetAllActiveRequests()
}
