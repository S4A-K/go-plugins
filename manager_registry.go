// manager_registry.go: Plugin registry management methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"errors"
	"fmt"
	"time"
)

// Plugin Registry Management Methods

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
			return NewSecurityValidationError(fmt.Sprintf("security validation error for plugin %s", info.Name), err)
		}

		if !validationResult.Authorized {
			return NewSecurityValidationError(fmt.Sprintf("plugin %s rejected by security policy: %v", info.Name, validationResult.Violations), nil)
		}

		m.logger.Info("Plugin security validation passed",
			"plugin", info.Name,
			"policy", validationResult.Policy.String())
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.plugins[info.Name]; exists {
		return NewRegistryError(fmt.Sprintf("plugin %s is already registered", info.Name), nil)
	}

	// Initialize circuit breaker for the plugin
	m.breakers[info.Name] = NewCircuitBreaker(CircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    5,
		RecoveryTimeout:     30 * time.Second,
		MinRequestThreshold: 3,
		SuccessThreshold:    2,
	})

	// Initialize health checker and status
	healthChecker := m.initializeHealthChecker(plugin)
	m.healthCheckers[info.Name] = healthChecker
	m.plugins[info.Name] = plugin
	m.initializeHealthStatus(info.Name)

	// Start health monitoring
	m.startHealthMonitoring(info.Name)

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
		return NewPluginNotFoundError(name)
	}

	// Stop health monitoring
	m.stopHealthChecker(name)

	// Clean up circuit breaker and health status
	delete(m.breakers, name)
	m.cleanupHealthStatus(name)

	// Close the plugin
	if err := plugin.Close(); err != nil {
		m.logger.Warn("Error closing plugin during unregister",
			"plugin", name, "error", err)
	}

	delete(m.plugins, name)

	m.logger.Info("Plugin unregistered", "plugin", name)
	return nil
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

// RegisterFactory registers a plugin factory for a specific plugin type
func (m *Manager[Req, Resp]) RegisterFactory(pluginType string, factory PluginFactory[Req, Resp]) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.factories[pluginType]; exists {
		return NewFactoryError(pluginType, "factory for plugin type already registered", nil)
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
		return nil, NewFactoryError(pluginType, "no factory registered for plugin type", nil)
	}

	return factory, nil
}

// closeAllPlugins closes all registered plugins during shutdown
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

// GracefulUnregister removes a plugin after draining all active requests
func (m *Manager[Req, Resp]) GracefulUnregister(pluginName string, drainTimeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if plugin exists
	if _, exists := m.plugins[pluginName]; !exists {
		return NewPluginNotFoundError(pluginName)
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
			return NewRegistryError(fmt.Sprintf("failed to drain plugin %s", pluginName), err)
		}
	}

	// Remove plugin components
	delete(m.plugins, pluginName)
	delete(m.breakers, pluginName)

	// Stop health monitoring and cleanup
	m.stopHealthChecker(pluginName)
	m.cleanupHealthStatus(pluginName)

	m.logger.Info("Plugin successfully unregistered after graceful drain", "plugin", pluginName)
	return nil
}
