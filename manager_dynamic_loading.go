// manager_dynamic_loading.go: Dynamic loading and discovery methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"fmt"
)

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
		return NewRegistryError("failed to enable dynamic loading", err)
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
		return NewRegistryError("failed to disable dynamic loading", err)
	}

	m.logger.Info("Dynamic loading disabled")
	return nil
}

// ConfigureDiscovery configures the discovery engine with new settings.
//
// This method allows runtime reconfiguration of the discovery engine including
// directories to scan, patterns to match, and other discovery parameters.
// The configuration is applied immediately and affects subsequent discovery operations.
func (m *Manager[Req, Resp]) ConfigureDiscovery(config ExtendedDiscoveryConfig) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	// Update the discovery engine configuration
	if err := m.discoveryEngine.UpdateConfig(config); err != nil {
		return NewDiscoveryError("failed to update discovery configuration", err)
	}

	m.logger.Info("Discovery configuration updated successfully",
		"enabled", config.Enabled,
		"directories", len(config.Directories),
		"patterns", len(config.Patterns))

	return nil
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
		return NewDiscoveryError(fmt.Sprintf("failed to load discovered plugin %s", pluginName), err)
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
		return NewRegistryError(fmt.Sprintf("failed to unload dynamic plugin %s", pluginName), err)
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
