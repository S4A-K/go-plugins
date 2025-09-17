// manager_config.go: Configuration management methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"

	"github.com/agilira/argus"
)

// Configuration Management Methods

// LoadFromConfig implements PluginManager.LoadFromConfig
func (m *Manager[Req, Resp]) LoadFromConfig(config ManagerConfig) error {
	if err := config.Validate(); err != nil {
		return NewConfigValidationError("invalid configuration", err)
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
			return NewFactoryError(pluginConfig.Type, "no factory registered for plugin type", nil)
		}

		plugin, err := factory.CreatePlugin(pluginConfig)
		if err != nil {
			return NewFactoryError(pluginConfig.Type, fmt.Sprintf("failed to create plugin %s", pluginConfig.Name), err)
		}

		if err := m.RegisterWithConfig(plugin, pluginConfig); err != nil {
			return NewRegistryError(fmt.Sprintf("failed to register plugin %s", pluginConfig.Name), err)
		}
	}

	return nil
}

// ReloadConfig implements PluginManager.ReloadConfig with simple recreation strategy
func (m *Manager[Req, Resp]) ReloadConfig(config ManagerConfig) error {
	if err := config.Validate(); err != nil {
		return NewConfigValidationError("invalid configuration", err)
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
		return NewConfigValidationError("dynamic configuration is already enabled", nil)
	}

	watcher, err := NewConfigWatcher(m, configPath, options, m.logger)
	if err != nil {
		return NewConfigWatcherError("failed to create config watcher", err)
	}

	ctx := context.Background()
	if err := watcher.Start(ctx); err != nil {
		return NewConfigWatcherError("failed to start config watcher", err)
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
		return NewConfigValidationError("dynamic configuration is not enabled", nil)
	}

	if err := m.configWatcher.Stop(); err != nil {
		return NewConfigWatcherError("failed to stop config watcher", err)
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
