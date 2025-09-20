// manager_security.go: Plugin security management methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"errors"
)

// Security Management Methods

// EnablePluginSecurity enables the plugin security validator with the given configuration
func (m *Manager[Req, Resp]) EnablePluginSecurity(config SecurityConfig) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.securityValidator == nil {
		validator, err := NewSecurityValidator(config, m.logger)
		if err != nil {
			return NewSecurityValidationError("failed to create security validator", err)
		}
		m.securityValidator = validator
	} else {
		if err := m.securityValidator.UpdateConfig(config); err != nil {
			return NewSecurityValidationError("failed to update security config", err)
		}
	}

	// Only call Enable if not already enabled (avoid "already enabled" error)
	if !m.securityValidator.IsEnabled() {
		if err := m.securityValidator.Enable(); err != nil {
			return NewSecurityValidationError("failed to enable security validator", err)
		}
	}

	m.logger.Info("Plugin security enabled", "policy", config.Policy.String())
	return nil
}

// DisablePluginSecurity disables the plugin security validator
func (m *Manager[Req, Resp]) DisablePluginSecurity() error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.securityValidator == nil {
		return errors.New("security validator not initialized")
	}

	if err := m.securityValidator.Disable(); err != nil {
		return NewSecurityValidationError("failed to disable security validator", err)
	}

	m.logger.Info("Plugin security disabled")
	return nil
}

// IsPluginSecurityEnabled returns whether plugin security is currently enabled
func (m *Manager[Req, Resp]) IsPluginSecurityEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.securityValidator != nil && m.securityValidator.IsEnabled()
}

// GetPluginSecurityStats returns current security validation statistics
func (m *Manager[Req, Resp]) GetPluginSecurityStats() (SecurityStats, error) {
	if m.shutdown.Load() {
		return SecurityStats{}, errors.New("manager is shut down")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return SecurityStats{}, errors.New("security validator not initialized")
	}

	if !m.securityValidator.IsEnabled() {
		return SecurityStats{}, errors.New("security is disabled")
	}

	return m.securityValidator.GetStats(), nil
}

// GetPluginSecurityConfig returns the current security configuration
func (m *Manager[Req, Resp]) GetPluginSecurityConfig() (SecurityConfig, error) {
	if m.shutdown.Load() {
		return SecurityConfig{}, errors.New("manager is shut down")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return SecurityConfig{}, errors.New("security validator not initialized")
	}

	if !m.securityValidator.IsEnabled() {
		return SecurityConfig{}, errors.New("security is disabled")
	}

	return m.securityValidator.GetConfig(), nil
}

// ReloadPluginWhitelist manually reloads the plugin whitelist from file
func (m *Manager[Req, Resp]) ReloadPluginWhitelist() error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return errors.New("security validator not initialized")
	}

	if err := m.securityValidator.ReloadWhitelist(); err != nil {
		return NewWhitelistError("failed to reload whitelist", err)
	}

	m.logger.Info("Plugin whitelist reloaded successfully")
	return nil
}

// GetPluginWhitelistInfo returns information about the current plugin whitelist
func (m *Manager[Req, Resp]) GetPluginWhitelistInfo() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return nil, errors.New("security validator not initialized")
	}

	return m.securityValidator.GetWhitelistInfo(), nil
}

// ValidatePluginSecurity manually validates a plugin against the security policy
// This is useful for testing or pre-validation before actual registration
func (m *Manager[Req, Resp]) ValidatePluginSecurity(config PluginConfig, pluginPath string) (*ValidationResult, error) {
	if m.shutdown.Load() {
		return nil, errors.New("manager is shut down")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return nil, errors.New("security validator not initialized")
	}

	return m.securityValidator.ValidatePlugin(config, pluginPath)
}

// GetArgusIntegrationInfo returns information about the Argus integration for security
func (m *Manager[Req, Resp]) GetArgusIntegrationInfo() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.securityValidator == nil {
		return nil, errors.New("security validator not initialized")
	}

	return m.securityValidator.GetArgusIntegrationInfo(), nil
}
