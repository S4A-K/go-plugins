// manager_registry.go: Plugin registry management methods for Manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Plugin Registry Management Methods

// Register implements PluginManager.Register.
// This method provides a simplified interface for plugin registration using default
// configuration settings. It's the most common way to register plugins when no
// custom configuration is needed.
//
// The method automatically:
//   - Extracts plugin information from the plugin's Info() method
//   - Uses the plugin name as the configuration name
//   - Applies default security settings if security is enabled
//   - Initializes circuit breakers and health checkers with default settings
//
// This is equivalent to calling RegisterWithConfig with an empty PluginConfig,
// which causes the manager to derive all configuration from the plugin's metadata
// and apply system defaults.
//
// Parameters:
//   - plugin: Plugin instance to register (must implement Plugin interface)
//
// Returns:
//   - Error if registration fails due to validation, security, or runtime issues
//
// Example:
//
//	plugin := myPlugin{name: "auth-service"}
//	err := manager.Register(plugin)
//	if err != nil {
//	    log.Printf("Failed to register plugin: %v", err)
//	}
func (m *Manager[Req, Resp]) Register(plugin Plugin[Req, Resp]) error {
	return m.RegisterWithConfig(plugin, PluginConfig{})
}

// RegisterWithConfig registers a plugin with security validation using the provided config
// RegisterWithConfig registers a plugin with the manager using the provided configuration.
//
// This function orchestrates the complete plugin registration process, including
// configuration preparation, security validation, and runtime initialization.
// The registration process is atomic - if any step fails, no partial state
// is left in the manager.
//
// Registration Process:
//  1. Pre-flight validation (shutdown state, plugin info)
//  2. Configuration normalization and security validation
//  3. Thread-safe registration with runtime component initialization
//
// The function separates security concerns from business logic, making it
// easier to test individual components and maintain security policies
// independently from registration mechanics.
//
// Returns an error if registration fails at any step, with specific error
// types to distinguish between validation failures and runtime issues.
func (m *Manager[Req, Resp]) RegisterWithConfig(plugin Plugin[Req, Resp], config PluginConfig) error {
	// Pre-flight validation - fast checks before expensive operations
	if err := m.validatePreRegistrationState(); err != nil {
		return err
	}

	// Validate plugin is not nil before accessing its methods
	if plugin == nil {
		return errors.New("plugin cannot be nil")
	}

	info := plugin.Info()
	if err := m.validatePluginInfo(info); err != nil {
		return err
	}

	// Prepare and validate configuration
	normalizedConfig := m.normalizePluginConfig(config, info)
	if err := m.validatePluginSecurity(normalizedConfig, info); err != nil {
		return err
	}

	// Perform thread-safe registration
	return m.performPluginRegistration(plugin, normalizedConfig, info)
}

// validatePreRegistrationState checks if the manager is in a valid state for registration.
//
// This fast pre-flight check prevents expensive security validation and
// initialization work when the manager is already shut down.
func (m *Manager[Req, Resp]) validatePreRegistrationState() error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}
	return nil
}

// validatePluginInfo ensures the plugin provides required identification information.
//
// Plugin name is essential for registry management, health monitoring,
// and security validation. This check prevents registration of plugins
// that cannot be properly identified or managed.
func (m *Manager[Req, Resp]) validatePluginInfo(info PluginInfo) error {
	if info.Name == "" {
		return errors.New("plugin name cannot be empty")
	}

	// Validate version format (semantic version check)
	if !isValidSemanticVersion(info.Version) {
		return fmt.Errorf("invalid version format: %s", info.Version)
	}

	// Validate plugin name for security (prevent path traversal and malicious patterns)
	if containsMaliciousPattern(info.Name) {
		return fmt.Errorf("plugin name contains forbidden patterns: %s", info.Name)
	}

	return nil
}

// normalizePluginConfig ensures configuration completeness using plugin info.
//
// This function fills in missing configuration fields using information
// from the plugin itself, ensuring consistent configuration state regardless
// of how much detail was provided in the original config.
//
// Note: Plugin type must be provided in config as it's not available in PluginInfo.
func (m *Manager[Req, Resp]) normalizePluginConfig(config PluginConfig, info PluginInfo) PluginConfig {
	// Use plugin info to populate config if not provided
	if config.Name == "" {
		config.Name = info.Name
	}
	return config
}

// validatePluginSecurity performs security validation if security policies are enabled.
//
// This function isolates security validation logic, making it easier to test
// security policies independently and modify security requirements without
// affecting the core registration logic.
//
// Security validation is only performed if a security validator is configured
// and enabled, allowing for flexible security policy deployment.
func (m *Manager[Req, Resp]) validatePluginSecurity(config PluginConfig, info PluginInfo) error {
	if m.securityValidator == nil || !m.securityValidator.IsEnabled() {
		return nil // Security validation disabled
	}

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

	return nil
}

// performPluginRegistration executes the thread-safe registration and initialization.
//
// This function handles the actual registration mechanics, including duplicate
// detection, runtime component initialization, and health monitoring setup.
// All operations are performed under lock to ensure thread safety.
//
// The registration is atomic - if any initialization step fails, no partial
// state is left in the manager's internal structures.
func (m *Manager[Req, Resp]) performPluginRegistration(plugin Plugin[Req, Resp], config PluginConfig, info PluginInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate registration
	if _, exists := m.plugins[info.Name]; exists {
		return NewRegistryError(fmt.Sprintf("plugin %s is already registered", info.Name), nil)
	}

	// Initialize runtime components
	m.initializeCircuitBreaker(info.Name, config.CircuitBreaker)
	m.initializeHealthComponents(plugin, info.Name)
	m.plugins[info.Name] = plugin

	// Start monitoring
	m.startHealthMonitoring(info.Name)

	m.logger.Info("Plugin registered successfully",
		"plugin", info.Name,
		"version", info.Version)

	return nil
}

// initializeCircuitBreaker sets up circuit breaker protection for the plugin.
//
// Circuit breaker configuration can be provided through the plugin config.
// If the config has default/empty values, production-ready defaults are used
// that balance reliability with responsiveness.
//
// This approach allows per-plugin circuit breaker customization while maintaining
// sensible defaults for plugins that don't specify custom settings.
func (m *Manager[Req, Resp]) initializeCircuitBreaker(pluginName string, cbConfig CircuitBreakerConfig) {
	// Use provided config, falling back to defaults for unspecified values
	config := m.normalizeCircuitBreakerConfig(cbConfig)
	m.breakers[pluginName] = NewCircuitBreaker(config)
}

// normalizeCircuitBreakerConfig applies defaults to circuit breaker configuration.
//
// This function ensures that circuit breaker configuration has sensible values
// even when the plugin config doesn't specify custom settings. The defaults
// are chosen for production reliability and responsiveness.
func (m *Manager[Req, Resp]) normalizeCircuitBreakerConfig(config CircuitBreakerConfig) CircuitBreakerConfig {
	// Apply defaults for unspecified values
	if !config.Enabled && config.FailureThreshold == 0 && config.RecoveryTimeout == 0 {
		// Config appears to be default/empty, use production defaults
		return CircuitBreakerConfig{
			Enabled:             true,
			FailureThreshold:    5,
			RecoveryTimeout:     30 * time.Second,
			MinRequestThreshold: 3,
			SuccessThreshold:    2,
		}
	}

	// Use provided config but ensure minimum values for safety
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.RecoveryTimeout <= 0 {
		config.RecoveryTimeout = 30 * time.Second
	}
	if config.MinRequestThreshold <= 0 {
		config.MinRequestThreshold = 3
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 2
	}

	return config
}

// initializeHealthComponents sets up health monitoring for the plugin.
//
// This function centralizes health monitoring initialization, making it
// easier to modify health check strategies or add new monitoring capabilities
// without affecting the main registration flow.
func (m *Manager[Req, Resp]) initializeHealthComponents(plugin Plugin[Req, Resp], pluginName string) {
	healthChecker := m.initializeHealthChecker(plugin)
	m.healthCheckers[pluginName] = healthChecker
	m.initializeHealthStatus(pluginName)
}

// Unregister implements PluginManager.Unregister.
// This method removes a plugin from the manager and performs complete cleanup
// of all associated resources including health checkers, circuit breakers, and metrics.
//
// The unregistration process:
//  1. Validates that the plugin exists
//  2. Stops health monitoring for the plugin
//  3. Cleans up circuit breaker and health status
//  4. Calls the plugin's Close() method for resource cleanup
//  5. Removes the plugin from the registry
//
// Note: This method does not wait for active requests to complete. For graceful
// removal that waits for request draining, use GracefulUnregister instead.
//
// Parameters:
//   - name: Name of the plugin to unregister
//
// Returns:
//   - Error if plugin not found or cleanup fails
//
// Example:
//
//	err := manager.Unregister("auth-service")
//	if err != nil {
//	    log.Printf("Failed to unregister plugin: %v", err)
//	}
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

// GetPlugin implements PluginManager.GetPlugin.
// This method retrieves a registered plugin by name, providing thread-safe access
// to plugin instances for direct method calls or inspection.
//
// Use cases:
//   - Direct plugin method invocation outside of the Execute framework
//   - Plugin introspection and debugging
//   - Custom plugin management scenarios
//   - Plugin health status checking
//
// Parameters:
//   - name: Name of the plugin to retrieve
//
// Returns:
//   - Plugin instance if found
//   - Error if plugin not found
//
// Example:
//
//	plugin, err := manager.GetPlugin("auth-service")
//	if err != nil {
//	    log.Printf("Plugin not found: %v", err)
//	    return
//	}
//	info := plugin.Info()
//	fmt.Printf("Plugin version: %s", info.Version)
func (m *Manager[Req, Resp]) GetPlugin(name string) (Plugin[Req, Resp], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return plugin, nil
}

// RegisterFactory registers a plugin factory for a specific plugin type.
// This method enables the manager to create plugin instances from configuration
// during LoadFromConfig operations. Each plugin type requires a corresponding factory.
//
// The factory is responsible for:
//   - Creating plugin instances from PluginConfig
//   - Validating plugin-specific configuration
//   - Handling transport-specific initialization
//   - Supporting the plugin lifecycle
//
// Common factory types:
//   - "subprocess": For executable-based plugins (recommended)
//   - "grpc": For gRPC-based plugins
//   - Custom types: For specialized plugin implementations
//
// Parameters:
//   - pluginType: Unique identifier for the plugin type (matches PluginConfig.Type)
//   - factory: Factory implementation that can create plugins of this type
//
// Returns:
//   - Error if a factory for this type is already registered
//
// Example:
//
//	subprocessFactory := NewSubprocessPluginFactory[MyReq, MyResp](logger)
//	err := manager.RegisterFactory("subprocess", subprocessFactory)
//	if err != nil {
//	    log.Printf("Failed to register factory: %v", err)
//	}
func (m *Manager[Req, Resp]) RegisterFactory(pluginType string, factory PluginFactory[Req, Resp]) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.factories[pluginType]; exists {
		return NewFactoryError(pluginType, "factory for plugin type already registered", nil)
	}

	m.factories[pluginType] = factory
	return nil
}

// GetFactory retrieves a plugin factory by type.
// This method provides access to registered factories for plugin creation,
// factory inspection, or custom plugin management scenarios.
//
// Use cases:
//   - Custom plugin creation outside of LoadFromConfig
//   - Factory capability inspection
//   - Dynamic factory selection
//   - Plugin system introspection
//
// Parameters:
//   - pluginType: Type identifier for the desired factory
//
// Returns:
//   - Factory instance if registered
//   - Error if no factory is registered for the specified type
//
// Example:
//
//	factory, err := manager.GetFactory("subprocess")
//	if err != nil {
//	    log.Printf("Factory not found: %v", err)
//	    return
//	}
//	supportedTransports := factory.SupportedTransports()
//	fmt.Printf("Supported transports: %v", supportedTransports)
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

// GracefulUnregister removes a plugin after draining all active requests.
// This method provides a safe way to remove plugins without interrupting ongoing
// operations, making it ideal for maintenance, updates, and graceful degradation scenarios.
//
// The graceful unregistration process:
//  1. Validates that the plugin exists
//  2. Initiates request draining with the specified timeout
//  3. Waits for all active requests to complete or timeout
//  4. Performs standard unregistration and cleanup
//
// Draining behavior:
//   - New requests to the plugin are rejected during draining
//   - Existing requests are allowed to complete naturally
//   - If timeout is reached, remaining requests may be cancelled
//   - Progress callbacks provide visibility into the draining process
//
// Parameters:
//   - pluginName: Name of the plugin to remove gracefully
//   - drainTimeout: Maximum time to wait for active requests to complete
//
// Returns:
//   - Error if plugin not found, draining fails, or cleanup fails
//
// Example:
//
//	// Allow up to 30 seconds for requests to complete
//	err := manager.GracefulUnregister("auth-service", 30*time.Second)
//	if err != nil {
//	    log.Printf("Graceful unregistration failed: %v", err)
//	}
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

// isValidSemanticVersion validates if a version string follows semantic versioning format
// Accepts formats like: 1.0.0, 2.1.3, 1.0.0-alpha, 1.0.0-beta.1
func isValidSemanticVersion(version string) bool {
	if version == "" {
		return false
	}

	// Basic semantic version regex pattern
	semverPattern := `^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`
	matched, err := regexp.MatchString(semverPattern, version)
	if err != nil {
		// If regex fails, assume invalid version
		return false
	}
	return matched
}

// containsMaliciousPattern checks for potentially dangerous patterns in plugin names
// This prevents path traversal, command injection, and other security issues
func containsMaliciousPattern(name string) bool {
	if name == "" {
		return false
	}

	// List of dangerous patterns
	maliciousPatterns := []string{
		"..", // Path traversal
		"/",  // Absolute paths
		"\\", // Windows paths
		"<",  // XML/HTML injection
		">",  // XML/HTML injection
		"|",  // Command injection
		"&",  // Command injection
		";",  // Command injection
		"`",  // Command injection
		"$",  // Variable expansion
		"*",  // Wildcards
		"?",  // Wildcards
		"\n", // Newlines
		"\r", // Carriage returns
		"\t", // Tabs
	}

	for _, pattern := range maliciousPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}

	return false
}
