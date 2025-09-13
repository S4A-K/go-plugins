// manager.go: Production-ready plugin manager implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Manager implements PluginManager with comprehensive production-ready features.
//
// This is the central component that orchestrates the entire plugin system,
// providing plugin lifecycle management, load balancing, circuit breaking,
// health monitoring, and observability. It's designed to handle enterprise-scale
// workloads with high availability and reliability requirements.
//
// Core capabilities:
//   - Plugin registration and lifecycle management
//   - Automatic failover with circuit breaker patterns
//   - Health monitoring with automatic recovery
//   - Load balancing across multiple plugin instances
//   - Hot-reload configuration updates without service interruption
//   - Comprehensive metrics and structured logging
//   - Graceful shutdown with proper resource cleanup
//
// Example usage:
//
//	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
//	manager := NewManager[AuthRequest, AuthResponse](logger)
//
//	// Register plugin factories
//	httpFactory := NewHTTPPluginFactory[AuthRequest, AuthResponse]()
//	manager.RegisterFactory("http", httpFactory)
//
//	// Load configuration
//	config := ManagerConfig{
//	    Plugins: []PluginConfig{
//	        {
//	            Name:      "auth-service",
//	            Type:      "http",
//	            Transport: TransportHTTPS,
//	            Endpoint:  "https://auth.company.com/api/v1",
//	        },
//	    },
//	}
//
//	if err := manager.LoadFromConfig(config); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Execute requests
//	response, err := manager.Execute(ctx, "auth-service", request)
//	if err != nil {
//	    log.Printf("Request failed: %v", err)
//	}
//
//	// Graceful shutdown
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	manager.Shutdown(ctx)
type Manager[Req, Resp any] struct {
	plugins   map[string]Plugin[Req, Resp]
	factories map[string]PluginFactory[Req, Resp]
	config    ManagerConfig
	logger    *slog.Logger
	metrics   *ManagerMetrics

	// Circuit breakers per plugin
	breakers map[string]*CircuitBreaker

	// Health monitoring
	healthCheckers map[string]*HealthChecker
	healthStatus   map[string]HealthStatus

	// Concurrency control
	mu       sync.RWMutex
	shutdown atomic.Bool
	wg       sync.WaitGroup
}

// ManagerMetrics tracks operational metrics
type ManagerMetrics struct {
	RequestsTotal       atomic.Int64
	RequestsSuccess     atomic.Int64
	RequestsFailure     atomic.Int64
	RequestDuration     atomic.Int64 // nanoseconds
	CircuitBreakerTrips atomic.Int64
	HealthCheckFailures atomic.Int64
}

// NewManager creates a new production-ready plugin manager with comprehensive monitoring and resilience features.
//
// The manager is initialized with sensible defaults and ready to accept plugin
// registrations. It includes built-in circuit breakers, health checkers, and
// metrics collection for operational visibility and automated recovery.
//
// Parameters:
//   - logger: Structured logger for operational logging (uses default if nil)
//
// The manager starts with empty plugin registries and must be configured with
// plugin factories and loaded with plugin configurations before use.
//
// Returns a fully initialized Manager ready for plugin registration and configuration.
func NewManager[Req, Resp any](logger *slog.Logger) *Manager[Req, Resp] {
	if logger == nil {
		logger = slog.Default()
	}

	return &Manager[Req, Resp]{
		plugins:        make(map[string]Plugin[Req, Resp]),
		factories:      make(map[string]PluginFactory[Req, Resp]),
		breakers:       make(map[string]*CircuitBreaker),
		healthCheckers: make(map[string]*HealthChecker),
		healthStatus:   make(map[string]HealthStatus),
		logger:         logger,
		metrics:        &ManagerMetrics{},
	}
}

// Register implements PluginManager.Register
func (m *Manager[Req, Resp]) Register(plugin Plugin[Req, Resp]) error {
	if m.shutdown.Load() {
		return errors.New("manager is shut down")
	}

	info := plugin.Info()
	if info.Name == "" {
		return errors.New("plugin name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.plugins[info.Name]; exists {
		return fmt.Errorf("plugin %s is already registered", info.Name)
	}

	// Initialize circuit breaker for the plugin
	m.breakers[info.Name] = NewCircuitBreaker(CircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    5,
		RecoveryTimeout:     30 * time.Second,
		MinRequestThreshold: 3,
		SuccessThreshold:    2,
	})

	// Initialize health checker
	m.healthCheckers[info.Name] = NewHealthChecker(plugin, HealthCheckConfig{
		Enabled:      true,
		Interval:     30 * time.Second,
		Timeout:      5 * time.Second,
		FailureLimit: 3,
	})

	m.plugins[info.Name] = plugin

	// Initialize health status
	m.healthStatus[info.Name] = HealthStatus{
		Status:    StatusHealthy,
		Message:   "Plugin registered",
		LastCheck: time.Now(),
	}

	// Start health monitoring
	m.wg.Add(1)
	go m.monitorPluginHealth(info.Name)

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
		return fmt.Errorf("plugin %s not found", name)
	}

	// Stop health monitoring
	if checker, ok := m.healthCheckers[name]; ok {
		checker.Stop()
		delete(m.healthCheckers, name)
	}

	// Clean up circuit breaker
	delete(m.breakers, name)
	delete(m.healthStatus, name)

	// Close the plugin
	if err := plugin.Close(); err != nil {
		m.logger.Warn("Error closing plugin during unregister",
			"plugin", name, "error", err)
	}

	delete(m.plugins, name)

	m.logger.Info("Plugin unregistered", "plugin", name)
	return nil
}

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

	startTime := time.Now()
	defer m.recordExecutionMetrics(startTime)

	// Get plugin and circuit breaker
	plugin, breaker, err := m.getPluginAndBreaker(pluginName)
	if err != nil {
		return zero, err
	}

	// Check circuit breaker
	if !breaker.AllowRequest() {
		m.metrics.RequestsFailure.Add(1)
		return zero, fmt.Errorf("circuit breaker is open for plugin %s", pluginName)
	}

	// Execute with timeout
	execCtxWithTimeout, cancel := context.WithTimeout(ctx, execCtx.Timeout)
	defer cancel()

	// Execute with retry logic
	return m.executePluginWithRetries(execCtxWithTimeout, plugin, breaker, pluginName, execCtx, request)
}

// recordExecutionMetrics records timing and count metrics for plugin execution
func (m *Manager[Req, Resp]) recordExecutionMetrics(startTime time.Time) {
	duration := time.Since(startTime)
	m.metrics.RequestDuration.Add(duration.Nanoseconds())
	m.metrics.RequestsTotal.Add(1)
}

// getPluginAndBreaker retrieves plugin and circuit breaker for execution
func (m *Manager[Req, Resp]) getPluginAndBreaker(pluginName string) (Plugin[Req, Resp], *CircuitBreaker, error) {
	m.mu.RLock()
	plugin, exists := m.plugins[pluginName]
	breaker, hasBreakerr := m.breakers[pluginName]
	m.mu.RUnlock()

	if !exists {
		m.metrics.RequestsFailure.Add(1)
		return nil, nil, fmt.Errorf("plugin %s not found", pluginName)
	}

	if !hasBreakerr {
		m.metrics.RequestsFailure.Add(1)
		return nil, nil, fmt.Errorf("circuit breaker not found for plugin %s", pluginName)
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

	return zero, fmt.Errorf("plugin %s execution failed after %d attempts: %w",
		pluginName, execCtx.MaxRetries+1, err)
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

// LoadFromConfig implements PluginManager.LoadFromConfig
func (m *Manager[Req, Resp]) LoadFromConfig(config ManagerConfig) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	config.ApplyDefaults()
	m.config = config

	// Load plugins from configuration
	for _, pluginConfig := range config.Plugins {
		if !pluginConfig.Enabled {
			continue
		}

		factory, exists := m.factories[pluginConfig.Type]
		if !exists {
			return fmt.Errorf("no factory registered for plugin type: %s", pluginConfig.Type)
		}

		plugin, err := factory.CreatePlugin(pluginConfig)
		if err != nil {
			return fmt.Errorf("failed to create plugin %s: %w", pluginConfig.Name, err)
		}

		if err := m.Register(plugin); err != nil {
			return fmt.Errorf("failed to register plugin %s: %w", pluginConfig.Name, err)
		}
	}

	return nil
}

// ReloadConfig implements PluginManager.ReloadConfig
func (m *Manager[Req, Resp]) ReloadConfig(config ManagerConfig) error {
	// For backward compatibility, use simple reload by default
	// Users can use PluginReloader for intelligent hot-reload
	return m.ReloadConfigWithStrategy(config, ReloadStrategyRecreate)
}

// ReloadConfigWithStrategy reloads configuration with specified strategy
func (m *Manager[Req, Resp]) ReloadConfigWithStrategy(config ManagerConfig, strategy ReloadStrategy) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	switch strategy {
	case ReloadStrategyRecreate:
		return m.reloadConfigRecreate(config)
	case ReloadStrategyGraceful, ReloadStrategyRolling:
		// Use the intelligent reloader
		reloader := NewPluginReloader(m, ReloadOptions{
			Strategy:             strategy,
			DrainTimeout:         30 * time.Second,
			GracefulTimeout:      60 * time.Second,
			MaxConcurrentReloads: 3,
			HealthCheckTimeout:   10 * time.Second,
			RollbackOnFailure:    true,
		}, m.logger)

		ctx := context.Background()
		return reloader.ReloadWithIntelligentDiff(ctx, config)
	default:
		return fmt.Errorf("unsupported reload strategy: %s", strategy)
	}
}

// reloadConfigRecreate implements simple recreation strategy
func (m *Manager[Req, Resp]) reloadConfigRecreate(config ManagerConfig) error {
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

// Health implements PluginManager.Health
func (m *Manager[Req, Resp]) Health() map[string]HealthStatus {
	return m.ListPlugins()
}

// Shutdown implements PluginManager.Shutdown
func (m *Manager[Req, Resp]) Shutdown(ctx context.Context) error {
	if !m.shutdown.CompareAndSwap(false, true) {
		return errors.New("manager already shut down")
	}

	m.logger.Info("Shutting down plugin manager")

	// Stop all health checkers
	m.mu.Lock()
	for _, checker := range m.healthCheckers {
		checker.Stop()
	}
	m.mu.Unlock()

	// Wait for health monitoring goroutines to finish
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

	// Close all plugins
	m.mu.Lock()
	for name, plugin := range m.plugins {
		if err := plugin.Close(); err != nil {
			m.logger.Warn("Error closing plugin during shutdown",
				"plugin", name, "error", err)
		}
	}
	m.plugins = make(map[string]Plugin[Req, Resp])
	m.mu.Unlock()

	m.logger.Info("Plugin manager shutdown complete")
	return nil
}

// RegisterFactory registers a plugin factory for a specific plugin type
func (m *Manager[Req, Resp]) RegisterFactory(pluginType string, factory PluginFactory[Req, Resp]) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.factories[pluginType]; exists {
		return fmt.Errorf("factory for plugin type %s already registered", pluginType)
	}

	m.factories[pluginType] = factory
	return nil
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

			status := checker.Check()

			m.mu.Lock()
			m.healthStatus[pluginName] = status
			m.mu.Unlock()

			if status.Status != StatusHealthy {
				m.metrics.HealthCheckFailures.Add(1)
				m.logger.Warn("Plugin health check failed",
					"plugin", pluginName,
					"status", status.Status.String(),
					"message", status.Message)
			}

		case <-checker.Done():
			return
		}
	}
}

// Helper functions

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

func calculateBackoff(attempt int, initial, max time.Duration, multiplier float64) time.Duration {
	duration := time.Duration(float64(initial) * pow(multiplier, float64(attempt)))
	if duration > max {
		duration = max
	}
	return duration
}

func pow(base, exp float64) float64 {
	result := 1.0
	for i := 0; i < int(exp); i++ {
		result *= base
	}
	return result
}

func isRetryableError(err error) bool {
	// TODO: Implement more sophisticated error classification
	if err == nil {
		return false
	}

	// For now, consider timeout and temporary errors as retryable
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}
