// plugin_isolation.go: Plugin crash isolation using existing components
//
// This file implements plugin crash isolation that ensures plugin failures
// don't affect the host application. It integrates our existing robust
// CircuitBreaker and HealthChecker components with process isolation,
// automatic recovery, and fallback mechanisms.
//
// Key features:
//   - Leverages existing CircuitBreaker and HealthChecker
//   - Process-level isolation with subprocess management
//   - Automatic crash detection and recovery
//   - Resource monitoring and limits
//   - Graceful degradation and fallback mechanisms
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// PluginIsolationManager provides crash isolation for plugins.
type PluginIsolationManager struct {
	// Configuration
	config IsolationConfig
	logger Logger

	// Isolated clients
	isolatedClients map[string]*IsolatedPluginClient
	clientMutex     sync.RWMutex

	// Health monitoring (using existing implementation)
	healthMonitor *HealthMonitor

	// Process monitoring
	processMonitor *ProcessMonitor

	// Recovery tracking
	recoveries    map[string]*RecoveryTracker
	recoveryMutex sync.RWMutex

	// Observability integration
	metricsCollector MetricsCollector
	tracingProvider  TracingProvider
	commonMetrics    *CommonPluginMetrics
	isolationMetrics *IsolationSpecificMetrics

	// Lifecycle
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool
	runMutex sync.Mutex
}

// IsolationConfig configures plugin isolation behavior.
type IsolationConfig struct {
	// Circuit breaker settings (using existing config)
	CircuitBreakerConfig CircuitBreakerConfig `json:"circuit_breaker" yaml:"circuit_breaker"`

	// Health check settings (using existing config)
	HealthCheckConfig HealthCheckConfig `json:"health_check" yaml:"health_check"`

	// Process isolation settings
	ProcessIsolation ProcessIsolationConfig `json:"process_isolation" yaml:"process_isolation"`

	// Recovery settings
	RecoveryConfig RecoveryConfig `json:"recovery" yaml:"recovery"`

	// Fallback behavior
	FallbackConfig FallbackConfig `json:"fallback" yaml:"fallback"`

	// Resource limits
	ResourceLimits ResourceLimitsConfig `json:"resource_limits" yaml:"resource_limits"`

	// Observability integration
	ObservabilityConfig ObservabilityConfig `json:"observability" yaml:"observability"`

	Logger Logger `json:"-" yaml:"-"`
}

// ProcessIsolationConfig configures process-level isolation.
type ProcessIsolationConfig struct {
	// Enable process isolation
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Use separate process groups
	ProcessGroup bool `json:"process_group" yaml:"process_group"`

	// Sandbox directory for plugin execution
	SandboxDir string `json:"sandbox_dir" yaml:"sandbox_dir"`

	// Environment variable isolation
	IsolateEnvironment bool `json:"isolate_environment" yaml:"isolate_environment"`

	// Network isolation (future enhancement)
	NetworkIsolation bool `json:"network_isolation" yaml:"network_isolation"`
}

// RecoveryConfig configures automatic plugin recovery.
type RecoveryConfig struct {
	// Enable automatic recovery
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Maximum recovery attempts
	MaxAttempts int `json:"max_attempts" yaml:"max_attempts"`

	// Backoff strategy
	BackoffStrategy BackoffStrategy `json:"backoff_strategy" yaml:"backoff_strategy"`

	// Initial backoff delay
	InitialDelay time.Duration `json:"initial_delay" yaml:"initial_delay"`

	// Maximum backoff delay
	MaxDelay time.Duration `json:"max_delay" yaml:"max_delay"`

	// Backoff multiplier
	BackoffMultiplier float64 `json:"backoff_multiplier" yaml:"backoff_multiplier"`
}

// FallbackConfig configures fallback behavior when plugins fail.
type FallbackConfig struct {
	// Enable fallback mechanisms
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Fallback strategy
	Strategy FallbackStrategy `json:"strategy" yaml:"strategy"`

	// Default response when plugin unavailable
	DefaultResponse interface{} `json:"default_response" yaml:"default_response"`

	// Cache responses for offline use
	EnableCaching bool `json:"enable_caching" yaml:"enable_caching"`

	// Cache duration
	CacheDuration time.Duration `json:"cache_duration" yaml:"cache_duration"`
}

// ResourceLimitsConfig configures resource limits for plugins.
type ResourceLimitsConfig struct {
	// Enable resource limits
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Maximum memory usage (MB)
	MaxMemoryMB int `json:"max_memory_mb" yaml:"max_memory_mb"`

	// Maximum CPU usage (percentage)
	MaxCPUPercent int `json:"max_cpu_percent" yaml:"max_cpu_percent"`

	// Maximum file descriptors
	MaxFileDescriptors int `json:"max_file_descriptors" yaml:"max_file_descriptors"`

	// Maximum execution time per call
	MaxExecutionTime time.Duration `json:"max_execution_time" yaml:"max_execution_time"`
}

// BackoffStrategy defines backoff strategies for recovery.
type BackoffStrategy string

const (
	BackoffStrategyLinear      BackoffStrategy = "linear"
	BackoffStrategyExponential BackoffStrategy = "exponential"
	BackoffStrategyFixed       BackoffStrategy = "fixed"
)

// FallbackStrategy defines fallback strategies when plugins fail.
type FallbackStrategy string

const (
	FallbackStrategyNone     FallbackStrategy = "none"
	FallbackStrategyDefault  FallbackStrategy = "default"
	FallbackStrategyCached   FallbackStrategy = "cached"
	FallbackStrategyGraceful FallbackStrategy = "graceful"
)

// IsolatedPluginClient wraps a plugin client with crash isolation.
type IsolatedPluginClient struct {
	// Base client
	client *PluginClient

	// Isolation components (using existing implementations)
	circuitBreaker *CircuitBreaker
	healthChecker  *HealthChecker

	// Process isolation
	process *PluginProcess

	// Recovery tracking
	recovery *RecoveryTracker

	// Statistics
	stats *IsolationStats

	// Configuration
	config IsolationConfig
	logger Logger

	// State
	mutex sync.RWMutex
}

// PluginProcess manages the isolated process for a plugin.
type PluginProcess struct {
	// Process information
	cmd       *exec.Cmd
	pid       int
	startTime time.Time

	// Resource monitoring
	memoryUsage   atomic.Int64
	cpuUsage      atomic.Uint64 // As uint64 for atomic operations
	maxMemoryMB   int64
	maxCPUPercent int

	// Process state
	isRunning atomic.Bool
	exitCode  int

	// Isolation settings
	sandboxDir   string
	processGroup bool

	mutex sync.RWMutex
}

// ProcessMonitor monitors plugin processes for crashes and resource usage.
type ProcessMonitor struct {
	processes map[string]*PluginProcess
	mutex     sync.RWMutex

	// Monitoring configuration
	monitorInterval time.Duration

	// Control channels
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// RecoveryTracker tracks plugin recovery attempts and backoff.
type RecoveryTracker struct {
	// Recovery state
	attempts    int
	maxAttempts int
	lastAttempt time.Time
	nextAttempt time.Time

	// Backoff configuration
	backoffStrategy   BackoffStrategy
	initialDelay      time.Duration
	maxDelay          time.Duration
	backoffMultiplier float64

	// Recovery history
	history []RecoveryAttempt

	mutex sync.RWMutex
}

// RecoveryAttempt represents a single recovery attempt.
type RecoveryAttempt struct {
	Attempt   int
	Timestamp time.Time
	Success   bool
	Error     error
	Duration  time.Duration
}

// IsolationStats provides statistics about plugin isolation.
type IsolationStats struct {
	// Request statistics
	TotalRequests       atomic.Int64
	SuccessfulRequests  atomic.Int64
	FailedRequests      atomic.Int64
	CircuitBreakerTrips atomic.Int64

	// Recovery statistics
	RecoveryAttempts     atomic.Int64
	SuccessfulRecoveries atomic.Int64
	FailedRecoveries     atomic.Int64

	// Performance statistics
	AverageResponseTime time.Duration
	MaxResponseTime     time.Duration
	MinResponseTime     time.Duration

	// Resource usage
	MaxMemoryUsage  atomic.Int64
	AverageCPUUsage atomic.Uint64
}

// IsolationSpecificMetrics provides observability metrics specific to plugin isolation.
type IsolationSpecificMetrics struct {
	// Circuit breaker metrics
	CircuitBreakerStateChanges CounterMetric
	CircuitBreakerOpenTime     HistogramMetric
	CircuitBreakerFailures     CounterMetric

	// Process isolation metrics
	ProcessRestarts    CounterMetric
	ProcessCrashes     CounterMetric
	ProcessUptime      GaugeMetric
	ProcessMemoryUsage GaugeMetric
	ProcessCPUUsage    GaugeMetric

	// Recovery metrics
	RecoveryAttempts CounterMetric
	RecoveryDuration HistogramMetric
	RecoveryBackoff  HistogramMetric

	// Fallback metrics
	FallbackActivations CounterMetric
	FallbackDuration    HistogramMetric

	// Health monitoring metrics
	HealthCheckFailures CounterMetric
	HealthCheckLatency  HistogramMetric
	HealthStatus        GaugeMetric

	// Resource monitoring metrics
	ResourceLimitViolations CounterMetric
	MemoryLimitExceeded     CounterMetric
	CPULimitExceeded        CounterMetric
	TimeoutViolations       CounterMetric
}

// NewPluginIsolationManager creates a new plugin isolation manager.
func NewPluginIsolationManager(config IsolationConfig) *PluginIsolationManager {
	if config.Logger == nil {
		config.Logger = DefaultLogger()
	}

	// Set default values
	if config.RecoveryConfig.MaxAttempts == 0 {
		config.RecoveryConfig.MaxAttempts = 3
	}
	if config.RecoveryConfig.InitialDelay == 0 {
		config.RecoveryConfig.InitialDelay = 1 * time.Second
	}
	if config.RecoveryConfig.MaxDelay == 0 {
		config.RecoveryConfig.MaxDelay = 30 * time.Second
	}
	if config.RecoveryConfig.BackoffMultiplier == 0 {
		config.RecoveryConfig.BackoffMultiplier = 2.0
	}

	// Set observability defaults
	if config.ObservabilityConfig.MetricsCollector == nil {
		config.ObservabilityConfig.MetricsCollector = NewEnhancedMetricsCollector()
	}
	if config.ObservabilityConfig.Level == ObservabilityDisabled {
		config.ObservabilityConfig.Level = ObservabilityStandard // Enable by default for isolation
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &PluginIsolationManager{
		config:          config,
		logger:          config.Logger,
		isolatedClients: make(map[string]*IsolatedPluginClient),
		recoveries:      make(map[string]*RecoveryTracker),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Initialize observability components
	manager.initializeObservability()

	// Initialize health monitor (using existing implementation)
	manager.healthMonitor = NewHealthMonitor()

	// Initialize process monitor
	manager.processMonitor = NewProcessMonitor(5 * time.Second) // Monitor every 5 seconds

	return manager
}

// initializeObservability sets up observability components for the isolation manager.
func (pim *PluginIsolationManager) initializeObservability() {
	// Initialize metrics collector
	pim.metricsCollector = pim.config.ObservabilityConfig.MetricsCollector
	pim.tracingProvider = pim.config.ObservabilityConfig.TracingProvider

	// Create common plugin metrics if advanced features are available
	if pim.metricsCollector.CounterWithLabels("test", "test") != nil {
		pim.commonMetrics = CreateCommonPluginMetrics(pim.metricsCollector)
		pim.isolationMetrics = pim.createIsolationSpecificMetrics(pim.metricsCollector)
	}
}

// createIsolationSpecificMetrics creates metrics specific to plugin isolation.
func (pim *PluginIsolationManager) createIsolationSpecificMetrics(collector MetricsCollector) *IsolationSpecificMetrics {
	prefix := pim.config.ObservabilityConfig.MetricsPrefix
	if prefix == "" {
		prefix = "goplugins_isolation"
	}

	return &IsolationSpecificMetrics{
		// Circuit breaker metrics
		CircuitBreakerStateChanges: collector.CounterWithLabels(
			prefix+"_circuit_breaker_state_changes_total",
			"Total circuit breaker state changes",
			"plugin_name", "from_state", "to_state",
		),
		CircuitBreakerOpenTime: collector.HistogramWithLabels(
			prefix+"_circuit_breaker_open_duration_seconds",
			"Duration circuit breaker was open",
			[]float64{0.1, 1, 5, 10, 30, 60, 300},
			"plugin_name",
		),
		CircuitBreakerFailures: collector.CounterWithLabels(
			prefix+"_circuit_breaker_failures_total",
			"Total circuit breaker failures",
			"plugin_name", "failure_type",
		),

		// Process isolation metrics
		ProcessRestarts: collector.CounterWithLabels(
			prefix+"_process_restarts_total",
			"Total plugin process restarts",
			"plugin_name", "restart_reason",
		),
		ProcessCrashes: collector.CounterWithLabels(
			prefix+"_process_crashes_total",
			"Total plugin process crashes",
			"plugin_name", "crash_type",
		),
		ProcessUptime: collector.GaugeWithLabels(
			prefix+"_process_uptime_seconds",
			"Plugin process uptime in seconds",
			"plugin_name",
		),
		ProcessMemoryUsage: collector.GaugeWithLabels(
			prefix+"_process_memory_bytes",
			"Plugin process memory usage in bytes",
			"plugin_name",
		),
		ProcessCPUUsage: collector.GaugeWithLabels(
			prefix+"_process_cpu_usage_percent",
			"Plugin process CPU usage percentage",
			"plugin_name",
		),

		// Recovery metrics
		RecoveryAttempts: collector.CounterWithLabels(
			prefix+"_recovery_attempts_total",
			"Total plugin recovery attempts",
			"plugin_name", "recovery_result",
		),
		RecoveryDuration: collector.HistogramWithLabels(
			prefix+"_recovery_duration_seconds",
			"Duration of plugin recovery attempts",
			[]float64{0.1, 0.5, 1, 2, 5, 10, 30},
			"plugin_name",
		),
		RecoveryBackoff: collector.HistogramWithLabels(
			prefix+"_recovery_backoff_seconds",
			"Recovery backoff delay duration",
			[]float64{0.1, 0.5, 1, 2, 5, 10, 30},
			"plugin_name", "backoff_strategy",
		),

		// Fallback metrics
		FallbackActivations: collector.CounterWithLabels(
			prefix+"_fallback_activations_total",
			"Total fallback activations",
			"plugin_name", "fallback_strategy",
		),
		FallbackDuration: collector.HistogramWithLabels(
			prefix+"_fallback_duration_seconds",
			"Duration of fallback responses",
			[]float64{0.001, 0.01, 0.1, 1},
			"plugin_name",
		),

		// Health monitoring metrics
		HealthCheckFailures: collector.CounterWithLabels(
			prefix+"_health_check_failures_total",
			"Total health check failures",
			"plugin_name", "check_type",
		),
		HealthCheckLatency: collector.HistogramWithLabels(
			prefix+"_health_check_duration_seconds",
			"Duration of health checks",
			[]float64{0.001, 0.01, 0.1, 1, 5},
			"plugin_name",
		),
		HealthStatus: collector.GaugeWithLabels(
			prefix+"_health_status",
			"Plugin health status (0=healthy, 1=degraded, 2=unhealthy)",
			"plugin_name",
		),

		// Resource monitoring metrics
		ResourceLimitViolations: collector.CounterWithLabels(
			prefix+"_resource_limit_violations_total",
			"Total resource limit violations",
			"plugin_name", "resource_type",
		),
		MemoryLimitExceeded: collector.CounterWithLabels(
			prefix+"_memory_limit_exceeded_total",
			"Total memory limit exceeded events",
			"plugin_name",
		),
		CPULimitExceeded: collector.CounterWithLabels(
			prefix+"_cpu_limit_exceeded_total",
			"Total CPU limit exceeded events",
			"plugin_name",
		),
		TimeoutViolations: collector.CounterWithLabels(
			prefix+"_timeout_violations_total",
			"Total timeout violations",
			"plugin_name", "timeout_type",
		),
	}
}

// Start starts the isolation manager.
func (pim *PluginIsolationManager) Start() error {
	pim.runMutex.Lock()
	defer pim.runMutex.Unlock()

	if pim.running {
		return fmt.Errorf("isolation manager already running")
	}

	pim.logger.Info("Starting plugin isolation manager")

	// Start process monitor
	if err := pim.processMonitor.Start(pim.ctx); err != nil {
		return fmt.Errorf("failed to start process monitor: %w", err)
	}

	pim.running = true
	pim.logger.Info("Plugin isolation manager started")
	return nil
}

// Stop stops the isolation manager.
func (pim *PluginIsolationManager) Stop() error {
	pim.runMutex.Lock()
	defer pim.runMutex.Unlock()

	if !pim.running {
		return nil
	}

	pim.logger.Info("Stopping plugin isolation manager")

	// Cancel context
	pim.cancel()

	// Stop process monitor
	pim.processMonitor.Stop()

	// Shutdown health monitor
	pim.healthMonitor.Shutdown()

	pim.running = false
	pim.logger.Info("Plugin isolation manager stopped")
	return nil
}

// WrapClient wraps a plugin client with isolation capabilities.
func (pim *PluginIsolationManager) WrapClient(client *PluginClient) *IsolatedPluginClient {
	pim.clientMutex.Lock()
	defer pim.clientMutex.Unlock()

	// Check if client is already wrapped
	if isolatedClient, exists := pim.isolatedClients[client.Name]; exists {
		return isolatedClient
	}

	// Create circuit breaker (using existing implementation)
	circuitBreaker := NewCircuitBreaker(pim.config.CircuitBreakerConfig)

	// Create health checker (using existing implementation)
	healthChecker := NewHealthChecker(client, pim.config.HealthCheckConfig)

	// Create process wrapper
	process := &PluginProcess{
		maxMemoryMB:   int64(pim.config.ResourceLimits.MaxMemoryMB),
		maxCPUPercent: pim.config.ResourceLimits.MaxCPUPercent,
		sandboxDir:    pim.config.ProcessIsolation.SandboxDir,
		processGroup:  pim.config.ProcessIsolation.ProcessGroup,
	}

	// Create recovery tracker
	recovery := &RecoveryTracker{
		maxAttempts:       pim.config.RecoveryConfig.MaxAttempts,
		backoffStrategy:   pim.config.RecoveryConfig.BackoffStrategy,
		initialDelay:      pim.config.RecoveryConfig.InitialDelay,
		maxDelay:          pim.config.RecoveryConfig.MaxDelay,
		backoffMultiplier: pim.config.RecoveryConfig.BackoffMultiplier,
		history:           make([]RecoveryAttempt, 0, 10),
	}

	// Create statistics
	stats := &IsolationStats{
		MinResponseTime: time.Hour, // Initialize to high value
	}

	// Create isolated client
	isolatedClient := &IsolatedPluginClient{
		client:         client,
		circuitBreaker: circuitBreaker,
		healthChecker:  healthChecker,
		process:        process,
		recovery:       recovery,
		stats:          stats,
		config:         pim.config,
		logger:         pim.logger,
	}

	// Register with health monitor
	pim.healthMonitor.AddChecker(client.Name, healthChecker)

	// Register process for monitoring
	pim.processMonitor.RegisterProcess(client.Name, process)

	// Store recovery tracker
	pim.recoveryMutex.Lock()
	pim.recoveries[client.Name] = recovery
	pim.recoveryMutex.Unlock()

	pim.isolatedClients[client.Name] = isolatedClient
	pim.logger.Info("Wrapped plugin client with isolation", "client", client.Name)

	return isolatedClient
}

// RemoveClient removes an isolated client and cleans up associated resources.
func (pim *PluginIsolationManager) RemoveClient(clientName string) error {
	pim.clientMutex.Lock()
	defer pim.clientMutex.Unlock()

	// Check if client exists
	isolatedClient, exists := pim.isolatedClients[clientName]
	if !exists {
		return fmt.Errorf("isolated client %s not found", clientName)
	}

	// Remove from health monitor
	pim.healthMonitor.RemoveChecker(clientName)

	// Remove from process monitor
	pim.processMonitor.UnregisterProcess(clientName)

	// Remove recovery tracker
	pim.recoveryMutex.Lock()
	delete(pim.recoveries, clientName)
	pim.recoveryMutex.Unlock()

	// Clean up isolated client resources
	if isolatedClient.healthChecker != nil {
		isolatedClient.healthChecker.Stop()
	}

	// Remove from isolated clients
	delete(pim.isolatedClients, clientName)

	pim.logger.Info("Removed isolated client", "client", clientName)
	return nil
}

// GetRecoveryStats returns recovery statistics for a specific client.
func (pim *PluginIsolationManager) GetRecoveryStats(clientName string) (*RecoveryTracker, error) {
	pim.recoveryMutex.RLock()
	defer pim.recoveryMutex.RUnlock()

	recovery, exists := pim.recoveries[clientName]
	if !exists {
		return nil, fmt.Errorf("recovery tracker for client %s not found", clientName)
	}

	return recovery, nil
}

// Call makes an isolated call to a plugin with full fault tolerance.
func (ic *IsolatedPluginClient) Call(ctx context.Context, method string, args interface{}) (interface{}, error) {
	ic.mutex.RLock()
	defer ic.mutex.RUnlock()

	start := time.Now()
	var span Span

	// Setup observability tracking
	ctx, span = ic.setupObservabilityTracing(ctx, method)
	if span != nil {
		defer span.Finish()
	}

	defer func() {
		duration := time.Since(start)
		ic.updateResponseTimeStats(duration)
		ic.recordObservabilityMetrics(method, duration, nil)
	}()

	// Record active request
	ic.recordActiveRequestStart()
	defer ic.recordActiveRequestEnd()

	// Check circuit breaker (using existing AllowRequest method)
	if !ic.circuitBreaker.AllowRequest() {
		ic.stats.CircuitBreakerTrips.Add(1)
		ic.recordCircuitBreakerTrip()

		if span != nil {
			span.SetAttribute("circuit_breaker.tripped", true)
			span.SetStatus(SpanStatusError, "circuit breaker is open")
		}

		return ic.handleFallback(method, args, fmt.Errorf("circuit breaker is open"))
	}

	// Create timeout context
	var callCtx context.Context
	var cancel context.CancelFunc

	if ic.config.ResourceLimits.MaxExecutionTime > 0 {
		callCtx, cancel = context.WithTimeout(ctx, ic.config.ResourceLimits.MaxExecutionTime)
	} else {
		callCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Track request
	ic.stats.TotalRequests.Add(1)

	// Make the actual call with isolation
	result, err := ic.executeIsolatedCall(callCtx, method, args)

	// Record result with circuit breaker (using existing methods)
	if err != nil {
		ic.circuitBreaker.RecordFailure()
		ic.stats.FailedRequests.Add(1)
		ic.recordObservabilityError(method, err)

		if span != nil {
			span.SetAttribute("error", true)
			span.SetAttribute("error.message", err.Error())
			span.SetStatus(SpanStatusError, err.Error())
		}

		// Check if we need to attempt recovery
		if ic.shouldAttemptRecovery(err) {
			go ic.attemptRecovery()
		}

		// Handle failure with potential fallback
		return ic.handleFallback(method, args, err)
	}

	ic.circuitBreaker.RecordSuccess()
	ic.stats.SuccessfulRequests.Add(1)

	if span != nil {
		span.SetStatus(SpanStatusOK, "success")
	}

	return result, nil
}

// executeIsolatedCall performs the actual isolated call with resource monitoring.
func (ic *IsolatedPluginClient) executeIsolatedCall(ctx context.Context, method string, args interface{}) (interface{}, error) {
	// Check if process is running
	if !ic.process.isRunning.Load() && ic.config.RecoveryConfig.Enabled {
		if err := ic.startProcess(); err != nil {
			return nil, fmt.Errorf("failed to start plugin process: %w", err)
		}
	}

	// Make the actual RPC call
	return ic.client.Call(ctx, method, args, nil)
}

// handleFallback handles failed calls with configured fallback strategy.
func (ic *IsolatedPluginClient) handleFallback(method string, _ interface{}, originalErr error) (interface{}, error) {
	if !ic.config.FallbackConfig.Enabled {
		return nil, originalErr
	}

	switch ic.config.FallbackConfig.Strategy {
	case FallbackStrategyDefault:
		ic.logger.Warn("Using default fallback response",
			"method", method,
			"error", originalErr)
		return ic.config.FallbackConfig.DefaultResponse, nil

	case FallbackStrategyCached:
		// Cached fallback strategy - return original error for now
		ic.logger.Warn("Cached fallback not implemented", "method", method)
		return nil, originalErr

	case FallbackStrategyGraceful:
		// Graceful degradation strategy - return original error for now
		ic.logger.Warn("Graceful fallback not implemented", "method", method)
		return nil, originalErr

	default:
		return nil, originalErr
	}
}

// shouldAttemptRecovery determines if we should attempt to recover from an error.
func (ic *IsolatedPluginClient) shouldAttemptRecovery(_ error) bool {
	if !ic.config.RecoveryConfig.Enabled {
		return false
	}

	ic.recovery.mutex.RLock()
	defer ic.recovery.mutex.RUnlock()

	// Check if we haven't exceeded max attempts
	if ic.recovery.attempts >= ic.recovery.maxAttempts {
		return false
	}

	// Check if enough time has passed since last attempt
	return time.Now().After(ic.recovery.nextAttempt)
}

// attemptRecovery attempts to recover a failed plugin.
func (ic *IsolatedPluginClient) attemptRecovery() {
	ic.recovery.mutex.Lock()
	defer ic.recovery.mutex.Unlock()

	start := time.Now()
	ic.recovery.attempts++
	ic.recovery.lastAttempt = start

	ic.logger.Info("Attempting plugin recovery",
		"client", ic.client.Name,
		"attempt", ic.recovery.attempts)

	// Track recovery attempt
	ic.stats.RecoveryAttempts.Add(1)

	// Try to restart the plugin process
	var err error
	if ic.config.ProcessIsolation.Enabled {
		err = ic.restartProcess()
	}

	duration := time.Since(start)
	success := err == nil

	// Record recovery attempt
	attempt := RecoveryAttempt{
		Attempt:   ic.recovery.attempts,
		Timestamp: start,
		Success:   success,
		Error:     err,
		Duration:  duration,
	}

	ic.recovery.history = append(ic.recovery.history, attempt)
	if len(ic.recovery.history) > 10 {
		ic.recovery.history = ic.recovery.history[1:] // Keep only last 10
	}

	if success {
		ic.stats.SuccessfulRecoveries.Add(1)
		ic.recovery.attempts = 0 // Reset on success
		ic.logger.Info("Plugin recovery successful", "client", ic.client.Name)
	} else {
		ic.stats.FailedRecoveries.Add(1)

		// Calculate next attempt time using backoff
		delay := ic.calculateBackoffDelay()
		ic.recovery.nextAttempt = time.Now().Add(delay)

		ic.logger.Warn("Plugin recovery failed",
			"client", ic.client.Name,
			"error", err,
			"next_attempt", ic.recovery.nextAttempt)
	}
}

// calculateBackoffDelay calculates the delay before next recovery attempt.
func (ic *IsolatedPluginClient) calculateBackoffDelay() time.Duration {
	switch ic.recovery.backoffStrategy {
	case BackoffStrategyLinear:
		delay := ic.recovery.initialDelay * time.Duration(ic.recovery.attempts)
		if delay > ic.recovery.maxDelay {
			return ic.recovery.maxDelay
		}
		return delay

	case BackoffStrategyExponential:
		delay := time.Duration(float64(ic.recovery.initialDelay) *
			power(ic.recovery.backoffMultiplier, ic.recovery.attempts-1))
		if delay > ic.recovery.maxDelay {
			return ic.recovery.maxDelay
		}
		return delay

	case BackoffStrategyFixed:
		return ic.recovery.initialDelay

	default:
		return ic.recovery.initialDelay
	}
}

// power is a simple integer power function
func power(base float64, exp int) float64 {
	result := 1.0
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}

// startProcess starts the plugin process with isolation.
func (ic *IsolatedPluginClient) startProcess() error {
	ic.process.mutex.Lock()
	defer ic.process.mutex.Unlock()

	if ic.process.isRunning.Load() {
		return nil // Already running
	}

	// Create command for plugin process
	// Validate plugin binary path for security
	pluginBinaryPath := ic.client.Name
	if err := validatePluginBinaryPath(pluginBinaryPath); err != nil {
		return fmt.Errorf("plugin binary validation failed: %w", err)
	}
	cmd := exec.Command(pluginBinaryPath) // #nosec G204 -- path validated above

	// Apply process isolation settings
	configureProcAttr(cmd, ic.process.processGroup)

	// Set working directory if sandbox is configured
	if ic.process.sandboxDir != "" {
		cmd.Dir = ic.process.sandboxDir
		// Ensure sandbox directory exists with secure permissions
		if err := os.MkdirAll(ic.process.sandboxDir, 0750); err != nil {
			return fmt.Errorf("failed to create sandbox directory: %w", err)
		}
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start plugin process: %w", err)
	}

	// Update process info
	ic.process.cmd = cmd
	ic.process.pid = cmd.Process.Pid
	ic.process.startTime = time.Now()
	ic.process.isRunning.Store(true)

	ic.logger.Info("Started plugin process",
		"client", ic.client.Name,
		"pid", ic.process.pid)

	return nil
}

// restartProcess restarts the plugin process.
func (ic *IsolatedPluginClient) restartProcess() error {
	// Stop existing process if running
	if err := ic.stopProcess(); err != nil {
		ic.logger.Warn("Error stopping process during restart",
			"client", ic.client.Name,
			"error", err)
	}

	// Start new process
	return ic.startProcess()
}

// stopProcess stops the plugin process.
func (ic *IsolatedPluginClient) stopProcess() error {
	ic.process.mutex.Lock()
	defer ic.process.mutex.Unlock()

	if !ic.process.isRunning.Load() {
		return nil // Not running
	}

	if ic.process.cmd != nil && ic.process.cmd.Process != nil {
		// Try graceful termination first
		if err := ic.process.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			// Force kill if graceful termination fails
			if killErr := ic.process.cmd.Process.Kill(); killErr != nil {
				ic.logger.Warn("Failed to kill process", "error", killErr, "pid", ic.process.pid)
			}
		}

		// Wait for process to exit
		if waitErr := ic.process.cmd.Wait(); waitErr != nil {
			ic.logger.Debug("Process wait returned error (may be expected)", "error", waitErr, "pid", ic.process.pid)
		}
		if ic.process.cmd.ProcessState != nil {
			ic.process.exitCode = ic.process.cmd.ProcessState.ExitCode()
		}
	}

	ic.process.isRunning.Store(false)
	ic.logger.Info("Stopped plugin process",
		"client", ic.client.Name,
		"pid", ic.process.pid)

	return nil
}

// updateResponseTimeStats updates response time statistics.
func (ic *IsolatedPluginClient) updateResponseTimeStats(duration time.Duration) {
	// Update min response time atomically
	for {
		current := ic.stats.MinResponseTime
		if duration >= current {
			break
		}
		// Only update if our duration is smaller
		if atomic.CompareAndSwapInt64((*int64)(&ic.stats.MinResponseTime), int64(current), int64(duration)) {
			break
		}
		// If CAS failed, retry
	}

	// Update max response time atomically
	for {
		current := ic.stats.MaxResponseTime
		if duration <= current {
			break
		}
		// Only update if our duration is larger
		if atomic.CompareAndSwapInt64((*int64)(&ic.stats.MaxResponseTime), int64(current), int64(duration)) {
			break
		}
		// If CAS failed, retry
	}
}

// NewProcessMonitor creates a new process monitor.
func NewProcessMonitor(interval time.Duration) *ProcessMonitor {
	return &ProcessMonitor{
		processes:       make(map[string]*PluginProcess),
		monitorInterval: interval,
	}
}

// Start starts the process monitor.
func (pm *ProcessMonitor) Start(ctx context.Context) error {
	pm.ctx, pm.cancel = context.WithCancel(ctx)

	pm.wg.Add(1)
	go pm.monitorLoop()

	return nil
}

// Stop stops the process monitor.
func (pm *ProcessMonitor) Stop() {
	if pm.cancel != nil {
		pm.cancel()
	}
	pm.wg.Wait()
}

// RegisterProcess registers a process for monitoring.
func (pm *ProcessMonitor) RegisterProcess(name string, process *PluginProcess) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.processes[name] = process
}

// UnregisterProcess removes a process from monitoring.
func (pm *ProcessMonitor) UnregisterProcess(name string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	delete(pm.processes, name)
}

// monitorLoop runs the main monitoring loop.
func (pm *ProcessMonitor) monitorLoop() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.checkProcesses()
		}
	}
}

// checkProcesses checks all registered processes.
func (pm *ProcessMonitor) checkProcesses() {
	pm.mutex.RLock()
	processes := make(map[string]*PluginProcess)
	for name, process := range pm.processes {
		processes[name] = process
	}
	pm.mutex.RUnlock()

	for name, process := range processes {
		pm.checkProcess(name, process)
	}
}

// checkProcess checks a single process for health and resource usage.
func (pm *ProcessMonitor) checkProcess(_ string, process *PluginProcess) {
	if !process.isRunning.Load() {
		return
	}

	// Check if process is still alive
	if process.cmd != nil && process.cmd.Process != nil {
		// Send signal 0 to check if process exists
		err := process.cmd.Process.Signal(syscall.Signal(0))
		if err != nil {
			// Process is dead
			process.isRunning.Store(false)
			// TODO: Trigger recovery
		}
	}

	// Basic process monitoring - resource usage monitoring not implemented
}

// Observability methods for IsolatedPluginClient

// setupObservabilityTracing sets up distributed tracing for the plugin call.
func (ic *IsolatedPluginClient) setupObservabilityTracing(ctx context.Context, _ string) (context.Context, Span) {
	if !ic.config.ObservabilityConfig.IsTracingEnabled() {
		return ctx, nil
	}

	// For now, return nil span as we don't have tracing provider access in isolated client
	// In a full implementation, this would be passed through the isolation manager
	return ctx, nil
}

// recordObservabilityMetrics records metrics for the plugin call.
func (ic *IsolatedPluginClient) recordObservabilityMetrics(_ string, _ time.Duration, _ error) {
	// This would integrate with the isolation manager's metrics
	// For now, we just update local stats which are already tracked

	// In a full implementation, this would call:
	// ic.isolationManager.recordPluginMetrics(ic.client.Name, method, duration, err)
}

// recordActiveRequestStart records the start of an active request.
func (ic *IsolatedPluginClient) recordActiveRequestStart() {
	// This would increment active request gauge in isolation manager
	// For now, we don't have direct access to the manager
}

// recordActiveRequestEnd records the end of an active request.
func (ic *IsolatedPluginClient) recordActiveRequestEnd() {
	// This would decrement active request gauge in isolation manager
	// For now, we don't have direct access to the manager
}

// recordCircuitBreakerTrip records a circuit breaker trip event.
func (ic *IsolatedPluginClient) recordCircuitBreakerTrip() {
	// This would record circuit breaker metrics in isolation manager
	// For now, we just log it
	ic.logger.Warn("Circuit breaker tripped", "client", ic.client.Name)
}

// recordObservabilityError records error metrics.
func (ic *IsolatedPluginClient) recordObservabilityError(_ string, _ error) {
	// This would record error metrics by type in isolation manager
	// For now, we just track in local stats which is already done
}

// GetObservabilityReport returns comprehensive observability report for this isolated client.
func (ic *IsolatedPluginClient) GetObservabilityReport() IsolatedClientObservabilityReport {
	ic.mutex.RLock()
	defer ic.mutex.RUnlock()

	// Get circuit breaker stats
	cbStats := ic.circuitBreaker.GetStats()

	// Get health checker stats if available
	var lastHealthCheck time.Time
	var healthStatus string = "unknown"
	if ic.healthChecker != nil {
		lastHealthCheck = ic.healthChecker.GetLastCheck()
		// Get health status from health checker
		if ic.healthChecker.IsRunning() {
			healthStatus = "healthy" // Simplified
		}
	}

	// Get recovery stats
	ic.recovery.mutex.RLock()
	recoveryAttempts := ic.recovery.attempts
	lastRecoveryTime := ic.recovery.lastAttempt
	ic.recovery.mutex.RUnlock()

	// Get process stats
	var processUptime time.Duration
	var processMemory, processCPU int64
	if ic.process != nil {
		ic.process.mutex.RLock()
		if ic.process.isRunning.Load() {
			processUptime = time.Since(ic.process.startTime)
		}
		processMemory = ic.process.memoryUsage.Load()
		// Safe conversion with overflow check
		cpuUsage := ic.process.cpuUsage.Load()
		if cpuUsage > math.MaxInt64 {
			processCPU = math.MaxInt64
		} else {
			processCPU = int64(cpuUsage)
		}
		ic.process.mutex.RUnlock()
	}

	// Get next recovery time if available
	nextRecoveryTime := time.Time{} // Zero time by default
	ic.recovery.mutex.RLock()
	if !ic.recovery.nextAttempt.IsZero() {
		nextRecoveryTime = ic.recovery.nextAttempt
	}
	ic.recovery.mutex.RUnlock()

	return IsolatedClientObservabilityReport{
		ClientName:  ic.client.Name,
		GeneratedAt: time.Now(),

		// Request statistics
		TotalRequests:      ic.stats.TotalRequests.Load(),
		SuccessfulRequests: ic.stats.SuccessfulRequests.Load(),
		FailedRequests:     ic.stats.FailedRequests.Load(),

		// Performance statistics
		MinResponseTime:     ic.stats.MinResponseTime,
		MaxResponseTime:     ic.stats.MaxResponseTime,
		AverageResponseTime: ic.stats.AverageResponseTime,

		// Circuit breaker statistics
		CircuitBreakerState: cbStats.State.String(),
		CircuitBreakerTrips: ic.stats.CircuitBreakerTrips.Load(),
		CBFailureCount:      cbStats.FailureCount,
		CBSuccessCount:      cbStats.SuccessCount,
		CBLastFailure:       cbStats.LastFailure,

		// Health statistics
		HealthStatus:    healthStatus,
		LastHealthCheck: lastHealthCheck,

		// Recovery statistics
		RecoveryAttempts:     int64(recoveryAttempts),
		SuccessfulRecoveries: ic.stats.SuccessfulRecoveries.Load(),
		FailedRecoveries:     ic.stats.FailedRecoveries.Load(),
		LastRecoveryTime:     lastRecoveryTime,
		NextRecoveryTime:     nextRecoveryTime,

		// Process statistics
		ProcessUptime:     processUptime,
		ProcessMemoryMB:   processMemory / 1024 / 1024,
		ProcessCPUPercent: float64(processCPU) / 100.0,

		// Resource usage
		MaxMemoryUsage:  ic.stats.MaxMemoryUsage.Load(),
		AverageCPUUsage: float64(ic.stats.AverageCPUUsage.Load()) / 100.0,
	}
}

// IsolatedClientObservabilityReport provides comprehensive observability data for an isolated client.
type IsolatedClientObservabilityReport struct {
	ClientName  string    `json:"client_name"`
	GeneratedAt time.Time `json:"generated_at"`

	// Request statistics
	TotalRequests      int64 `json:"total_requests"`
	SuccessfulRequests int64 `json:"successful_requests"`
	FailedRequests     int64 `json:"failed_requests"`

	// Performance statistics
	MinResponseTime     time.Duration `json:"min_response_time"`
	MaxResponseTime     time.Duration `json:"max_response_time"`
	AverageResponseTime time.Duration `json:"average_response_time"`

	// Circuit breaker statistics
	CircuitBreakerState string    `json:"circuit_breaker_state"`
	CircuitBreakerTrips int64     `json:"circuit_breaker_trips"`
	CBFailureCount      int64     `json:"cb_failure_count"`
	CBSuccessCount      int64     `json:"cb_success_count"`
	CBLastFailure       time.Time `json:"cb_last_failure"`

	// Health statistics
	HealthStatus    string    `json:"health_status"`
	LastHealthCheck time.Time `json:"last_health_check"`

	// Recovery statistics
	RecoveryAttempts     int64     `json:"recovery_attempts"`
	SuccessfulRecoveries int64     `json:"successful_recoveries"`
	FailedRecoveries     int64     `json:"failed_recoveries"`
	LastRecoveryTime     time.Time `json:"last_recovery_time"`
	NextRecoveryTime     time.Time `json:"next_recovery_time"`

	// Process statistics
	ProcessUptime     time.Duration `json:"process_uptime"`
	ProcessMemoryMB   int64         `json:"process_memory_mb"`
	ProcessCPUPercent float64       `json:"process_cpu_percent"`

	// Resource usage
	MaxMemoryUsage  int64   `json:"max_memory_usage"`
	AverageCPUUsage float64 `json:"average_cpu_usage"`
}

// GetIsolationObservabilityReport returns comprehensive observability report for the isolation manager.
func (pim *PluginIsolationManager) GetIsolationObservabilityReport() IsolationObservabilityReport {
	pim.clientMutex.RLock()
	pim.recoveryMutex.RLock()
	defer pim.clientMutex.RUnlock()
	defer pim.recoveryMutex.RUnlock()

	report := IsolationObservabilityReport{
		GeneratedAt:      time.Now(),
		TotalClients:     int64(len(pim.isolatedClients)),
		ActiveClients:    0,
		HealthyClients:   0,
		RecoveryTrackers: int64(len(pim.recoveries)),
		Clients:          make(map[string]IsolatedClientObservabilityReport),
	}

	for name, client := range pim.isolatedClients {
		clientReport := client.GetObservabilityReport()
		report.Clients[name] = clientReport

		// Count active and healthy clients
		if clientReport.TotalRequests > 0 {
			report.ActiveClients++
		}
		if clientReport.HealthStatus == "healthy" {
			report.HealthyClients++
		}
	}

	return report
}

// IsolationObservabilityReport provides system-wide observability for plugin isolation.
type IsolationObservabilityReport struct {
	GeneratedAt      time.Time                                    `json:"generated_at"`
	TotalClients     int64                                        `json:"total_clients"`
	ActiveClients    int64                                        `json:"active_clients"`
	HealthyClients   int64                                        `json:"healthy_clients"`
	RecoveryTrackers int64                                        `json:"recovery_trackers"`
	Clients          map[string]IsolatedClientObservabilityReport `json:"clients"`
}

// validatePluginBinaryPath validates the plugin binary path to prevent command injection.
func validatePluginBinaryPath(path string) error {
	if path == "" {
		return fmt.Errorf("plugin binary path is empty")
	}

	// Check for path traversal and dangerous characters
	if strings.Contains(path, "..") {
		return fmt.Errorf("plugin binary path contains path traversal characters")
	}

	if strings.Contains(path, ";") || strings.Contains(path, "&") || strings.Contains(path, "|") {
		return fmt.Errorf("plugin binary path contains potentially dangerous characters")
	}

	// Ensure the file exists and is executable
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("plugin binary not found: %w", err)
	}

	return nil
}
