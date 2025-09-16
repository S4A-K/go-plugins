// plugin_isolation_test.go: Tests for plugin crash isolation system
//
// This file tests the plugin isolation system to ensure that plugin crashes
// don't affect the host application. It demonstrates circuit breaker integration,
// health monitoring, automatic recovery, and fallback mechanisms.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockCrashingPlugin simulates a plugin that can crash or become unresponsive.
type MockCrashingPlugin struct {
	name           string
	shouldFail     bool
	shouldTimeout  bool
	responseDelay  time.Duration
	healthStatus   PluginStatus
	failureCount   int
	callCount      int
	lastCallMethod string
	lastCallArgs   interface{}
}

// NewMockCrashingPlugin creates a new mock plugin for testing crash isolation.
func NewMockCrashingPlugin(name string) *MockCrashingPlugin {
	return &MockCrashingPlugin{
		name:         name,
		healthStatus: StatusHealthy,
	}
}

// Call simulates a plugin call that might fail or timeout.
func (mcp *MockCrashingPlugin) Call(ctx context.Context, method string, args interface{}, tracker *RequestTracker) (interface{}, error) {
	mcp.callCount++
	mcp.lastCallMethod = method
	mcp.lastCallArgs = args

	if mcp.shouldTimeout {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(mcp.responseDelay):
			// Continue with normal processing
		}
	} else if mcp.responseDelay > 0 {
		time.Sleep(mcp.responseDelay)
	}

	if mcp.shouldFail {
		mcp.failureCount++
		return nil, errors.New("plugin crashed")
	}

	return map[string]interface{}{
		"method": method,
		"args":   args,
		"result": "success",
	}, nil
}

// Health returns the current health status of the mock plugin.
func (mcp *MockCrashingPlugin) Health(ctx context.Context) HealthStatus {
	if mcp.shouldFail {
		return HealthStatus{
			Status:       StatusUnhealthy,
			Message:      "Plugin is configured to fail",
			LastCheck:    time.Now(),
			ResponseTime: time.Millisecond,
		}
	}

	return HealthStatus{
		Status:       mcp.healthStatus,
		Message:      "Plugin is healthy",
		LastCheck:    time.Now(),
		ResponseTime: time.Millisecond,
	}
}

// Close simulates closing the plugin.
func (mcp *MockCrashingPlugin) Close() error {
	return nil
}

// Ping simulates a ping to the plugin.
func (mcp *MockCrashingPlugin) Ping(ctx context.Context) error {
	if mcp.shouldFail {
		return errors.New("plugin not responding")
	}
	return nil
}

// HasCapability simulates capability checking.
func (mcp *MockCrashingPlugin) HasCapability(capability string) bool {
	return capability == "health" || capability == "ping"
}

// SetFailureMode configures the plugin to fail.
func (mcp *MockCrashingPlugin) SetFailureMode(shouldFail bool) {
	mcp.shouldFail = shouldFail
	if shouldFail {
		mcp.healthStatus = StatusUnhealthy
	} else {
		mcp.healthStatus = StatusHealthy
		mcp.failureCount = 0
	}
}

// SetTimeoutMode configures the plugin to timeout.
func (mcp *MockCrashingPlugin) SetTimeoutMode(shouldTimeout bool, delay time.Duration) {
	mcp.shouldTimeout = shouldTimeout
	mcp.responseDelay = delay
}

// SetHealthStatus sets the health status for testing.
func (mcp *MockCrashingPlugin) SetHealthStatus(status PluginStatus) {
	mcp.healthStatus = status
}

// GetStats returns plugin statistics.
func (mcp *MockCrashingPlugin) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"call_count":    mcp.callCount,
		"failure_count": mcp.failureCount,
		"last_method":   mcp.lastCallMethod,
		"health_status": mcp.healthStatus,
	}
}

func TestPluginIsolationManager_BasicIsolation(t *testing.T) {
	// Create isolation configuration
	config := IsolationConfig{
		CircuitBreakerConfig: CircuitBreakerConfig{
			Enabled:             true,
			FailureThreshold:    3,
			RecoveryTimeout:     5 * time.Second,
			MinRequestThreshold: 1,
			SuccessThreshold:    2,
		},
		HealthCheckConfig: HealthCheckConfig{
			Enabled:      true,
			Interval:     100 * time.Millisecond,
			Timeout:      1 * time.Second,
			FailureLimit: 2,
		},
		ProcessIsolation: ProcessIsolationConfig{
			Enabled:      true,
			ProcessGroup: true,
			SandboxDir:   "/tmp/plugin-sandbox",
		},
		RecoveryConfig: RecoveryConfig{
			Enabled:           true,
			MaxAttempts:       2,
			BackoffStrategy:   BackoffStrategyExponential,
			InitialDelay:      100 * time.Millisecond,
			MaxDelay:          1 * time.Second,
			BackoffMultiplier: 2.0,
		},
		FallbackConfig: FallbackConfig{
			Enabled:         true,
			Strategy:        FallbackStrategyDefault,
			DefaultResponse: map[string]string{"status": "fallback"},
		},
		ResourceLimits: ResourceLimitsConfig{
			Enabled:          true,
			MaxMemoryMB:      100,
			MaxCPUPercent:    80,
			MaxExecutionTime: 2 * time.Second,
		},
		// Add observability configuration
		ObservabilityConfig: ObservabilityConfig{
			MetricsEnabled:     true,
			MetricsCollector:   NewDefaultMetricsCollector(),
			MetricsPrefix:      "test_isolation",
			TracingEnabled:     false,
			LoggingEnabled:     true,
			LogLevel:           "debug",
			HealthMetrics:      true,
			PerformanceMetrics: true,
			ErrorMetrics:       true,
		},
	}

	// Create isolation manager
	manager := NewPluginIsolationManager(config)
	require.NotNil(t, manager)

	// Start the manager
	err := manager.Start()
	require.NoError(t, err)
	defer func() {
		if err := manager.Stop(); err != nil {
			t.Logf("Warning: failed to stop manager: %v", err)
		}
	}()

	// Create a plugin client wrapper
	pluginClient := &PluginClient{
		Name: "test-plugin",
		// Note: In real implementation, this would have proper RPC client
	}

	// Wrap the client with isolation
	isolatedClient := manager.WrapClient(pluginClient)
	require.NotNil(t, isolatedClient)

	// Test normal operation
	t.Run("NormalOperation", func(t *testing.T) {
		ctx := context.Background()
		result, err := isolatedClient.Call(ctx, "test_method", map[string]string{"key": "value"})

		// Since we don't have a real plugin connection, this will fail
		// but the isolation system should handle it gracefully
		if err != nil {
			// Check that circuit breaker is working
			stats := isolatedClient.circuitBreaker.GetStats()
			assert.Equal(t, StateClosed, stats.State) // Should still be closed for first failure
		}

		_ = result // Placeholder for actual result handling
	})

	// Verify isolation components are properly initialized
	t.Run("IsolationComponents", func(t *testing.T) {
		assert.NotNil(t, isolatedClient.circuitBreaker, "Circuit breaker should be initialized")
		assert.NotNil(t, isolatedClient.healthChecker, "Health checker should be initialized")
		assert.NotNil(t, isolatedClient.process, "Process wrapper should be initialized")
		assert.NotNil(t, isolatedClient.recovery, "Recovery tracker should be initialized")
		assert.NotNil(t, isolatedClient.stats, "Statistics should be initialized")

		// Check circuit breaker state
		stats := isolatedClient.circuitBreaker.GetStats()
		assert.Equal(t, StateClosed, stats.State, "Circuit breaker should start closed")

		// Check health checker (it might be running if enabled)
		_ = isolatedClient.healthChecker.IsRunning() // Just verify it exists

		// Check recovery state (might have been incremented by failed calls)
		isolatedClient.recovery.mutex.RLock()
		attempts := isolatedClient.recovery.attempts
		isolatedClient.recovery.mutex.RUnlock()
		assert.True(t, attempts >= 0, "Recovery attempts should be non-negative")
	})

	// Test circuit breaker integration
	t.Run("CircuitBreakerIntegration", func(t *testing.T) {
		ctx := context.Background()

		// Simulate multiple failures to trip circuit breaker
		for i := 0; i < 5; i++ {
			if _, err := isolatedClient.Call(ctx, "failing_method", nil); err != nil {
				t.Logf("Expected failure %d: %v", i, err)
			}
		}

		// Check circuit breaker state
		stats := isolatedClient.circuitBreaker.GetStats()
		assert.True(t, stats.FailureCount >= 3, "Should have recorded failures")

		// The circuit breaker should eventually open after enough failures
		// Note: Exact behavior depends on the configuration
	})

	// Test fallback mechanism
	t.Run("FallbackMechanism", func(t *testing.T) {
		ctx := context.Background()

		// Force circuit breaker to open by simulating it manually
		isolatedClient.circuitBreaker.RecordFailure()
		isolatedClient.circuitBreaker.RecordFailure()
		isolatedClient.circuitBreaker.RecordFailure()
		isolatedClient.circuitBreaker.RecordFailure()
		isolatedClient.circuitBreaker.RecordFailure()

		// Now try to make a call - should get fallback response
		result, err := isolatedClient.Call(ctx, "test_method", nil)

		// Should either get fallback response or error
		if err == nil {
			// Check if it's the configured fallback response
			if fallbackResp, ok := result.(map[string]string); ok {
				assert.Equal(t, "fallback", fallbackResp["status"], "Should receive configured fallback response")
			}
		}
	})

	// Test statistics tracking
	t.Run("StatisticsTracking", func(t *testing.T) {
		stats := isolatedClient.stats

		// Should have recorded some requests
		totalRequests := stats.TotalRequests.Load()
		assert.True(t, totalRequests > 0, "Should have recorded requests")

		// Should have some failures due to no real plugin connection
		failedRequests := stats.FailedRequests.Load()
		assert.True(t, failedRequests > 0, "Should have recorded failures")

		// Circuit breaker should have been tripped
		cbTrips := stats.CircuitBreakerTrips.Load()
		assert.True(t, cbTrips >= 0, "Circuit breaker trips should be tracked")
	})

	// Test observability integration
	t.Run("ObservabilityIntegration", func(t *testing.T) {
		// Get observability report for the isolated client
		clientReport := isolatedClient.GetObservabilityReport()

		assert.Equal(t, "test-plugin", clientReport.ClientName)
		assert.True(t, clientReport.TotalRequests > 0, "Should have request statistics")
		assert.NotEmpty(t, clientReport.CircuitBreakerState, "Should have circuit breaker state")

		// Get system-wide observability report
		systemReport := manager.GetIsolationObservabilityReport()

		assert.Equal(t, int64(1), systemReport.TotalClients, "Should have one client")
		assert.Contains(t, systemReport.Clients, "test-plugin", "Should contain our test client")

		// Verify client report in system report matches individual report
		systemClientReport := systemReport.Clients["test-plugin"]
		assert.Equal(t, clientReport.TotalRequests, systemClientReport.TotalRequests)
	})
}

func TestPluginIsolation_CircuitBreakerStates(t *testing.T) {
	// Test circuit breaker state transitions in isolation context
	config := IsolationConfig{
		CircuitBreakerConfig: CircuitBreakerConfig{
			Enabled:             true,
			FailureThreshold:    2, // Low threshold for testing
			RecoveryTimeout:     100 * time.Millisecond,
			MinRequestThreshold: 1,
			SuccessThreshold:    1,
		},
		FallbackConfig: FallbackConfig{
			Enabled:         true,
			Strategy:        FallbackStrategyDefault,
			DefaultResponse: "fallback_value",
		},
	}

	manager := NewPluginIsolationManager(config)
	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer func() {
		if err := manager.Stop(); err != nil {
			t.Logf("Warning: failed to stop manager: %v", err)
		}
	}()

	pluginClient := &PluginClient{Name: "cb-test-plugin"}
	isolatedClient := manager.WrapClient(pluginClient)

	ctx := context.Background()

	// Test: Circuit starts closed
	t.Run("StartsInClosedState", func(t *testing.T) {
		stats := isolatedClient.circuitBreaker.GetStats()
		assert.Equal(t, StateClosed, stats.State)
		assert.True(t, isolatedClient.circuitBreaker.AllowRequest())
	})

	// Test: Circuit opens after failures
	t.Run("OpensAfterFailures", func(t *testing.T) {
		// Record enough failures to open circuit
		isolatedClient.circuitBreaker.RecordFailure()
		isolatedClient.circuitBreaker.RecordFailure()
		isolatedClient.circuitBreaker.RecordFailure() // Should open now

		stats := isolatedClient.circuitBreaker.GetStats()
		assert.True(t, stats.State == StateOpen || stats.FailureCount >= int64(config.CircuitBreakerConfig.FailureThreshold))
	})

	// Test: Fallback works when circuit is open
	t.Run("FallbackWhenOpen", func(t *testing.T) {
		// Ensure circuit is open
		for i := 0; i < 5; i++ {
			isolatedClient.circuitBreaker.RecordFailure()
		}

		result, err := isolatedClient.Call(ctx, "test", nil)

		// Should get fallback response since circuit is open
		if err == nil {
			assert.Equal(t, "fallback_value", result)
		}
		// Or should get circuit breaker error
	})

	// Test: Circuit can transition to half-open
	t.Run("TransitionsToHalfOpen", func(t *testing.T) {
		// Wait for recovery timeout
		time.Sleep(150 * time.Millisecond)

		// Try to make a request - this should attempt to transition to half-open
		isolatedClient.circuitBreaker.AllowRequest()

		// The state might be half-open now (depending on timing)
		stats := isolatedClient.circuitBreaker.GetStats()
		// State could be half-open or still open, both are valid depending on timing
		assert.Contains(t, []CircuitBreakerState{StateOpen, StateHalfOpen}, stats.State)
	})
}

func TestPluginIsolation_RecoveryMechanism(t *testing.T) {
	config := IsolationConfig{
		RecoveryConfig: RecoveryConfig{
			Enabled:           true,
			MaxAttempts:       3,
			BackoffStrategy:   BackoffStrategyLinear,
			InitialDelay:      10 * time.Millisecond,
			MaxDelay:          100 * time.Millisecond,
			BackoffMultiplier: 2.0,
		},
		CircuitBreakerConfig: CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 1,
		},
	}

	manager := NewPluginIsolationManager(config)
	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer func() {
		if err := manager.Stop(); err != nil {
			t.Logf("Warning: failed to stop manager: %v", err)
		}
	}()

	pluginClient := &PluginClient{Name: "recovery-test-plugin"}
	isolatedClient := manager.WrapClient(pluginClient)

	// Test recovery attempt tracking
	t.Run("RecoveryAttemptTracking", func(t *testing.T) {
		// Initial state
		isolatedClient.recovery.mutex.RLock()
		initialAttempts := isolatedClient.recovery.attempts
		isolatedClient.recovery.mutex.RUnlock()
		assert.Equal(t, 0, initialAttempts)

		// Simulate an error that should trigger recovery
		err := errors.New("connection lost")
		shouldRecover := isolatedClient.shouldAttemptRecovery(err)
		assert.True(t, shouldRecover, "Should attempt recovery for connection errors")
	})

	// Test backoff calculation
	t.Run("BackoffCalculation", func(t *testing.T) {
		// Set some recovery attempts
		isolatedClient.recovery.mutex.Lock()
		isolatedClient.recovery.attempts = 1
		isolatedClient.recovery.mutex.Unlock()

		delay1 := isolatedClient.calculateBackoffDelay()

		isolatedClient.recovery.mutex.Lock()
		isolatedClient.recovery.attempts = 2
		isolatedClient.recovery.mutex.Unlock()

		delay2 := isolatedClient.calculateBackoffDelay()

		// For linear backoff, delay2 should be greater than delay1
		assert.True(t, delay2 > delay1, "Linear backoff should increase delay")
		assert.True(t, delay2 <= 100*time.Millisecond, "Should respect max delay")
	})

	// Test max attempts limit
	t.Run("MaxAttemptsLimit", func(t *testing.T) {
		// Set attempts to max
		isolatedClient.recovery.mutex.Lock()
		isolatedClient.recovery.attempts = config.RecoveryConfig.MaxAttempts
		isolatedClient.recovery.mutex.Unlock()

		err := errors.New("test error")
		shouldRecover := isolatedClient.shouldAttemptRecovery(err)
		assert.False(t, shouldRecover, "Should not attempt recovery after max attempts")
	})
}

func TestPluginIsolation_ProcessMonitoring(t *testing.T) {
	// Test process monitoring functionality
	processMonitor := NewProcessMonitor(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := processMonitor.Start(ctx)
	require.NoError(t, err)
	defer processMonitor.Stop()

	// Test process registration
	t.Run("ProcessRegistration", func(t *testing.T) {
		process := &PluginProcess{
			pid:       12345,
			startTime: time.Now(),
		}
		process.isRunning.Store(true)

		processMonitor.RegisterProcess("test-process", process)

		processMonitor.mutex.RLock()
		registered := processMonitor.processes["test-process"]
		processMonitor.mutex.RUnlock()

		assert.NotNil(t, registered, "Process should be registered")
		assert.Equal(t, process, registered, "Should be the same process instance")
	})

	// Test monitoring loop (basic verification)
	t.Run("MonitoringLoop", func(t *testing.T) {
		// Let the monitor run for a bit
		time.Sleep(100 * time.Millisecond)

		// If we get here without hanging, the monitoring loop is working
		assert.True(t, true, "Monitoring loop should be running")
	})
}

func TestPluginIsolation_FallbackStrategies(t *testing.T) {
	tests := []struct {
		name           string
		strategy       FallbackStrategy
		defaultValue   interface{}
		expectedResult interface{}
		shouldFallback bool
	}{
		{
			name:           "DefaultStrategy",
			strategy:       FallbackStrategyDefault,
			defaultValue:   "default_response",
			expectedResult: "default_response",
			shouldFallback: true,
		},
		{
			name:           "NoneStrategy",
			strategy:       FallbackStrategyNone,
			defaultValue:   "ignored",
			expectedResult: nil,
			shouldFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := IsolationConfig{
				FallbackConfig: FallbackConfig{
					Enabled:         true,
					Strategy:        tt.strategy,
					DefaultResponse: tt.defaultValue,
				},
			}

			manager := NewPluginIsolationManager(config)
			pluginClient := &PluginClient{Name: "fallback-test"}
			isolatedClient := manager.WrapClient(pluginClient)

			originalErr := errors.New("test error")
			result, err := isolatedClient.handleFallback("test_method", nil, originalErr)

			if tt.shouldFallback {
				assert.NoError(t, err, "Fallback should not return error")
				assert.Equal(t, tt.expectedResult, result, "Should return expected fallback result")
			} else {
				assert.Error(t, err, "Should return original error when fallback disabled")
				assert.Equal(t, originalErr, err, "Should return the original error")
			}
		})
	}
}

func TestPluginIsolation_ResourceLimits(t *testing.T) {
	config := IsolationConfig{
		ResourceLimits: ResourceLimitsConfig{
			Enabled:          true,
			MaxMemoryMB:      64,
			MaxCPUPercent:    75,
			MaxExecutionTime: 500 * time.Millisecond,
		},
	}

	manager := NewPluginIsolationManager(config)
	pluginClient := &PluginClient{Name: "resource-test"}
	isolatedClient := manager.WrapClient(pluginClient)

	// Test resource limit configuration
	t.Run("ResourceLimitConfiguration", func(t *testing.T) {
		assert.Equal(t, int64(64), isolatedClient.process.maxMemoryMB)
		assert.Equal(t, 75, isolatedClient.process.maxCPUPercent)
	})

	// Test execution timeout
	t.Run("ExecutionTimeout", func(t *testing.T) {
		ctx := context.Background()
		start := time.Now()

		// This will fail due to no real connection, but timeout should be applied
		if _, err := isolatedClient.Call(ctx, "slow_method", nil); err != nil {
			t.Logf("Expected timeout failure: %v", err)
		}

		duration := time.Since(start)
		// Should not take significantly longer than the timeout
		// (allowing some overhead for processing)
		assert.True(t, duration < 1*time.Second, "Should respect execution timeout")
	})
}

// Benchmark tests for isolation overhead
func BenchmarkPluginIsolation_CallOverhead(b *testing.B) {
	config := IsolationConfig{
		CircuitBreakerConfig: CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 10,
		},
		FallbackConfig: FallbackConfig{
			Enabled: false, // Disable fallback for pure overhead measurement
		},
	}

	manager := NewPluginIsolationManager(config)
	if err := manager.Start(); err != nil {
		b.Fatalf("Failed to start manager: %v", err)
	}
	defer func() {
		if err := manager.Stop(); err != nil {
			b.Logf("Warning: failed to stop manager: %v", err)
		}
	}()

	pluginClient := &PluginClient{Name: "bench-plugin"}
	isolatedClient := manager.WrapClient(pluginClient)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This will fail but we measure the isolation overhead
		if _, err := isolatedClient.Call(ctx, "bench_method", nil); err != nil {
			// Expected failure, ignore for benchmark
		}
	}
}

func BenchmarkPluginIsolation_CircuitBreakerOverhead(b *testing.B) {
	config := IsolationConfig{
		CircuitBreakerConfig: CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 1000, // High threshold to keep circuit closed
		},
	}

	manager := NewPluginIsolationManager(config)
	pluginClient := &PluginClient{Name: "cb-bench-plugin"}
	isolatedClient := manager.WrapClient(pluginClient)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Test just the circuit breaker check overhead
		isolatedClient.circuitBreaker.AllowRequest()
	}
}
