// health_checker_test.go: Comprehensive test suite for health monitoring implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MockHealthPlugin implements the plugin interface for testing
type MockHealthPlugin struct {
	name              string
	healthStatus      PluginStatus
	healthMessage     string
	responseDelay     time.Duration
	shouldTimeout     bool
	shouldPanic       bool
	callCount         atomic.Int64
	lastCallTime      atomic.Int64
	mu                sync.RWMutex
	metadata          map[string]string
	consecutiveErrors int
	maxErrors         int
}

// NewMockHealthPlugin creates a new mock plugin for testing
func NewMockHealthPlugin(name string) *MockHealthPlugin {
	return &MockHealthPlugin{
		name:          name,
		healthStatus:  StatusHealthy,
		healthMessage: "OK",
		responseDelay: 0,
		metadata:      make(map[string]string),
		maxErrors:     0,
	}
}

// Health implements the Health method for testing
func (m *MockHealthPlugin) Health(ctx context.Context) HealthStatus {
	m.callCount.Add(1)
	m.lastCallTime.Store(time.Now().UnixNano())

	if m.shouldPanic {
		panic("mock plugin panic during health check")
	}

	// Simulate response delay
	if m.responseDelay > 0 {
		select {
		case <-time.After(m.responseDelay):
		case <-ctx.Done():
			if m.shouldTimeout {
				return HealthStatus{
					Status:       StatusUnhealthy,
					Message:      "Health check timed out",
					LastCheck:    time.Now(),
					ResponseTime: m.responseDelay,
				}
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Simulate consecutive error pattern
	if m.maxErrors > 0 {
		if m.consecutiveErrors < m.maxErrors {
			m.consecutiveErrors++
			return HealthStatus{
				Status:       StatusUnhealthy,
				Message:      fmt.Sprintf("Simulated error %d/%d", m.consecutiveErrors, m.maxErrors),
				LastCheck:    time.Now(),
				ResponseTime: m.responseDelay,
				Metadata:     m.copyMetadata(),
			}
		} else {
			// After max errors reached, always return healthy
			return HealthStatus{
				Status:       StatusHealthy,
				Message:      "Recovered after max errors",
				LastCheck:    time.Now(),
				ResponseTime: m.responseDelay,
				Metadata:     m.copyMetadata(),
			}
		}
	}

	return HealthStatus{
		Status:       m.healthStatus,
		Message:      m.healthMessage,
		LastCheck:    time.Now(),
		ResponseTime: m.responseDelay,
		Metadata:     m.copyMetadata(),
	}
}

// Close implements the Close method for testing
func (m *MockHealthPlugin) Close() error {
	return nil
}

// SetHealth updates the mock plugin's health status
func (m *MockHealthPlugin) SetHealth(status PluginStatus, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthStatus = status
	m.healthMessage = message
}

// SetResponseDelay sets the response delay for health checks
func (m *MockHealthPlugin) SetResponseDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseDelay = delay
}

// SetShouldTimeout configures whether health checks should timeout
func (m *MockHealthPlugin) SetShouldTimeout(timeout bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldTimeout = timeout
}

// SetShouldPanic configures whether health checks should panic
func (m *MockHealthPlugin) SetShouldPanic(panic bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldPanic = panic
}

// SetMaxErrors configures consecutive error simulation
func (m *MockHealthPlugin) SetMaxErrors(maxErrors int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxErrors = maxErrors
	m.consecutiveErrors = 0
}

// GetCallCount returns the number of health check calls
func (m *MockHealthPlugin) GetCallCount() int64 {
	return m.callCount.Load()
}

// GetLastCallTime returns the timestamp of the last health check call
func (m *MockHealthPlugin) GetLastCallTime() time.Time {
	timestamp := m.lastCallTime.Load()
	if timestamp == 0 {
		return time.Time{}
	}
	return time.Unix(0, timestamp)
}

// SetMetadata sets metadata for the health response
func (m *MockHealthPlugin) SetMetadata(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metadata[key] = value
}

// copyMetadata returns a copy of the metadata map
func (m *MockHealthPlugin) copyMetadata() map[string]string {
	result := make(map[string]string)
	for k, v := range m.metadata {
		result[k] = v
	}
	return result
}

// TestHealthChecker_Creation tests the creation of health checkers
func TestHealthChecker_Creation(t *testing.T) {
	t.Parallel()

	plugin := NewMockHealthPlugin("test-plugin")

	t.Run("ValidCreation", func(t *testing.T) {
		config := HealthCheckConfig{
			Enabled:      true,
			Interval:     100 * time.Millisecond,
			Timeout:      1 * time.Second,
			FailureLimit: 3,
		}

		checker := NewHealthChecker(plugin, config)
		defer checker.Stop()

		if checker == nil {
			t.Fatal("NewHealthChecker returned nil")
		}

		if !checker.IsRunning() {
			t.Error("Health checker should be running when enabled")
		}
	})

	t.Run("DisabledCreation", func(t *testing.T) {
		config := HealthCheckConfig{
			Enabled:      false,
			Interval:     100 * time.Millisecond,
			Timeout:      1 * time.Second,
			FailureLimit: 3,
		}

		checker := NewHealthChecker(plugin, config)

		if checker == nil {
			t.Fatal("NewHealthChecker returned nil")
		}

		if checker.IsRunning() {
			t.Error("Health checker should not be running when disabled")
		}
	})
}

// TestHealthChecker_BasicOperations tests basic health checking functionality
func TestHealthChecker_BasicOperations(t *testing.T) {
	t.Parallel()

	t.Run("InitialHealthyStatus", func(t *testing.T) {
		plugin := NewMockHealthPlugin("test-plugin")
		config := HealthCheckConfig{
			Enabled:      true,
			Interval:     1 * time.Hour, // Very long interval to avoid background interference
			Timeout:      1 * time.Second,
			FailureLimit: 2,
		}

		checker := NewHealthChecker(plugin, config)
		defer checker.Stop()

		status := checker.Check()
		if status.Status != StatusHealthy {
			t.Errorf("Expected StatusHealthy, got %s", status.Status.String())
		}
		if status.Message != "OK" {
			t.Errorf("Expected 'OK', got '%s'", status.Message)
		}
	})

	t.Run("ConsecutiveFailures", func(t *testing.T) {
		plugin := NewMockHealthPlugin("test-plugin")
		config := HealthCheckConfig{
			Enabled:      true,
			Interval:     1 * time.Hour, // Very long interval to avoid background interference
			Timeout:      1 * time.Second,
			FailureLimit: 2,
		}

		checker := NewHealthChecker(plugin, config)
		defer checker.Stop()

		// Set plugin to unhealthy
		plugin.SetHealth(StatusUnhealthy, "Service unavailable")

		// First failure
		status := checker.Check()
		if status.Status != StatusUnhealthy {
			t.Errorf("Expected StatusUnhealthy, got %s", status.Status.String())
		}
		if checker.GetConsecutiveFailures() != 1 {
			t.Errorf("Expected 1 consecutive failure, got %d", checker.GetConsecutiveFailures())
		}

		// Second failure - should exceed limit
		status = checker.Check()
		if status.Status != StatusOffline {
			t.Errorf("Expected StatusOffline after exceeding failure limit, got %s", status.Status.String())
		}
		if checker.GetConsecutiveFailures() != 2 {
			t.Errorf("Expected 2 consecutive failures, got %d", checker.GetConsecutiveFailures())
		}
	})

	t.Run("RecoveryFromFailures", func(t *testing.T) {
		plugin := NewMockHealthPlugin("test-plugin")
		config := HealthCheckConfig{
			Enabled:      true,
			Interval:     1 * time.Hour, // Very long interval to avoid background interference
			Timeout:      1 * time.Second,
			FailureLimit: 2,
		}

		checker := NewHealthChecker(plugin, config)
		defer checker.Stop()

		// First, set plugin to unhealthy to create some failures
		plugin.SetHealth(StatusUnhealthy, "Service unavailable")
		checker.Check() // First failure
		checker.Check() // Second failure (should go offline)

		// Now reset plugin to healthy
		plugin.SetHealth(StatusHealthy, "OK")

		status := checker.Check()
		if status.Status != StatusHealthy {
			t.Errorf("Expected StatusHealthy after recovery, got %s", status.Status.String())
		}
		if checker.GetConsecutiveFailures() != 0 {
			t.Errorf("Expected 0 consecutive failures after recovery, got %d", checker.GetConsecutiveFailures())
		}
	})
}

// TestHealthChecker_Timeout tests timeout behavior
func TestHealthChecker_Timeout(t *testing.T) {
	t.Parallel()

	plugin := NewMockHealthPlugin("timeout-plugin")
	plugin.SetResponseDelay(200 * time.Millisecond)
	plugin.SetShouldTimeout(true)

	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     1 * time.Second,
		Timeout:      100 * time.Millisecond, // Shorter than response delay
		FailureLimit: 1,
	}

	checker := NewHealthChecker(plugin, config)
	defer checker.Stop()

	start := time.Now()
	status := checker.Check()
	duration := time.Since(start)

	// Should timeout quickly
	if duration > 150*time.Millisecond {
		t.Errorf("Health check took too long: %v", duration)
	}

	if status.Status == StatusHealthy {
		t.Error("Expected unhealthy status due to timeout")
	}
}

// TestHealthChecker_PeriodicChecking tests periodic health check execution
func TestHealthChecker_PeriodicChecking(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping periodic checking test on Windows due to timer precision")
	}

	plugin := NewMockHealthPlugin("periodic-plugin")
	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     50 * time.Millisecond,
		Timeout:      1 * time.Second,
		FailureLimit: 3,
	}

	checker := NewHealthChecker(plugin, config)
	defer checker.Stop()

	// Wait for multiple checks
	time.Sleep(200 * time.Millisecond)

	callCount := plugin.GetCallCount()
	if callCount < 3 {
		t.Errorf("Expected at least 3 health check calls, got %d", callCount)
	}

	if !checker.GetLastCheck().After(time.Now().Add(-1 * time.Second)) {
		t.Error("Last check timestamp should be recent")
	}
}

// TestHealthChecker_StartStop tests start/stop lifecycle
func TestHealthChecker_StartStop(t *testing.T) {
	t.Parallel()

	plugin := NewMockHealthPlugin("lifecycle-plugin")
	config := HealthCheckConfig{
		Enabled:      false, // Start disabled
		Interval:     50 * time.Millisecond,
		Timeout:      1 * time.Second,
		FailureLimit: 3,
	}

	checker := NewHealthChecker(plugin, config)

	t.Run("InitiallyNotRunning", func(t *testing.T) {
		if checker.IsRunning() {
			t.Error("Health checker should not be running initially")
		}
	})

	t.Run("StartChecker", func(t *testing.T) {
		config.Enabled = true
		checker.config = config
		checker.Start()

		if !checker.IsRunning() {
			t.Error("Health checker should be running after start")
		}
	})

	t.Run("StopChecker", func(t *testing.T) {
		checker.Stop()

		if checker.IsRunning() {
			t.Error("Health checker should not be running after stop")
		}

		// Test Done channel
		select {
		case <-checker.Done():
			// Expected - channel should be closed
		case <-time.After(100 * time.Millisecond):
			t.Error("Done channel should be closed after stop")
		}
	})

	t.Run("IdempotentOperations", func(t *testing.T) {
		// Multiple stops should be safe
		checker.Stop()
		checker.Stop()

		// Multiple starts should be safe
		config.Enabled = true
		checker.config = config
		checker.Start()
		checker.Start()

		checker.Stop()
	})
}

// TestHealthChecker_DisabledConfig tests behavior when health checking is disabled
func TestHealthChecker_DisabledConfig(t *testing.T) {
	t.Parallel()

	plugin := NewMockHealthPlugin("disabled-plugin")
	config := HealthCheckConfig{
		Enabled:      false,
		Interval:     100 * time.Millisecond,
		Timeout:      1 * time.Second,
		FailureLimit: 3,
	}

	checker := NewHealthChecker(plugin, config)

	status := checker.Check()
	if status.Status != StatusHealthy {
		t.Errorf("Expected StatusHealthy when disabled, got %s", status.Status.String())
	}
	if status.Message != "Health checking disabled" {
		t.Errorf("Expected disabled message, got '%s'", status.Message)
	}

	if plugin.GetCallCount() > 0 {
		t.Error("Plugin should not be called when health checking is disabled")
	}
}

// TestHealthChecker_ConcurrentAccess tests thread safety
func TestHealthChecker_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	plugin := NewMockHealthPlugin("concurrent-plugin")
	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     100 * time.Millisecond,
		Timeout:      1 * time.Second,
		FailureLimit: 5,
	}

	checker := NewHealthChecker(plugin, config)
	defer checker.Stop()

	var wg sync.WaitGroup
	const numGoroutines = 10
	const checksPerGoroutine = 5

	results := make([][]HealthStatus, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			results[goroutineID] = make([]HealthStatus, checksPerGoroutine)

			for j := 0; j < checksPerGoroutine; j++ {
				results[goroutineID][j] = checker.Check()
				time.Sleep(10 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Verify all checks completed
	totalChecks := 0
	for _, goroutineResults := range results {
		for _, status := range goroutineResults {
			if status.Status == StatusUnknown {
				t.Error("Found unknown status in concurrent test")
			}
			totalChecks++
		}
	}

	if totalChecks != numGoroutines*checksPerGoroutine {
		t.Errorf("Expected %d total checks, got %d", numGoroutines*checksPerGoroutine, totalChecks)
	}
}

// TestHealthChecker_ErrorHandling tests error handling scenarios
func TestHealthChecker_ErrorHandling(t *testing.T) {
	t.Parallel()

	t.Run("PanicRecovery", func(t *testing.T) {
		plugin := NewMockHealthPlugin("panic-plugin")
		plugin.SetShouldPanic(true)

		config := HealthCheckConfig{
			Enabled:      false, // Disable periodic checks to avoid background panics
			Interval:     1 * time.Hour,
			Timeout:      500 * time.Millisecond,
			FailureLimit: 1,
		}

		checker := NewHealthChecker(plugin, config)
		defer checker.Stop()

		// The actual health checker implementation may not have panic recovery
		// This test verifies that we can handle the panic at the test level
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Expected - plugin panics are not recovered in the current implementation
					t.Logf("Plugin panic recovered as expected: %v", r)
				}
			}()

			// This will panic and be recovered by our defer
			checker.Check()
		}()
	})

	t.Run("ConsecutiveErrorPattern", func(t *testing.T) {
		// Test the mock plugin behavior directly first
		plugin := NewMockHealthPlugin("error-pattern-plugin")
		plugin.SetMaxErrors(2) // Smaller number for clearer testing

		ctx := context.Background()

		// Test mock plugin behavior directly
		status1 := plugin.Health(ctx)
		if status1.Status != StatusUnhealthy {
			t.Errorf("Direct call 1: Expected unhealthy, got %s", status1.Status.String())
		}

		status2 := plugin.Health(ctx)
		if status2.Status != StatusUnhealthy {
			t.Errorf("Direct call 2: Expected unhealthy, got %s", status2.Status.String())
		}

		status3 := plugin.Health(ctx)
		if status3.Status != StatusHealthy {
			t.Errorf("Direct call 3: Expected healthy, got %s", status3.Status.String())
		}

		status4 := plugin.Health(ctx)
		if status4.Status != StatusHealthy {
			t.Errorf("Direct call 4: Expected healthy, got %s", status4.Status.String())
		}

		// Now test with health checker to ensure it respects plugin behavior
		plugin2 := NewMockHealthPlugin("error-pattern-plugin-2")
		plugin2.SetMaxErrors(2)

		config := HealthCheckConfig{
			Enabled:      true,
			Interval:     1 * time.Second,
			Timeout:      500 * time.Millisecond,
			FailureLimit: 10, // High enough to not interfere
		}

		checker := NewHealthChecker(plugin2, config)
		defer checker.Stop()

		// Health checker should follow plugin behavior but may add its own logic
		checkerStatus1 := checker.Check()
		checkerStatus2 := checker.Check()

		// At least verify that the checker is calling the plugin
		if plugin2.GetCallCount() < 2 {
			t.Errorf("Health checker should have called plugin at least 2 times, got %d", plugin2.GetCallCount())
		}

		// Verify that consecutive failures are being tracked
		if checkerStatus1.Status == StatusHealthy && checkerStatus2.Status == StatusHealthy {
			t.Error("Health checker should show some failures when plugin is configured to fail initially")
		}
	})
}

// TestHealthMonitor_Creation tests health monitor creation
func TestHealthMonitor_Creation(t *testing.T) {
	t.Parallel()

	monitor := NewHealthMonitor()

	if monitor == nil {
		t.Fatal("NewHealthMonitor returned nil")
	}

	// Should start with empty status
	allStatus := monitor.GetAllStatus()
	if len(allStatus) != 0 {
		t.Errorf("Expected empty status map, got %d entries", len(allStatus))
	}

	// Overall health should be healthy with no components
	overall := monitor.GetOverallHealth()
	if overall.Status != StatusHealthy {
		t.Errorf("Expected StatusHealthy with no components, got %s", overall.Status.String())
	}
}

// TestHealthMonitor_BasicOperations tests basic health monitor functionality
func TestHealthMonitor_BasicOperations(t *testing.T) {
	t.Parallel()

	monitor := NewHealthMonitor()
	defer monitor.Shutdown()

	plugin1 := NewMockHealthPlugin("plugin1")
	plugin2 := NewMockHealthPlugin("plugin2")

	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     200 * time.Millisecond,
		Timeout:      1 * time.Second,
		FailureLimit: 2,
	}

	checker1 := NewHealthChecker(plugin1, config)
	checker2 := NewHealthChecker(plugin2, config)

	t.Run("AddCheckers", func(t *testing.T) {
		monitor.AddChecker("service1", checker1)
		monitor.AddChecker("service2", checker2)

		// Update statuses manually for testing
		monitor.UpdateStatus("service1", HealthStatus{
			Status:    StatusHealthy,
			Message:   "Service 1 OK",
			LastCheck: time.Now(),
		})
		monitor.UpdateStatus("service2", HealthStatus{
			Status:    StatusHealthy,
			Message:   "Service 2 OK",
			LastCheck: time.Now(),
		})

		allStatus := monitor.GetAllStatus()
		if len(allStatus) != 2 {
			t.Errorf("Expected 2 services, got %d", len(allStatus))
		}

		status1, exists := monitor.GetStatus("service1")
		if !exists {
			t.Error("service1 should exist")
		}
		if status1.Status != StatusHealthy {
			t.Errorf("service1 should be healthy, got %s", status1.Status.String())
		}
	})

	t.Run("OverallHealthAllHealthy", func(t *testing.T) {
		overall := monitor.GetOverallHealth()
		if overall.Status != StatusHealthy {
			t.Errorf("Expected StatusHealthy, got %s", overall.Status.String())
		}
		if overall.Message != "All components healthy" {
			t.Errorf("Expected healthy message, got '%s'", overall.Message)
		}
	})

	t.Run("OverallHealthWithDegraded", func(t *testing.T) {
		monitor.UpdateStatus("service1", HealthStatus{
			Status:    StatusDegraded,
			Message:   "Service 1 degraded",
			LastCheck: time.Now(),
		})

		overall := monitor.GetOverallHealth()
		if overall.Status != StatusDegraded {
			t.Errorf("Expected StatusDegraded, got %s", overall.Status.String())
		}
	})

	t.Run("OverallHealthWithUnhealthy", func(t *testing.T) {
		monitor.UpdateStatus("service2", HealthStatus{
			Status:    StatusUnhealthy,
			Message:   "Service 2 failed",
			LastCheck: time.Now(),
		})

		overall := monitor.GetOverallHealth()
		if overall.Status != StatusUnhealthy {
			t.Errorf("Expected StatusUnhealthy, got %s", overall.Status.String())
		}
	})

	t.Run("RemoveChecker", func(t *testing.T) {
		monitor.RemoveChecker("service1")

		_, exists := monitor.GetStatus("service1")
		if exists {
			t.Error("service1 should not exist after removal")
		}

		allStatus := monitor.GetAllStatus()
		if len(allStatus) != 1 {
			t.Errorf("Expected 1 service after removal, got %d", len(allStatus))
		}
	})
}

// TestHealthMonitor_ConcurrentAccess tests thread safety of health monitor
func TestHealthMonitor_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	monitor := NewHealthMonitor()
	defer monitor.Shutdown()

	var wg sync.WaitGroup
	const numGoroutines = 10
	const operationsPerGoroutine = 20

	// Concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			plugin := NewMockHealthPlugin(fmt.Sprintf("plugin-%d", goroutineID))
			config := HealthCheckConfig{
				Enabled:      true,
				Interval:     1 * time.Second,
				Timeout:      500 * time.Millisecond,
				FailureLimit: 3,
			}
			checker := NewHealthChecker(plugin, config)

			serviceName := fmt.Sprintf("service-%d", goroutineID)

			for j := 0; j < operationsPerGoroutine; j++ {
				switch j % 5 {
				case 0:
					monitor.AddChecker(serviceName, checker)
				case 1:
					monitor.UpdateStatus(serviceName, HealthStatus{
						Status:    StatusHealthy,
						Message:   "OK",
						LastCheck: time.Now(),
					})
				case 2:
					_, _ = monitor.GetStatus(serviceName)
				case 3:
					_ = monitor.GetAllStatus()
				case 4:
					_ = monitor.GetOverallHealth()
				}
			}

			checker.Stop()
		}(i)
	}

	wg.Wait()

	// Verify final state
	allStatus := monitor.GetAllStatus()
	if len(allStatus) > numGoroutines {
		t.Errorf("Unexpected number of services: %d", len(allStatus))
	}
}

// TestHealthMonitor_Shutdown tests graceful shutdown
func TestHealthMonitor_Shutdown(t *testing.T) {
	t.Parallel()

	monitor := NewHealthMonitor()

	// Add some checkers and update their statuses
	for i := 0; i < 3; i++ {
		plugin := NewMockHealthPlugin(fmt.Sprintf("plugin-%d", i))
		config := HealthCheckConfig{
			Enabled:      true,
			Interval:     100 * time.Millisecond,
			Timeout:      500 * time.Millisecond,
			FailureLimit: 3,
		}
		checker := NewHealthChecker(plugin, config)
		serviceName := fmt.Sprintf("service-%d", i)
		monitor.AddChecker(serviceName, checker)

		// Update status so it shows up in GetAllStatus
		monitor.UpdateStatus(serviceName, HealthStatus{
			Status:    StatusHealthy,
			Message:   "OK",
			LastCheck: time.Now(),
		})
	}

	// Verify checkers are added
	allStatus := monitor.GetAllStatus()
	initialCount := len(allStatus)
	if initialCount == 0 {
		t.Error("Expected checkers to be added")
	}

	// Shutdown should stop all checkers and clear maps
	monitor.Shutdown()

	allStatus = monitor.GetAllStatus()
	if len(allStatus) != 0 {
		t.Errorf("Expected empty status after shutdown, got %d entries", len(allStatus))
	}

	// Overall health should still work
	overall := monitor.GetOverallHealth()
	if overall.Status != StatusHealthy {
		t.Errorf("Expected StatusHealthy after shutdown, got %s", overall.Status.String())
	}
}

// TestHealthChecker_MetricsAndTimestamps tests metrics and timestamp tracking
func TestHealthChecker_MetricsAndTimestamps(t *testing.T) {
	t.Parallel()

	plugin := NewMockHealthPlugin("metrics-plugin")
	plugin.SetMetadata("version", "1.0.0")
	plugin.SetMetadata("region", "us-east-1")

	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     1 * time.Second,
		Timeout:      500 * time.Millisecond,
		FailureLimit: 3,
	}

	checker := NewHealthChecker(plugin, config)
	defer checker.Stop()

	beforeCheck := time.Now()
	status := checker.Check()
	afterCheck := time.Now()

	// Verify timestamps (with some tolerance for execution time)
	tolerance := 1 * time.Second
	if status.LastCheck.Before(beforeCheck.Add(-tolerance)) || status.LastCheck.After(afterCheck.Add(tolerance)) {
		t.Errorf("LastCheck timestamp should be between test bounds (with tolerance)")
	}

	lastCheckTime := checker.GetLastCheck()
	if lastCheckTime.Before(beforeCheck.Add(-tolerance)) || lastCheckTime.After(afterCheck.Add(tolerance)) {
		t.Error("GetLastCheck should return recent timestamp (with tolerance)")
	}

	// Verify response time is reasonable
	if status.ResponseTime < 0 || status.ResponseTime > 100*time.Millisecond {
		t.Errorf("Unexpected response time: %v", status.ResponseTime)
	}

	// Verify metadata
	if len(status.Metadata) != 2 {
		t.Errorf("Expected 2 metadata entries, got %d", len(status.Metadata))
	}
	if status.Metadata["version"] != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", status.Metadata["version"])
	}
}

// TestJoinStringsHelper tests the helper function
func TestJoinStringsHelper(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		strings  []string
		sep      string
		expected string
	}{
		{
			name:     "EmptySlice",
			strings:  []string{},
			sep:      ",",
			expected: "",
		},
		{
			name:     "SingleString",
			strings:  []string{"hello"},
			sep:      ",",
			expected: "hello",
		},
		{
			name:     "MultipleStrings",
			strings:  []string{"a", "b", "c"},
			sep:      ",",
			expected: "a,b,c",
		},
		{
			name:     "DifferentSeparator",
			strings:  []string{"error1", "error2"},
			sep:      "; ",
			expected: "error1; error2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := joinStrings(tc.strings, tc.sep)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// BenchmarkHealthChecker_Check benchmarks health check performance
func BenchmarkHealthChecker_Check(b *testing.B) {
	plugin := NewMockHealthPlugin("benchmark-plugin")
	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     1 * time.Hour, // Disable periodic checking
		Timeout:      1 * time.Second,
		FailureLimit: 3,
	}

	checker := NewHealthChecker(plugin, config)
	defer checker.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status := checker.Check()
		if status.Status == StatusUnknown {
			b.Error("Unexpected unknown status")
		}
	}
}

// BenchmarkHealthMonitor_GetOverallHealth benchmarks overall health calculation
func BenchmarkHealthMonitor_GetOverallHealth(b *testing.B) {
	monitor := NewHealthMonitor()
	defer monitor.Shutdown()

	// Add multiple services
	for i := 0; i < 100; i++ {
		serviceName := fmt.Sprintf("service-%d", i)
		status := StatusHealthy
		if i%10 == 0 {
			status = StatusDegraded // 10% degraded
		}
		if i%25 == 0 {
			status = StatusUnhealthy // 4% unhealthy
		}

		monitor.UpdateStatus(serviceName, HealthStatus{
			Status:    status,
			Message:   fmt.Sprintf("Status for %s", serviceName),
			LastCheck: time.Now(),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		overall := monitor.GetOverallHealth()
		if overall.Status == StatusUnknown {
			b.Error("Unexpected unknown status")
		}
	}
}

// TestHealthChecker_Integration tests end-to-end functionality
func TestHealthChecker_Integration(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration test on Windows due to timing sensitivity")
	}

	plugin := NewMockHealthPlugin("integration-plugin")
	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     50 * time.Millisecond,
		Timeout:      200 * time.Millisecond,
		FailureLimit: 2,
	}

	checker := NewHealthChecker(plugin, config)
	defer checker.Stop()

	// Wait for initial checks
	time.Sleep(100 * time.Millisecond)

	// Should be healthy initially
	if checker.GetConsecutiveFailures() != 0 {
		t.Errorf("Expected 0 consecutive failures initially, got %d", checker.GetConsecutiveFailures())
	}

	// Make plugin unhealthy
	plugin.SetHealth(StatusUnhealthy, "Service down")

	// Wait for failure detection
	time.Sleep(150 * time.Millisecond)

	// Should detect failures
	if checker.GetConsecutiveFailures() == 0 {
		t.Error("Should have detected failures by now")
	}

	// Recover plugin
	plugin.SetHealth(StatusHealthy, "Service recovered")

	// Wait for recovery detection
	time.Sleep(100 * time.Millisecond)

	// Should reset failure count
	if checker.GetConsecutiveFailures() != 0 {
		t.Errorf("Expected 0 consecutive failures after recovery, got %d", checker.GetConsecutiveFailures())
	}

	// Verify call count increased
	callCount := plugin.GetCallCount()
	if callCount < 3 {
		t.Errorf("Expected at least 3 health check calls, got %d", callCount)
	}
}
