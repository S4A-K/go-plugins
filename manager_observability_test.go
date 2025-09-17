// manager_observability_test.go: Safety tests for observability manager
//
// These tests ensure that the extracted observability functionality
// works correctly and maintains the same behavior as the original
// implementation in manager.go.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"errors"
	"testing"
	"time"
)

// TestObservabilityManagerCreation tests the creation of ObservabilityManager.
func TestObservabilityManagerCreation(t *testing.T) {
	logger := NewTestLogger()
	config := DefaultObservabilityConfig()

	om := NewObservabilityManager(config, logger)

	if om == nil {
		t.Fatal("ObservabilityManager should not be nil")
	}

	if om.config.Level != config.Level {
		t.Errorf("Expected level %v, got %v", config.Level, om.config.Level)
	}

	if om.metricsCollector != config.MetricsCollector {
		t.Error("MetricsCollector should be set from config")
	}

	if om.totalRequests == nil {
		t.Error("totalRequests should be initialized")
	}

	if om.pluginMetrics == nil {
		t.Error("pluginMetrics map should be initialized")
	}
}

// TestObservabilityManagerMetricsRecording tests metrics recording functionality.
func TestObservabilityManagerMetricsRecording(t *testing.T) {
	logger := NewTestLogger()
	config := DefaultObservabilityConfig()
	config.Level = ObservabilityStandard // Enable metrics

	om := NewObservabilityManager(config, logger)

	pluginName := "test-plugin"

	// Test recording start
	om.RecordObservabilityStart(pluginName)

	// Check that metrics were created
	metrics := om.GetPluginMetrics(pluginName)
	if metrics == nil {
		t.Fatal("Plugin metrics should be created")
	}

	if metrics.TotalRequests.Load() != 1 {
		t.Errorf("Expected 1 total request, got %d", metrics.TotalRequests.Load())
	}

	if metrics.ActiveRequests.Load() != 1 {
		t.Errorf("Expected 1 active request, got %d", metrics.ActiveRequests.Load())
	}

	if om.totalRequests.Load() != 1 {
		t.Errorf("Expected 1 global total request, got %d", om.totalRequests.Load())
	}

	// Test recording end (success)
	duration := 100 * time.Millisecond
	om.RecordObservabilityEnd(pluginName, duration, nil)

	if metrics.ActiveRequests.Load() != 0 {
		t.Errorf("Expected 0 active requests after end, got %d", metrics.ActiveRequests.Load())
	}

	if metrics.SuccessfulRequests.Load() != 1 {
		t.Errorf("Expected 1 successful request, got %d", metrics.SuccessfulRequests.Load())
	}

	if metrics.FailedRequests.Load() != 0 {
		t.Errorf("Expected 0 failed requests, got %d", metrics.FailedRequests.Load())
	}

	// Test recording end (failure)
	om.RecordObservabilityStart(pluginName)
	om.RecordObservabilityEnd(pluginName, duration, errors.New("test error"))

	if metrics.FailedRequests.Load() != 1 {
		t.Errorf("Expected 1 failed request, got %d", metrics.FailedRequests.Load())
	}

	if om.totalErrors.Load() != 1 {
		t.Errorf("Expected 1 global error, got %d", om.totalErrors.Load())
	}
}

// TestObservabilityManagerCircuitBreakerMetrics tests circuit breaker metrics.
func TestObservabilityManagerCircuitBreakerMetrics(t *testing.T) {
	logger := NewTestLogger()
	config := DefaultObservabilityConfig()
	config.Level = ObservabilityStandard

	om := NewObservabilityManager(config, logger)

	pluginName := "test-plugin"

	// Record circuit breaker state change
	om.RecordCircuitBreakerMetrics(pluginName, StateOpen)

	metrics := om.GetPluginMetrics(pluginName)
	if metrics == nil {
		t.Fatal("Plugin metrics should be created")
	}

	if state := metrics.CircuitBreakerState.Load().(string); state != "open" {
		t.Errorf("Expected circuit breaker state 'open', got '%s'", state)
	}

	if metrics.CircuitBreakerTrips.Load() != 1 {
		t.Errorf("Expected 1 circuit breaker trip, got %d", metrics.CircuitBreakerTrips.Load())
	}

	if om.managerMetrics.CircuitBreakerTrips.Load() != 1 {
		t.Errorf("Expected 1 manager circuit breaker trip, got %d", om.managerMetrics.CircuitBreakerTrips.Load())
	}
}

// TestObservabilityManagerGetMetrics tests metrics retrieval.
func TestObservabilityManagerGetMetrics(t *testing.T) {
	logger := NewTestLogger()
	config := DefaultObservabilityConfig()
	config.Level = ObservabilityStandard

	om := NewObservabilityManager(config, logger)

	pluginName := "test-plugin"

	// Record some activity
	om.RecordObservabilityStart(pluginName)
	om.RecordObservabilityEnd(pluginName, 50*time.Millisecond, nil)
	om.RecordCircuitBreakerMetrics(pluginName, StateClosed)

	// Get metrics
	allMetrics := om.GetObservabilityMetrics()

	// Check global metrics
	globalMetrics, ok := allMetrics["global"].(map[string]interface{})
	if !ok {
		t.Fatal("Global metrics should be present")
	}

	if globalMetrics["total_requests"].(int64) != 1 {
		t.Errorf("Expected 1 global total request, got %v", globalMetrics["total_requests"])
	}

	// Check plugin metrics
	pluginMetricsMap, ok := allMetrics["plugins"].(map[string]interface{})
	if !ok {
		t.Fatal("Plugin metrics should be present")
	}

	pluginData, ok := pluginMetricsMap[pluginName].(map[string]interface{})
	if !ok {
		t.Fatal("Test plugin metrics should be present")
	}

	if pluginData["successful_requests"].(int64) != 1 {
		t.Errorf("Expected 1 successful request, got %v", pluginData["successful_requests"])
	}

	if pluginData["success_rate"].(float64) != 100.0 {
		t.Errorf("Expected 100%% success rate, got %v", pluginData["success_rate"])
	}
}

// TestObservabilityManagerConfiguration tests configuration updates.
func TestObservabilityManagerConfiguration(t *testing.T) {
	logger := NewTestLogger()
	config := DefaultObservabilityConfig()

	om := NewObservabilityManager(config, logger)

	// Test initial configuration
	if !om.IsMetricsEnabled() {
		t.Error("Metrics should be enabled by default")
	}

	// Test configuration update
	newConfig := DefaultObservabilityConfig()
	newConfig.Level = ObservabilityDisabled

	err := om.ConfigureObservability(newConfig)
	if err != nil {
		t.Fatalf("ConfigureObservability failed: %v", err)
	}

	if om.IsMetricsEnabled() {
		t.Error("Metrics should be disabled after config update")
	}

	// Test that disabled metrics don't record
	pluginName := "test-plugin"
	om.RecordObservabilityStart(pluginName)

	// With disabled metrics, plugin metrics shouldn't be created
	metrics := om.GetPluginMetrics(pluginName)
	if metrics != nil {
		t.Error("Plugin metrics should not be created when disabled")
	}
}

// TestObservabilityManagerCompatibility tests compatibility with existing behavior.
func TestObservabilityManagerCompatibility(t *testing.T) {
	// This test ensures that the extracted ObservabilityManager
	// behaves identically to the original manager.go implementation

	logger := NewTestLogger()
	config := DefaultObservabilityConfig()
	config.Level = ObservabilityStandard

	om := NewObservabilityManager(config, logger)

	pluginName := "compatibility-test-plugin"

	// Simulate the exact sequence that manager.go would do
	om.RecordObservabilityStart(pluginName)

	// Simulate processing time
	time.Sleep(1 * time.Millisecond)

	om.RecordObservabilityEnd(pluginName, 1*time.Millisecond, nil)
	om.RecordCircuitBreakerMetrics(pluginName, StateClosed)

	// Verify the metrics match expected behavior
	allMetrics := om.GetObservabilityMetrics()

	// Check that all expected metric categories are present
	expectedCategories := []string{"global", "manager", "plugins", "collector", "prometheus", "circuit_breaker_states", "health_status"}

	for _, category := range expectedCategories {
		if _, exists := allMetrics[category]; !exists {
			t.Errorf("Expected metric category '%s' to be present", category)
		}
	}

	// Check circuit breaker states
	cbStates, ok := allMetrics["circuit_breaker_states"].(map[string]string)
	if !ok {
		t.Fatal("Circuit breaker states should be a map[string]string")
	}

	if cbStates[pluginName] != "closed" {
		t.Errorf("Expected circuit breaker state 'closed', got '%s'", cbStates[pluginName])
	}
}
