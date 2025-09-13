// advanced_features_test.go: Tests for the advanced features implemented
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"
)

// TestLoadBalancerRoundRobin tests round-robin load balancing
func TestLoadBalancerRoundRobin(t *testing.T) {
	logger := slog.Default()
	lb := NewLoadBalancer[string, string](StrategyRoundRobin, logger)

	// Add multiple plugins
	plugin1 := &MockPlugin{name: "plugin1", version: "1.0.0", healthy: true, response: "response1"}
	plugin2 := &MockPlugin{name: "plugin2", version: "1.0.0", healthy: true, response: "response2"}
	plugin3 := &MockPlugin{name: "plugin3", version: "1.0.0", healthy: true, response: "response3"}

	err := lb.AddPlugin("plugin1", plugin1, 1, 1)
	if err != nil {
		t.Fatalf("Failed to add plugin1: %v", err)
	}

	err = lb.AddPlugin("plugin2", plugin2, 1, 1)
	if err != nil {
		t.Fatalf("Failed to add plugin2: %v", err)
	}

	err = lb.AddPlugin("plugin3", plugin3, 1, 1)
	if err != nil {
		t.Fatalf("Failed to add plugin3: %v", err)
	}

	// Test round-robin selection
	selections := make(map[string]int)
	for i := 0; i < 9; i++ {
		name, _, err := lb.SelectPlugin(LoadBalanceRequest{RequestID: "test"})
		if err != nil {
			t.Fatalf("Failed to select plugin: %v", err)
		}
		selections[name]++
	}

	// Each plugin should be selected 3 times
	for pluginName, count := range selections {
		if count != 3 {
			t.Errorf("Plugin %s was selected %d times, expected 3", pluginName, count)
		}
	}
}

// TestLoadBalancerLeastConnections tests least connections load balancing
func TestLoadBalancerLeastConnections(t *testing.T) {
	logger := slog.Default()
	lb := NewLoadBalancer[string, string](StrategyLeastConnections, logger)

	// Add multiple plugins
	plugin1 := &MockPlugin{name: "plugin1", version: "1.0.0", healthy: true, response: "response1"}
	plugin2 := &MockPlugin{name: "plugin2", version: "1.0.0", healthy: true, response: "response2"}

	err := lb.AddPlugin("plugin1", plugin1, 1, 1)
	if err != nil {
		t.Fatalf("Failed to add plugin1: %v", err)
	}

	err = lb.AddPlugin("plugin2", plugin2, 1, 1)
	if err != nil {
		t.Fatalf("Failed to add plugin2: %v", err)
	}

	// Simulate different connection counts
	wrapper1 := lb.plugins["plugin1"]
	wrapper2 := lb.plugins["plugin2"]

	wrapper1.Active.Store(5) // plugin1 has 5 active connections
	wrapper2.Active.Store(2) // plugin2 has 2 active connections

	// Should select plugin2 (least connections)
	name, _, err := lb.SelectPlugin(LoadBalanceRequest{RequestID: "test"})
	if err != nil {
		t.Fatalf("Failed to select plugin: %v", err)
	}

	if name != "plugin2" {
		t.Errorf("Expected plugin2 to be selected (least connections), got %s", name)
	}
}

// TestLoadBalancerWeightedRandom tests weighted random load balancing
func TestLoadBalancerWeightedRandom(t *testing.T) {
	logger := slog.Default()
	lb := NewLoadBalancer[string, string](StrategyWeightedRandom, logger)

	// Add plugins with different weights
	plugin1 := &MockPlugin{name: "plugin1", version: "1.0.0", healthy: true, response: "response1"}
	plugin2 := &MockPlugin{name: "plugin2", version: "1.0.0", healthy: true, response: "response2"}

	err := lb.AddPlugin("plugin1", plugin1, 9, 1) // Weight 9
	if err != nil {
		t.Fatalf("Failed to add plugin1: %v", err)
	}

	err = lb.AddPlugin("plugin2", plugin2, 1, 1) // Weight 1
	if err != nil {
		t.Fatalf("Failed to add plugin2: %v", err)
	}

	// Test selections - plugin1 should be selected more often
	selections := make(map[string]int)
	for i := 0; i < 1000; i++ {
		name, _, err := lb.SelectPlugin(LoadBalanceRequest{RequestID: "test"})
		if err != nil {
			t.Fatalf("Failed to select plugin: %v", err)
		}
		selections[name]++
	}

	// Plugin1 should be selected approximately 9 times more often
	ratio := float64(selections["plugin1"]) / float64(selections["plugin2"])
	if ratio < 5 || ratio > 15 { // Allow some variance
		t.Errorf("Expected ratio around 9, got %.2f (plugin1: %d, plugin2: %d)",
			ratio, selections["plugin1"], selections["plugin2"])
	}
}

// TestHotReloadConfigDiff tests configuration diff calculation
func TestHotReloadConfigDiff(t *testing.T) {
	logger := slog.Default()
	manager := NewManager[string, string](logger)
	reloader := NewPluginReloader(manager, DefaultReloadOptions(), logger)

	oldConfig, newConfig := createTestConfigs()
	diff := reloader.calculateDiff(oldConfig, newConfig)

	validateAddedPlugins(t, diff)
	validateUpdatedPlugins(t, diff)
	validateRemovedPlugins(t, diff)
	validatePluginChanges(t, diff)
}

// createTestConfigs creates old and new configurations for testing
func createTestConfigs() (ManagerConfig, ManagerConfig) {
	oldConfig := ManagerConfig{
		Plugins: []PluginConfig{
			{
				Name:      "plugin1",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8080",
				Enabled:   true,
			},
			{
				Name:      "plugin2",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8081",
				Enabled:   true,
			},
		},
	}

	newConfig := ManagerConfig{
		Plugins: []PluginConfig{
			{
				Name:      "plugin1",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:9080", // Changed endpoint
				Enabled:   true,
			},
			{
				Name:      "plugin3", // New plugin
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8082",
				Enabled:   true,
			},
		},
		// plugin2 is removed
	}

	return oldConfig, newConfig
}

// validateAddedPlugins checks added plugins in diff
func validateAddedPlugins(t *testing.T, diff PluginDiff) {
	if len(diff.Added) != 1 || diff.Added[0].Name != "plugin3" {
		t.Errorf("Expected 1 added plugin (plugin3), got %d: %+v", len(diff.Added), diff.Added)
	}
}

// validateUpdatedPlugins checks updated plugins in diff
func validateUpdatedPlugins(t *testing.T, diff PluginDiff) {
	if len(diff.Updated) != 1 || diff.Updated[0].Name != "plugin1" {
		t.Errorf("Expected 1 updated plugin (plugin1), got %d: %+v", len(diff.Updated), diff.Updated)
	}
}

// validateRemovedPlugins checks removed plugins in diff
func validateRemovedPlugins(t *testing.T, diff PluginDiff) {
	if len(diff.Removed) != 1 || diff.Removed[0] != "plugin2" {
		t.Errorf("Expected 1 removed plugin (plugin2), got %d: %+v", len(diff.Removed), diff.Removed)
	}
}

// validatePluginChanges checks specific changes in updated plugins
func validatePluginChanges(t *testing.T, diff PluginDiff) {
	if len(diff.Updated) == 0 {
		return
	}

	changes := diff.Updated[0].Changes
	expectedChange := "endpoint"
	found := false
	for _, change := range changes {
		if change == expectedChange {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected change '%s' not found in: %+v", expectedChange, changes)
	}
}

// TestObservabilityMetrics tests the observability system
func TestObservabilityMetrics(t *testing.T) {
	logger := slog.Default()
	baseManager := NewManager[string, string](logger)

	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	// Register a test plugin
	plugin := &MockPlugin{
		name:     "test-plugin",
		version:  "1.0.0",
		healthy:  true,
		response: "test-response",
	}

	err := observableManager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Execute some requests
	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-1",
		Timeout:   30 * time.Second,
	}

	// Successful request
	_, err = observableManager.ExecuteWithObservability(ctx, "test-plugin", execCtx, "test-request")
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

	// Get metrics
	report := observableManager.GetObservabilityMetrics()

	// Verify global metrics
	if report.Global.TotalRequests != 1 {
		t.Errorf("Expected 1 total request, got %d", report.Global.TotalRequests)
	}

	if report.Global.TotalErrors != 0 {
		t.Errorf("Expected 0 total errors, got %d", report.Global.TotalErrors)
	}

	// Verify plugin-specific metrics
	pluginMetrics, exists := report.Plugins["test-plugin"]
	if !exists {
		t.Fatal("Expected plugin metrics for test-plugin")
	}

	if pluginMetrics.TotalRequests != 1 {
		t.Errorf("Expected 1 plugin request, got %d", pluginMetrics.TotalRequests)
	}

	if pluginMetrics.SuccessfulRequests != 1 {
		t.Errorf("Expected 1 successful request, got %d", pluginMetrics.SuccessfulRequests)
	}

	if pluginMetrics.SuccessRate != 100.0 {
		t.Errorf("Expected 100%% success rate, got %.2f", pluginMetrics.SuccessRate)
	}
}

// TestDefaultMetricsCollector tests the default metrics collector
func TestDefaultMetricsCollector(t *testing.T) {
	collector := NewDefaultMetricsCollector()

	// Test counter
	labels := map[string]string{"plugin": "test"}
	collector.IncrementCounter("requests_total", labels, 1)
	collector.IncrementCounter("requests_total", labels, 2)

	// Test gauge
	collector.SetGauge("active_connections", labels, 10.5)

	// Test histogram
	collector.RecordHistogram("request_duration", labels, 0.1)
	collector.RecordHistogram("request_duration", labels, 0.2)
	collector.RecordHistogram("request_duration", labels, 0.15)

	// Get metrics
	metrics := collector.GetMetrics()

	// Verify counter
	expectedCounterKey := "requests_total_plugin_test"
	if metrics[expectedCounterKey] != int64(3) {
		t.Errorf("Expected counter value 3, got %v", metrics[expectedCounterKey])
	}

	// Verify gauge
	expectedGaugeKey := "active_connections_plugin_test"
	if metrics[expectedGaugeKey] != 10.5 {
		t.Errorf("Expected gauge value 10.5, got %v", metrics[expectedGaugeKey])
	}

	// Verify histogram stats
	expectedHistKey := "request_duration_plugin_test"
	if metrics[expectedHistKey+"_count"] != 3 {
		t.Errorf("Expected histogram count 3, got %v", metrics[expectedHistKey+"_count"])
	}

	avgValue, ok := metrics[expectedHistKey+"_avg"].(float64)
	if !ok {
		t.Fatalf("Expected histogram average to be float64, got %T", metrics[expectedHistKey+"_avg"])
	}
	if avgValue < 0.149 || avgValue > 0.151 {
		t.Errorf("Expected histogram average around 0.15, got %v", avgValue)
	}
}

// TestCircuitBreakerIntegration tests circuit breaker with load balancer
func TestCircuitBreakerIntegration(t *testing.T) {
	logger := slog.Default()
	manager := NewManager[string, string](logger)

	// Create a plugin that will fail
	failingPlugin := &MockPlugin{
		name:     "failing-plugin",
		version:  "1.0.0",
		healthy:  false, // This will cause health checks to fail
		response: "should-not-return",
	}

	err := manager.Register(failingPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	ctx := context.Background()

	// Execute requests until circuit breaker trips
	var lastErr error
	for i := 0; i < 10; i++ {
		_, lastErr = manager.Execute(ctx, "failing-plugin", "test-request")
		if lastErr != nil && lastErr.Error() == "circuit breaker is open for plugin failing-plugin" {
			break
		}
	}

	// Verify circuit breaker tripped
	if lastErr == nil || lastErr.Error() != "circuit breaker is open for plugin failing-plugin" {
		t.Errorf("Expected circuit breaker to trip, got error: %v", lastErr)
	}
}

// TestPluginFactories tests plugin factory system
func TestPluginFactories(t *testing.T) {
	logger := slog.Default()
	manager := NewManager[string, string](logger)

	// Register HTTP factory
	httpFactory := NewHTTPPluginFactory[string, string]()
	err := manager.RegisterFactory("http", httpFactory)
	if err != nil {
		t.Fatalf("Failed to register HTTP factory: %v", err)
	}

	// Test supported transports
	transports := httpFactory.SupportedTransports()
	expectedTransports := []string{"http", "https"}

	if len(transports) != len(expectedTransports) {
		t.Errorf("Expected %d transports, got %d", len(expectedTransports), len(transports))
	}

	for i, transport := range transports {
		if transport != expectedTransports[i] {
			t.Errorf("Expected transport %s, got %s", expectedTransports[i], transport)
		}
	}

	// Test config validation
	validConfig := PluginConfig{
		Name:      "test-http-plugin",
		Type:      "http",
		Transport: TransportHTTP,
		Endpoint:  "http://localhost:8080",
		Auth:      AuthConfig{Method: AuthNone},
	}

	err = httpFactory.ValidateConfig(validConfig)
	if err != nil {
		t.Errorf("Valid config should not produce error: %v", err)
	}

	// Test invalid config
	invalidConfig := validConfig
	invalidConfig.Endpoint = ""

	err = httpFactory.ValidateConfig(invalidConfig)
	if err == nil {
		t.Error("Invalid config should produce error")
	}
}

// BenchmarkLoadBalancer benchmarks load balancer performance
func BenchmarkLoadBalancer(b *testing.B) {
	logger := slog.Default()
	lb := NewLoadBalancer[string, string](StrategyRoundRobin, logger)

	// Add plugins
	for i := 0; i < 10; i++ {
		plugin := &MockPlugin{
			name:     fmt.Sprintf("plugin%d", i),
			version:  "1.0.0",
			healthy:  true,
			response: fmt.Sprintf("response%d", i),
		}
		if err := lb.AddPlugin(plugin.name, plugin, 1, 1); err != nil {
			b.Fatalf("Failed to add plugin: %v", err)
		}
	}

	lbReq := LoadBalanceRequest{RequestID: "bench"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := lb.SelectPlugin(lbReq)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkObservability benchmarks observability overhead
func BenchmarkObservability(b *testing.B) {
	logger := slog.Default()
	baseManager := NewManager[string, string](logger)

	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	// Register a test plugin
	plugin := &MockPlugin{
		name:     "bench-plugin",
		version:  "1.0.0",
		healthy:  true,
		response: "bench-response",
	}

	if err := observableManager.Register(plugin); err != nil {
		b.Fatalf("Failed to register plugin: %v", err)
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "bench",
		Timeout:   30 * time.Second,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := observableManager.ExecuteWithObservability(ctx, "bench-plugin", execCtx, "bench-request")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
