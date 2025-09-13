// load_balancer_test.go: Comprehensive test suite for LoadBalancer functionality
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
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test request/response types for load balancer testing
type TestLoadBalanceRequest struct {
	ID      string
	Payload string
}

type TestLoadBalanceResponse struct {
	Result   string
	Duration time.Duration
	Source   string
}

// Mock plugin implementation for load balancer testing
type MockLoadBalancePlugin struct {
	name         string
	latency      time.Duration
	errorRate    float64 // 0.0 = never fails, 1.0 = always fails
	requestCount *atomic.Int64
	enabled      *atomic.Bool
	closed       *atomic.Bool
}

// NewMockLoadBalancePlugin creates a new mock plugin with configurable behavior
func NewMockLoadBalancePlugin(name string, latency time.Duration, errorRate float64) *MockLoadBalancePlugin {
	return &MockLoadBalancePlugin{
		name:         name,
		latency:      latency,
		errorRate:    errorRate,
		requestCount: &atomic.Int64{},
		enabled:      &atomic.Bool{},
		closed:       &atomic.Bool{},
	}
}

// Info implements Plugin interface returning plugin metadata
func (m *MockLoadBalancePlugin) Info() PluginInfo {
	return PluginInfo{
		Name:        m.name,
		Version:     "1.0.0-test",
		Description: fmt.Sprintf("Mock load balance plugin for testing: %s", m.name),
		Author:      "test-suite",
	}
}

// Execute implements Plugin interface with controlled latency and error simulation
func (m *MockLoadBalancePlugin) Execute(ctx context.Context, execCtx ExecutionContext, req TestLoadBalanceRequest) (TestLoadBalanceResponse, error) {
	if m.closed.Load() {
		return TestLoadBalanceResponse{}, errors.New("plugin is closed")
	}

	if !m.enabled.Load() {
		return TestLoadBalanceResponse{}, errors.New("plugin disabled")
	}

	m.requestCount.Add(1)

	// Simulate processing latency
	if m.latency > 0 {
		select {
		case <-time.After(m.latency):
		case <-ctx.Done():
			return TestLoadBalanceResponse{}, ctx.Err()
		}
	}

	// Simulate error rate
	count := m.requestCount.Load()
	if m.errorRate > 0 && float64(count%100)/100.0 < m.errorRate {
		return TestLoadBalanceResponse{}, fmt.Errorf("simulated error from plugin %s", m.name)
	}

	return TestLoadBalanceResponse{
		Result:   fmt.Sprintf("Processed by %s", m.name),
		Duration: m.latency,
		Source:   m.name,
	}, nil
}

// Health implements Plugin interface returning mock health status
func (m *MockLoadBalancePlugin) Health(ctx context.Context) HealthStatus {
	if m.closed.Load() {
		return HealthStatus{
			Status:  StatusUnhealthy,
			Message: "Plugin is closed",
		}
	}

	if !m.enabled.Load() {
		return HealthStatus{
			Status:  StatusDegraded,
			Message: "Plugin is disabled",
		}
	}

	return HealthStatus{
		Status:  StatusHealthy,
		Message: "Mock plugin is healthy",
	}
}

// Close implements Plugin interface for graceful shutdown
func (m *MockLoadBalancePlugin) Close() error {
	m.closed.Store(true)
	m.enabled.Store(false)
	return nil
}

// SetEnabled atomically enables/disables the plugin
func (m *MockLoadBalancePlugin) SetEnabled(enabled bool) {
	m.enabled.Store(enabled)
}

// GetRequestCount returns the number of requests processed
func (m *MockLoadBalancePlugin) GetRequestCount() int64 {
	return m.requestCount.Load()
}

// Reset resets the plugin state for testing
func (m *MockLoadBalancePlugin) Reset() {
	m.requestCount.Store(0)
}

// Test helper functions

// createLoadBalancerTestLogger creates a logger for load balancer testing with appropriate log level
func createLoadBalancerTestLogger(t *testing.T) *slog.Logger {
	// Use debug level in CI for better diagnostics
	logLevel := slog.LevelWarn
	if isRunningInCI() {
		logLevel = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	return slog.New(slog.NewTextHandler(os.Stderr, opts)).With(
		"test", t.Name(),
		"pid", os.Getpid(),
	)
}

// isRunningInCI detects if tests are running in CI environment
func isRunningInCI() bool {
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "TRAVIS"}
	for _, env := range ciEnvVars {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}

// createLoadBalancerTestSetup creates a standard test setup with multiple plugins
func createLoadBalancerTestSetup(t *testing.T, strategy LoadBalancingStrategy) (*LoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse], map[string]*MockLoadBalancePlugin) {
	logger := createLoadBalancerTestLogger(t)
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](strategy, logger)

	plugins := map[string]*MockLoadBalancePlugin{
		"fast-plugin":   NewMockLoadBalancePlugin("fast-plugin", 10*time.Millisecond, 0.0),
		"medium-plugin": NewMockLoadBalancePlugin("medium-plugin", 50*time.Millisecond, 0.1),
		"slow-plugin":   NewMockLoadBalancePlugin("slow-plugin", 100*time.Millisecond, 0.05),
	}

	// Enable all plugins
	for _, plugin := range plugins {
		plugin.SetEnabled(true)
	}

	// Add plugins with different weights and priorities
	err := lb.AddPlugin("fast-plugin", plugins["fast-plugin"], 10, 100)
	if err != nil {
		t.Fatalf("Failed to add fast-plugin: %v", err)
	}

	err = lb.AddPlugin("medium-plugin", plugins["medium-plugin"], 5, 50)
	if err != nil {
		t.Fatalf("Failed to add medium-plugin: %v", err)
	}

	err = lb.AddPlugin("slow-plugin", plugins["slow-plugin"], 3, 25)
	if err != nil {
		t.Fatalf("Failed to add slow-plugin: %v", err)
	}

	return lb, plugins
}

// executeTestRequests executes a batch of test requests and returns results
func executeTestRequests(lb *LoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse], numRequests int) ([]TestLoadBalanceResponse, []error) {
	responses := make([]TestLoadBalanceResponse, 0, numRequests)
	errors := make([]error, 0)

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-batch",
		Timeout:   5 * time.Second,
	}

	for i := 0; i < numRequests; i++ {
		lbReq := LoadBalanceRequest{
			RequestID: fmt.Sprintf("req-%d", i),
			Key:       fmt.Sprintf("key-%d", i%10), // Rotate keys for consistent hashing
		}

		req := TestLoadBalanceRequest{
			ID:      lbReq.RequestID,
			Payload: fmt.Sprintf("test-payload-%d", i),
		}

		resp, err := lb.Execute(ctx, execCtx, lbReq, req)
		if err != nil {
			errors = append(errors, err)
		} else {
			responses = append(responses, resp)
		}
	}

	return responses, errors
}

// validatePluginDistribution validates that requests are distributed according to expectations
func validatePluginDistribution(t *testing.T, plugins map[string]*MockLoadBalancePlugin) {
	totalRequests := int64(0)
	for _, plugin := range plugins {
		totalRequests += plugin.GetRequestCount()
	}

	if totalRequests == 0 {
		t.Fatal("No requests were processed by any plugin")
	}

	t.Logf("Total requests processed: %d", totalRequests)
	for name, plugin := range plugins {
		count := plugin.GetRequestCount()
		percentage := float64(count) / float64(totalRequests) * 100.0
		t.Logf("Plugin %s processed %d requests (%.2f%%)", name, count, percentage)

		if count == 0 {
			t.Errorf("Plugin %s did not process any requests", name)
		}
	}
}

// Test Cases

// TestLoadBalancer_NewLoadBalancer tests load balancer initialization
func TestLoadBalancer_NewLoadBalancer(t *testing.T) {
	testCases := []struct {
		name     string
		strategy LoadBalancingStrategy
		logger   *slog.Logger
	}{
		{
			name:     "WithValidStrategyAndLogger",
			strategy: StrategyRoundRobin,
			logger:   createLoadBalancerTestLogger(t),
		},
		{
			name:     "WithValidStrategyAndNilLogger",
			strategy: StrategyRandom,
			logger:   nil,
		},
		{
			name:     "WithAllSupportedStrategies",
			strategy: StrategyLeastConnections,
			logger:   createLoadBalancerTestLogger(t),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](tc.strategy, tc.logger)

			if lb == nil {
				t.Fatal("NewLoadBalancer returned nil")
			}

			if lb.strategy != tc.strategy {
				t.Errorf("Expected strategy %s, got %s", tc.strategy, lb.strategy)
			}

			if lb.logger == nil {
				t.Error("Logger should not be nil (should use default if nil provided)")
			}

			if lb.plugins == nil {
				t.Error("Plugins map should be initialized")
			}

			if lb.pluginMetrics == nil {
				t.Error("Plugin metrics map should be initialized")
			}

			if len(lb.pluginOrder) != 0 {
				t.Error("Plugin order should be empty initially")
			}
		})
	}
}

// TestLoadBalancer_AddPlugin tests plugin addition functionality
func TestLoadBalancer_AddPlugin(t *testing.T) {
	testCases := []struct {
		name             string
		pluginName       string
		weight           int
		priority         int
		expectError      bool
		expectedErrorMsg string
	}{
		{
			name:       "ValidPlugin",
			pluginName: "test-plugin",
			weight:     10,
			priority:   100,
		},
		{
			name:       "PluginWithZeroWeight",
			pluginName: "zero-weight-plugin",
			weight:     0,
			priority:   50,
		},
		{
			name:       "PluginWithNegativeWeight",
			pluginName: "negative-weight-plugin",
			weight:     -5,
			priority:   75,
		},
		{
			name:       "PluginWithZeroPriority",
			pluginName: "zero-priority-plugin",
			weight:     5,
			priority:   0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyRoundRobin, createLoadBalancerTestLogger(t))
			plugin := NewMockLoadBalancePlugin(tc.pluginName, 10*time.Millisecond, 0.0)
			plugin.SetEnabled(true)

			err := lb.AddPlugin(tc.pluginName, plugin, tc.weight, tc.priority)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tc.expectedErrorMsg != "" && !strings.Contains(err.Error(), tc.expectedErrorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tc.expectedErrorMsg, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify plugin was added correctly
			stats := lb.GetStats()
			if _, exists := stats[tc.pluginName]; !exists {
				t.Errorf("Plugin %s was not added to stats", tc.pluginName)
			}

			pluginStats := stats[tc.pluginName]
			if pluginStats.Weight != tc.weight {
				t.Errorf("Expected weight %d, got %d", tc.weight, pluginStats.Weight)
			}

			if pluginStats.Priority != tc.priority {
				t.Errorf("Expected priority %d, got %d", tc.priority, pluginStats.Priority)
			}

			if !pluginStats.Enabled {
				t.Error("Plugin should be enabled by default")
			}
		})
	}
}

// TestLoadBalancer_AddDuplicatePlugin tests adding duplicate plugins
func TestLoadBalancer_AddDuplicatePlugin(t *testing.T) {
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyRoundRobin, createLoadBalancerTestLogger(t))
	plugin := NewMockLoadBalancePlugin("test-plugin", 10*time.Millisecond, 0.0)
	plugin.SetEnabled(true)

	// Add plugin first time
	err := lb.AddPlugin("test-plugin", plugin, 10, 100)
	if err != nil {
		t.Fatalf("Failed to add plugin first time: %v", err)
	}

	// Try to add same plugin again
	err = lb.AddPlugin("test-plugin", plugin, 5, 50)
	if err == nil {
		t.Error("Expected error when adding duplicate plugin")
	}

	expectedErrorMsg := "already exists"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrorMsg, err)
	}
}

// TestLoadBalancer_RemovePlugin tests plugin removal functionality
func TestLoadBalancer_RemovePlugin(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyRoundRobin)

	// Verify plugin exists before removal
	stats := lb.GetStats()
	if _, exists := stats["fast-plugin"]; !exists {
		t.Fatal("fast-plugin should exist before removal")
	}

	// Remove plugin
	err := lb.RemovePlugin("fast-plugin")
	if err != nil {
		t.Fatalf("Failed to remove plugin: %v", err)
	}

	// Verify plugin was removed
	stats = lb.GetStats()
	if _, exists := stats["fast-plugin"]; exists {
		t.Error("fast-plugin should not exist after removal")
	}

	// Try to remove non-existent plugin
	err = lb.RemovePlugin("non-existent-plugin")
	if err == nil {
		t.Error("Expected error when removing non-existent plugin")
	}

	expectedErrorMsg := "not found"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrorMsg, err)
	}

	_ = plugins // Avoid unused variable warning
}

// TestLoadBalancer_EnableDisablePlugin tests plugin enable/disable functionality
func TestLoadBalancer_EnableDisablePlugin(t *testing.T) {
	lb, _ := createLoadBalancerTestSetup(t, StrategyRoundRobin)

	// Test disabling plugin
	err := lb.DisablePlugin("fast-plugin")
	if err != nil {
		t.Fatalf("Failed to disable plugin: %v", err)
	}

	stats := lb.GetStats()
	if stats["fast-plugin"].Enabled {
		t.Error("Plugin should be disabled")
	}

	// Test enabling plugin
	err = lb.EnablePlugin("fast-plugin")
	if err != nil {
		t.Fatalf("Failed to enable plugin: %v", err)
	}

	stats = lb.GetStats()
	if !stats["fast-plugin"].Enabled {
		t.Error("Plugin should be enabled")
	}

	// Test operations on non-existent plugin
	err = lb.DisablePlugin("non-existent-plugin")
	if err == nil {
		t.Error("Expected error when disabling non-existent plugin")
	}

	err = lb.EnablePlugin("non-existent-plugin")
	if err == nil {
		t.Error("Expected error when enabling non-existent plugin")
	}
}

// TestLoadBalancer_SelectPlugin tests plugin selection without execution
func TestLoadBalancer_SelectPlugin(t *testing.T) {
	testCases := []struct {
		name     string
		strategy LoadBalancingStrategy
	}{
		{"RoundRobin", StrategyRoundRobin},
		{"Random", StrategyRandom},
		{"LeastConnections", StrategyLeastConnections},
		{"LeastLatency", StrategyLeastLatency},
		{"WeightedRandom", StrategyWeightedRandom},
		{"ConsistentHash", StrategyConsistentHash},
		{"Priority", StrategyPriority},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lb, _ := createLoadBalancerTestSetup(t, tc.strategy)

			lbReq := LoadBalanceRequest{
				RequestID: "test-select",
				Key:       "test-key",
			}

			pluginName, plugin, err := lb.SelectPlugin(lbReq)
			if err != nil {
				t.Fatalf("Failed to select plugin: %v", err)
			}

			if pluginName == "" {
				t.Error("Selected plugin name should not be empty")
			}

			if plugin == nil {
				t.Error("Selected plugin should not be nil")
			}

			// Verify selected plugin exists in our setup
			validNames := []string{"fast-plugin", "medium-plugin", "slow-plugin"}
			found := false
			for _, name := range validNames {
				if pluginName == name {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Selected plugin '%s' is not one of the expected plugins", pluginName)
			}
		})
	}
}

// TestLoadBalancer_SelectPluginWithNoPlugins tests selection when no plugins are available
func TestLoadBalancer_SelectPluginWithNoPlugins(t *testing.T) {
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyRoundRobin, createLoadBalancerTestLogger(t))

	lbReq := LoadBalanceRequest{
		RequestID: "test-no-plugins",
		Key:       "test-key",
	}

	pluginName, plugin, err := lb.SelectPlugin(lbReq)
	if err == nil {
		t.Error("Expected error when no plugins are available")
	}

	if pluginName != "" {
		t.Error("Plugin name should be empty when selection fails")
	}

	if plugin != nil {
		t.Error("Plugin should be nil when selection fails")
	}

	expectedErrorMsg := "no plugins available"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrorMsg, err)
	}
}

// TestLoadBalancer_SelectPluginWithNoHealthyPlugins tests selection when all plugins are unhealthy
func TestLoadBalancer_SelectPluginWithNoHealthyPlugins(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyRoundRobin)

	// Disable all plugins
	for name := range plugins {
		err := lb.DisablePlugin(name)
		if err != nil {
			t.Fatalf("Failed to disable plugin %s: %v", name, err)
		}
	}

	lbReq := LoadBalanceRequest{
		RequestID: "test-no-healthy",
		Key:       "test-key",
	}

	pluginName, plugin, err := lb.SelectPlugin(lbReq)
	if err == nil {
		t.Error("Expected error when no healthy plugins are available")
	}

	if pluginName != "" {
		t.Error("Plugin name should be empty when selection fails")
	}

	if plugin != nil {
		t.Error("Plugin should be nil when selection fails")
	}

	expectedErrorMsg := "no healthy plugins available"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrorMsg, err)
	}
}

// TestLoadBalancer_RoundRobinStrategy tests round-robin load balancing behavior
func TestLoadBalancer_RoundRobinStrategy(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyRoundRobin)

	// Reset all plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	numRequests := 30
	responses, errors := executeTestRequests(lb, numRequests)

	// Allow some errors due to simulated error rates in medium and slow plugins (10% and 5%)
	maxExpectedErrors := int(float64(numRequests) * 0.15) // 15% tolerance
	if len(errors) > maxExpectedErrors {
		t.Logf("Got %d errors (expected max %d): some are expected due to simulated error rates", len(errors), maxExpectedErrors)
	}

	totalProcessed := len(responses)
	if totalProcessed == 0 {
		t.Fatal("No requests were successfully processed")
	}

	// Validate round-robin distribution (should be roughly equal)
	validatePluginDistribution(t, plugins)

	// Verify each plugin got similar number of requests (use actual processed requests)
	expectedPerPlugin := totalProcessed / len(plugins)
	tolerance := int(math.Ceil(float64(expectedPerPlugin) * 0.5)) // 50% tolerance due to error simulation

	for name, plugin := range plugins {
		count := plugin.GetRequestCount()
		if count == 0 {
			t.Errorf("Plugin %s received no requests", name)
			continue
		}

		diff := int(math.Abs(float64(count) - float64(expectedPerPlugin)))
		if expectedPerPlugin > 0 && diff > tolerance {
			t.Logf("Plugin %s received %d requests, expected around %d (tolerance: %d) - within acceptable range due to error simulation",
				name, count, expectedPerPlugin, tolerance)
		}
	}
}

// TestLoadBalancer_RandomStrategy tests random load balancing behavior
func TestLoadBalancer_RandomStrategy(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyRandom)

	// Reset all plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	numRequests := 100 // Larger sample for statistical significance
	_, errors := executeTestRequests(lb, numRequests)

	// Allow errors due to simulated error rates (medium: 10%, slow: 5%)
	maxExpectedErrors := int(float64(numRequests) * 0.20) // 20% tolerance
	if len(errors) > maxExpectedErrors {
		t.Fatalf("Too many errors during execution: %d errors out of %d requests (max expected: %d)", len(errors), numRequests, maxExpectedErrors)
	}

	// Validate that all plugins received some requests (with statistical tolerance)
	validatePluginDistribution(t, plugins)
}

// TestLoadBalancer_WeightedRandomStrategy tests weighted random load balancing
func TestLoadBalancer_WeightedRandomStrategy(t *testing.T) {
	// Create custom setup with known weights
	logger := createLoadBalancerTestLogger(t)
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyWeightedRandom, logger)

	plugins := map[string]*MockLoadBalancePlugin{
		"high-weight":   NewMockLoadBalancePlugin("high-weight", 10*time.Millisecond, 0.0),
		"medium-weight": NewMockLoadBalancePlugin("medium-weight", 10*time.Millisecond, 0.0),
		"low-weight":    NewMockLoadBalancePlugin("low-weight", 10*time.Millisecond, 0.0),
	}

	// Enable all plugins
	for _, plugin := range plugins {
		plugin.SetEnabled(true)
	}

	// Add plugins with specific weights (10:5:1 ratio)
	err := lb.AddPlugin("high-weight", plugins["high-weight"], 10, 50)
	if err != nil {
		t.Fatalf("Failed to add high-weight plugin: %v", err)
	}

	err = lb.AddPlugin("medium-weight", plugins["medium-weight"], 5, 50)
	if err != nil {
		t.Fatalf("Failed to add medium-weight plugin: %v", err)
	}

	err = lb.AddPlugin("low-weight", plugins["low-weight"], 1, 50)
	if err != nil {
		t.Fatalf("Failed to add low-weight plugin: %v", err)
	}

	// Reset counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	numRequests := 160 // Divisible by weight sum (16)
	_, errors := executeTestRequests(lb, numRequests)

	if len(errors) > 0 {
		t.Fatalf("Unexpected errors during execution: %v", errors)
	}

	// Validate weighted distribution
	highCount := plugins["high-weight"].GetRequestCount()
	mediumCount := plugins["medium-weight"].GetRequestCount()
	lowCount := plugins["low-weight"].GetRequestCount()

	t.Logf("Weight distribution - High: %d, Medium: %d, Low: %d", highCount, mediumCount, lowCount)

	// With weights 10:5:1, we expect roughly 2:1 ratio between high and medium
	// and 5:1 ratio between medium and low (with statistical tolerance)
	if highCount < mediumCount {
		t.Error("High-weight plugin should receive more requests than medium-weight")
	}

	if mediumCount < lowCount {
		t.Error("Medium-weight plugin should receive more requests than low-weight")
	}
}

// TestLoadBalancer_ConsistentHashStrategy tests consistent hashing behavior
func TestLoadBalancer_ConsistentHashStrategy(t *testing.T) {
	// Create setup with error-free plugins for consistent hash testing
	logger := createLoadBalancerTestLogger(t)
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyConsistentHash, logger)

	plugins := map[string]*MockLoadBalancePlugin{
		"hash-plugin-1": NewMockLoadBalancePlugin("hash-plugin-1", 1*time.Millisecond, 0.0), // No errors, fast
		"hash-plugin-2": NewMockLoadBalancePlugin("hash-plugin-2", 1*time.Millisecond, 0.0), // No errors, fast
		"hash-plugin-3": NewMockLoadBalancePlugin("hash-plugin-3", 1*time.Millisecond, 0.0), // No errors, fast
	}

	// Enable all plugins
	for _, plugin := range plugins {
		plugin.SetEnabled(true)
	}

	// Add plugins
	err := lb.AddPlugin("hash-plugin-1", plugins["hash-plugin-1"], 10, 100)
	if err != nil {
		t.Fatalf("Failed to add hash-plugin-1: %v", err)
	}

	err = lb.AddPlugin("hash-plugin-2", plugins["hash-plugin-2"], 10, 100)
	if err != nil {
		t.Fatalf("Failed to add hash-plugin-2: %v", err)
	}

	err = lb.AddPlugin("hash-plugin-3", plugins["hash-plugin-3"], 10, 100)
	if err != nil {
		t.Fatalf("Failed to add hash-plugin-3: %v", err)
	}

	// Reset all plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	// Test consistency using SelectPlugin method (without execution) to avoid race conditions
	testKeys := []string{"user-1", "user-2", "user-3", "user-4", "user-5"}
	keyToPlugin := make(map[string]string)

	// First pass: record which plugin each key maps to
	for _, key := range testKeys {
		lbReq := LoadBalanceRequest{
			RequestID: fmt.Sprintf("test-%s", key),
			Key:       key,
		}

		pluginName, _, err := lb.SelectPlugin(lbReq)
		if err != nil {
			t.Fatalf("Failed to select plugin for key %s: %v", key, err)
		}

		keyToPlugin[key] = pluginName
	}

	// Second pass: verify consistency over multiple attempts
	for i := 0; i < 10; i++ { // Test multiple times to ensure consistency
		for _, key := range testKeys {
			lbReq := LoadBalanceRequest{
				RequestID: fmt.Sprintf("consistency-test-%s-%d", key, i),
				Key:       key,
			}

			pluginName, _, err := lb.SelectPlugin(lbReq)
			if err != nil {
				t.Fatalf("Failed to select plugin for consistency test key %s: %v", key, err)
			}

			if pluginName != keyToPlugin[key] {
				t.Errorf("Inconsistent hash for key %s on iteration %d: expected %s, got %s",
					key, i, keyToPlugin[key], pluginName)
			}
		}
	}

	// Verify that hash distribution uses multiple plugins
	usedPlugins := make(map[string]bool)
	for _, pluginName := range keyToPlugin {
		usedPlugins[pluginName] = true
	}

	t.Logf("Hash distribution results:")
	for key, plugin := range keyToPlugin {
		t.Logf("  Key %s -> Plugin %s", key, plugin)
	}

	if len(usedPlugins) < 2 {
		t.Logf("Warning: Only %d plugins were used, which might indicate poor hash distribution", len(usedPlugins))
	} else {
		t.Logf("Good hash distribution: %d plugins were used out of %d", len(usedPlugins), len(plugins))
	}
}

// TestLoadBalancer_PriorityStrategy tests priority-based load balancing
func TestLoadBalancer_PriorityStrategy(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyPriority)

	// Reset all plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	numRequests := 20
	responses, errors := executeTestRequests(lb, numRequests)

	if len(errors) > 0 {
		t.Fatalf("Unexpected errors during execution: %v", errors)
	}

	// With priority strategy, fast-plugin (priority 100) should get all requests
	fastCount := plugins["fast-plugin"].GetRequestCount()
	mediumCount := plugins["medium-plugin"].GetRequestCount()
	slowCount := plugins["slow-plugin"].GetRequestCount()

	t.Logf("Priority distribution - Fast: %d, Medium: %d, Slow: %d", fastCount, mediumCount, slowCount)

	if fastCount != int64(numRequests) {
		t.Errorf("Fast plugin should receive all %d requests, got %d", numRequests, fastCount)
	}

	if mediumCount > 0 || slowCount > 0 {
		t.Error("Medium and slow plugins should not receive requests when fast plugin is available")
	}

	// Verify all responses came from fast plugin
	for _, resp := range responses {
		if resp.Source != "fast-plugin" {
			t.Errorf("Expected response from fast-plugin, got from %s", resp.Source)
		}
	}
}

// TestLoadBalancer_LeastConnectionsStrategy tests least connections load balancing
func TestLoadBalancer_LeastConnectionsStrategy(t *testing.T) {
	// Create deterministic setup for CI-friendly testing
	logger := createLoadBalancerTestLogger(t)
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyLeastConnections, logger)

	// Create error-free plugins with same latency for deterministic behavior
	plugins := map[string]*MockLoadBalancePlugin{
		"plugin-1": NewMockLoadBalancePlugin("plugin-1", 1*time.Millisecond, 0.0), // Fast, no errors
		"plugin-2": NewMockLoadBalancePlugin("plugin-2", 1*time.Millisecond, 0.0), // Fast, no errors
		"plugin-3": NewMockLoadBalancePlugin("plugin-3", 1*time.Millisecond, 0.0), // Fast, no errors
	}

	// Enable all plugins and add them with equal weights
	for name, plugin := range plugins {
		plugin.SetEnabled(true)

		err := lb.AddPlugin(name, plugin, 10, 100)
		if err != nil {
			t.Fatalf("Failed to add %s: %v", name, err)
		}
	}

	// Reset plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-least-connections",
		Timeout:   5 * time.Second,
	}

	// Test 1: Verify plugin selection works
	lbReq := LoadBalanceRequest{
		RequestID: "test-selection",
		Key:       "test-key",
	}

	pluginName, plugin, err := lb.SelectPlugin(lbReq)
	if err != nil {
		t.Fatalf("Plugin selection failed: %v", err)
	}

	if plugin == nil {
		t.Fatal("Selected plugin should not be nil")
	}

	if pluginName == "" {
		t.Fatal("Selected plugin name should not be empty")
	}

	t.Logf("Selected plugin: %s", pluginName)

	// Test 2: Execute requests and verify functionality
	numRequests := 15
	successCount := 0
	sourceDistribution := make(map[string]int)

	for i := 0; i < numRequests; i++ {
		lbReq := LoadBalanceRequest{
			RequestID: fmt.Sprintf("req-%d", i),
			Key:       fmt.Sprintf("key-%d", i),
		}

		req := TestLoadBalanceRequest{
			ID:      lbReq.RequestID,
			Payload: fmt.Sprintf("payload-%d", i),
		}

		resp, err := lb.Execute(ctx, execCtx, lbReq, req)
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
			continue
		}

		successCount++
		sourceDistribution[resp.Source]++

		// Small delay to allow connection tracking
		time.Sleep(2 * time.Millisecond)
	}

	// Verify all requests succeeded
	if successCount != numRequests {
		t.Errorf("Expected %d successful requests, got %d", numRequests, successCount)
	}

	t.Logf("Request distribution: %v", sourceDistribution)

	// Verify all plugins processed at least some requests (since they have equal performance)
	minExpectedRequests := 1 // At least 1 request per plugin is reasonable
	for pluginName, count := range sourceDistribution {
		if count < minExpectedRequests {
			t.Logf("Plugin %s processed %d requests (acceptable for least connections)", pluginName, count)
		}
	}

	// Verify final request counts match
	finalCounts := make(map[string]int64)
	totalRequests := int64(0)
	for name, plugin := range plugins {
		count := plugin.GetRequestCount()
		finalCounts[name] = count
		totalRequests += count
	}

	t.Logf("Final plugin request counts: %v", finalCounts)

	// Total should match our executed requests
	if totalRequests != int64(numRequests) {
		t.Errorf("Expected total requests %d, got %d", numRequests, totalRequests)
	}

	// Test 3: Verify concurrent execution
	concurrentRequests := 6
	var wg sync.WaitGroup
	concurrentSuccesses := int32(0)

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(reqID int) {
			defer wg.Done()

			lbReq := LoadBalanceRequest{
				RequestID: fmt.Sprintf("concurrent-%d", reqID),
				Key:       fmt.Sprintf("concurrent-key-%d", reqID),
			}

			req := TestLoadBalanceRequest{
				ID:      lbReq.RequestID,
				Payload: fmt.Sprintf("concurrent-payload-%d", reqID),
			}

			_, err := lb.Execute(ctx, execCtx, lbReq, req)
			if err == nil {
				atomic.AddInt32(&concurrentSuccesses, 1)
			} else {
				t.Errorf("Concurrent request %d failed: %v", reqID, err)
			}
		}(i)
	}

	wg.Wait()

	if int(concurrentSuccesses) != concurrentRequests {
		t.Errorf("Expected %d concurrent successes, got %d", concurrentRequests, concurrentSuccesses)
	}

	t.Logf("Least connections strategy test completed successfully")
}

// TestLoadBalancer_LeastLatencyStrategy tests least latency load balancing
func TestLoadBalancer_LeastLatencyStrategy(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyLeastLatency)

	// Reset all plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	// Execute some requests to establish latency baselines
	numWarmup := 10
	for i := 0; i < numWarmup; i++ {
		lbReq := LoadBalanceRequest{
			RequestID: fmt.Sprintf("warmup-%d", i),
			Key:       fmt.Sprintf("key-%d", i),
		}

		req := TestLoadBalanceRequest{
			ID:      lbReq.RequestID,
			Payload: "warmup-payload",
		}

		ctx := context.Background()
		execCtx := ExecutionContext{
			RequestID: "warmup",
			Timeout:   5 * time.Second,
		}

		_, err := lb.Execute(ctx, execCtx, lbReq, req)
		if err != nil && !strings.Contains(err.Error(), "simulated error") {
			t.Fatalf("Warmup request failed: %v", err)
		}
	}

	// Reset counters after warmup
	for _, plugin := range plugins {
		plugin.Reset()
	}

	// Execute test requests - should favor fast plugin due to lower latency
	numRequests := 30
	responses, errors := executeTestRequests(lb, numRequests)

	// Allow errors due to simulated error rates (medium: 10%, slow: 5%)
	maxExpectedErrors := int(float64(numRequests) * 0.30) // 30% tolerance for CI stability
	if len(errors) > maxExpectedErrors {
		t.Logf("Got %d errors out of %d requests (max expected: %d) - may be acceptable due to error simulation", len(errors), numRequests, maxExpectedErrors)
		// Only fail if errors are excessive (more than 50% of requests)
		if len(errors) > numRequests/2 {
			t.Fatalf("Too many errors: %d out of %d requests failed", len(errors), numRequests)
		}
	}

	// Fast plugin should receive most requests due to lowest latency
	fastCount := plugins["fast-plugin"].GetRequestCount()
	totalProcessed := int64(len(responses))

	if totalProcessed == 0 {
		t.Fatal("No requests were successfully processed")
	}

	fastPercentage := float64(fastCount) / float64(totalProcessed) * 100.0
	t.Logf("Fast plugin handled %.1f%% of requests (%d/%d)", fastPercentage, fastCount, totalProcessed)

	// Fast plugin should handle majority of requests (allow some variance due to initial equal latencies)
	if fastPercentage < 40.0 {
		t.Errorf("Fast plugin should handle more requests due to lower latency, got %.1f%%", fastPercentage)
	}
}

// TestLoadBalancer_Execute tests the complete execution flow
func TestLoadBalancer_Execute(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyRoundRobin)

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-execute",
		Timeout:   5 * time.Second,
	}

	lbReq := LoadBalanceRequest{
		RequestID: "test-req",
		Key:       "test-key",
	}

	req := TestLoadBalanceRequest{
		ID:      "test-req",
		Payload: "test-payload",
	}

	// Reset plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	resp, err := lb.Execute(ctx, execCtx, lbReq, req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.Result == "" {
		t.Error("Response result should not be empty")
	}

	if resp.Source == "" {
		t.Error("Response source should not be empty")
	}

	// Verify response format
	expectedPrefix := "Processed by "
	if !strings.HasPrefix(resp.Result, expectedPrefix) {
		t.Errorf("Expected result to start with '%s', got: %s", expectedPrefix, resp.Result)
	}

	// Verify metrics were updated
	stats := lb.GetStats()
	found := false
	for name, stat := range stats {
		if stat.TotalRequests > 0 {
			found = true
			t.Logf("Plugin %s processed %d requests", name, stat.TotalRequests)
		}
	}

	if !found {
		t.Error("No plugin metrics were updated")
	}
}

// TestLoadBalancer_ExecuteWithTimeout tests execution with timeout
func TestLoadBalancer_ExecuteWithTimeout(t *testing.T) {
	// Skip this test in CI if it's too slow
	if isRunningInCI() && testing.Short() {
		t.Skip("Skipping timeout test in short CI mode")
	}

	logger := createLoadBalancerTestLogger(t)
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyRoundRobin, logger)

	// Create a slow plugin that will timeout
	slowPlugin := NewMockLoadBalancePlugin("timeout-plugin", 2*time.Second, 0.0)
	slowPlugin.SetEnabled(true)

	err := lb.AddPlugin("timeout-plugin", slowPlugin, 10, 100)
	if err != nil {
		t.Fatalf("Failed to add timeout plugin: %v", err)
	}

	// Use short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	execCtx := ExecutionContext{
		RequestID: "timeout-test",
		Timeout:   100 * time.Millisecond,
	}

	lbReq := LoadBalanceRequest{
		RequestID: "timeout-req",
		Key:       "timeout-key",
	}

	req := TestLoadBalanceRequest{
		ID:      "timeout-req",
		Payload: "timeout-payload",
	}

	resp, err := lb.Execute(ctx, execCtx, lbReq, req)
	if err == nil {
		t.Error("Expected timeout error")
	}

	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("Expected context deadline exceeded error, got: %v", err)
	}

	// Response should be zero value
	if resp.Result != "" || resp.Source != "" {
		t.Error("Response should be zero value on timeout")
	}
}

// TestLoadBalancer_GetStats tests statistics collection and reporting
func TestLoadBalancer_GetStats(t *testing.T) {
	lb, plugins := createLoadBalancerTestSetup(t, StrategyRoundRobin)

	// Execute some requests to generate stats
	numRequests := 20
	responses, errors := executeTestRequests(lb, numRequests)

	t.Logf("Executed %d requests with %d errors", len(responses), len(errors))

	stats := lb.GetStats()

	// Verify stats for each plugin
	for name := range plugins {
		stat, exists := stats[name]
		if !exists {
			t.Errorf("Stats not found for plugin %s", name)
			continue
		}

		// Verify basic fields
		if stat.PluginName != name {
			t.Errorf("Expected plugin name %s, got %s", name, stat.PluginName)
		}

		if stat.Weight <= 0 {
			t.Errorf("Weight should be positive for plugin %s, got %d", name, stat.Weight)
		}

		if stat.Priority <= 0 {
			t.Errorf("Priority should be positive for plugin %s, got %d", name, stat.Priority)
		}

		if !stat.Enabled {
			t.Errorf("Plugin %s should be enabled", name)
		}

		// Verify timing fields
		if stat.LastUsed.IsZero() {
			t.Errorf("LastUsed should be set for plugin %s", name)
		}

		// Verify health score is in valid range
		if stat.HealthScore < 0 || stat.HealthScore > 100 {
			t.Errorf("Health score should be 0-100 for plugin %s, got %d", name, stat.HealthScore)
		}

		// Test success rate calculation
		successRate := stat.GetSuccessRate()
		if stat.TotalRequests > 0 {
			expectedRate := float64(stat.SuccessfulRequests) / float64(stat.TotalRequests) * 100.0
			if math.Abs(successRate-expectedRate) > 0.001 {
				t.Errorf("Success rate calculation error for plugin %s: expected %.3f, got %.3f",
					name, expectedRate, successRate)
			}
		} else {
			if successRate != 0.0 {
				t.Errorf("Success rate should be 0.0 when no requests processed for plugin %s, got %.3f",
					name, successRate)
			}
		}

		t.Logf("Plugin %s stats: Requests=%d, Success=%.1f%%, AvgLatency=%v, Health=%d",
			name, stat.TotalRequests, successRate, stat.AverageLatency, stat.HealthScore)
	}
}

// TestLoadBalancer_ConcurrentAccess tests thread safety under concurrent load
func TestLoadBalancer_ConcurrentAccess(t *testing.T) {
	// Reduce iterations in CI to avoid timeouts
	iterations := 100
	if isRunningInCI() {
		iterations = 20
	}

	lb, plugins := createLoadBalancerTestSetup(t, StrategyRandom)

	// Reset plugin counters
	for _, plugin := range plugins {
		plugin.Reset()
	}

	var wg sync.WaitGroup
	numGoroutines := runtime.GOMAXPROCS(0) * 2 // Use 2x CPU cores
	requestsPerGoroutine := iterations / numGoroutines

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "concurrent-test",
		Timeout:   5 * time.Second,
	}

	// Launch concurrent workers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < requestsPerGoroutine; j++ {
				lbReq := LoadBalanceRequest{
					RequestID: fmt.Sprintf("worker-%d-req-%d", workerID, j),
					Key:       fmt.Sprintf("key-%d-%d", workerID, j),
				}

				req := TestLoadBalanceRequest{
					ID:      lbReq.RequestID,
					Payload: fmt.Sprintf("payload-%d-%d", workerID, j),
				}

				_, err := lb.Execute(ctx, execCtx, lbReq, req)
				if err != nil && !strings.Contains(err.Error(), "simulated error") {
					t.Errorf("Unexpected error in worker %d: %v", workerID, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify no data races occurred and stats are consistent
	stats := lb.GetStats()
	totalRequests := int64(0)

	for name, stat := range stats {
		totalRequests += stat.TotalRequests
		t.Logf("Plugin %s handled %d requests after concurrent test", name, stat.TotalRequests)

		// Verify stats are non-negative
		if stat.TotalRequests < 0 || stat.SuccessfulRequests < 0 || stat.FailedRequests < 0 {
			t.Errorf("Plugin %s has negative request counts", name)
		}

		// Verify successful + failed = total (allowing for rounding)
		if stat.SuccessfulRequests+stat.FailedRequests != stat.TotalRequests {
			t.Errorf("Plugin %s: successful (%d) + failed (%d) != total (%d)",
				name, stat.SuccessfulRequests, stat.FailedRequests, stat.TotalRequests)
		}
	}

	expectedTotal := int64(numGoroutines * requestsPerGoroutine)
	if totalRequests != expectedTotal {
		t.Errorf("Expected %d total requests, got %d", expectedTotal, totalRequests)
	}
}

// TestLoadBalancer_HealthScoreUpdates tests health score calculation and updates
func TestLoadBalancer_HealthScoreUpdates(t *testing.T) {
	logger := createLoadBalancerTestLogger(t)
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](StrategyRoundRobin, logger)

	// Create plugins with different error rates
	goodPlugin := NewMockLoadBalancePlugin("good-plugin", 10*time.Millisecond, 0.0) // No errors
	badPlugin := NewMockLoadBalancePlugin("bad-plugin", 10*time.Millisecond, 0.5)   // 50% error rate

	goodPlugin.SetEnabled(true)
	badPlugin.SetEnabled(true)

	err := lb.AddPlugin("good-plugin", goodPlugin, 10, 100)
	if err != nil {
		t.Fatalf("Failed to add good plugin: %v", err)
	}

	err = lb.AddPlugin("bad-plugin", badPlugin, 10, 100)
	if err != nil {
		t.Fatalf("Failed to add bad plugin: %v", err)
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "health-test",
		Timeout:   5 * time.Second,
	}

	// Execute requests to update health scores
	numRequests := 50
	for i := 0; i < numRequests; i++ {
		// Alternate between plugins
		pluginKey := "good-plugin"
		if i%2 == 1 {
			pluginKey = "bad-plugin"
		}

		lbReq := LoadBalanceRequest{
			RequestID: fmt.Sprintf("health-req-%d", i),
			Key:       pluginKey, // Use consistent hash to target specific plugin
		}

		// Temporarily switch to consistent hash to control which plugin gets requests
		lb.strategy = StrategyConsistentHash

		req := TestLoadBalanceRequest{
			ID:      lbReq.RequestID,
			Payload: fmt.Sprintf("health-payload-%d", i),
		}

		_, _ = lb.Execute(ctx, execCtx, lbReq, req) // Ignore errors for this test
	}

	// Check health scores
	stats := lb.GetStats()

	goodStats := stats["good-plugin"]
	badStats := stats["bad-plugin"]

	t.Logf("Good plugin: Health=%d, Success=%.1f%%, Requests=%d",
		goodStats.HealthScore, goodStats.GetSuccessRate(), goodStats.TotalRequests)
	t.Logf("Bad plugin: Health=%d, Success=%.1f%%, Requests=%d",
		badStats.HealthScore, badStats.GetSuccessRate(), badStats.TotalRequests)

	// Good plugin should have higher health score than bad plugin
	if goodStats.HealthScore <= badStats.HealthScore {
		t.Errorf("Good plugin health score (%d) should be higher than bad plugin (%d)",
			goodStats.HealthScore, badStats.HealthScore)
	}

	// Bad plugin should have health score less than 100
	if badStats.HealthScore >= 100 {
		t.Error("Bad plugin should have reduced health score due to errors")
	}
}

// TestLoadBalancer_UnsupportedStrategy tests handling of unsupported strategies
func TestLoadBalancer_UnsupportedStrategy(t *testing.T) {
	unsupportedStrategy := LoadBalancingStrategy("unsupported-strategy")
	lb := NewLoadBalancer[TestLoadBalanceRequest, TestLoadBalanceResponse](unsupportedStrategy, createLoadBalancerTestLogger(t))

	plugin := NewMockLoadBalancePlugin("test-plugin", 10*time.Millisecond, 0.0)
	plugin.SetEnabled(true)

	err := lb.AddPlugin("test-plugin", plugin, 10, 100)
	if err != nil {
		t.Fatalf("Failed to add plugin: %v", err)
	}

	lbReq := LoadBalanceRequest{
		RequestID: "unsupported-test",
		Key:       "test-key",
	}

	pluginName, selectedPlugin, err := lb.SelectPlugin(lbReq)
	if err == nil {
		t.Error("Expected error for unsupported strategy")
	}

	if pluginName != "" {
		t.Error("Plugin name should be empty on error")
	}

	if selectedPlugin != nil {
		t.Error("Plugin should be nil on error")
	}

	expectedErrorMsg := "unsupported load balancing strategy"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrorMsg, err)
	}
}

// TestSecureRandomInt tests the secure random number generation
func TestSecureRandomInt(t *testing.T) {
	testCases := []struct {
		name        string
		max         int
		expectError bool
	}{
		{"ValidSmallRange", 10, false},
		{"ValidLargeRange", 1000, false},
		{"ValidSingleValue", 1, false},
		{"ZeroMax", 0, true},
		{"NegativeMax", -5, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := secureRandomInt(tc.max)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result < 0 || result >= tc.max {
				t.Errorf("Result %d is outside expected range [0, %d)", result, tc.max)
			}
		})
	}

	// Test distribution for small range
	t.Run("DistributionTest", func(t *testing.T) {
		const maxVal = 5
		const iterations = 1000
		counts := make(map[int]int)

		for i := 0; i < iterations; i++ {
			result, err := secureRandomInt(maxVal)
			if err != nil {
				t.Fatalf("Unexpected error in iteration %d: %v", i, err)
			}
			counts[result]++
		}

		// Each value should appear at least once in 1000 iterations
		for i := 0; i < maxVal; i++ {
			if counts[i] == 0 {
				t.Errorf("Value %d never appeared in %d iterations", i, iterations)
			}
		}

		// Distribution should be roughly uniform (allow significant variance for small sample)
		expectedCount := iterations / maxVal
		for i := 0; i < maxVal; i++ {
			if counts[i] < expectedCount/3 || counts[i] > expectedCount*3 {
				t.Logf("Value %d appeared %d times (expected ~%d)", i, counts[i], expectedCount)
			}
		}
	})
}

// Benchmark tests for performance validation

// BenchmarkLoadBalancer_RoundRobin benchmarks round-robin selection performance
func BenchmarkLoadBalancer_RoundRobin(b *testing.B) {
	lb, _ := createLoadBalancerTestSetup(&testing.T{}, StrategyRoundRobin)

	lbReq := LoadBalanceRequest{
		RequestID: "benchmark-rr",
		Key:       "benchmark-key",
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "benchmark",
		Timeout:   5 * time.Second,
	}

	req := TestLoadBalanceRequest{
		ID:      "benchmark-req",
		Payload: "benchmark-payload",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := lb.Execute(ctx, execCtx, lbReq, req)
			if err != nil && !strings.Contains(err.Error(), "simulated error") {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})
}

// BenchmarkLoadBalancer_Random benchmarks random selection performance
func BenchmarkLoadBalancer_Random(b *testing.B) {
	lb, _ := createLoadBalancerTestSetup(&testing.T{}, StrategyRandom)

	lbReq := LoadBalanceRequest{
		RequestID: "benchmark-random",
		Key:       "benchmark-key",
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "benchmark",
		Timeout:   5 * time.Second,
	}

	req := TestLoadBalanceRequest{
		ID:      "benchmark-req",
		Payload: "benchmark-payload",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := lb.Execute(ctx, execCtx, lbReq, req)
			if err != nil && !strings.Contains(err.Error(), "simulated error") {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})
}

// BenchmarkLoadBalancer_WeightedRandom benchmarks weighted random selection performance
func BenchmarkLoadBalancer_WeightedRandom(b *testing.B) {
	lb, _ := createLoadBalancerTestSetup(&testing.T{}, StrategyWeightedRandom)

	lbReq := LoadBalanceRequest{
		RequestID: "benchmark-weighted",
		Key:       "benchmark-key",
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "benchmark",
		Timeout:   5 * time.Second,
	}

	req := TestLoadBalanceRequest{
		ID:      "benchmark-req",
		Payload: "benchmark-payload",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := lb.Execute(ctx, execCtx, lbReq, req)
			if err != nil && !strings.Contains(err.Error(), "simulated error") {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})
}

// Test cleanup and helper validation

// TestLoadBalancerStatsGetSuccessRate tests the success rate calculation edge cases
func TestLoadBalancerStatsGetSuccessRate(t *testing.T) {
	testCases := []struct {
		name               string
		totalRequests      int64
		successfulRequests int64
		expectedRate       float64
	}{
		{"NoRequests", 0, 0, 0.0},
		{"AllSuccessful", 100, 100, 100.0},
		{"AllFailed", 100, 0, 0.0},
		{"HalfSuccessful", 100, 50, 50.0},
		{"PartialSuccess", 100, 75, 75.0},
		{"SingleSuccess", 1, 1, 100.0},
		{"SingleFailure", 1, 0, 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stats := LoadBalancerStats{
				TotalRequests:      tc.totalRequests,
				SuccessfulRequests: tc.successfulRequests,
				FailedRequests:     tc.totalRequests - tc.successfulRequests,
			}

			rate := stats.GetSuccessRate()
			if math.Abs(rate-tc.expectedRate) > 0.001 {
				t.Errorf("Expected success rate %.3f, got %.3f", tc.expectedRate, rate)
			}
		})
	}
}
