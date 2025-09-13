// manager_test.go: Basic tests for the plugin manager
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// MockPlugin implements Plugin interface for testing
type MockPlugin struct {
	name     string
	version  string
	mu       sync.RWMutex
	healthy  bool
	response string
}

func (m *MockPlugin) Info() PluginInfo {
	return PluginInfo{
		Name:    m.name,
		Version: m.version,
	}
}

func (m *MockPlugin) Execute(ctx context.Context, execCtx ExecutionContext, request string) (string, error) {
	m.mu.RLock()
	healthy := m.healthy
	m.mu.RUnlock()

	if !healthy {
		return "", fmt.Errorf("plugin is unhealthy")
	}
	return m.response, nil
}

func (m *MockPlugin) Health(ctx context.Context) HealthStatus {
	m.mu.RLock()
	healthy := m.healthy
	m.mu.RUnlock()

	status := StatusHealthy
	if !healthy {
		status = StatusUnhealthy
	}

	return HealthStatus{
		Status:       status,
		Message:      "Mock plugin health",
		LastCheck:    time.Now(),
		ResponseTime: 1 * time.Millisecond,
	}
}

func (m *MockPlugin) SetHealthy(healthy bool) {
	m.mu.Lock()
	m.healthy = healthy
	m.mu.Unlock()
}

func (m *MockPlugin) Close() error {
	return nil
}

func TestManagerBasicOperations(t *testing.T) {
	logger := slog.Default()
	manager := NewManager[string, string](logger)

	// Test plugin registration
	plugin := &MockPlugin{
		name:     "test-plugin",
		version:  "1.0.0",
		healthy:  true,
		response: "test-response",
	}

	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test plugin execution
	ctx := context.Background()
	response, err := manager.Execute(ctx, "test-plugin", "test-request")
	if err != nil {
		t.Fatalf("Failed to execute plugin: %v", err)
	}

	if response != "test-response" {
		t.Errorf("Expected 'test-response', got '%s'", response)
	}

	// Test plugin listing
	plugins := manager.ListPlugins()
	if len(plugins) != 1 {
		t.Errorf("Expected 1 plugin, got %d", len(plugins))
	}

	if _, exists := plugins["test-plugin"]; !exists {
		t.Error("Plugin 'test-plugin' not found in list")
	}

	// Test plugin unregistration
	err = manager.Unregister("test-plugin")
	if err != nil {
		t.Fatalf("Failed to unregister plugin: %v", err)
	}

	// Verify plugin is removed
	plugins = manager.ListPlugins()
	if len(plugins) != 0 {
		t.Errorf("Expected 0 plugins after unregistration, got %d", len(plugins))
	}

	// Test manager shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(shutdownCtx)
	if err != nil {
		t.Fatalf("Failed to shutdown manager: %v", err)
	}
}

func TestCircuitBreakerBasicOperations(t *testing.T) {
	config := CircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    2,
		RecoveryTimeout:     5 * time.Second, // Longer timeout to ensure it stays closed
		MinRequestThreshold: 2,
		SuccessThreshold:    1,
	}

	cb := NewCircuitBreaker(config)

	// Initially closed
	if !cb.AllowRequest() {
		t.Error("Circuit breaker should allow requests initially")
	}

	if cb.GetState() != StateClosed {
		t.Errorf("Expected StateClosed, got %s", cb.GetState().String())
	}

	// Record failures to trip the breaker
	cb.RecordFailure() // failure=1, request=1
	cb.RecordFailure() // failure=2, request=2

	// Should be open now
	if cb.GetState() != StateOpen {
		t.Errorf("Expected StateOpen after failures, got %s", cb.GetState().String())
	}

	// Should not allow requests when open (with long recovery timeout)
	if cb.AllowRequest() {
		t.Error("Circuit breaker should not allow requests when open")
	}

	// Test recovery with short timeout
	cb2 := NewCircuitBreaker(CircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    1,
		RecoveryTimeout:     50 * time.Millisecond,
		MinRequestThreshold: 1,
		SuccessThreshold:    1,
	})

	cb2.RecordFailure()
	if cb2.GetState() != StateOpen {
		t.Error("Second circuit breaker should be open")
	}

	// Wait for recovery timeout
	time.Sleep(100 * time.Millisecond)

	// Should allow a test request (half-open)
	if !cb2.AllowRequest() {
		t.Error("Circuit breaker should allow test request after recovery timeout")
	}

	// Record success to close the circuit
	cb2.RecordSuccess()

	if cb2.GetState() != StateClosed {
		t.Errorf("Expected StateClosed after success, got %s", cb2.GetState().String())
	}
}

func TestHealthCheckerBasicOperations(t *testing.T) {
	plugin := &MockPlugin{
		name:    "health-test",
		version: "1.0.0",
		healthy: true,
	}

	config := HealthCheckConfig{
		Enabled:      true,
		Interval:     50 * time.Millisecond,
		Timeout:      1 * time.Second,
		FailureLimit: 2,
	}

	checker := NewHealthChecker(plugin, config)
	defer checker.Stop()

	// Check initial health
	status := checker.Check()
	if status.Status != StatusHealthy {
		t.Errorf("Expected StatusHealthy, got %s", status.Status.String())
	}

	// Simulate plugin failure
	plugin.SetHealthy(false)

	// Wait for health check to detect failure
	time.Sleep(100 * time.Millisecond)

	status = checker.Check()
	if status.Status == StatusHealthy {
		t.Error("Expected plugin to be unhealthy")
	}

	// Simulate recovery
	plugin.SetHealthy(true)

	status = checker.Check()
	if status.Status != StatusHealthy {
		t.Errorf("Expected StatusHealthy after recovery, got %s", status.Status.String())
	}
}

func TestConfigValidation(t *testing.T) {
	// Test valid configuration
	config := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportHTTP,
		Endpoint:  "http://localhost:8080",
		Enabled:   true,
		Auth:      AuthConfig{Method: AuthNone},
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Valid config should not produce error: %v", err)
	}

	// Test invalid configuration - missing name
	invalidConfig := config
	invalidConfig.Name = ""

	if err := invalidConfig.Validate(); err == nil {
		t.Error("Config with empty name should produce error")
	}

	// Test invalid configuration - missing endpoint
	invalidConfig = config
	invalidConfig.Endpoint = ""

	if err := invalidConfig.Validate(); err == nil {
		t.Error("Config with empty endpoint should produce error")
	}

	// Test invalid configuration - bad URL
	invalidConfig = config
	invalidConfig.Endpoint = "not-a-url"

	if err := invalidConfig.Validate(); err == nil {
		t.Error("Config with invalid URL should produce error")
	}
}

func TestManagerConfig(t *testing.T) {
	config := GetDefaultManagerConfig()

	// Add a test plugin
	config.Plugins = []PluginConfig{
		{
			Name:      "test-plugin",
			Transport: TransportHTTP,
			Endpoint:  "http://localhost:8080",
			Enabled:   true,
			Auth:      AuthConfig{Method: AuthNone},
		},
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Default config with valid plugin should not produce error: %v", err)
	}

	// Test duplicate plugin names
	config.Plugins = append(config.Plugins, config.Plugins[0])

	if err := config.Validate(); err == nil {
		t.Error("Config with duplicate plugin names should produce error")
	}
}
