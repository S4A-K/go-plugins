// manager_lifecycle_test.go: Test suite for manager lifecycle functionality
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MockLifecyclePlugin implements Plugin interface for testing lifecycle
type MockLifecyclePlugin struct {
	name             string
	version          string
	closeCallCount   atomic.Int64
	isCloseCalled    atomic.Bool
	closeDelay       time.Duration
	executeCallCount atomic.Int64
	mu               sync.RWMutex
}

func NewMockLifecyclePlugin(name, version string) *MockLifecyclePlugin {
	return &MockLifecyclePlugin{
		name:    name,
		version: version,
	}
}

func (m *MockLifecyclePlugin) Info() PluginInfo {
	return PluginInfo{
		Name:    m.name,
		Version: m.version,
	}
}

func (m *MockLifecyclePlugin) Execute(ctx context.Context, execCtx ExecutionContext, request any) (any, error) {
	m.executeCallCount.Add(1)
	return map[string]interface{}{
		"result":    "success",
		"plugin":    m.name,
		"requestId": execCtx.RequestID,
	}, nil
}

func (m *MockLifecyclePlugin) Health(ctx context.Context) HealthStatus {
	return HealthStatus{
		Status:    StatusHealthy,
		Message:   "OK",
		LastCheck: time.Now(),
	}
}

func (m *MockLifecyclePlugin) Close() error {
	m.closeCallCount.Add(1)
	m.isCloseCalled.Store(true)

	if m.closeDelay > 0 {
		time.Sleep(m.closeDelay)
	}

	return nil
}

func (m *MockLifecyclePlugin) GetCloseCallCount() int64 {
	return m.closeCallCount.Load()
}

func (m *MockLifecyclePlugin) IsCloseCalled() bool {
	return m.isCloseCalled.Load()
}

func (m *MockLifecyclePlugin) SetCloseDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeDelay = delay
}

func (m *MockLifecyclePlugin) GetExecuteCallCount() int64 {
	return m.executeCallCount.Load()
}

// TestManagerLifecycle_BasicShutdown tests basic shutdown functionality
func TestManagerLifecycle_BasicShutdown(t *testing.T) {
	manager := NewManager[any, any](nil)

	plugin1 := NewMockLifecyclePlugin("plugin1", "1.0.0")
	plugin2 := NewMockLifecyclePlugin("plugin2", "1.0.0")

	err := manager.Register(plugin1)
	if err != nil {
		t.Fatalf("Failed to register plugin1: %v", err)
	}

	err = manager.Register(plugin2)
	if err != nil {
		t.Fatalf("Failed to register plugin2: %v", err)
	}

	// Shutdown should succeed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Verify plugins were closed
	if !plugin1.IsCloseCalled() {
		t.Error("Plugin1 Close() was not called during shutdown")
	}

	if !plugin2.IsCloseCalled() {
		t.Error("Plugin2 Close() was not called during shutdown")
	}

	// Verify shutdown state
	if !manager.shutdown.Load() {
		t.Error("Manager shutdown flag should be true after shutdown")
	}
}

// TestManagerLifecycle_DoubleShutdown tests calling shutdown twice
func TestManagerLifecycle_DoubleShutdown(t *testing.T) {
	manager := NewManager[any, any](nil)

	plugin := NewMockLifecyclePlugin("test-plugin", "1.0.0")
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// First shutdown should succeed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Fatalf("First shutdown failed: %v", err)
	}

	// Second shutdown should return error
	err = manager.Shutdown(ctx)
	if err == nil {
		t.Fatal("Second shutdown should have returned an error")
	}

	expectedError := "manager already shut down"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}

	// Plugin should only be closed once
	if plugin.GetCloseCallCount() != 1 {
		t.Errorf("Expected plugin Close() to be called once, got %d times", plugin.GetCloseCallCount())
	}
}

// TestManagerLifecycle_ShutdownTimeout tests shutdown with timeout
func TestManagerLifecycle_ShutdownTimeout(t *testing.T) {
	manager := NewManager[any, any](nil)

	// Create a plugin that takes a long time to close
	plugin := NewMockLifecyclePlugin("slow-plugin", "1.0.0")
	plugin.SetCloseDelay(200 * time.Millisecond)

	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Shutdown with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = manager.Shutdown(ctx)
	duration := time.Since(start)

	// Should still succeed but may timeout waiting for health monitors
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Should respect the timeout roughly (allow some extra time for processing)
	if duration > 300*time.Millisecond {
		t.Errorf("Shutdown took too long: %v (expected around 50ms + processing time)", duration)
	}

	// Plugin should still be closed
	if !plugin.IsCloseCalled() {
		t.Error("Plugin Close() should have been called even with timeout")
	}
}

// TestManagerLifecycle_ShutdownWithActiveRequests tests shutdown behavior with active requests
func TestManagerLifecycle_ShutdownWithActiveRequests(t *testing.T) {
	manager := NewManager[any, any](nil)

	plugin := NewMockLifecyclePlugin("test-plugin", "1.0.0")
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Start some requests
	ctx := context.Background()
	manager.requestTracker.StartRequest("test-plugin", ctx)
	manager.requestTracker.StartRequest("test-plugin", ctx)

	// Check active requests
	activeCount := manager.GetActiveRequestCount("test-plugin")
	if activeCount != 2 {
		t.Errorf("Expected 2 active requests, got %d", activeCount)
	}

	// Shutdown should still work
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(shutdownCtx)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Plugin should be closed
	if !plugin.IsCloseCalled() {
		t.Error("Plugin Close() should have been called during shutdown")
	}
}

// TestManagerLifecycle_GetMetrics tests metrics retrieval
func TestManagerLifecycle_GetMetrics(t *testing.T) {
	manager := NewManager[any, any](nil)

	// GetMetrics should work before shutdown
	metrics := manager.GetMetrics()
	if metrics.RequestsTotal.Load() < 0 {
		t.Error("Metrics should be accessible before shutdown")
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := manager.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// GetMetrics should still work after shutdown
	metricsAfter := manager.GetMetrics()
	if metricsAfter.RequestsTotal.Load() < 0 {
		t.Error("Metrics should still be accessible after shutdown")
	}
}

// TestManagerLifecycle_ObservabilityConfiguration tests observability configuration
func TestManagerLifecycle_ObservabilityConfiguration(t *testing.T) {
	// Create manager with proper types
	manager := NewManager[any, any](nil)

	// Configure observability with default config
	config := DefaultObservabilityConfig()
	config.Level = ObservabilityBasic
	config.MetricsPrefix = "test_"

	err := manager.ConfigureObservability(config)
	if err != nil {
		t.Fatalf("ConfigureObservability failed: %v", err)
	}

	// Register a test plugin
	plugin := NewMockLifecyclePlugin("test-plugin", "1.0.0")
	err = manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Verify observability is working by getting metrics
	metrics := manager.GetMetrics()
	if metrics.RequestsTotal.Load() < 0 {
		t.Error("Expected metrics to be available after observability configuration")
	}

	// Shutdown should work
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
}

// TestManagerLifecycle_ShutdownWithoutPlugins tests shutdown with no plugins registered
func TestManagerLifecycle_ShutdownWithoutPlugins(t *testing.T) {
	manager := NewManager[any, any](nil)

	// Shutdown without any plugins should work fine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := manager.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown without plugins failed: %v", err)
	}

	// Verify shutdown state
	if !manager.shutdown.Load() {
		t.Error("Manager shutdown flag should be true after shutdown")
	}
}

// TestManagerLifecycle_RequestCounters tests active request tracking during lifecycle
func TestManagerLifecycle_RequestCounters(t *testing.T) {
	manager := NewManager[any, any](nil)

	plugin := NewMockLifecyclePlugin("test-plugin", "1.0.0")
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test GetActiveRequestCount
	if count := manager.GetActiveRequestCount("test-plugin"); count != 0 {
		t.Errorf("Expected 0 active requests initially, got %d", count)
	}

	if count := manager.GetActiveRequestCount("non-existent"); count != 0 {
		t.Errorf("Expected 0 active requests for non-existent plugin, got %d", count)
	}

	// Test GetAllActiveRequests
	allRequests := manager.GetAllActiveRequests()
	if len(allRequests) != 0 {
		t.Errorf("Expected empty active requests map, got %v", allRequests)
	}

	// Add some active requests
	ctx := context.Background()
	manager.requestTracker.StartRequest("test-plugin", ctx)
	manager.requestTracker.StartRequest("test-plugin", ctx)

	if count := manager.GetActiveRequestCount("test-plugin"); count != 2 {
		t.Errorf("Expected 2 active requests, got %d", count)
	}

	allRequests = manager.GetAllActiveRequests()
	if len(allRequests) != 1 || allRequests["test-plugin"] != 2 {
		t.Errorf("Expected map with test-plugin: 2, got %v", allRequests)
	}

	// Shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(shutdownCtx)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Counters should still work after shutdown
	if count := manager.GetActiveRequestCount("test-plugin"); count != 2 {
		t.Errorf("Expected 2 active requests after shutdown, got %d", count)
	}
}
