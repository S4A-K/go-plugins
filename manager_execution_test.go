// manager_execution_test.go: Test suite for plugin execution functionality
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MockExecutionPlugin implements Plugin interface for testing execution
type MockExecutionPlugin struct {
	name                     string
	version                  string
	executeCallCount         atomic.Int64
	shouldFail               bool
	shouldTimeout            bool
	shouldRetry              bool
	failureCount             atomic.Int64
	maxFailuresBeforeSuccess int
	responseDelay            time.Duration
	mu                       sync.RWMutex
}

func NewMockExecutionPlugin(name, version string) *MockExecutionPlugin {
	return &MockExecutionPlugin{
		name:    name,
		version: version,
	}
}

func (m *MockExecutionPlugin) Info() PluginInfo {
	return PluginInfo{
		Name:    m.name,
		Version: m.version,
	}
}

func (m *MockExecutionPlugin) Execute(ctx context.Context, execCtx ExecutionContext, request any) (any, error) {
	m.executeCallCount.Add(1)

	if m.responseDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.responseDelay):
			// Continue after delay
		}
	}

	if m.shouldTimeout {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
			// Continue
		}
	}

	m.mu.RLock()
	shouldFail := m.shouldFail
	shouldRetry := m.shouldRetry
	maxFailures := m.maxFailuresBeforeSuccess
	m.mu.RUnlock()

	if shouldFail {
		if shouldRetry {
			failCount := m.failureCount.Load()
			if int(failCount) < maxFailures {
				m.failureCount.Add(1)
				// Return a context deadline exceeded error which is retryable
				return nil, context.DeadlineExceeded
			}
			// After max failures, succeed on next call
			m.mu.Lock()
			m.shouldFail = false
			m.mu.Unlock()
		} else {
			return nil, errors.New("permanent failure")
		}
	}

	return map[string]interface{}{
		"result":    "success",
		"plugin":    m.name,
		"requestId": execCtx.RequestID,
	}, nil
}

func (m *MockExecutionPlugin) Health(ctx context.Context) HealthStatus {
	return HealthStatus{
		Status:    StatusHealthy,
		Message:   "OK",
		LastCheck: time.Now(),
	}
}

func (m *MockExecutionPlugin) Close() error {
	return nil
}

func (m *MockExecutionPlugin) GetExecuteCallCount() int64 {
	return m.executeCallCount.Load()
}

func (m *MockExecutionPlugin) SetShouldFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
}

func (m *MockExecutionPlugin) SetShouldRetry(retry bool, maxFailures int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldRetry = retry
	m.maxFailuresBeforeSuccess = maxFailures
	m.failureCount.Store(0)
	m.shouldFail = true // Ensure it starts in failing state
}

func (m *MockExecutionPlugin) SetResponseDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseDelay = delay
}

func (m *MockExecutionPlugin) SetShouldTimeout(timeout bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldTimeout = timeout
}

// TestManagerExecution_BasicExecution tests basic plugin execution
func TestManagerExecution_BasicExecution(t *testing.T) {
	manager := NewManager[any, any](nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	}()

	plugin := NewMockExecutionPlugin("test-plugin", "1.0.0")
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test basic execution
	ctx := context.Background()
	response, err := manager.Execute(ctx, "test-plugin", map[string]string{"test": "data"})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	result, ok := response.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map response, got %T", response)
	}

	if result["result"] != "success" {
		t.Errorf("Expected result 'success', got %v", result["result"])
	}

	if plugin.GetExecuteCallCount() != 1 {
		t.Errorf("Expected 1 execute call, got %d", plugin.GetExecuteCallCount())
	}
}

// TestManagerExecution_ExecuteWithOptions tests execution with custom options
func TestManagerExecution_ExecuteWithOptions(t *testing.T) {
	manager := NewManager[any, any](nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	}()

	plugin := NewMockExecutionPlugin("test-plugin", "1.0.0")
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test execution with custom options
	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID:  "custom-request-123",
		Timeout:    10 * time.Second,
		MaxRetries: 1,
		Headers:    map[string]string{"custom": "header"},
	}

	response, err := manager.ExecuteWithOptions(ctx, "test-plugin", execCtx, map[string]string{"test": "data"})
	if err != nil {
		t.Fatalf("ExecuteWithOptions failed: %v", err)
	}

	result, ok := response.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map response, got %T", response)
	}

	if result["requestId"] != "custom-request-123" {
		t.Errorf("Expected requestId 'custom-request-123', got %v", result["requestId"])
	}
}

// TestManagerExecution_RetryLogic tests retry functionality
func TestManagerExecution_RetryLogic(t *testing.T) {
	manager := NewManager[any, any](nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	}()

	plugin := NewMockExecutionPlugin("test-plugin", "1.0.0")
	plugin.SetShouldRetry(true, 2) // Fail 2 times, then succeed
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test retry logic
	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID:  "retry-test",
		Timeout:    10 * time.Second,
		MaxRetries: 3,
	}

	response, err := manager.ExecuteWithOptions(ctx, "test-plugin", execCtx, map[string]string{"test": "data"})
	if err != nil {
		t.Fatalf("ExecuteWithOptions failed after retries: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response after retries")
	}

	// Should have been called 3 times (2 failures + 1 success)
	callCount := plugin.GetExecuteCallCount()
	if callCount != 3 {
		t.Errorf("Expected exactly 3 execute calls (2 retries + 1 success), got %d", callCount)
		t.Logf("Plugin failure count: %d", plugin.failureCount.Load())
		t.Logf("Plugin should fail: %t", plugin.shouldFail)
		t.Logf("Plugin should retry: %t", plugin.shouldRetry)
		t.Logf("Max failures before success: %d", plugin.maxFailuresBeforeSuccess)
	}
}

// TestManagerExecution_PermanentFailure tests handling of non-retryable errors
func TestManagerExecution_PermanentFailure(t *testing.T) {
	manager := NewManager[any, any](nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	}()

	plugin := NewMockExecutionPlugin("test-plugin", "1.0.0")
	plugin.SetShouldFail(true) // Permanent failure
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test permanent failure
	ctx := context.Background()
	response, err := manager.Execute(ctx, "test-plugin", map[string]string{"test": "data"})
	if err == nil {
		t.Fatal("Expected error for permanent failure")
	}

	if response != nil {
		t.Fatal("Expected nil response for failure")
	}

	// Should have been called only once (no retries for permanent failure)
	if plugin.GetExecuteCallCount() != 1 {
		t.Errorf("Expected 1 execute call (no retries for permanent failure), got %d", plugin.GetExecuteCallCount())
	}
}

// TestManagerExecution_Timeout tests execution timeout handling
func TestManagerExecution_Timeout(t *testing.T) {
	manager := NewManager[any, any](nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	}()

	plugin := NewMockExecutionPlugin("test-plugin", "1.0.0")
	plugin.SetResponseDelay(100 * time.Millisecond) // Delay longer than timeout
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	execCtx := ExecutionContext{
		RequestID:  "timeout-test",
		Timeout:    10 * time.Second, // Manager timeout (context timeout will trigger first)
		MaxRetries: 1,
	}

	response, err := manager.ExecuteWithOptions(ctx, "test-plugin", execCtx, map[string]string{"test": "data"})
	if err == nil {
		t.Fatal("Expected timeout error")
	}

	if response != nil {
		t.Fatal("Expected nil response for timeout")
	}
}

// TestManagerExecution_PluginNotFound tests handling of non-existent plugins
func TestManagerExecution_PluginNotFound(t *testing.T) {
	manager := NewManager[any, any](nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	}()

	// Test plugin not found
	ctx := context.Background()
	response, err := manager.Execute(ctx, "non-existent-plugin", map[string]string{"test": "data"})
	if err == nil {
		t.Fatal("Expected error for non-existent plugin")
	}

	if response != nil {
		t.Fatal("Expected nil response for non-existent plugin")
	}

	// Should contain "not found" in the error message
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' in error message, got: %v", err)
	}
}

// TestManagerExecution_ShutdownState tests execution after manager shutdown
func TestManagerExecution_ShutdownState(t *testing.T) {
	manager := NewManager[any, any](nil)

	plugin := NewMockExecutionPlugin("test-plugin", "1.0.0")
	err := manager.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Shutdown manager
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manager.Shutdown(ctx)

	// Test execution after shutdown
	response, err := manager.Execute(context.Background(), "test-plugin", map[string]string{"test": "data"})
	if err == nil {
		t.Fatal("Expected error for execution after shutdown")
	}

	if response != nil {
		t.Fatal("Expected nil response for execution after shutdown")
	}

	if err.Error() != "manager is shut down" {
		t.Errorf("Expected 'manager is shut down' error, got: %v", err)
	}
}
