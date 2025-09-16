// graceful_draining_test.go: tests for graceful draining and request tracking
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const requestIDKey contextKey = "requestID"

func TestRequestTracker_BasicTracking(t *testing.T) {
	tracker := NewRequestTracker()

	ctx := context.Background()
	pluginName := "test-plugin"

	// Initially no active requests
	if count := tracker.GetActiveRequestCount(pluginName); count != 0 {
		t.Errorf("Expected 0 active requests, got %d", count)
	}

	// Start a request
	tracker.StartRequest(pluginName, ctx)
	if count := tracker.GetActiveRequestCount(pluginName); count != 1 {
		t.Errorf("Expected 1 active request, got %d", count)
	}

	// End the request
	tracker.EndRequest(pluginName, ctx)
	if count := tracker.GetActiveRequestCount(pluginName); count != 0 {
		t.Errorf("Expected 0 active requests after end, got %d", count)
	}
}

func TestRequestTracker_WaitForDrain(t *testing.T) {
	tracker := NewRequestTracker()
	pluginName := "test-plugin"

	ctx := context.Background()
	tracker.StartRequest(pluginName, ctx)

	// Start a goroutine that ends the request after 100ms
	go func() {
		time.Sleep(100 * time.Millisecond)
		tracker.EndRequest(pluginName, ctx)
	}()

	// Wait for drain should succeed within 1 second
	start := time.Now()
	if !tracker.WaitForDrain(pluginName, 1*time.Second) {
		t.Error("WaitForDrain should have succeeded")
	}

	// Should have completed in ~100ms
	duration := time.Since(start)
	if duration > 500*time.Millisecond {
		t.Errorf("Drain took too long: %v", duration)
	}
}

func TestRequestTracker_DrainTimeout(t *testing.T) {
	tracker := NewRequestTracker()
	pluginName := "test-plugin"

	ctx := context.Background()
	tracker.StartRequest(pluginName, ctx)

	// Don't end the request - should timeout
	if tracker.WaitForDrain(pluginName, 50*time.Millisecond) {
		t.Error("WaitForDrain should have timed out")
	}

	// Clean up
	tracker.EndRequest(pluginName, ctx)
}

func TestRequestTracker_ConcurrentRequests(t *testing.T) {
	tracker := NewRequestTracker()
	pluginName := "test-plugin"

	const numGoroutines = 100
	var wg sync.WaitGroup
	var completedCount atomic.Int32

	// Start concurrent requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ctx := context.WithValue(context.Background(), requestIDKey, id)
			tracker.StartRequest(pluginName, ctx)

			// Simulate work
			time.Sleep(10 * time.Millisecond)

			tracker.EndRequest(pluginName, ctx)
			completedCount.Add(1)
		}(i)
	}

	// Wait for a moment then check active count
	time.Sleep(5 * time.Millisecond)
	activeCount := tracker.GetActiveRequestCount(pluginName)

	// Should have some active requests
	if activeCount == 0 {
		t.Error("Expected some active requests")
	}

	// Wait for all to complete
	wg.Wait()

	// Should be no active requests
	if count := tracker.GetActiveRequestCount(pluginName); count != 0 {
		t.Errorf("Expected 0 active requests after completion, got %d", count)
	}

	// All should have completed
	if completed := completedCount.Load(); completed != numGoroutines {
		t.Errorf("Expected %d completed requests, got %d", numGoroutines, completed)
	}
}

func TestRequestTracker_GracefulDrain(t *testing.T) {
	tracker := NewRequestTracker()
	pluginName := "test-plugin"

	const numRequests = 5
	var wg sync.WaitGroup

	// Start multiple requests
	contexts := make([]context.Context, numRequests)
	for i := 0; i < numRequests; i++ {
		ctx := context.WithValue(context.Background(), requestIDKey, i)
		contexts[i] = ctx
		tracker.StartRequest(pluginName, ctx)

		// Simulate ongoing work
		wg.Add(1)
		go func(ctx context.Context, id int) {
			defer wg.Done()
			time.Sleep(time.Duration(50+id*10) * time.Millisecond) // Staggered completion
			tracker.EndRequest(pluginName, ctx)
		}(ctx, i)
	}

	// Start graceful drain
	drainOptions := DrainOptions{
		DrainTimeout:            200 * time.Millisecond,
		ForceCancelAfterTimeout: false,
	}

	start := time.Now()
	err := tracker.GracefulDrain(pluginName, drainOptions)
	duration := time.Since(start)

	// Should complete successfully within the timeout
	if err != nil {
		t.Errorf("GracefulDrain failed: %v", err)
	}

	// Should take roughly the time for longest request to complete
	if duration > 300*time.Millisecond {
		t.Errorf("Drain took too long: %v", duration)
	}

	wg.Wait() // Ensure all goroutines complete
}

func TestRequestTracker_DrainTimeoutWithForceCancel(t *testing.T) {
	tracker := NewRequestTracker()
	pluginName := "test-plugin"

	// Start a long-running request with cancellable context
	baseCtx, cancel := context.WithCancel(context.Background())
	// Create context with cancel function stored in Value so ForceCancel can access it
	ctx := context.WithValue(baseCtx, cancelKey, cancel)

	tracker.StartRequest(pluginName, ctx)

	// Don't end the request naturally - simulate a hanging request
	requestEnded := make(chan bool, 1)
	go func() {
		<-ctx.Done() // Wait for cancellation
		tracker.EndRequest(pluginName, ctx)
		requestEnded <- true
	}()

	// Drain with force cancel
	drainOptions := DrainOptions{
		DrainTimeout:            50 * time.Millisecond,
		ForceCancelAfterTimeout: true,
	}

	err := tracker.GracefulDrain(pluginName, drainOptions)

	// Should get timeout error
	if err == nil {
		t.Error("Expected drain timeout error")
	}

	drainErr, ok := err.(*DrainTimeoutError)
	if !ok {
		t.Errorf("Expected DrainTimeoutError, got %T", err)
	}

	if drainErr.CanceledRequests == 0 {
		t.Error("Expected canceled requests > 0")
	}

	// Wait for the goroutine to finish after cancellation
	select {
	case <-requestEnded:
		// Request was properly cancelled and ended
	case <-time.After(100 * time.Millisecond):
		t.Error("Request should have been cancelled and ended within timeout")
	}
}

func TestManager_GracefulDraining(t *testing.T) {
	manager := NewManager[string, string](nil)

	// Create a mock plugin that simulates work
	plugin := &TestMockPlugin[string, string]{
		name: "slow-plugin",
		executeFunc: func(ctx context.Context, execCtx ExecutionContext, request string) (string, error) {
			// Simulate slow work
			time.Sleep(100 * time.Millisecond)
			return "response-" + request, nil
		},
	}

	// Register plugin
	if err := manager.Register(plugin); err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Start concurrent requests
	const numRequests = 5
	var wg sync.WaitGroup
	var responses []string
	var responseMu sync.Mutex

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			request := fmt.Sprintf("request-%d", id)
			resp, err := manager.Execute(context.Background(), "slow-plugin", request)
			if err != nil {
				t.Errorf("Request %d failed: %v", id, err)
				return
			}

			responseMu.Lock()
			responses = append(responses, resp)
			responseMu.Unlock()
		}(i)
	}

	// Wait for requests to start
	time.Sleep(10 * time.Millisecond)

	// Check active requests
	activeCount := manager.GetActiveRequestCount("slow-plugin")
	if activeCount == 0 {
		t.Error("Expected active requests")
	}

	// Wait for requests to complete
	wg.Wait()

	// Verify all responses
	responseMu.Lock()
	if len(responses) != numRequests {
		t.Errorf("Expected %d responses, got %d", numRequests, len(responses))
	}
	responseMu.Unlock()

	// Should have no active requests now
	if count := manager.GetActiveRequestCount("slow-plugin"); count != 0 {
		t.Errorf("Expected 0 active requests, got %d", count)
	}
}

// TestMockPlugin for graceful draining testing
type TestMockPlugin[Req, Resp any] struct {
	name        string
	executeFunc func(context.Context, ExecutionContext, Req) (Resp, error)
}

func (p *TestMockPlugin[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	return p.executeFunc(ctx, execCtx, request)
}

func (p *TestMockPlugin[Req, Resp]) Info() PluginInfo {
	return PluginInfo{
		Name:        p.name,
		Version:     "1.0.0",
		Description: "mock plugin for testing",
	}
}

func (p *TestMockPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	return HealthStatus{
		Status:       StatusHealthy,
		Message:      "mock plugin is healthy",
		ResponseTime: 1 * time.Millisecond,
	}
}

func (p *TestMockPlugin[Req, Resp]) Shutdown(ctx context.Context) error {
	return nil
}

func (p *TestMockPlugin[Req, Resp]) Close() error {
	return nil
}
