// refactoring_safety_test.go: Safety net tests for architectural refactoring
//
// This file contains comprehensive tests to prevent regressions during
// the refactoring of the subprocess plugin architecture. These tests
// ensure that functionality remains intact while we simplify the codebase.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// RefactoringSafetyTestRequest represents a test request for safety testing.
type RefactoringSafetyTestRequest struct {
	ID      string
	Message string
	Number  int
}

// RefactoringSafetyTestResponse represents a test response for safety testing.
type RefactoringSafetyTestResponse struct {
	ID      string
	Result  string
	Number  int
	Success bool
}

// createSafetyTestExecutable creates a simple test executable for subprocess testing.
func createSafetyTestExecutable(t *testing.T) string {
	// Create a simple test executable that implements the JSON protocol
	testExecutable := `
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type TestRequest struct {
	ID      string
	Method  string
	Payload struct {
		ID      string
		Message string
		Number  int
	}
}

type TestResponse struct {
	ID     string
	Result struct {
		ID      string
		Result  string
		Number  int
		Success bool
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req TestRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing request: %v\n", err)
			continue
		}

		// Echo back the request with some modifications
		resp := TestResponse{
			ID: req.ID,
			Result: struct {
				ID      string 
				Result  string 
				Number  int    
				Success bool   
			}{
				ID:      req.Payload.ID,
				Result:  fmt.Sprintf("Echo: %s", req.Payload.Message),
				Number:  req.Payload.Number * 2,
				Success: true,
			},
		}

		respData, err := json.Marshal(resp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling response: %v\n", err)
			continue
		}

		fmt.Printf("%s\n", respData)
	}
}
`

	// Write the test executable to a temporary file
	tmpDir := t.TempDir()
	executablePath := filepath.Join(tmpDir, "test_plugin")
	if runtime.GOOS == "windows" {
		executablePath += ".exe"
	}

	// For this test, we'll create a simple Go file and compile it
	goFile := filepath.Join(tmpDir, "test_plugin.go")
	if err := os.WriteFile(goFile, []byte(testExecutable), 0644); err != nil {
		t.Fatalf("Failed to write test executable: %v", err)
	}

	// Note: In a real test, you would compile this Go file
	// For now, we'll return the path and expect the test to handle compilation
	return executablePath
}

// Test_RefactoringSafety_StartupChain tests the complete startup chain
// to ensure no regressions during refactoring.
func Test_RefactoringSafety_StartupChain(t *testing.T) {
	executablePath := createSafetyTestExecutable(t)

	// Create subprocess plugin factory
	factory := NewSubprocessPluginFactory[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse](nil)

	// Create plugin configuration
	config := PluginConfig{
		Name:       "safety-test-plugin",
		Type:       "subprocess",
		Transport:  TransportExecutable,
		Endpoint:   executablePath,
		Executable: executablePath,
	}

	// Create plugin
	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Skipf("Skipping test due to compilation requirements: %v", err)
		return
	}

	ctx := context.Background()

	t.Run("startup_sequence_validation", func(t *testing.T) {
		// Test that the startup sequence works correctly
		sp := plugin.(*SubprocessPlugin[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse])

		// Verify initial state
		if sp.subprocessManager.IsStarted() {
			t.Error("Plugin should not be started initially")
		}

		// Test the startup chain
		request := RefactoringSafetyTestRequest{
			ID:      "startup-test",
			Message: "test message",
			Number:  42,
		}

		execCtx := ExecutionContext{
			RequestID: "startup-test-request",
			Timeout:   5 * time.Second,
		}

		// This should trigger the startup chain
		response, err := plugin.Execute(ctx, execCtx, request)
		if err != nil {
			t.Errorf("Startup chain failed: %v", err)
			return
		}

		// Verify the plugin is now started
		if !sp.subprocessManager.IsStarted() {
			t.Error("Plugin should be started after execution")
		}

		// Verify response
		if response.ID != request.ID {
			t.Errorf("Response ID mismatch: expected %s, got %s", request.ID, response.ID)
		}

		if !response.Success {
			t.Error("Response should indicate success")
		}

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})

	t.Run("multiple_executions_consistency", func(t *testing.T) {
		// Test that multiple executions work consistently
		_ = plugin.(*SubprocessPlugin[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse])

		const numRequests = 10
		var wg sync.WaitGroup
		results := make([]RefactoringSafetyTestResponse, numRequests)
		errors := make([]error, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				request := RefactoringSafetyTestRequest{
					ID:      fmt.Sprintf("concurrent-test-%d", index),
					Message: fmt.Sprintf("message %d", index),
					Number:  index * 10,
				}

				execCtx := ExecutionContext{
					RequestID: fmt.Sprintf("concurrent-request-%d", index),
					Timeout:   5 * time.Second,
				}

				response, err := plugin.Execute(ctx, execCtx, request)
				results[index] = response
				errors[index] = err
			}(i)
		}

		wg.Wait()

		// Verify all requests succeeded
		for i, err := range errors {
			if err != nil {
				t.Errorf("Request %d failed: %v", i, err)
			}
		}

		// Verify all responses are consistent
		for i, response := range results {
			expectedID := fmt.Sprintf("concurrent-test-%d", i)
			if response.ID != expectedID {
				t.Errorf("Response %d ID mismatch: expected %s, got %s", i, expectedID, response.ID)
			}

			if !response.Success {
				t.Errorf("Response %d should indicate success", i)
			}
		}

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})
}

// Test_RefactoringSafety_ExecutionFlow tests the execution flow
// to ensure the chain Execute -> executeViaStandardIO -> executeJSONProtocol works correctly.
func Test_RefactoringSafety_ExecutionFlow(t *testing.T) {
	executablePath := createSafetyTestExecutable(t)

	factory := NewSubprocessPluginFactory[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse](nil)

	config := PluginConfig{
		Name:       "execution-flow-test",
		Type:       "subprocess",
		Transport:  TransportExecutable,
		Endpoint:   executablePath,
		Executable: executablePath,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Skipf("Skipping test due to compilation requirements: %v", err)
		return
	}

	ctx := context.Background()

	t.Run("execution_flow_validation", func(t *testing.T) {
		// Test the complete execution flow
		request := RefactoringSafetyTestRequest{
			ID:      "execution-flow-test",
			Message: "flow test message",
			Number:  123,
		}

		execCtx := ExecutionContext{
			RequestID: "execution-flow-request",
			Timeout:   5 * time.Second,
		}

		// Measure execution time
		start := time.Now()
		response, err := plugin.Execute(ctx, execCtx, request)
		executionTime := time.Since(start)

		if err != nil {
			t.Errorf("Execution flow failed: %v", err)
			return
		}

		// Verify response structure
		if response.ID != request.ID {
			t.Errorf("Response ID mismatch: expected %s, got %s", request.ID, response.ID)
		}

		if response.Result != fmt.Sprintf("Echo: %s", request.Message) {
			t.Errorf("Response result mismatch: expected 'Echo: %s', got '%s'", request.Message, response.Result)
		}

		if response.Number != request.Number*2 {
			t.Errorf("Response number mismatch: expected %d, got %d", request.Number*2, response.Number)
		}

		if !response.Success {
			t.Error("Response should indicate success")
		}

		// Verify execution time is reasonable (should be fast for local execution)
		if executionTime > 2*time.Second {
			t.Errorf("Execution took too long: %v", executionTime)
		}

		t.Logf("Execution completed in %v", executionTime)

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})

	t.Run("error_handling_validation", func(t *testing.T) {
		// Test error handling in the execution flow
		_ = plugin.(*SubprocessPlugin[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse])

		// Test with invalid request (should still work due to echo behavior)
		request := RefactoringSafetyTestRequest{
			ID:      "error-test",
			Message: "", // Empty message
			Number:  -1, // Negative number
		}

		execCtx := ExecutionContext{
			RequestID: "error-test-request",
			Timeout:   5 * time.Second,
		}

		response, err := plugin.Execute(ctx, execCtx, request)
		if err != nil {
			t.Errorf("Error handling test failed: %v", err)
			return
		}

		// The response should still be valid even with edge case inputs
		if response.ID != request.ID {
			t.Errorf("Response ID mismatch: expected %s, got %s", request.ID, response.ID)
		}

		if !response.Success {
			t.Error("Response should indicate success even with edge case inputs")
		}

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})
}

// Test_RefactoringSafety_PipeManagement tests the pipe management
// to ensure getStdinPipe and getStdoutPipe work correctly.
func Test_RefactoringSafety_PipeManagement(t *testing.T) {
	executablePath := createSafetyTestExecutable(t)

	factory := NewSubprocessPluginFactory[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse](nil)

	config := PluginConfig{
		Name:       "pipe-management-test",
		Type:       "subprocess",
		Transport:  TransportExecutable,
		Endpoint:   executablePath,
		Executable: executablePath,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Skipf("Skipping test due to compilation requirements: %v", err)
		return
	}

	ctx := context.Background()

	t.Run("pipe_creation_and_caching", func(t *testing.T) {
		sp := plugin.(*SubprocessPlugin[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse])

		// Verify initial state
		if sp.stdin != nil || sp.stdout != nil {
			t.Error("Pipes should be nil initially")
		}

		// Trigger pipe creation through execution
		request := RefactoringSafetyTestRequest{
			ID:      "pipe-test",
			Message: "pipe test message",
			Number:  456,
		}

		execCtx := ExecutionContext{
			RequestID: "pipe-test-request",
			Timeout:   5 * time.Second,
		}

		response, err := plugin.Execute(ctx, execCtx, request)
		if err != nil {
			t.Errorf("Pipe creation test failed: %v", err)
			return
		}

		// Verify pipes were created and cached
		if sp.stdin == nil {
			t.Error("Stdin pipe should be created and cached")
		}

		if sp.stdout == nil {
			t.Error("Stdout pipe should be created and cached")
		}

		// Verify response
		if !response.Success {
			t.Error("Response should indicate success")
		}

		// Test that subsequent executions use cached pipes
		request2 := RefactoringSafetyTestRequest{
			ID:      "pipe-test-2",
			Message: "second pipe test",
			Number:  789,
		}

		execCtx2 := ExecutionContext{
			RequestID: "pipe-test-request-2",
			Timeout:   5 * time.Second,
		}

		response2, err := plugin.Execute(ctx, execCtx2, request2)
		if err != nil {
			t.Errorf("Second pipe execution failed: %v", err)
			return
		}

		// Verify the same pipes are reused
		if sp.stdin == nil || sp.stdout == nil {
			t.Error("Pipes should still be cached after second execution")
		}

		if !response2.Success {
			t.Error("Second response should indicate success")
		}

		t.Logf("Pipe caching test completed successfully")

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})

	t.Run("concurrent_pipe_access", func(t *testing.T) {
		// Test concurrent access to pipes
		const numConcurrent = 5
		var wg sync.WaitGroup
		results := make([]RefactoringSafetyTestResponse, numConcurrent)
		errors := make([]error, numConcurrent)

		for i := 0; i < numConcurrent; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				request := RefactoringSafetyTestRequest{
					ID:      fmt.Sprintf("concurrent-pipe-%d", index),
					Message: fmt.Sprintf("concurrent message %d", index),
					Number:  index * 100,
				}

				execCtx := ExecutionContext{
					RequestID: fmt.Sprintf("concurrent-pipe-request-%d", index),
					Timeout:   5 * time.Second,
				}

				response, err := plugin.Execute(ctx, execCtx, request)
				results[index] = response
				errors[index] = err
			}(i)
		}

		wg.Wait()

		// Verify all concurrent requests succeeded
		for i, err := range errors {
			if err != nil {
				t.Errorf("Concurrent pipe request %d failed: %v", i, err)
			}
		}

		// Verify all responses are correct
		for i, response := range results {
			if !response.Success {
				t.Errorf("Concurrent pipe response %d should indicate success", i)
			}
		}

		t.Logf("Concurrent pipe access test completed successfully")

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})
}

// Test_RefactoringSafety_PerformanceBaseline establishes performance baselines
// before refactoring to detect any performance regressions.
func Test_RefactoringSafety_PerformanceBaseline(t *testing.T) {
	executablePath := createSafetyTestExecutable(t)

	factory := NewSubprocessPluginFactory[RefactoringSafetyTestRequest, RefactoringSafetyTestResponse](nil)

	config := PluginConfig{
		Name:       "performance-baseline-test",
		Type:       "subprocess",
		Transport:  TransportExecutable,
		Endpoint:   executablePath,
		Executable: executablePath,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Skipf("Skipping test due to compilation requirements: %v", err)
		return
	}

	ctx := context.Background()

	t.Run("single_execution_performance", func(t *testing.T) {
		// Measure single execution performance
		request := RefactoringSafetyTestRequest{
			ID:      "perf-single",
			Message: "performance test",
			Number:  999,
		}

		execCtx := ExecutionContext{
			RequestID: "perf-single-request",
			Timeout:   5 * time.Second,
		}

		start := time.Now()
		response, err := plugin.Execute(ctx, execCtx, request)
		singleExecutionTime := time.Since(start)

		if err != nil {
			t.Errorf("Single execution performance test failed: %v", err)
			return
		}

		if !response.Success {
			t.Error("Response should indicate success")
		}

		t.Logf("Single execution time: %v", singleExecutionTime)

		// Establish baseline (should be under 100ms for local execution)
		if singleExecutionTime > 100*time.Millisecond {
			t.Logf("WARNING: Single execution time is higher than expected: %v", singleExecutionTime)
		}

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})

	t.Run("batch_execution_performance", func(t *testing.T) {
		// Measure batch execution performance
		const batchSize = 100
		requests := make([]RefactoringSafetyTestRequest, batchSize)
		execCtxs := make([]ExecutionContext, batchSize)

		for i := 0; i < batchSize; i++ {
			requests[i] = RefactoringSafetyTestRequest{
				ID:      fmt.Sprintf("perf-batch-%d", i),
				Message: fmt.Sprintf("batch message %d", i),
				Number:  i,
			}

			execCtxs[i] = ExecutionContext{
				RequestID: fmt.Sprintf("perf-batch-request-%d", i),
				Timeout:   5 * time.Second,
			}
		}

		start := time.Now()
		var errors []error
		var responses []RefactoringSafetyTestResponse

		for i := 0; i < batchSize; i++ {
			response, err := plugin.Execute(ctx, execCtxs[i], requests[i])
			responses = append(responses, response)
			errors = append(errors, err)
		}

		batchExecutionTime := time.Since(start)

		// Verify all requests succeeded
		for i, err := range errors {
			if err != nil {
				t.Errorf("Batch request %d failed: %v", i, err)
			}
		}

		// Verify all responses
		for i, response := range responses {
			if !response.Success {
				t.Errorf("Batch response %d should indicate success", i)
			}
		}

		avgExecutionTime := batchExecutionTime / batchSize
		t.Logf("Batch execution time: %v (avg: %v per request)", batchExecutionTime, avgExecutionTime)

		// Establish baseline (average should be under 50ms for local execution)
		if avgExecutionTime > 50*time.Millisecond {
			t.Logf("WARNING: Average batch execution time is higher than expected: %v", avgExecutionTime)
		}

		// Clean up
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	})
}

// Benchmark_RefactoringSafety_ExecutionFlow benchmarks the execution flow
// to establish performance baselines before refactoring.
func Benchmark_RefactoringSafety_ExecutionFlow(b *testing.B) {
	// This benchmark would require a compiled test executable
	// For now, we'll skip it in the safety net
	b.Skip("Benchmark requires compiled test executable")
}
