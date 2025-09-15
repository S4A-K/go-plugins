// main_test.go: Comprehensive test suite for the gRPC plugin example
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	goplugins "github.com/agilira/go-plugins"
)

const testServerAddress = "localhost:50052"

func TestMain(m *testing.M) {
	// Setup test logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors during tests
	}))

	// Start test gRPC server
	ctx := context.Background()
	server, err := StartServer(ctx, testServerAddress, logger)
	if err != nil {
		logger.Error("Failed to start test server", "error", err)
		os.Exit(1)
	}

	// Wait for server to be ready
	time.Sleep(200 * time.Millisecond)

	// Run tests
	code := m.Run()

	// Cleanup
	server.Stop()

	os.Exit(code)
}

func TestCalculatorPlugin_Info(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	info := plugin.Info()

	if info.Name == "" {
		t.Error("Plugin name should not be empty")
	}

	if info.Version == "" {
		t.Error("Plugin version should not be empty")
	}

	if len(info.Capabilities) == 0 {
		t.Error("Plugin should have capabilities")
	}

	t.Logf("Plugin info: %+v", info)
}

func TestCalculatorPlugin_Health(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	health := plugin.Health(ctx)

	if health.Status != goplugins.StatusHealthy {
		t.Errorf("Expected healthy status, got %v: %s", health.Status, health.Message)
	}

	if health.ResponseTime <= 0 {
		t.Error("Response time should be positive")
	}

	if health.LastCheck.IsZero() {
		t.Error("LastCheck should be set")
	}

	t.Logf("Health check: %+v", health)
}

func TestCalculatorPlugin_Execute_Add(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := goplugins.ExecutionContext{
		RequestID: "test-add-001",
		Timeout:   5 * time.Second,
	}

	request := CalculationRequest{
		Operation: "add",
		A:         10.5,
		B:         5.3,
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := 15.8
	if response.Result != expected {
		t.Errorf("Expected result %f, got %f", expected, response.Result)
	}

	if response.Error != "" {
		t.Errorf("Expected no error, got: %s", response.Error)
	}
}

func TestCalculatorPlugin_Execute_Multiply(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := goplugins.ExecutionContext{
		RequestID: "test-multiply-001",
		Timeout:   5 * time.Second,
	}

	request := CalculationRequest{
		Operation: "multiply",
		A:         7,
		B:         8,
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := 56.0
	if response.Result != expected {
		t.Errorf("Expected result %f, got %f", expected, response.Result)
	}
}

func TestCalculatorPlugin_Execute_Divide(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := goplugins.ExecutionContext{
		RequestID: "test-divide-001",
		Timeout:   5 * time.Second,
	}

	request := CalculationRequest{
		Operation: "divide",
		A:         20,
		B:         4,
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := 5.0
	if response.Result != expected {
		t.Errorf("Expected result %f, got %f", expected, response.Result)
	}
}

func TestCalculatorPlugin_Execute_DivideByZero(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := goplugins.ExecutionContext{
		RequestID: "test-divide-zero-001",
		Timeout:   5 * time.Second,
	}

	request := CalculationRequest{
		Operation: "divide",
		A:         10,
		B:         0,
	}

	_, err = plugin.Execute(ctx, execCtx, request)
	if err == nil {
		t.Error("Expected error for division by zero")
	}

	t.Logf("Division by zero error: %v", err)
}

func TestCalculatorPlugin_Execute_UnsupportedOperation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := goplugins.ExecutionContext{
		RequestID: "test-unsupported-001",
		Timeout:   5 * time.Second,
	}

	request := CalculationRequest{
		Operation: "subtract",
		A:         10,
		B:         5,
	}

	_, err = plugin.Execute(ctx, execCtx, request)
	if err == nil {
		t.Error("Expected error for unsupported operation")
	}

	t.Logf("Unsupported operation error: %v", err)
}

func TestCalculatorPlugin_Execute_WithTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := goplugins.ExecutionContext{
		RequestID: "test-timeout-001",
		Timeout:   1 * time.Nanosecond, // Very short timeout
	}

	request := CalculationRequest{
		Operation: "add",
		A:         1,
		B:         2,
	}

	start := time.Now()
	_, err = plugin.Execute(ctx, execCtx, request)
	duration := time.Since(start)

	// The operation should either complete very quickly or timeout
	if err == nil {
		// If no error, operation completed within timeout
		t.Logf("Operation completed in %v", duration)
	} else {
		// If error, should be timeout-related
		t.Logf("Operation timed out as expected: %v", err)
	}
}

func TestCalculatorPlugin_ConcurrentExecutions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()

	// Run multiple operations concurrently
	const numOperations = 10
	results := make(chan float64, numOperations)
	errors := make(chan error, numOperations)

	for i := 0; i < numOperations; i++ {
		go func(id int) {
			execCtx := goplugins.ExecutionContext{
				RequestID: fmt.Sprintf("concurrent-test-%d", id),
				Timeout:   5 * time.Second,
			}

			request := CalculationRequest{
				Operation: "add",
				A:         float64(id),
				B:         float64(id * 2),
			}

			response, err := plugin.Execute(ctx, execCtx, request)
			if err != nil {
				errors <- err
			} else {
				results <- response.Result
			}
		}(i)
	}

	// Collect results
	var successCount int
	var errorCount int

	for i := 0; i < numOperations; i++ {
		select {
		case result := <-results:
			successCount++
			t.Logf("Operation %d succeeded with result: %f", i, result)
		case err := <-errors:
			errorCount++
			t.Logf("Operation %d failed: %v", i, err)
		case <-time.After(10 * time.Second):
			t.Errorf("Timeout waiting for operation %d", i)
		}
	}

	if errorCount > 0 {
		t.Errorf("Expected all operations to succeed, but %d failed", errorCount)
	}

	if successCount != numOperations {
		t.Errorf("Expected %d successful operations, got %d", numOperations, successCount)
	}
}

func TestCalculatorPlugin_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	// Close should not return error
	err = plugin.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Second close should also not return error (idempotent)
	err = plugin.Close()
	if err != nil {
		t.Errorf("Second close returned error: %v", err)
	}
}

// Benchmark tests
func BenchmarkCalculatorPlugin_Add(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		b.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			b.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := goplugins.ExecutionContext{
		RequestID: "benchmark-add",
		Timeout:   5 * time.Second,
	}

	request := CalculationRequest{
		Operation: "add",
		A:         10,
		B:         20,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plugin.Execute(ctx, execCtx, request)
		if err != nil {
			b.Fatalf("Execute failed: %v", err)
		}
	}
}

func BenchmarkCalculatorPlugin_Health(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewCalculatorPlugin(testServerAddress, logger)
	if err != nil {
		b.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			b.Errorf("Failed to close plugin: %v", err)
		}
	}()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		health := plugin.Health(ctx)
		if health.Status != goplugins.StatusHealthy {
			b.Fatalf("Plugin is not healthy: %v", health.Message)
		}
	}
}
