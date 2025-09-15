// main_test.go: Comprehensive test suite for the HTTP plugin example
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"

	goplugins "github.com/agilira/go-plugins"
)

const testServerAddress = "localhost:8081"
const testPluginBaseURL = "http://localhost:8081"

var testServer *TextProcessorServer

func TestMain(m *testing.M) {
	// Setup test logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors during tests
	}))

	// Start test HTTP server
	testServer = NewTextProcessorServer(logger, "1.0.0-test")
	ctx := context.Background()

	if err := testServer.Start(ctx, testServerAddress); err != nil {
		logger.Error("Failed to start test server", "error", err)
		os.Exit(1)
	}

	// Wait for server to be ready
	time.Sleep(200 * time.Millisecond)

	// Run tests
	code := m.Run()

	// Cleanup
	if err := testServer.Stop(); err != nil {
		log.Printf("Failed to stop test server: %v", err)
	}

	os.Exit(code)
}

func TestTextProcessorPlugin_Info(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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

	expectedCapabilities := []string{"uppercase", "lowercase", "reverse", "word_count", "clean_whitespace", "extract_emails", "capitalize"}
	for _, expected := range expectedCapabilities {
		found := false
		for _, actual := range info.Capabilities {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected capability %s not found in %v", expected, info.Capabilities)
		}
	}

	t.Logf("Plugin info: %+v", info)
}

func TestTextProcessorPlugin_Health(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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

	// Check metadata
	if health.Metadata["transport"] != "HTTP" {
		t.Error("Expected transport metadata to be HTTP")
	}

	if health.Metadata["uptime"] == "" {
		t.Error("Expected uptime in metadata")
	}

	t.Logf("Health check: %+v", health)
}

func TestTextProcessorPlugin_Execute_Uppercase(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
		RequestID: "test-uppercase-001",
		Timeout:   5 * time.Second,
	}

	request := TextProcessingRequest{
		Operation: "uppercase",
		Text:      "hello world",
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := "HELLO WORLD"
	if response.Result != expected {
		t.Errorf("Expected result %s, got %s", expected, response.Result)
	}

	if response.Error != "" {
		t.Errorf("Expected no error, got: %s", response.Error)
	}

	if response.Metadata["original_length"] != "11" {
		t.Errorf("Expected original_length metadata to be 11, got %s", response.Metadata["original_length"])
	}
}

func TestTextProcessorPlugin_Execute_Lowercase(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
		RequestID: "test-lowercase-001",
		Timeout:   5 * time.Second,
	}

	request := TextProcessingRequest{
		Operation: "lowercase",
		Text:      "HELLO WORLD",
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := "hello world"
	if response.Result != expected {
		t.Errorf("Expected result %s, got %s", expected, response.Result)
	}
}

func TestTextProcessorPlugin_Execute_Reverse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
		RequestID: "test-reverse-001",
		Timeout:   5 * time.Second,
	}

	request := TextProcessingRequest{
		Operation: "reverse",
		Text:      "hello",
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := "olleh"
	if response.Result != expected {
		t.Errorf("Expected result %s, got %s", expected, response.Result)
	}
}

func TestTextProcessorPlugin_Execute_WordCount(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
		RequestID: "test-word-count-001",
		Timeout:   5 * time.Second,
	}

	request := TextProcessingRequest{
		Operation: "word_count",
		Text:      "hello world test",
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := "3"
	if response.Result != expected {
		t.Errorf("Expected result %s, got %s", expected, response.Result)
	}

	if response.Metadata["character_count"] != "16" {
		t.Errorf("Expected character_count to be 16, got %s", response.Metadata["character_count"])
	}
}

func TestTextProcessorPlugin_Execute_ExtractEmails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
		RequestID: "test-extract-emails-001",
		Timeout:   5 * time.Second,
	}

	request := TextProcessingRequest{
		Operation: "extract_emails",
		Text:      "Contact us at info@example.com or support@test.org for help.",
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should contain both emails
	if response.Result != "info@example.com, support@test.org" {
		t.Errorf("Expected emails to be extracted, got: %s", response.Result)
	}

	if response.Metadata["emails_found"] != "2" {
		t.Errorf("Expected 2 emails found, got %s", response.Metadata["emails_found"])
	}
}

func TestTextProcessorPlugin_Execute_CleanWhitespace(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
		RequestID: "test-clean-whitespace-001",
		Timeout:   5 * time.Second,
	}

	request := TextProcessingRequest{
		Operation: "clean_whitespace",
		Text:      "  hello    world   ",
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := "hello world"
	if response.Result != expected {
		t.Errorf("Expected result %s, got %s", expected, response.Result)
	}
}

func TestTextProcessorPlugin_Execute_UnsupportedOperation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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

	request := TextProcessingRequest{
		Operation: "nonexistent",
		Text:      "test",
	}

	_, err = plugin.Execute(ctx, execCtx, request)
	if err == nil {
		t.Error("Expected error for unsupported operation")
	}

	t.Logf("Unsupported operation error: %v", err)
}

func TestTextProcessorPlugin_Execute_WithTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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

	request := TextProcessingRequest{
		Operation: "uppercase",
		Text:      "test",
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

func TestTextProcessorPlugin_ConcurrentExecutions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
	results := make(chan string, numOperations)
	errors := make(chan error, numOperations)

	for i := 0; i < numOperations; i++ {
		go func(id int) {
			execCtx := goplugins.ExecutionContext{
				RequestID: fmt.Sprintf("concurrent-test-%d", id),
				Timeout:   5 * time.Second,
			}

			request := TextProcessingRequest{
				Operation: "uppercase",
				Text:      fmt.Sprintf("test %d", id),
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
			t.Logf("Operation %d succeeded with result: %s", i, result)
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

func TestTextProcessorPlugin_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
func BenchmarkTextProcessorPlugin_Uppercase(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
		RequestID: "benchmark-uppercase",
		Timeout:   5 * time.Second,
	}

	request := TextProcessingRequest{
		Operation: "uppercase",
		Text:      "hello world test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plugin.Execute(ctx, execCtx, request)
		if err != nil {
			b.Fatalf("Execute failed: %v", err)
		}
	}
}

func BenchmarkTextProcessorPlugin_Health(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	plugin, err := NewTextProcessorPlugin(testPluginBaseURL, logger)
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
