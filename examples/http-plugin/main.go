// main.go: Example demonstrating the HTTP plugin in action
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	goplugins "github.com/agilira/go-plugins"
)

const (
	serverAddress = "localhost:8080"
	pluginBaseURL = "http://localhost:8080"
)

func main() {
	// Setup logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start the HTTP server
	logger.Info("Starting HTTP server...")
	server := NewTextProcessorServer(logger, "1.0.0")
	if err := server.Start(ctx, serverAddress); err != nil {
		logger.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			logger.Error("Failed to stop server", "error", err)
		}
	}()

	// Wait a moment for server to be ready
	time.Sleep(500 * time.Millisecond)

	// Create the plugin client
	logger.Info("Creating HTTP plugin client...")
	plugin, err := NewTextProcessorPlugin(pluginBaseURL, logger)
	if err != nil {
		logger.Error("Failed to create plugin", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			logger.Error("Failed to close plugin", "error", err)
		}
	}()

	// Demonstrate plugin usage
	wg.Add(1)
	go func() {
		defer wg.Done()
		demonstratePlugin(ctx, plugin, logger)
	}()

	// Wait for shutdown signal
	go func() {
		<-sigChan
		logger.Info("Shutdown signal received, stopping...")
		cancel()
	}()

	// Wait for demonstration to complete or context cancellation
	wg.Wait()

	logger.Info("Example completed successfully")
}

// demonstratePlugin shows various plugin operations
func demonstratePlugin(ctx context.Context, plugin *TextProcessorPlugin, logger *slog.Logger) {
	// Display plugin information
	info := plugin.Info()
	logger.Info("Plugin Information",
		"name", info.Name,
		"version", info.Version,
		"description", info.Description,
		"capabilities", info.Capabilities)

	// Check plugin health
	health := plugin.Health(ctx)
	logger.Info("Plugin Health Check",
		"status", health.Status.String(),
		"message", health.Message,
		"response_time", health.ResponseTime,
		"metadata", health.Metadata)

	if health.Status != goplugins.StatusHealthy {
		logger.Error("Plugin is not healthy, skipping operations")
		return
	}

	// Prepare execution context
	execCtx := goplugins.ExecutionContext{
		RequestID:  "demo-request-001",
		Timeout:    10 * time.Second,
		MaxRetries: 3,
		Headers:    map[string]string{"X-Client": "HTTP-Example"},
	}

	// Test operations
	testTexts := []string{
		"Hello World! This is a test.",
		"the quick brown fox jumps over the lazy dog",
		"Contact us at info@example.com or support@test.org for help.",
		"   Multiple    spaces   and   newlines\n\n   need   cleaning   ",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
	}

	operations := []string{
		"uppercase",
		"lowercase",
		"reverse",
		"word_count",
		"clean_whitespace",
		"extract_emails",
		"capitalize",
		"invalid_operation", // This should fail
	}

	logger.Info("Starting text processing demonstrations...")

	for i, operation := range operations {
		for j, text := range testTexts {
			// Skip long demonstrations for some operations
			if operation == "word_count" && j > 0 {
				break
			}
			if operation == "extract_emails" && j != 2 {
				continue // Only test with email text
			}

			execCtx.RequestID = fmt.Sprintf("demo-request-%03d", i*len(testTexts)+j+1)

			logger.Info("Executing text processing",
				"request_id", execCtx.RequestID,
				"operation", operation,
				"text", truncateText(text, 50))

			req := TextProcessingRequest{
				Operation: operation,
				Text:      text,
			}

			start := time.Now()
			resp, err := plugin.Execute(ctx, execCtx, req)
			duration := time.Since(start)

			if err != nil {
				logger.Error("Text processing failed",
					"request_id", execCtx.RequestID,
					"operation", operation,
					"error", err,
					"duration", duration)
			} else {
				logger.Info("Text processing completed",
					"request_id", execCtx.RequestID,
					"operation", operation,
					"result", truncateText(resp.Result, 100),
					"metadata", resp.Metadata,
					"duration", duration)
			}

			// Small delay between operations
			time.Sleep(200 * time.Millisecond)

			// Check for context cancellation
			if ctx.Err() != nil {
				logger.Info("Context cancelled, stopping demonstrations")
				return
			}
		}
	}

	// Perform multiple health checks to show continuous monitoring
	logger.Info("Performing continuous health monitoring...")
	for i := 0; i < 5; i++ {
		health := plugin.Health(ctx)
		logger.Info("Health monitor",
			"check", i+1,
			"status", health.Status.String(),
			"response_time", health.ResponseTime,
			"uptime", health.Metadata["uptime"])

		time.Sleep(1 * time.Second)

		if ctx.Err() != nil {
			return
		}
	}

	// Demonstrate concurrent operations
	logger.Info("Demonstrating concurrent operations...")
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			execCtx := goplugins.ExecutionContext{
				RequestID: fmt.Sprintf("concurrent-req-%d", id),
				Timeout:   5 * time.Second,
			}

			req := TextProcessingRequest{
				Operation: "uppercase",
				Text:      fmt.Sprintf("concurrent operation %d", id),
			}

			resp, err := plugin.Execute(ctx, execCtx, req)
			if err != nil {
				logger.Error("Concurrent operation failed",
					"request_id", execCtx.RequestID,
					"error", err)
			} else {
				logger.Info("Concurrent operation completed",
					"request_id", execCtx.RequestID,
					"result", resp.Result)
			}
		}(i)
	}

	wg.Wait()
	logger.Info("All concurrent operations completed")

	// Test error handling with invalid JSON
	logger.Info("Testing error handling...")
	execCtx.RequestID = "error-test-001"

	req := TextProcessingRequest{
		Operation: "nonexistent",
		Text:      "test",
	}

	_, err := plugin.Execute(ctx, execCtx, req)
	if err != nil {
		logger.Info("Error handling test successful", "expected_error", err)
	} else {
		logger.Error("Expected error but got success")
	}
}

// truncateText truncates text to a maximum length for display
func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen-3] + "..."
}
