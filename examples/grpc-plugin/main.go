// main.go: Example demonstrating the gRPC plugin in action
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
	serverAddress = "localhost:50051"
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

	// Start the gRPC server
	logger.Info("Starting gRPC server...")
	server, err := StartServer(ctx, serverAddress, logger)
	if err != nil {
		logger.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
	defer server.Stop()

	// Wait a moment for server to be ready
	time.Sleep(500 * time.Millisecond)

	// Create the plugin client
	logger.Info("Creating gRPC plugin client...")
	plugin, err := NewCalculatorPlugin(serverAddress, logger)
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
func demonstratePlugin(ctx context.Context, plugin *CalculatorPlugin, logger *slog.Logger) {
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
		"response_time", health.ResponseTime)

	if health.Status != goplugins.StatusHealthy {
		logger.Error("Plugin is not healthy, skipping operations")
		return
	}

	// Prepare execution context
	execCtx := goplugins.ExecutionContext{
		RequestID:  "demo-request-001",
		Timeout:    10 * time.Second,
		MaxRetries: 3,
		Headers:    map[string]string{"X-Client": "gRPC-Example"},
	}

	// Test operations
	testOperations := []CalculationRequest{
		{Operation: "add", A: 10, B: 5},
		{Operation: "multiply", A: 7, B: 8},
		{Operation: "divide", A: 20, B: 4},
		{Operation: "divide", A: 15, B: 0},   // This should fail gracefully
		{Operation: "subtract", A: 10, B: 3}, // This should fail (unsupported operation)
	}

	logger.Info("Starting calculation demonstrations...")

	for i, req := range testOperations {
		execCtx.RequestID = fmt.Sprintf("demo-request-%03d", i+1)

		logger.Info("Executing calculation",
			"request_id", execCtx.RequestID,
			"operation", req.Operation,
			"a", req.A,
			"b", req.B)

		start := time.Now()
		resp, err := plugin.Execute(ctx, execCtx, req)
		duration := time.Since(start)

		if err != nil {
			logger.Error("Calculation failed",
				"request_id", execCtx.RequestID,
				"error", err,
				"duration", duration)
		} else {
			logger.Info("Calculation completed",
				"request_id", execCtx.RequestID,
				"result", resp.Result,
				"error", resp.Error,
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

	// Perform multiple health checks to show continuous monitoring
	logger.Info("Performing continuous health monitoring...")
	for i := 0; i < 5; i++ {
		health := plugin.Health(ctx)
		logger.Info("Health monitor",
			"check", i+1,
			"status", health.Status.String(),
			"response_time", health.ResponseTime)

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

			req := CalculationRequest{
				Operation: "add",
				A:         float64(id * 10),
				B:         float64(id * 5),
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
}
