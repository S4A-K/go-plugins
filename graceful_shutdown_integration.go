// graceful_shutdown_integration.go: Complete example of graceful shutdown integration
//
// This example demonstrates how to use the integrated graceful shutdown system
// across all components: registry, clients, RPC protocols, and subprocess plugins.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// GracefulShutdownExample demonstrates complete graceful shutdown integration.
func GracefulShutdownExample() {
	// Create registry configuration with graceful shutdown settings
	config := RegistryConfig{
		MaxClients:        50,
		ClientTimeout:     30 * time.Second,
		AutoDiscovery:     false,
		DiscoveryPaths:    []string{},
		DiscoveryInterval: 60 * time.Second,
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "EXAMPLE_PLUGIN",
			MagicCookieValue: "hello-world",
			ProtocolVersion:  1,
		},
		HealthCheckConfig: HealthCheckConfig{
			Enabled:  true,
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
		},
		DrainOptions: DrainOptions{
			DrainTimeout:            30 * time.Second,
			ForceCancelAfterTimeout: true,
			ProgressCallback: func(pluginName string, activeCount int64) {
				log.Printf("Draining progress: Plugin %s has %d active requests remaining",
					pluginName, activeCount)
			},
		},
		Logger: DefaultLogger(),
	}

	// Create and start registry
	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		log.Fatalf("Failed to start plugin registry: %v", err)
	}

	// Create shutdown coordinator
	coordinator := NewShutdownCoordinator(registry)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("Plugin system started. Setting up example plugins...")

	// Register some example plugin clients
	if err := setupExamplePlugins(registry); err != nil {
		log.Fatalf("Failed to setup example plugins: %v", err)
	}

	// Simulate some work with the plugins
	workCtx, workCancel := context.WithCancel(ctx)
	var wg sync.WaitGroup

	// Start background work that makes requests to plugins
	wg.Add(1)
	go func() {
		defer wg.Done()
		simulateWorkload(workCtx, registry)
	}()

	log.Println("System running. Send SIGINT (Ctrl+C) or SIGTERM to trigger graceful shutdown...")

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, starting graceful shutdown...", sig)
	case <-ctx.Done():
		log.Println("Context cancelled, starting shutdown...")
	}

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer shutdownCancel()

	// Start graceful shutdown
	log.Println("Phase 1: Stopping new work...")
	workCancel() // Stop generating new work

	log.Println("Phase 2: Graceful shutdown in progress...")

	// Show status before shutdown
	status := coordinator.GetShutdownStatus()
	log.Printf("Pre-shutdown status: Phase=%s, Running=%v, Draining=%v, ActiveRequests=%d",
		status.Phase, status.IsRunning, status.IsDraining, status.ActiveRequests)

	// Perform graceful shutdown
	if err := coordinator.GracefulShutdown(shutdownCtx); err != nil {
		log.Printf("Graceful shutdown encountered errors: %v", err)
		log.Println("Attempting force shutdown...")

		if forceErr := coordinator.ForceShutdown(); forceErr != nil {
			log.Fatalf("Force shutdown failed: %v", forceErr)
		}
	}

	// Wait for background work to finish
	wg.Wait()

	// Show final status
	finalStatus := coordinator.GetShutdownStatus()
	log.Printf("Final status: Phase=%s, Running=%v, ActiveRequests=%d",
		finalStatus.Phase, finalStatus.IsRunning, finalStatus.ActiveRequests)

	log.Println("Graceful shutdown completed successfully!")
}

// setupExamplePlugins creates example plugin clients for demonstration.
func setupExamplePlugins(registry *PluginRegistry) error {
	pluginConfigs := []PluginConfig{
		{
			Name:       "auth-plugin",
			Type:       "authentication",
			Transport:  TransportExecutable,
			Executable: "/bin/echo", // Mock executable for example
			Args:       []string{"auth-service"},
		},
		{
			Name:       "data-plugin",
			Type:       "data-processing",
			Transport:  TransportExecutable,
			Executable: "/bin/echo", // Mock executable for example
			Args:       []string{"data-service"},
		},
		{
			Name:       "notification-plugin",
			Type:       "notification",
			Transport:  TransportExecutable,
			Executable: "/bin/echo", // Mock executable for example
			Args:       []string{"notification-service"},
		},
	}

	for _, config := range pluginConfigs {
		client, err := registry.CreateClient(config)
		if err != nil {
			return NewPluginConnectionFailedError(config.Name, err)
		}

		log.Printf("Created plugin client: %s (%s)", client.Name, client.Type)
	}

	return nil
}

// simulateWorkload simulates continuous work that makes requests to plugins.
func simulateWorkload(ctx context.Context, registry *PluginRegistry) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	requestID := 0
	clientNames := []string{"auth-plugin", "data-plugin", "notification-plugin"}

	for {
		select {
		case <-ctx.Done():
			log.Println("Workload simulation stopped")
			return
		case <-ticker.C:
			// Make requests to random plugins
			for _, clientName := range clientNames {
				requestID++

				// Create context for this request
				reqCtx, reqCancel := context.WithTimeout(ctx, 10*time.Second)

				go func(client, method string, id int) {
					defer reqCancel()

					// Simulate request processing time
					processingTime := time.Duration(1+id%3) * time.Second

					log.Printf("Making request %d to %s (processing time: %v)", id, client, processingTime)

					// Simulate processing time
					select {
					case <-time.After(processingTime):
						// Request completed normally
						log.Printf("Request %d to %s completed", id, client)
					case <-reqCtx.Done():
						// Request was cancelled (likely due to shutdown)
						log.Printf("Request %d to %s was cancelled: %v", id, client, reqCtx.Err())
					}
				}(clientName, "process", requestID)
			}

			// Show active requests periodically
			if requestID%5 == 0 {
				activeRequests := registry.GetActiveRequestsCount()
				totalActive := int64(0)
				for _, count := range activeRequests {
					totalActive += count
				}
				if totalActive > 0 {
					log.Printf("Current active requests: %d (by client: %v)", totalActive, activeRequests)
				}
			}
		}
	}
}

// SignalBasedShutdown provides a reusable signal-based shutdown handler.
type SignalBasedShutdown struct {
	coordinator *ShutdownCoordinator
	logger      Logger
	sigChan     chan os.Signal
}

// NewSignalBasedShutdown creates a new signal-based shutdown handler.
func NewSignalBasedShutdown(coordinator *ShutdownCoordinator, logger Logger) *SignalBasedShutdown {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	return &SignalBasedShutdown{
		coordinator: coordinator,
		logger:      logger,
		sigChan:     sigChan,
	}
}

// WaitForShutdown waits for a shutdown signal and handles graceful shutdown.
func (sbs *SignalBasedShutdown) WaitForShutdown(ctx context.Context, timeout time.Duration) error {
	select {
	case sig := <-sbs.sigChan:
		sbs.logger.Info("Received shutdown signal", "signal", sig.String())
	case <-ctx.Done():
		sbs.logger.Info("Context cancelled, starting shutdown")
	}

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Perform graceful shutdown
	if err := sbs.coordinator.GracefulShutdown(shutdownCtx); err != nil {
		sbs.logger.Error("Graceful shutdown failed", "error", err)

		// Attempt force shutdown as fallback
		sbs.logger.Warn("Attempting force shutdown")
		if forceErr := sbs.coordinator.ForceShutdown(); forceErr != nil {
			return NewPluginExecutionFailedError("shutdown", err)
		}

		return NewPluginExecutionFailedError("graceful-shutdown", err)
	}

	sbs.logger.Info("Graceful shutdown completed successfully")
	return nil
}

// HealthAwareShutdown provides health-aware shutdown that monitors system health.
type HealthAwareShutdown struct {
	coordinator *ShutdownCoordinator
	logger      Logger

	// Health monitoring
	healthCheckInterval time.Duration
	unhealthyThreshold  int
}

// NewHealthAwareShutdown creates a health-aware shutdown handler.
func NewHealthAwareShutdown(coordinator *ShutdownCoordinator, logger Logger) *HealthAwareShutdown {
	return &HealthAwareShutdown{
		coordinator:         coordinator,
		logger:              logger,
		healthCheckInterval: 10 * time.Second,
		unhealthyThreshold:  3,
	}
}

// MonitorAndShutdown monitors system health and performs shutdown when unhealthy.
func (has *HealthAwareShutdown) MonitorAndShutdown(ctx context.Context) error {
	ticker := time.NewTicker(has.healthCheckInterval)
	defer ticker.Stop()

	unhealthyCount := 0

	for {
		select {
		case <-ctx.Done():
			has.logger.Info("Health monitoring stopped")
			return ctx.Err()
		case <-ticker.C:
			status := has.coordinator.GetShutdownStatus()

			// Check if system is healthy
			healthy := status.IsRunning && !status.IsDraining

			if !healthy {
				unhealthyCount++
				has.logger.Warn("System unhealthy",
					"consecutive_unhealthy", unhealthyCount,
					"phase", status.Phase,
					"active_requests", status.ActiveRequests)

				if unhealthyCount >= has.unhealthyThreshold {
					has.logger.Error("System unhealthy for too long, triggering shutdown")

					shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()

					return has.coordinator.GracefulShutdown(shutdownCtx)
				}
			} else {
				// Reset counter on healthy status
				if unhealthyCount > 0 {
					has.logger.Info("System back to healthy state")
					unhealthyCount = 0
				}
			}
		}
	}
}

// Example usage functions for documentation and testing

// ExampleBasicGracefulShutdown demonstrates basic graceful shutdown usage.
func ExampleBasicGracefulShutdown() {
	// Setup registry
	config := RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		DrainOptions: DrainOptions{
			DrainTimeout:            10 * time.Second,
			ForceCancelAfterTimeout: true,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		// Log error but continue for example purposes
		fmt.Printf("Failed to start registry: %v\n", err)
		return
	}

	// Create shutdown coordinator
	coordinator := NewShutdownCoordinator(registry)

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := coordinator.GracefulShutdown(ctx); err != nil {
		log.Fatalf("Shutdown failed: %v", err)
	}

	fmt.Println("Shutdown completed")
	// Output: Shutdown completed
}

// ExampleSignalBasedShutdown demonstrates signal-based shutdown.
func ExampleSignalBasedShutdown() {
	registry := NewPluginRegistry(RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
	})
	if err := registry.Start(); err != nil {
		fmt.Printf("Failed to start registry: %v\n", err)
		return
	}

	coordinator := NewShutdownCoordinator(registry)
	signalShutdown := NewSignalBasedShutdown(coordinator, DefaultLogger())

	// This would wait for actual signals in a real application
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Simulate signal/cancellation

	err := signalShutdown.WaitForShutdown(ctx, 30*time.Second)
	if err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	fmt.Println("Signal-based shutdown completed")
	// Output: Signal-based shutdown completed
}
