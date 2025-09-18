// main.go: Complete example of graceful shutdown integration
//
// This example demonstrates how to use the integrated graceful shutdown system
// with the go-plugins library.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	goplugins "github.com/agilira/go-plugins"
)

func main() {
	fmt.Println("Starting graceful shutdown integration example...")

	// Run the main example
	if err := gracefulShutdownExample(); err != nil {
		log.Fatalf("Example failed: %v", err)
	}

	fmt.Println("Graceful shutdown integration example completed successfully!")
}

// gracefulShutdownExample demonstrates complete graceful shutdown integration.
func gracefulShutdownExample() error {
	// Create basic registry configuration
	config := goplugins.RegistryConfig{
		MaxClients:        10,
		ClientTimeout:     30 * time.Second,
		AutoDiscovery:     false,
		DiscoveryPaths:    []string{},
		DiscoveryInterval: 60 * time.Second,
		HandshakeConfig: goplugins.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "GOPLUGINS_MAGIC",
			MagicCookieValue: "graceful_shutdown_demo",
		},
		Logger: goplugins.DefaultLogger(),
	}

	// Create and start the plugin registry
	registry := goplugins.NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		return fmt.Errorf("failed to start registry: %w", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			log.Printf("Error stopping registry: %v", err)
		}
	}()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Setup context with cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Plugin registry started. Press Ctrl+C to initiate graceful shutdown...")

	// Simulate some work
	workDone := make(chan bool)
	go func() {
		defer close(workDone)
		simulateWork(ctx)
	}()

	// Wait for signal or work completion
	select {
	case sig := <-sigChan:
		fmt.Printf("Received signal: %s. Initiating graceful shutdown...\n", sig)

		// Cancel context to signal all goroutines to stop
		cancel()

		// Give work time to finish gracefully
		select {
		case <-workDone:
			fmt.Println("Work completed gracefully")
		case <-time.After(10 * time.Second):
			fmt.Println("Work timed out, forcing shutdown")
		}

	case <-workDone:
		fmt.Println("Work completed normally")
	}

	fmt.Println("Graceful shutdown completed")
	return nil
}

// simulateWork simulates some ongoing work that respects context cancellation
func simulateWork(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	counter := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Work cancelled by context")
			return
		case <-ticker.C:
			counter++
			fmt.Printf("Work iteration %d completed\n", counter)

			// Simulate finishing after a few iterations
			if counter >= 5 {
				fmt.Println("Work finished naturally")
				return
			}
		}
	}
}
