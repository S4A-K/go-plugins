// plugin_registry_test.go: Comprehensive tests for the plugin registry system
//
// Tests cover registry lifecycle, client management, discovery integration,
// and standard plugin compatibility through subprocess plugins.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestPluginRegistry_Lifecycle tests the basic lifecycle of the plugin registry.
func TestPluginRegistry_Lifecycle(t *testing.T) {
	config := RegistryConfig{
		MaxClients:        10,
		ClientTimeout:     30 * time.Second,
		AutoDiscovery:     false, // Disabled for test
		DiscoveryPaths:    []string{},
		DiscoveryInterval: 60 * time.Second,
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
		HealthCheckConfig: HealthCheckConfig{
			Enabled:  false, // Simplified for test
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
		},
		Logger: DefaultLogger(),
	}

	registry := NewPluginRegistry(config)

	// Test creation
	if registry == nil {
		t.Fatal("Expected non-nil registry")
	}

	// Test start
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}

	// Verify running state
	if !registry.running {
		t.Error("Expected registry to be in running state")
	}

	// Test stop
	if err := registry.Stop(); err != nil {
		t.Fatalf("Failed to stop registry: %v", err)
	}

	// Verify stopped state
	if registry.running {
		t.Error("Expected registry to be in stopped state")
	}
}

// TestPluginRegistry_ClientManagement tests plugin client creation and management.
func TestPluginRegistry_ClientManagement(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    5,
		ClientTimeout: 30 * time.Second,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			t.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Test client creation
	clientConfig := PluginConfig{
		Name:       "test-client",
		Type:       "test",
		Transport:  TransportExecutable,
		Executable: "/bin/echo",
		Args:       []string{"hello"},
	}

	client, err := registry.CreateClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	if client.Name != "test-client" {
		t.Errorf("Expected client name 'test-client', got '%s'", client.Name)
	}

	// Test client retrieval
	retrievedClient, err := registry.GetClient("test-client")
	if err != nil {
		t.Fatalf("Failed to retrieve client: %v", err)
	}

	if retrievedClient != client {
		t.Error("Retrieved client should be the same instance")
	}

	// Test client listing
	clients := registry.ListClients()
	if len(clients) != 1 {
		t.Errorf("Expected 1 client, got %d", len(clients))
	}

	// Test duplicate creation
	_, err = registry.CreateClient(clientConfig)
	if err == nil {
		t.Error("Expected error when creating duplicate client")
	}

	// Test client removal
	if err := registry.RemoveClient("test-client"); err != nil {
		t.Fatalf("Failed to remove client: %v", err)
	}

	// Verify removal
	_, err = registry.GetClient("test-client")
	if err == nil {
		t.Error("Expected error when retrieving removed client")
	}
}

// TestPluginRegistry_ClientLimits tests client creation limits.
func TestPluginRegistry_ClientLimits(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    2, // Small limit for testing
		ClientTimeout: 30 * time.Second,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			t.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Create maximum number of clients
	for i := 0; i < 2; i++ {
		clientConfig := PluginConfig{
			Name:       fmt.Sprintf("test-client-%d", i),
			Type:       "test",
			Transport:  TransportExecutable,
			Executable: "/bin/echo",
			Args:       []string{"hello"},
		}

		_, err := registry.CreateClient(clientConfig)
		if err != nil {
			t.Fatalf("Failed to create client %d: %v", i, err)
		}
	}

	// Try to create one more (should fail)
	clientConfig := PluginConfig{
		Name:       "test-client-overflow",
		Type:       "test",
		Transport:  TransportExecutable,
		Executable: "/bin/echo",
		Args:       []string{"hello"},
	}

	_, err := registry.CreateClient(clientConfig)
	if err == nil {
		t.Error("Expected error when exceeding client limit")
	}
}

// TestPluginRegistry_FactoryRegistration tests plugin factory registration.
func TestPluginRegistry_FactoryRegistration(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
	}

	registry := NewPluginRegistry(config)

	// Create a mock factory
	factory := &SubprocessPluginFactory[any, any]{}

	// Test registration
	if err := registry.RegisterFactory("test-type", factory); err != nil {
		t.Fatalf("Failed to register factory: %v", err)
	}

	// Test duplicate registration
	if err := registry.RegisterFactory("test-type", factory); err == nil {
		t.Error("Expected error when registering duplicate factory")
	}
}

// TestPluginRegistry_Stats tests registry statistics collection.
func TestPluginRegistry_Stats(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    10,
		ClientTimeout: 30 * time.Second,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			t.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Get initial stats
	stats := registry.GetStats()
	if stats.TotalClients != 0 {
		t.Errorf("Expected 0 total clients, got %d", stats.TotalClients)
	}

	// Create some clients
	for i := 0; i < 3; i++ {
		clientConfig := PluginConfig{
			Name:       fmt.Sprintf("stats-test-client-%d", i),
			Type:       fmt.Sprintf("type-%d", i%2), // Two types
			Transport:  TransportExecutable,
			Executable: "/bin/echo",
			Args:       []string{"hello"},
		}

		_, err := registry.CreateClient(clientConfig)
		if err != nil {
			t.Fatalf("Failed to create client %d: %v", i, err)
		}
	}

	// Get updated stats
	stats = registry.GetStats()
	if stats.TotalClients != 3 {
		t.Errorf("Expected 3 total clients, got %d", stats.TotalClients)
	}

	if len(stats.ClientsByType) == 0 {
		t.Error("Expected client type statistics")
	}

	if len(stats.ClientStats) != 3 {
		t.Errorf("Expected 3 client stats, got %d", len(stats.ClientStats))
	}
}

// TestPluginClient_Lifecycle tests plugin client lifecycle management.
func TestPluginClient_Lifecycle(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
		HealthCheckConfig: HealthCheckConfig{
			Enabled: false, // Simplified for test
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			t.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Create client
	clientConfig := PluginConfig{
		Name:       "lifecycle-test-client",
		Type:       "test",
		Transport:  TransportExecutable,
		Executable: "/bin/echo",
		Args:       []string{"hello"},
	}

	client, err := registry.CreateClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Verify initial state
	if client.status != StatusOffline {
		t.Errorf("Expected initial status %s, got %s", StatusOffline, client.status)
	}

	// Note: We're not actually starting the subprocess in this test
	// because it would require a real plugin executable.
	// In a real scenario, you would:
	// 1. Start the client: client.Start()
	// 2. Verify it's running: client.status == StatusHealthy
	// 3. Stop the client: client.Stop()
	// 4. Verify it's stopped: client.status == StatusOffline

	t.Log("Client lifecycle test completed (subprocess not started due to test constraints)")
}

// TestPluginClient_Health tests plugin client health monitoring interface.
func TestPluginClient_Health(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			t.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Create client
	clientConfig := PluginConfig{
		Name:       "health-test-client",
		Type:       "test",
		Transport:  TransportExecutable,
		Executable: "/bin/echo",
		Args:       []string{"hello"},
	}

	client, err := registry.CreateClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test health interface
	ctx := context.Background()
	health := client.Health(ctx)

	if health.Status != StatusOffline {
		t.Errorf("Expected health status %s, got %s", StatusOffline, health.Status)
	}

	if health.Metadata["plugin_name"] != "health-test-client" {
		t.Errorf("Expected plugin_name in metadata")
	}
}

// BenchmarkPluginRegistry_ClientCreation benchmarks client creation performance.
func BenchmarkPluginRegistry_ClientCreation(b *testing.B) {
	config := RegistryConfig{
		MaxClients:    1000,
		ClientTimeout: 30 * time.Second,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		b.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			b.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		clientConfig := PluginConfig{
			Name:       fmt.Sprintf("bench-client-%d", i),
			Type:       "test",
			Transport:  TransportExecutable,
			Executable: "/bin/echo",
			Args:       []string{"hello"},
		}

		client, err := registry.CreateClient(clientConfig)
		if err != nil {
			b.Fatalf("Failed to create client: %v", err)
		}

		// Clean up for next iteration
		if err := registry.RemoveClient(client.Name); err != nil {
			b.Fatalf("Failed to remove client: %v", err)
		}
	}
}

// BenchmarkPluginRegistry_Stats benchmarks statistics collection performance.
func BenchmarkPluginRegistry_Stats(b *testing.B) {
	config := RegistryConfig{
		MaxClients:    100,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		b.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			b.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Create some clients for benchmarking
	for i := 0; i < 50; i++ {
		clientConfig := PluginConfig{
			Name:       fmt.Sprintf("bench-stats-client-%d", i),
			Type:       "test",
			Transport:  TransportExecutable,
			Executable: "/bin/echo",
			Args:       []string{"hello"},
		}

		_, err := registry.CreateClient(clientConfig)
		if err != nil {
			b.Fatalf("Failed to create client: %v", err)
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = registry.GetStats()
	}
}

// Example demonstrates basic usage of the plugin registry system.
func ExamplePluginRegistry_usage() {
	// Create registry configuration
	config := RegistryConfig{
		MaxClients:        50,
		ClientTimeout:     30 * time.Second,
		AutoDiscovery:     false,
		DiscoveryPaths:    []string{},
		DiscoveryInterval: 60 * time.Second,
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
		Logger: DefaultLogger(),
	}

	// Create and start registry
	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		panic(err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			panic(err)
		}
	}()

	// Create a plugin client
	clientConfig := PluginConfig{
		Name:       "example-plugin",
		Type:       "service",
		Transport:  TransportExecutable,
		Executable: "/path/to/plugin",
		Args:       []string{"--serve"},
	}

	_, err := registry.CreateClient(clientConfig)
	if err != nil {
		panic(err)
	}

	// Start the plugin (in real usage)
	// if err := client.Start(); err != nil {
	//     panic(err)
	// }

	// Make calls to the plugin (in real usage)
	// ctx := context.Background()
	// result, err := client.Call(ctx, "MyMethod", map[string]string{"key": "value"})

	// Get registry statistics
	stats := registry.GetStats()
	_ = stats // Use stats as needed

	fmt.Println("Plugin registry example completed")
	// Output: Plugin registry example completed
}

// TestPluginRegistry_GracefulShutdown tests graceful shutdown functionality.
func TestPluginRegistry_GracefulShutdown(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
		DrainOptions: DrainOptions{
			DrainTimeout:            5 * time.Second,
			ForceCancelAfterTimeout: true,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}

	// Create some clients
	for i := 0; i < 3; i++ {
		clientConfig := PluginConfig{
			Name:       fmt.Sprintf("shutdown-test-client-%d", i),
			Type:       "test",
			Transport:  TransportExecutable,
			Executable: "/bin/echo",
			Args:       []string{"hello"},
		}

		_, err := registry.CreateClient(clientConfig)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
	}

	// Test graceful shutdown with context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := registry.StopWithContext(ctx); err != nil {
		t.Fatalf("Failed to stop registry gracefully: %v", err)
	}

	// Verify stopped state
	if registry.running {
		t.Error("Expected registry to be stopped")
	}

	// Verify no active requests remain
	activeRequests := registry.GetActiveRequestsCount()
	totalActive := int64(0)
	for _, count := range activeRequests {
		totalActive += count
	}

	if totalActive > 0 {
		t.Errorf("Expected no active requests after shutdown, got %d", totalActive)
	}
}

// TestPluginRegistry_DrainMode tests draining mode functionality.
func TestPluginRegistry_DrainMode(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			t.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Initially not draining
	if registry.IsDraining() {
		t.Error("Registry should not be draining initially")
	}

	// Start draining
	if err := registry.StartDraining(); err != nil {
		t.Fatalf("Failed to start draining: %v", err)
	}

	// Should be draining now
	if !registry.IsDraining() {
		t.Error("Registry should be draining after StartDraining")
	}

	// Create a client
	clientConfig := PluginConfig{
		Name:       "drain-test-client",
		Type:       "test",
		Transport:  TransportExecutable,
		Executable: "/bin/echo",
		Args:       []string{"hello"},
	}

	client, err := registry.CreateClient(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Calls should be rejected during draining
	ctx := context.Background()
	_, err = registry.CallClient(ctx, client.Name, "test-method", "test-args")
	if err == nil {
		t.Error("Expected error when calling during draining mode")
	}
}

// TestShutdownCoordinator tests the shutdown coordinator functionality.
func TestShutdownCoordinator(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    5,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
		DrainOptions: DrainOptions{
			DrainTimeout:            2 * time.Second,
			ForceCancelAfterTimeout: true,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}

	coordinator := NewShutdownCoordinator(registry)

	// Test initial status
	status := coordinator.GetShutdownStatus()
	if status.Phase != ShutdownPhaseRunning {
		t.Errorf("Expected phase %s, got %s", ShutdownPhaseRunning, status.Phase)
	}

	if !status.IsRunning {
		t.Error("Expected registry to be running")
	}

	if status.IsDraining {
		t.Error("Expected registry not to be draining")
	}

	// Test graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := coordinator.GracefulShutdown(ctx); err != nil {
		t.Fatalf("Failed graceful shutdown: %v", err)
	}

	// Test final status
	finalStatus := coordinator.GetShutdownStatus()
	if finalStatus.Phase != ShutdownPhaseComplete {
		t.Errorf("Expected phase %s, got %s", ShutdownPhaseComplete, finalStatus.Phase)
	}

	if finalStatus.IsRunning {
		t.Error("Expected registry to be stopped")
	}

	if finalStatus.ActiveRequests > 0 {
		t.Errorf("Expected no active requests, got %d", finalStatus.ActiveRequests)
	}
}

// TestPluginRegistry_RequestTracking tests request tracking functionality.
func TestPluginRegistry_RequestTracking(t *testing.T) {
	config := RegistryConfig{
		MaxClients:    10,
		AutoDiscovery: false,
		Logger:        DefaultLogger(),
		HandshakeConfig: HandshakeConfig{
			MagicCookieKey:   "BASIC_PLUGIN",
			MagicCookieValue: "hello",
			ProtocolVersion:  1,
		},
	}

	registry := NewPluginRegistry(config)
	if err := registry.Start(); err != nil {
		t.Fatalf("Failed to start registry: %v", err)
	}
	defer func() {
		if err := registry.Stop(); err != nil {
			t.Logf("Warning: failed to stop registry: %v", err)
		}
	}()

	// Initially no active requests
	activeRequests := registry.GetActiveRequestsCount()
	if len(activeRequests) > 0 {
		t.Error("Expected no active requests initially")
	}

	// Test request tracker directly
	tracker := registry.requestTracker
	if tracker == nil {
		t.Fatal("Expected non-nil request tracker")
	}

	// Simulate tracked requests
	ctx1 := context.Background()
	ctx2 := context.Background()

	tracker.StartRequest("test-client", ctx1)
	tracker.StartRequest("test-client", ctx2)

	active := tracker.GetActiveRequestCount("test-client")
	if active != 2 {
		t.Errorf("Expected 2 active requests, got %d", active)
	}

	// End one request
	tracker.EndRequest("test-client", ctx1)

	active = tracker.GetActiveRequestCount("test-client")
	if active != 1 {
		t.Errorf("Expected 1 active request, got %d", active)
	}

	// End remaining request
	tracker.EndRequest("test-client", ctx2)

	active = tracker.GetActiveRequestCount("test-client")
	if active != 0 {
		t.Errorf("Expected 0 active requests, got %d", active)
	}
}

// BenchmarkPluginRegistry_GracefulShutdown benchmarks graceful shutdown performance.
func BenchmarkPluginRegistry_GracefulShutdown(b *testing.B) {
	for i := 0; i < b.N; i++ {
		config := RegistryConfig{
			MaxClients:    50,
			AutoDiscovery: false,
			Logger:        DefaultLogger(),
			HandshakeConfig: HandshakeConfig{
				MagicCookieKey:   "BASIC_PLUGIN",
				MagicCookieValue: "hello",
				ProtocolVersion:  1,
			},
			DrainOptions: DrainOptions{
				DrainTimeout:            1 * time.Second,
				ForceCancelAfterTimeout: true,
			},
		}

		registry := NewPluginRegistry(config)
		if err := registry.Start(); err != nil {
			b.Fatalf("Failed to start registry: %v", err)
		}

		// Create some clients
		for j := 0; j < 10; j++ {
			clientConfig := PluginConfig{
				Name:       fmt.Sprintf("bench-shutdown-client-%d", j),
				Type:       "test",
				Transport:  TransportExecutable,
				Executable: "/bin/echo",
				Args:       []string{"hello"},
			}

			_, err := registry.CreateClient(clientConfig)
			if err != nil {
				b.Fatalf("Failed to create client: %v", err)
			}
		}

		// Measure shutdown time
		b.StartTimer()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := registry.StopWithContext(ctx)
		cancel()
		b.StopTimer()

		if err != nil {
			b.Fatalf("Failed to shutdown: %v", err)
		}
	}
}
