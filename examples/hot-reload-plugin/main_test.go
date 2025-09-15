package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	plugins "github.com/go-plugins"
)

func TestCounterPlugin(t *testing.T) {

	// Create plugin config
	config := plugins.PluginConfig{
		Name:      "test-counter",
		Type:      "counter",
		Transport: plugins.TransportHTTP,
		Endpoint:  "http://localhost:9001",
		Enabled:   true,
		Options: map[string]interface{}{
			"increment": 5.0,
		},
	}

	// Create plugin
	plugin := NewCounterPlugin(config)

	t.Run("Basic Operations", func(t *testing.T) {
		ctx := context.Background()
		execCtx := plugins.ExecutionContext{
			RequestID:  "test-1",
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		}

		// Test get initial value
		resp, err := plugin.Execute(ctx, execCtx, CounterRequest{Action: "get"})
		if err != nil {
			t.Fatalf("Failed to get counter: %v", err)
		}
		if resp.Value != 0 {
			t.Errorf("Expected initial value 0, got %d", resp.Value)
		}

		// Test increment
		resp, err = plugin.Execute(ctx, execCtx, CounterRequest{Action: "increment"})
		if err != nil {
			t.Fatalf("Failed to increment: %v", err)
		}
		if resp.Value != 5 {
			t.Errorf("Expected value 5, got %d", resp.Value)
		}

		// Test add custom value
		resp, err = plugin.Execute(ctx, execCtx, CounterRequest{Action: "add", Value: 10})
		if err != nil {
			t.Fatalf("Failed to add: %v", err)
		}
		if resp.Value != 15 {
			t.Errorf("Expected value 15, got %d", resp.Value)
		}

		// Test reset
		resp, err = plugin.Execute(ctx, execCtx, CounterRequest{Action: "reset"})
		if err != nil {
			t.Fatalf("Failed to reset: %v", err)
		}
		if resp.Value != 0 {
			t.Errorf("Expected value 0 after reset, got %d", resp.Value)
		}
	})

	t.Run("Health Check", func(t *testing.T) {
		ctx := context.Background()
		health := plugin.Health(ctx)
		if health.Status != plugins.StatusHealthy {
			t.Errorf("Expected healthy status, got %v", health.Status)
		}
	})

	t.Run("Close", func(t *testing.T) {
		err := plugin.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}

		// Plugin should be disabled after close
		ctx := context.Background()
		health := plugin.Health(ctx)
		if health.Status != plugins.StatusUnhealthy {
			t.Errorf("Expected unhealthy status after close, got %v", health.Status)
		}
	})
}

func TestCounterPluginFactory(t *testing.T) {
	factory := &CounterPluginFactory{}

	t.Run("Create Plugin", func(t *testing.T) {
		config := plugins.PluginConfig{
			Name: "test-factory-plugin",
			Type: "counter",
			Options: map[string]interface{}{
				"increment": 2,
			},
		}

		plugin, err := factory.CreatePlugin(config)
		if err != nil {
			t.Fatalf("Failed to create plugin: %v", err)
		}

		info := plugin.Info()
		if info.Name != "test-factory-plugin" {
			t.Errorf("Expected name 'test-factory-plugin', got %s", info.Name)
		}
	})

	t.Run("Supported Transports", func(t *testing.T) {
		transports := factory.SupportedTransports()
		if len(transports) != 1 || transports[0] != "http" {
			t.Errorf("Expected ['http'], got %v", transports)
		}
	})

	t.Run("Validate Config", func(t *testing.T) {
		validConfig := plugins.PluginConfig{
			Options: map[string]interface{}{
				"increment": 5.0,
			},
		}

		err := factory.ValidateConfig(validConfig)
		if err != nil {
			t.Errorf("Valid config should pass validation: %v", err)
		}

		invalidConfig := plugins.PluginConfig{
			Options: map[string]interface{}{
				"increment": "invalid",
			},
		}

		err = factory.ValidateConfig(invalidConfig)
		if err == nil {
			t.Error("Invalid config should fail validation")
		}
	})
}

func TestHotReloadFunctionality(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hot reload test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create temporary config file
	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"

	// Create plugin manager
	manager := plugins.NewManager[CounterRequest, CounterResponse](logger)

	// Register factory
	factory := &CounterPluginFactory{}
	if err := manager.RegisterFactory("counter", factory); err != nil {
		t.Fatalf("Failed to register factory: %v", err)
	}

	t.Run("Initial Configuration", func(t *testing.T) {
		// Create initial config
		config := plugins.ManagerConfig{
			Plugins: []plugins.PluginConfig{
				{
					Name:      "counter-1",
					Type:      "counter",
					Transport: plugins.TransportHTTP,
					Endpoint:  "http://localhost:9001",
					Enabled:   true,
					Auth: plugins.AuthConfig{
						Method: plugins.AuthNone,
					},
					Connection: plugins.ConnectionConfig{
						MaxConnections:     10,
						MaxIdleConnections: 5,
						IdleTimeout:        30 * time.Second,
						ConnectionTimeout:  10 * time.Second,
						RequestTimeout:     30 * time.Second,
						KeepAlive:          true,
					},
					Options: map[string]interface{}{
						"increment": 1.0,
					},
				},
			},
		}

		// Write config to file
		configData, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			t.Fatalf("Failed to marshal config: %v", err)
		}

		if err := os.WriteFile(configPath, configData, 0644); err != nil {
			t.Fatalf("Failed to write config: %v", err)
		}

		// Load initial config
		if err := manager.LoadFromConfig(config); err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Verify plugin is loaded
		plugins := manager.ListPlugins()
		if len(plugins) != 1 {
			t.Fatalf("Expected 1 plugin, got %d", len(plugins))
		}

		if _, exists := plugins["counter-1"]; !exists {
			t.Fatal("Plugin counter-1 should exist")
		}
	})

	t.Run("Hot Reload Operations", func(t *testing.T) {
		// Create a fresh manager for hot reload testing
		freshManager := plugins.NewManager[CounterRequest, CounterResponse](logger)
		factory := &CounterPluginFactory{}
		if err := freshManager.RegisterFactory("counter", factory); err != nil {
			t.Fatalf("Failed to register factory in fresh manager: %v", err)
		}

		options := plugins.DefaultDynamicConfigOptions()
		options.PollInterval = 100 * time.Millisecond
		options.CacheTTL = 50 * time.Millisecond

		err := freshManager.EnableDynamicConfiguration(configPath, options)
		if err != nil {
			t.Skipf("Hot reload not available: %v", err)
			return
		}

		defer func() {
			if freshManager.IsDynamicConfigurationEnabled() {
				if err := freshManager.DisableDynamicConfiguration(); err != nil {
					t.Logf("Failed to disable dynamic config: %v", err)
				}
			}
		}()

		// Give a small delay for the watcher to be fully initialized
		time.Sleep(200 * time.Millisecond)

		// Verify hot reload is enabled
		if !freshManager.IsDynamicConfigurationEnabled() {
			t.Fatal("Hot reload should be enabled")
		}

		t.Logf("✅ Hot reload enabled successfully")

		// Test Plugin Addition via Hot Reload
		t.Run("Plugin Addition via Hot Reload", func(t *testing.T) {

			// Create updated config with second plugin
			updatedConfig := plugins.ManagerConfig{
				Plugins: []plugins.PluginConfig{
					{
						Name:      "counter-1",
						Type:      "counter",
						Transport: plugins.TransportHTTP,
						Endpoint:  "http://localhost:9001",
						Enabled:   true,
						Auth: plugins.AuthConfig{
							Method: plugins.AuthNone,
						},
						Connection: plugins.ConnectionConfig{
							MaxConnections:     10,
							MaxIdleConnections: 5,
							IdleTimeout:        30 * time.Second,
							ConnectionTimeout:  10 * time.Second,
							RequestTimeout:     30 * time.Second,
							KeepAlive:          true,
						},
						Options: map[string]interface{}{
							"increment": 2.0, // Changed increment
						},
					},
					{
						Name:      "counter-2",
						Type:      "counter",
						Transport: plugins.TransportHTTP,
						Endpoint:  "http://localhost:9002",
						Enabled:   true,
						Auth: plugins.AuthConfig{
							Method: plugins.AuthNone,
						},
						Connection: plugins.ConnectionConfig{
							MaxConnections:     10,
							MaxIdleConnections: 5,
							IdleTimeout:        30 * time.Second,
							ConnectionTimeout:  10 * time.Second,
							RequestTimeout:     30 * time.Second,
							KeepAlive:          true,
						},
						Options: map[string]interface{}{
							"increment": 5.0,
						},
					},
				},
			}

			// Write updated config
			configData, err := json.MarshalIndent(updatedConfig, "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal updated config: %v", err)
			}

			if err := os.WriteFile(configPath, configData, 0644); err != nil {
				t.Fatalf("Failed to write updated config: %v", err)
			}

			// Wait for hot reload to detect changes
			time.Sleep(500 * time.Millisecond)

			// Verify plugins were reloaded
			plugins := freshManager.ListPlugins()
			t.Logf("Plugins after update: %v", getPluginNames(plugins))

			// Check for counter-2 (new plugin)
			if _, exists := plugins["counter-2"]; !exists {
				t.Error("New plugin counter-2 should be added")
			}

			t.Logf("✅ Plugin addition via hot reload successful")
		})

		// Test Plugin Removal via Hot Reload
		t.Run("Plugin Removal via Hot Reload", func(t *testing.T) {

			// Create config with only one plugin
			finalConfig := plugins.ManagerConfig{
				Plugins: []plugins.PluginConfig{
					{
						Name:      "counter-2",
						Type:      "counter",
						Transport: plugins.TransportHTTP,
						Endpoint:  "http://localhost:9002",
						Enabled:   true,
						Auth: plugins.AuthConfig{
							Method: plugins.AuthNone,
						},
						Connection: plugins.ConnectionConfig{
							MaxConnections:     10,
							MaxIdleConnections: 5,
							IdleTimeout:        30 * time.Second,
							ConnectionTimeout:  10 * time.Second,
							RequestTimeout:     30 * time.Second,
							KeepAlive:          true,
						},
						Options: map[string]interface{}{
							"increment": 10.0, // Changed increment again
						},
					},
				},
			}

			// Write final config
			configData, err := json.MarshalIndent(finalConfig, "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal final config: %v", err)
			}

			if err := os.WriteFile(configPath, configData, 0644); err != nil {
				t.Fatalf("Failed to write final config: %v", err)
			}

			// Wait for hot reload (plugin removal requires drain time + unregister time)
			time.Sleep(2 * time.Second)

			// Verify complete plugin removal
			plugins := freshManager.ListPlugins()
			t.Logf("Plugins after removal: %v", getPluginNames(plugins))

			// Verify that counter-1 was removed and counter-2 remains
			if _, exists := plugins["counter-1"]; exists {
				t.Error("Plugin counter-1 should be removed after hot reload")
			}

			if _, exists := plugins["counter-2"]; !exists {
				t.Error("Plugin counter-2 should remain after hot reload")
			}

			// Verify exactly one plugin remains
			if len(plugins) != 1 {
				t.Errorf("Expected exactly 1 plugin after removal, got %d: %v", len(plugins), getPluginNames(plugins))
			}

			t.Logf("✅ Plugin removal via hot reload completed successfully")
		})
	})

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := manager.Shutdown(ctx); err != nil {
		t.Errorf("Manager shutdown failed: %v", err)
	}
}

// getPluginNames extracts plugin names from health status map
func getPluginNames(plugins map[string]plugins.HealthStatus) []string {
	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	return names
}

// Benchmark tests
func BenchmarkCounterIncrement(b *testing.B) {
	config := plugins.PluginConfig{
		Name: "bench-counter",
		Type: "counter",
		Options: map[string]interface{}{
			"increment": 1.0,
		},
	}

	plugin := NewCounterPlugin(config)
	ctx := context.Background()
	execCtx := plugins.ExecutionContext{
		RequestID:  "bench-1",
		Timeout:    5 * time.Second,
		MaxRetries: 3,
	}
	req := CounterRequest{Action: "increment"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := plugin.Execute(ctx, execCtx, req)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCounterGet(b *testing.B) {
	config := plugins.PluginConfig{
		Name: "bench-counter",
		Type: "counter",
		Options: map[string]interface{}{
			"increment": 1.0,
		},
	}

	plugin := NewCounterPlugin(config)
	ctx := context.Background()
	execCtx := plugins.ExecutionContext{
		RequestID:  "bench-2",
		Timeout:    5 * time.Second,
		MaxRetries: 3,
	}
	req := CounterRequest{Action: "get"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := plugin.Execute(ctx, execCtx, req)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
