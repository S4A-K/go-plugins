// manager_dynamic_loading_safety_test.go: Safety tests for dynamic loading methods before refactoring
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"testing"
	"time"
)

// TestManager_DynamicLoadingSafety tests that all dynamic loading methods are accessible and work
func TestManager_DynamicLoadingSafety(t *testing.T) {
	logger := NewLogger(nil)
	manager := NewManager[TestRequest, TestResponse](logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("EnableDynamicLoading", func(t *testing.T) {
		err := manager.EnableDynamicLoading(ctx)
		// We expect this to work (even if no plugins are discovered)
		if err != nil {
			t.Logf("EnableDynamicLoading returned error (may be expected): %v", err)
		}
	})

	t.Run("GetDiscoveredPlugins", func(t *testing.T) {
		plugins := manager.GetDiscoveredPlugins()
		if plugins == nil {
			t.Error("GetDiscoveredPlugins returned nil")
		}
		t.Logf("Discovered plugins: %d", len(plugins))
	})

	t.Run("GetDynamicLoadingStatus", func(t *testing.T) {
		status := manager.GetDynamicLoadingStatus()
		if status == nil {
			t.Error("GetDynamicLoadingStatus returned nil")
		}
		t.Logf("Dynamic loading status: %d plugins", len(status))
	})

	t.Run("GetDependencyGraph", func(t *testing.T) {
		graph := manager.GetDependencyGraph()
		if graph == nil {
			t.Error("GetDependencyGraph returned nil")
		}
	})

	t.Run("GetDynamicLoadingMetrics", func(t *testing.T) {
		// Just verify we can call it without panic
		manager.GetDynamicLoadingMetrics()
		t.Logf("Dynamic loading metrics retrieved successfully")
	})

	t.Run("SetPluginCompatibilityRule", func(t *testing.T) {
		// This should not panic
		manager.SetPluginCompatibilityRule("test-plugin", "^1.0.0")
		t.Log("SetPluginCompatibilityRule completed successfully")
	})

	t.Run("ConfigureDiscovery", func(t *testing.T) {
		config := ExtendedDiscoveryConfig{
			DiscoveryConfig: DiscoveryConfig{
				Enabled:     false,
				Directories: []string{},
				Patterns:    []string{"*.so"},
			},
		}
		err := manager.ConfigureDiscovery(config)
		// ConfigureDiscovery is now implemented, should succeed with valid config
		if err != nil {
			t.Errorf("ConfigureDiscovery should succeed with valid config, got error: %v", err)
		}
		t.Logf("ConfigureDiscovery completed successfully")
	})

	t.Run("LoadDiscoveredPlugin", func(t *testing.T) {
		err := manager.LoadDiscoveredPlugin(ctx, "non-existent-plugin")
		// This should return an error since the plugin doesn't exist
		if err == nil {
			t.Error("LoadDiscoveredPlugin should return error for non-existent plugin")
		}
		t.Logf("LoadDiscoveredPlugin returned expected error: %v", err)
	})

	t.Run("UnloadDynamicPlugin", func(t *testing.T) {
		err := manager.UnloadDynamicPlugin(ctx, "non-existent-plugin", false)
		// This should return an error since the plugin doesn't exist
		if err == nil {
			t.Error("UnloadDynamicPlugin should return error for non-existent plugin")
		}
		t.Logf("UnloadDynamicPlugin returned expected error: %v", err)
	})

	t.Run("DisableDynamicLoading", func(t *testing.T) {
		err := manager.DisableDynamicLoading()
		// This should work
		if err != nil {
			t.Logf("DisableDynamicLoading returned error: %v", err)
		}
	})

	// Test shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	if err := manager.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Manager shutdown failed: %v", err)
	}
}

// TestManager_DynamicLoadingAfterShutdown tests behavior after shutdown
func TestManager_DynamicLoadingAfterShutdown(t *testing.T) {
	logger := NewLogger(nil)
	manager := NewManager[TestRequest, TestResponse](logger)

	// Shutdown the manager first
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := manager.Shutdown(ctx); err != nil {
		t.Fatalf("Manager shutdown failed: %v", err)
	}

	// Now test that methods return appropriate errors
	t.Run("EnableDynamicLoading_AfterShutdown", func(t *testing.T) {
		err := manager.EnableDynamicLoading(ctx)
		if err == nil || err.Error() != "manager is shut down" {
			t.Errorf("Expected 'manager is shut down' error, got: %v", err)
		}
	})

	t.Run("DisableDynamicLoading_AfterShutdown", func(t *testing.T) {
		err := manager.DisableDynamicLoading()
		if err == nil || err.Error() != "manager is shut down" {
			t.Errorf("Expected 'manager is shut down' error, got: %v", err)
		}
	})

	t.Run("ConfigureDiscovery_AfterShutdown", func(t *testing.T) {
		config := ExtendedDiscoveryConfig{}
		err := manager.ConfigureDiscovery(config)
		if err == nil || err.Error() != "manager is shut down" {
			t.Errorf("Expected 'manager is shut down' error, got: %v", err)
		}
	})

	t.Run("LoadDiscoveredPlugin_AfterShutdown", func(t *testing.T) {
		err := manager.LoadDiscoveredPlugin(ctx, "test")
		if err == nil || err.Error() != "manager is shut down" {
			t.Errorf("Expected 'manager is shut down' error, got: %v", err)
		}
	})

	t.Run("UnloadDynamicPlugin_AfterShutdown", func(t *testing.T) {
		err := manager.UnloadDynamicPlugin(ctx, "test", false)
		if err == nil || err.Error() != "manager is shut down" {
			t.Errorf("Expected 'manager is shut down' error, got: %v", err)
		}
	})

	// Methods that should work even after shutdown
	t.Run("GetDiscoveredPlugins_AfterShutdown", func(t *testing.T) {
		plugins := manager.GetDiscoveredPlugins()
		if len(plugins) != 0 {
			t.Error("GetDiscoveredPlugins should return empty map after shutdown")
		}
	})

	t.Run("GetDynamicLoadingStatus_AfterShutdown", func(t *testing.T) {
		status := manager.GetDynamicLoadingStatus()
		if len(status) != 0 {
			t.Error("GetDynamicLoadingStatus should return empty map after shutdown")
		}
	})

	t.Run("GetDependencyGraph_AfterShutdown", func(t *testing.T) {
		graph := manager.GetDependencyGraph()
		if graph == nil {
			t.Error("GetDependencyGraph should return empty graph, not nil")
		}
	})

	t.Run("GetDynamicLoadingMetrics_AfterShutdown", func(t *testing.T) {
		// Should return zero metrics - just verify we can call it without panic
		manager.GetDynamicLoadingMetrics()
	})

	t.Run("SetPluginCompatibilityRule_AfterShutdown", func(t *testing.T) {
		// This should return early without panic
		manager.SetPluginCompatibilityRule("test", "^1.0.0")
	})
}
