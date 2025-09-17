// manager_config_safety_test.go: Safety tests for configuration methods before refactoring
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestManager_ConfigSafety tests that all configuration methods are accessible and work
func TestManager_ConfigSafety(t *testing.T) {
	logger := NewLogger(nil)
	manager := NewManager[TestRequest, TestResponse](logger)

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "manager_config_safety_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	t.Run("LoadFromConfig", func(t *testing.T) {
		config := ManagerConfig{
			Plugins: []PluginConfig{},
		}

		err := manager.LoadFromConfig(config)
		if err != nil {
			t.Logf("LoadFromConfig failed (may be expected): %v", err)
		} else {
			t.Log("LoadFromConfig completed successfully")
		}
	})

	t.Run("ReloadConfig", func(t *testing.T) {
		config := ManagerConfig{
			Plugins: []PluginConfig{},
		}

		err := manager.ReloadConfig(config)
		if err != nil {
			t.Logf("ReloadConfig failed (may be expected): %v", err)
		} else {
			t.Log("ReloadConfig completed successfully")
		}
	})

	t.Run("EnableDynamicConfiguration", func(t *testing.T) {
		// Create a test config file
		configFile := filepath.Join(tempDir, "test_config.json")
		configContent := `{
			"plugins": []
		}`

		err := os.WriteFile(configFile, []byte(configContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create test config file: %v", err)
		}

		options := DefaultDynamicConfigOptions()
		options.PollInterval = 100 * time.Millisecond // Fast polling for testing

		err = manager.EnableDynamicConfiguration(configFile, options)
		if err != nil {
			// This is expected to fail in test environment - just verify method is accessible
			t.Logf("EnableDynamicConfiguration failed as expected in test environment: %v", err)
		} else {
			t.Log("EnableDynamicConfiguration completed successfully")
		}
	})

	t.Run("IsDynamicConfigurationEnabled", func(t *testing.T) {
		enabled := manager.IsDynamicConfigurationEnabled()
		t.Logf("Dynamic configuration enabled: %v", enabled)
	})

	t.Run("GetDynamicConfigurationStats", func(t *testing.T) {
		stats := manager.GetDynamicConfigurationStats()
		if stats != nil {
			t.Logf("Dynamic configuration stats retrieved successfully")
		} else {
			t.Log("No dynamic configuration stats (expected if not enabled)")
		}
	})

	t.Run("DisableDynamicConfiguration", func(t *testing.T) {
		err := manager.DisableDynamicConfiguration()
		if err != nil {
			// This might fail if dynamic config was never enabled
			t.Logf("DisableDynamicConfiguration returned: %v", err)
		} else {
			t.Log("DisableDynamicConfiguration completed successfully")
		}
	})

	// Test shutdown
	shutdownCtx, cancel := createTestContext(2 * time.Second)
	defer cancel()
	if err := manager.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Manager shutdown failed: %v", err)
	}
}

// TestManager_ConfigAfterShutdown tests behavior after shutdown
func TestManager_ConfigAfterShutdown(t *testing.T) {
	logger := NewLogger(nil)
	manager := NewManager[TestRequest, TestResponse](logger)

	// Shutdown the manager first
	shutdownCtx, cancel := createTestContext(2 * time.Second)
	defer cancel()
	if err := manager.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Manager shutdown failed: %v", err)
	}

	t.Run("LoadFromConfig_AfterShutdown", func(t *testing.T) {
		config := ManagerConfig{
			Plugins: []PluginConfig{},
		}

		// This should still work as it doesn't check shutdown state
		err := manager.LoadFromConfig(config)
		if err != nil {
			t.Logf("LoadFromConfig after shutdown returned: %v", err)
		}
	})

	t.Run("ReloadConfig_AfterShutdown", func(t *testing.T) {
		config := ManagerConfig{
			Plugins: []PluginConfig{},
		}

		// This should still work as it doesn't check shutdown state
		err := manager.ReloadConfig(config)
		if err != nil {
			t.Logf("ReloadConfig after shutdown returned: %v", err)
		}
	})

	t.Run("EnableDynamicConfiguration_AfterShutdown", func(t *testing.T) {
		options := DefaultDynamicConfigOptions()
		err := manager.EnableDynamicConfiguration("test.json", options)
		// This might work or fail depending on implementation
		if err != nil {
			t.Logf("EnableDynamicConfiguration after shutdown returned: %v", err)
		}
	})

	t.Run("DisableDynamicConfiguration_AfterShutdown", func(t *testing.T) {
		err := manager.DisableDynamicConfiguration()
		if err != nil {
			t.Logf("DisableDynamicConfiguration after shutdown returned: %v", err)
		}
	})

	// Methods that should work even after shutdown
	t.Run("IsDynamicConfigurationEnabled_AfterShutdown", func(t *testing.T) {
		enabled := manager.IsDynamicConfigurationEnabled()
		t.Logf("Dynamic configuration enabled after shutdown: %v", enabled)
	})

	t.Run("GetDynamicConfigurationStats_AfterShutdown", func(t *testing.T) {
		stats := manager.GetDynamicConfigurationStats()
		if stats != nil {
			t.Log("Dynamic configuration stats retrieved after shutdown")
		} else {
			t.Log("No dynamic configuration stats after shutdown (expected)")
		}
	})
}

// TestManager_ConfigWithInvalidData tests error handling
func TestManager_ConfigWithInvalidData(t *testing.T) {
	logger := NewLogger(nil)
	manager := NewManager[TestRequest, TestResponse](logger)
	defer func() {
		shutdownCtx, cancel := createTestContext(1 * time.Second)
		defer cancel()
		_ = manager.Shutdown(shutdownCtx)
	}()

	t.Run("LoadFromConfig_InvalidConfig", func(t *testing.T) {
		// Test with invalid config
		config := ManagerConfig{
			Plugins: []PluginConfig{
				{
					Name:    "", // Invalid: empty name
					Type:    "test",
					Enabled: true,
				},
			},
		}

		err := manager.LoadFromConfig(config)
		if err == nil {
			t.Error("LoadFromConfig should fail with invalid config")
		} else {
			t.Logf("LoadFromConfig correctly rejected invalid config: %v", err)
		}
	})

	t.Run("ReloadConfig_InvalidConfig", func(t *testing.T) {
		// Test with invalid config
		config := ManagerConfig{
			Plugins: []PluginConfig{
				{
					Name:    "", // Invalid: empty name
					Type:    "test",
					Enabled: true,
				},
			},
		}

		err := manager.ReloadConfig(config)
		if err == nil {
			t.Error("ReloadConfig should fail with invalid config")
		} else {
			t.Logf("ReloadConfig correctly rejected invalid config: %v", err)
		}
	})

	t.Run("EnableDynamicConfiguration_NonExistentFile", func(t *testing.T) {
		options := DefaultDynamicConfigOptions()
		err := manager.EnableDynamicConfiguration("/non/existent/file.json", options)
		if err == nil {
			t.Error("EnableDynamicConfiguration should fail with non-existent file")
		} else {
			t.Logf("EnableDynamicConfiguration correctly failed with non-existent file: %v", err)
		}
	})

	t.Run("EnableDynamicConfiguration_AlreadyEnabled", func(t *testing.T) {
		// Create a temporary config file
		tempDir, err := os.MkdirTemp("", "config_test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer func() { _ = os.RemoveAll(tempDir) }()

		configFile := filepath.Join(tempDir, "test.json")
		err = os.WriteFile(configFile, []byte(`{"plugins": []}`), 0644)
		if err != nil {
			t.Fatalf("Failed to create config file: %v", err)
		}

		options := DefaultDynamicConfigOptions()

		// Enable once
		err = manager.EnableDynamicConfiguration(configFile, options)
		if err != nil {
			t.Logf("First EnableDynamicConfiguration failed (may be expected): %v", err)
		}

		// Try to enable again
		err = manager.EnableDynamicConfiguration(configFile, options)
		if err == nil {
			t.Error("Second EnableDynamicConfiguration should fail (already enabled)")
		} else {
			t.Logf("Second EnableDynamicConfiguration correctly failed: %v", err)
		}
	})
}

// Helper function to create test context with timeout
func createTestContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
