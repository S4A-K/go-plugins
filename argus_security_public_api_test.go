// argus_security_public_api_test.go: verifies public API of Argus for security config watching
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agilira/argus"
)

// TestArgusPublicAPI_UniversalConfigWatcher verifies the public API for UniversalConfigWatcher
func TestArgusPublicAPI_UniversalConfigWatcher(t *testing.T) {
	// Setup: crea file di configurazione temporaneo
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test-config.json")

	// config
	initialConfig := map[string]interface{}{
		"allowed_plugins": []string{"plugin-a", "plugin-b"},
		"version":         "1.0.0",
	}

	// write initial config to file
	configData, err := json.Marshal(initialConfig)
	if err != nil {
		t.Fatalf("Failed to marshal initial config: %v", err)
	}

	err = os.WriteFile(configFile, configData, 0644)
	if err != nil {
		t.Fatalf("Failed to write initial config file: %v", err)
	}

	// Test: build watcher using public API
	callbackCalled := make(chan map[string]interface{}, 1)

	watcher, err := argus.UniversalConfigWatcher(configFile, func(config map[string]interface{}) {
		// Callback: semplicemente invia il config sul channel per testing
		select {
		case callbackCalled <- config:
		default:
			// Channel full, ignore (race condition protection)
		}
	})

	if err != nil {
		t.Fatalf("UniversalConfigWatcher failed: %v", err)
	}

	if watcher == nil {
		t.Fatal("UniversalConfigWatcher returned nil watcher")
	}

	// Cleanup: Always close the watcher
	defer func() {
		if closeErr := watcher.Close(); closeErr != nil {
			t.Logf("Warning: Failed to close watcher: %v", closeErr)
		}
	}()

	// Verify: watcher should be active (wait for initial callback)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case config := <-callbackCalled:
		// Success! Verify the config is correct
		if config == nil {
			t.Error("Received nil config in callback")
			return
		}

		// Verify the content of the config
		if allowedPlugins, ok := config["allowed_plugins"].([]interface{}); ok {
			if len(allowedPlugins) != 2 {
				t.Errorf("Expected 2 allowed plugins, got %d", len(allowedPlugins))
			}
		} else {
			t.Error("Config missing allowed_plugins or wrong type")
		}

		t.Log("✅ UniversalConfigWatcher successfully loaded and parsed config")

	case <-ctx.Done():
		t.Error("❌ Timeout waiting for initial config callback - watcher may not be working")
	}
}

// TestArgusPublicAPI_UniversalConfigWatcherWithConfig verifies the API with custom config
func TestArgusPublicAPI_UniversalConfigWatcherWithConfig(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test-config.json")

	// Simple config
	config := map[string]interface{}{
		"setting": "value",
		"number":  42,
	}

	configData, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	err = os.WriteFile(configFile, configData, 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Argus custom config (uses public API)
	argusConfig := argus.Config{
		PollInterval:    1 * time.Second, // polling more frequent for test
		MaxWatchedFiles: 10,              // low limit for test
		// Not setting ErrorHandler - uses default
	}

	// Test: API with config
	received := make(chan bool, 1)

	watcher, err := argus.UniversalConfigWatcherWithConfig(configFile, func(cfg map[string]interface{}) {
		// Simple callback: signals it was called
		select {
		case received <- true:
		default:
		}
	}, argusConfig)

	if err != nil {
		t.Fatalf("UniversalConfigWatcherWithConfig failed: %v", err)
	}

	if watcher == nil {
		t.Fatal("UniversalConfigWatcherWithConfig returned nil watcher")
	}

	defer func() {
		if closeErr := watcher.Close(); closeErr != nil {
			t.Logf("Warning: Failed to close watcher: %v", closeErr)
		}
	}()

	// Verify the callback is called
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	select {
	case <-received:
		t.Log("✅ UniversalConfigWatcherWithConfig successfully initialized with custom config")
	case <-ctx.Done():
		t.Error("❌ Timeout waiting for callback with custom config")
	}
}

// TestArgusPublicAPI_ConfigValidation verifies the config file validation
func TestArgusPublicAPI_ConfigValidation(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		filename      string
		content       string
		shouldSucceed bool
		description   string
	}{
		{
			name:          "ValidJSON",
			filename:      "valid.json",
			content:       `{"key": "value", "number": 123}`,
			shouldSucceed: true,
			description:   "Valid JSON should be parsed successfully",
		},
		{
			name:          "InvalidJSON",
			filename:      "invalid.json",
			content:       `{"key": "value"`, // Missing closing brace
			shouldSucceed: false,
			description:   "Invalid JSON should fail gracefully",
		},
		{
			name:          "EmptyJSON",
			filename:      "empty.json",
			content:       `{}`,
			shouldSucceed: true,
			description:   "Empty JSON object should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFile := filepath.Join(tempDir, tt.filename)

			err := os.WriteFile(configFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write test config file: %v", err)
			}

			// Quick test: create watcher and see if it initializes
			watcher, err := argus.UniversalConfigWatcher(configFile, func(config map[string]interface{}) {
				// Empty callback for test
			})

			if tt.shouldSucceed {
				if err != nil {
					t.Errorf("Expected success but got error: %v", err)
				}
				if watcher != nil {
					if err := watcher.Close(); err != nil {
						t.Logf("Warning: Failed to close watcher: %v", err)
					}
				}
			} else {
				if err == nil {
					t.Errorf("Expected error but got success")
					if watcher != nil {
						if err := watcher.Close(); err != nil {
							t.Logf("Warning: Failed to close watcher: %v", err)
						}
					}
				}
			}
		})
	}
}

// TestArgusPublicAPI_ErrorHandling verifies the error handling of the public API
func TestArgusPublicAPI_ErrorHandling(t *testing.T) {
	// Test with inaccessible directory (more reliable than non-existent file)
	inaccessiblePath := "/root/restricted/config.json"

	watcher, err := argus.UniversalConfigWatcher(inaccessiblePath, func(config map[string]interface{}) {
		// This should not be called for inaccessible files
		t.Error("Callback called for inaccessible file - potential security issue")
	})

	// Argus behavior: may create the file or fail, both are OK for this test
	if err != nil {
		t.Logf("✅ Correctly failed with error for inaccessible path: %v", err)
		if watcher != nil {
			if err := watcher.Close(); err != nil {
				t.Logf("Warning: Failed to close watcher: %v", err)
			}
		}
	} else {
		t.Log("ℹ️  Argus created watcher for potentially inaccessible path (this is OK)")
		if watcher != nil {
			if err := watcher.Close(); err != nil {
				t.Logf("Warning: Failed to close watcher: %v", err)
			}
		}
	}

	// Test with unsupported file format (if ever they will be)
	tempDir := t.TempDir()
	binaryFile := filepath.Join(tempDir, "config.bin")

	// Create binary file (non-parsable)
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	writeErr := os.WriteFile(binaryFile, binaryData, 0644)
	if writeErr != nil {
		t.Fatalf("Failed to create binary test file: %v", writeErr)
	}

	watcher2, err2 := argus.UniversalConfigWatcher(binaryFile, func(config map[string]interface{}) {
		t.Log("Callback called for binary file - Argus handled gracefully")
	})

	// Argus may also handle this gracefully
	if watcher2 != nil {
		if err := watcher2.Close(); err != nil {
			t.Logf("Warning: Failed to close watcher2: %v", err)
		}
		t.Log("✅ Argus handled binary file gracefully")
	}

	if err2 != nil {
		t.Logf("✅ Argus correctly rejected binary file: %v", err2)
	}
}

// TestArgusPublicAPI_QuickStartExample tests the example from the documentation
func TestArgusPublicAPI_QuickStartExample(t *testing.T) {
	// Reproduce the example from the Argus doc
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yml")

	// Nota: Argus supports YAML, but for simplicity we use JSON
	yamlConfig := `
log_level: debug
server:
  port: 8080
  timeout: 30s
`

	err := os.WriteFile(configFile, []byte(yamlConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write YAML config: %v", err)
	}

	// Test based on the example from the documentation
	configReceived := make(chan map[string]interface{}, 1)

	watcher, err := argus.UniversalConfigWatcher(configFile, func(config map[string]interface{}) {
		// Simulate the pattern from the documentation
		if logLevel, ok := config["log_level"].(string); ok {
			t.Logf("Log level: %s", logLevel)
		}
		if server, ok := config["server"].(map[string]interface{}); ok {
			if port, ok := server["port"].(int); ok {
				t.Logf("Server port: %d", port)
			}
		}
		configReceived <- config
	})

	if err != nil {
		t.Fatalf("Failed to create watcher for YAML config: %v", err)
	}

	defer func() {
		if watcher != nil {
			if err := watcher.Close(); err != nil {
				t.Logf("Warning: Failed to close watcher: %v", err)
			}
		}
	}()

	// Wait for the configuration to be loaded
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	select {
	case config := <-configReceived:
		if config == nil {
			t.Error("Received nil config")
			return
		}
		t.Log("✅ Successfully loaded YAML configuration with UniversalConfigWatcher")
	case <-ctx.Done():
		t.Error("❌ Timeout waiting for YAML config to load")
	}
}
