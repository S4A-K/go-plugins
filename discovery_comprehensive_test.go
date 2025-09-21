// discovery_comprehensive_test.go: Comprehensive test suite for Plugin Discovery System
//
// This test suite provides complete coverage for the plugin discovery system,
// including security validation, error handling, and realistic integration scenarios.
// Tests are designed to find bugs and validate critical execution paths.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestDiscoveryEngine_CoreFunctionality validates essential discovery operations
// including engine creation, basic discovery, and manifest parsing.
func TestDiscoveryEngine_CoreFunctionality(t *testing.T) {
	t.Run("EngineCreation_ValidConfiguration", func(t *testing.T) {
		// Test: Engine should initialize correctly with valid configuration
		config := ExtendedDiscoveryConfig{
			DiscoveryConfig: DiscoveryConfig{
				Enabled:     true,
				Directories: []string{"/tmp/plugins"},
				Patterns:    []string{"*.json"},
			},
			SearchPaths:          []string{"/opt/plugins"},
			FilePatterns:         []string{"plugin.json", "manifest.yaml"},
			MaxDepth:             5,
			ValidateManifests:    true,
			AllowedTransports:    []TransportType{TransportGRPC, TransportExecutable},
			RequiredCapabilities: []string{"authentication"},
		}

		logger := NewTestLogger()
		engine := NewDiscoveryEngine(config, logger)

		// Validate: Engine should be properly initialized
		if engine == nil {
			t.Fatal("Discovery engine should not be nil after creation")
		}

		// Validate: Configuration should be preserved
		if len(engine.config.FilePatterns) != 2 {
			t.Errorf("Expected 2 file patterns, got %d", len(engine.config.FilePatterns))
		}

		if engine.config.MaxDepth != 5 {
			t.Errorf("Expected MaxDepth 5, got %d", engine.config.MaxDepth)
		}

		// Validate: Initial state should be empty
		discovered := engine.GetDiscoveredPlugins()
		if len(discovered) != 0 {
			t.Errorf("Expected empty discovery results initially, got %d plugins", len(discovered))
		}

		t.Logf("✅ Engine created successfully with %d search paths and %d patterns",
			len(config.SearchPaths), len(config.FilePatterns))
	})

	t.Run("BasicDiscovery_EmptyDirectory", func(t *testing.T) {
		// Test: Discovery should handle empty directories gracefully
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Warning: failed to cleanup temp directory: %v", err)
			}
		}()

		config := createTestDiscoveryConfig([]string{tempDir})
		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		results, err := engine.DiscoverPlugins(ctx)

		// Validate: No error should occur for empty directories
		if err != nil {
			t.Fatalf("Discovery should not fail on empty directory: %v", err)
		}

		// Validate: Results should be empty but not nil
		if results == nil {
			t.Fatal("Results should not be nil, even when empty")
		}

		if len(results) != 0 {
			t.Errorf("Expected 0 plugins in empty directory, found %d", len(results))
		}

		t.Logf("✅ Empty directory handled correctly - found %d plugins", len(results))
	})

	t.Run("ManifestParsing_JSONAndYAML", func(t *testing.T) {
		// Test: Engine should parse both JSON and YAML manifests correctly
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create valid JSON manifest
		jsonManifest := createValidManifest("json-plugin", "1.0.0")
		jsonPath := filepath.Join(tempDir, "plugin.json")
		writeJSONManifest(t, jsonPath, jsonManifest)

		// Create valid YAML manifest
		yamlManifest := createValidManifest("yaml-plugin", "2.0.0")
		yamlPath := filepath.Join(tempDir, "plugin.yaml")
		writeYAMLManifest(t, yamlPath, yamlManifest)

		// Create invalid JSON file to test error handling
		invalidPath := filepath.Join(tempDir, "invalid.json")
		writeInvalidJSON(t, invalidPath)

		config := createTestDiscoveryConfig([]string{tempDir})
		config.FilePatterns = []string{"*.json", "*.yaml"}
		config.ValidateManifests = true

		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx := context.Background()
		results, err := engine.DiscoverPlugins(ctx)

		// Validate: Should succeed despite invalid file
		if err != nil {
			t.Fatalf("Discovery should handle invalid files gracefully: %v", err)
		}

		// Validate: Should find valid manifests only
		if len(results) != 2 {
			t.Errorf("Expected 2 valid plugins, found %d", len(results))
		}

		// Validate: JSON plugin should be parsed correctly
		jsonPlugin, exists := results["json-plugin"]
		if !exists {
			t.Fatal("JSON plugin should be discovered")
		}

		if jsonPlugin.Manifest.Version != "1.0.0" {
			t.Errorf("JSON plugin version should be 1.0.0, got %s", jsonPlugin.Manifest.Version)
		}

		// Validate: YAML plugin should be parsed correctly
		yamlPlugin, exists := results["yaml-plugin"]
		if !exists {
			t.Fatal("YAML plugin should be discovered")
		}

		if yamlPlugin.Manifest.Version != "2.0.0" {
			t.Errorf("YAML plugin version should be 2.0.0, got %s", yamlPlugin.Manifest.Version)
		}

		t.Logf("✅ Successfully parsed JSON and YAML manifests - found %d plugins", len(results))
	})
}

// TestDiscoveryEngine_SecurityValidation validates security-critical functionality
// including path traversal prevention and access control.
func TestDiscoveryEngine_SecurityValidation(t *testing.T) {
	t.Run("PathTraversalPrevention_RelativePaths", func(t *testing.T) {
		// Test: Engine should prevent directory traversal attacks
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create malicious manifest with path traversal attempt
		maliciousDir := filepath.Join(tempDir, "malicious")
		if err := os.MkdirAll(maliciousDir, 0755); err != nil {
			t.Fatalf("Failed to create malicious directory: %v", err)
		}

		// Attempt to create manifest with relative path (should be prevented)
		maliciousManifest := PluginManifest{
			Name:      "../../../etc/passwd",
			Version:   "1.0.0",
			Transport: TransportExecutable,
			Endpoint:  "../../../bin/sh",
		}

		maliciousPath := filepath.Join(maliciousDir, "malicious.json")
		writeJSONManifest(t, maliciousPath, maliciousManifest)

		config := createTestDiscoveryConfig([]string{tempDir})
		config.ValidateManifests = true

		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx := context.Background()
		results, err := engine.DiscoverPlugins(ctx)

		// Validate: Should handle malicious manifests without failure
		if err != nil {
			t.Logf("Discovery properly rejected malicious content: %v", err)
		}

		// Validate: Malicious plugin should not be included in results
		if maliciousPlugin, exists := results["../../../etc/passwd"]; exists {
			t.Errorf("Malicious plugin with path traversal should not be discovered: %+v", maliciousPlugin)
		}

		t.Logf("✅ Path traversal prevention working - rejected malicious manifest")
	})

	t.Run("DirectoryPermissionHandling_RestrictedAccess", func(t *testing.T) {
		// Test: Engine should handle permission denied scenarios gracefully
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create restricted directory (if possible on current system)
		restrictedDir := filepath.Join(tempDir, "restricted")
		if err := os.MkdirAll(restrictedDir, 0000); err != nil { // No permissions
			t.Fatalf("Failed to create restricted directory: %v", err)
		}
		defer func() {
			_ = os.Chmod(restrictedDir, 0755) // Restore permissions for cleanup (ignore error)
		}()

		config := createTestDiscoveryConfig([]string{restrictedDir})
		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		results, err := engine.DiscoverPlugins(ctx)

		// Validate: Should handle permission errors without crashing
		// Note: Behavior may vary by OS and user permissions
		if results == nil {
			t.Fatal("Results should not be nil even with permission errors")
		}

		t.Logf("✅ Permission handling working - results: %d plugins, error: %v", len(results), err)
	})

	t.Run("MalformedManifestHandling_CorruptedData", func(t *testing.T) {
		// Test: Engine should handle corrupted manifest files safely
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create various types of corrupted manifests
		testCases := map[string]string{
			"incomplete.json":   `{"name": "incomplete"`,                            // Incomplete JSON
			"invalid_yaml.yaml": "name: test\nversion:\n  - invalid_structure",      // Invalid YAML structure
			"binary.json":       "\x00\x01\x02\x03\x04\x05",                         // Binary data
			"empty.json":        "",                                                 // Empty file
			"huge_field.json":   `{"name": "` + strings.Repeat("x", 1000000) + `"}`, // Extremely large field
		}

		for filename, content := range testCases {
			filePath := filepath.Join(tempDir, filename)
			err := os.WriteFile(filePath, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file %s: %v", filename, err)
			}
		}

		config := createTestDiscoveryConfig([]string{tempDir})
		config.FilePatterns = []string{"*.json", "*.yaml"}
		config.ValidateManifests = true

		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// This should not panic or hang
		results, err := engine.DiscoverPlugins(ctx)

		// Validate: Should survive malformed files
		if results == nil {
			t.Fatal("Results should not be nil even with malformed files")
		}

		// Log error if any, but don't fail test for malformed files
		if err != nil {
			t.Logf("Discovery handled malformed files gracefully with error: %v", err)
		}

		// Validate: Should not include malformed plugins
		for filename := range testCases {
			pluginName := strings.TrimSuffix(filename, filepath.Ext(filename))
			if plugin, exists := results[pluginName]; exists {
				t.Errorf("Malformed plugin %s should not be discovered: %+v", pluginName, plugin)
			}
		}

		t.Logf("✅ Malformed manifest handling working - processed %d test files safely", len(testCases))
	})
}

// TestDiscoveryEngine_DirectoryStructures validates complex directory scanning scenarios
func TestDiscoveryEngine_DirectoryStructures(t *testing.T) {
	t.Run("MultiLevelDirectoryScanning_WithDepthLimits", func(t *testing.T) {
		// Test: Engine should respect MaxDepth configuration
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create nested directory structure: level1/level2/level3/level4/level5
		deepPath := tempDir
		pluginPaths := make(map[int]string) // depth -> plugin path

		for depth := 1; depth <= 5; depth++ {
			deepPath = filepath.Join(deepPath, fmt.Sprintf("level%d", depth))
			if err := os.MkdirAll(deepPath, 0755); err != nil {
				t.Fatalf("Failed to create deep path %s: %v", deepPath, err)
			}

			// Create plugin at each level
			manifest := createValidManifest(fmt.Sprintf("plugin-depth-%d", depth), "1.0.0")
			pluginPath := filepath.Join(deepPath, "plugin.json")
			writeJSONManifest(t, pluginPath, manifest)
			pluginPaths[depth] = pluginPath
		}

		// Test with MaxDepth = 3
		config := createTestDiscoveryConfig([]string{tempDir})
		config.MaxDepth = 3

		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx := context.Background()
		results, err := engine.DiscoverPlugins(ctx)

		if err != nil {
			t.Fatalf("Discovery should not fail: %v", err)
		}

		// Validate: Should find plugins at depth 1, 2, and 3 only
		expectedPlugins := []string{"plugin-depth-1", "plugin-depth-2", "plugin-depth-3"}
		unexpectedPlugins := []string{"plugin-depth-4", "plugin-depth-5"}

		for _, expected := range expectedPlugins {
			if _, exists := results[expected]; !exists {
				t.Errorf("Expected plugin %s should be discovered (within depth limit)", expected)
			}
		}

		for _, unexpected := range unexpectedPlugins {
			if plugin, exists := results[unexpected]; exists {
				t.Errorf("Plugin %s should not be discovered (beyond depth limit): %+v", unexpected, plugin)
			}
		}

		t.Logf("✅ Depth limiting working correctly - found %d plugins within depth 3", len(results))
	})

	t.Run("ExcludePathsFiltering_IgnoreDirectories", func(t *testing.T) {
		// Test: Engine should respect ExcludePaths configuration
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create directory structure with included and excluded paths
		includedDir := filepath.Join(tempDir, "included")
		excludedDir := filepath.Join(tempDir, "excluded")
		hiddenDir := filepath.Join(tempDir, ".hidden")

		for _, dir := range []string{includedDir, excludedDir, hiddenDir} {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatalf("Failed to create directory %s: %v", dir, err)
			}

			// Create plugin in each directory
			pluginName := filepath.Base(dir) + "-plugin"
			manifest := createValidManifest(pluginName, "1.0.0")
			pluginPath := filepath.Join(dir, "plugin.json")
			writeJSONManifest(t, pluginPath, manifest)
		}

		config := createTestDiscoveryConfig([]string{tempDir})
		config.ExcludePaths = []string{"excluded", ".hidden"}

		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx := context.Background()
		results, err := engine.DiscoverPlugins(ctx)

		if err != nil {
			t.Fatalf("Discovery should not fail: %v", err)
		}

		// Validate: Should find only included plugin
		if _, exists := results["included-plugin"]; !exists {
			t.Error("Included plugin should be discovered")
		}

		if _, exists := results["excluded-plugin"]; exists {
			t.Error("Excluded plugin should not be discovered")
		}

		if _, exists := results[".hidden-plugin"]; exists {
			t.Error("Hidden plugin should not be discovered")
		}

		t.Logf("✅ Exclude paths filtering working - found %d plugins (excluded %d)",
			len(results), 2)
	})
}

// TestDiscoveryEngine_ErrorHandling validates error scenarios and edge cases
func TestDiscoveryEngine_ErrorHandling(t *testing.T) {
	t.Run("ConcurrentDiscoveryOperations_ThreadSafety", func(t *testing.T) {
		// Test: Engine should handle concurrent operations safely
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create multiple plugins
		for i := 0; i < 10; i++ {
			pluginDir := filepath.Join(tempDir, fmt.Sprintf("plugin%d", i))
			if err := os.MkdirAll(pluginDir, 0755); err != nil {
				t.Fatalf("Failed to create plugin directory %s: %v", pluginDir, err)
			}

			manifest := createValidManifest(fmt.Sprintf("concurrent-plugin-%d", i), "1.0.0")
			pluginPath := filepath.Join(pluginDir, "plugin.json")
			writeJSONManifest(t, pluginPath, manifest)
		}

		config := createTestDiscoveryConfig([]string{tempDir})
		engine := NewDiscoveryEngine(config, NewTestLogger())

		// Run concurrent discovery operations
		const numGoroutines = 5
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)
		results := make([]map[string]*DiscoveryResult, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				ctx := context.Background()
				result, err := engine.DiscoverPlugins(ctx)
				errors[index] = err
				results[index] = result
			}(i)
		}

		wg.Wait()

		// Validate: All operations should succeed
		for i, err := range errors {
			if err != nil {
				t.Errorf("Concurrent operation %d failed: %v", i, err)
			}
		}

		// Validate: Results should be consistent
		expectedCount := len(results[0])
		for i, result := range results[1:] {
			if len(result) != expectedCount {
				t.Errorf("Inconsistent results from operation %d: expected %d plugins, got %d",
					i+1, expectedCount, len(result))
			}
		}

		t.Logf("✅ Thread safety verified - %d concurrent operations completed successfully", numGoroutines)
	})

	t.Run("DiscoveryTimeout_ContextCancellation", func(t *testing.T) {
		// Test: Engine should respect context timeout
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create plugin
		manifest := createValidManifest("timeout-plugin", "1.0.0")
		pluginPath := filepath.Join(tempDir, "plugin.json")
		writeJSONManifest(t, pluginPath, manifest)

		config := createTestDiscoveryConfig([]string{tempDir})
		config.DiscoveryTimeout = 50 * time.Millisecond // Very short timeout

		engine := NewDiscoveryEngine(config, NewTestLogger())

		// Create context that will timeout quickly
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		results, err := engine.DiscoverPlugins(ctx)

		// Validate: Should handle timeout appropriately
		// Note: Fast modern systems might complete before timeout
		if err != nil {
			// If timeout occurred, should be context error
			if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "context") {
				t.Errorf("Expected timeout error, got: %v", err)
			}
			t.Logf("✅ Timeout handling working - discovery timed out as expected: %v", err)
		} else {
			t.Logf("✅ Discovery completed before timeout - found %d plugins", len(results))
		}
	})
}

// TestDiscoveryEngine_Integration validates realistic integration scenarios
func TestDiscoveryEngine_Integration(t *testing.T) {
	t.Run("MultiplePluginTypesDiscovery_RealWorldScenario", func(t *testing.T) {
		// Test: Engine should discover various plugin types correctly
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create plugins with different transports and capabilities
		plugins := []struct {
			name         string
			transport    TransportType
			capabilities []string
		}{
			{"auth-service", TransportGRPC, []string{"authentication", "authorization"}},
			{"logger", TransportExecutable, []string{"logging", "monitoring"}},
			{"cache-service", TransportGRPCTLS, []string{"caching", "performance"}},
			{"backup-tool", TransportExecutable, []string{"backup", "storage"}},
		}

		for _, plugin := range plugins {
			pluginDir := filepath.Join(tempDir, plugin.name)
			if err := os.MkdirAll(pluginDir, 0755); err != nil {
				t.Fatalf("Failed to create plugin directory %s: %v", pluginDir, err)
			}

			manifest := PluginManifest{
				Name:         plugin.name,
				Version:      "1.2.3",
				Transport:    plugin.transport,
				Endpoint:     fmt.Sprintf("/%s/api", plugin.name),
				Capabilities: plugin.capabilities,
				Description:  fmt.Sprintf("Test plugin: %s", plugin.name),
				Author:       "test-suite@example.com",
			}

			pluginPath := filepath.Join(pluginDir, "plugin.json")
			writeJSONManifest(t, pluginPath, manifest)
		}

		// Test discovery with transport filtering
		config := createTestDiscoveryConfig([]string{tempDir})
		config.AllowedTransports = []TransportType{TransportGRPC, TransportGRPCTLS}
		config.RequiredCapabilities = []string{"authentication"} // Should find only auth-service

		engine := NewDiscoveryEngine(config, NewTestLogger())

		ctx := context.Background()
		results, err := engine.DiscoverPlugins(ctx)

		if err != nil {
			t.Fatalf("Integration test discovery failed: %v", err)
		}

		// Validate: Should find only auth-service (matches transport and capabilities)
		if len(results) != 1 {
			t.Errorf("Expected 1 plugin matching criteria, found %d", len(results))
		}

		authPlugin, exists := results["auth-service"]
		if !exists {
			t.Fatal("auth-service should be discovered (matches all criteria)")
		}

		// Validate: Plugin details should be correct
		if authPlugin.Manifest.Transport != TransportGRPC {
			t.Errorf("Expected gRPC transport, got %s", authPlugin.Manifest.Transport)
		}

		if len(authPlugin.Capabilities) != 2 {
			t.Errorf("Expected 2 capabilities, got %d", len(authPlugin.Capabilities))
		}

		t.Logf("✅ Integration test successful - discovered %s with %d capabilities",
			authPlugin.Manifest.Name, len(authPlugin.Capabilities))
	})

	t.Run("EventNotificationWorkflow_DiscoveryEvents", func(t *testing.T) {
		// Test: Engine should emit discovery events correctly
		tempDir := createTempDirectory(t)
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Logf("Failed to remove temp directory %s: %v", tempDir, err)
			}
		}()

		// Create plugin
		manifest := createValidManifest("event-plugin", "1.0.0")
		pluginPath := filepath.Join(tempDir, "plugin.json")
		writeJSONManifest(t, pluginPath, manifest)

		config := createTestDiscoveryConfig([]string{tempDir})
		engine := NewDiscoveryEngine(config, NewTestLogger())

		// Setup event handler to capture events
		var capturedEvents []DiscoveryEvent
		var eventMutex sync.Mutex

		engine.AddEventHandler(func(event DiscoveryEvent) {
			eventMutex.Lock()
			capturedEvents = append(capturedEvents, event)
			eventMutex.Unlock()
		})

		ctx := context.Background()
		results, err := engine.DiscoverPlugins(ctx)

		if err != nil {
			t.Fatalf("Discovery should not fail: %v", err)
		}

		// Wait briefly for events to be processed
		time.Sleep(100 * time.Millisecond)

		// Validate: Should have received discovery events
		eventMutex.Lock()
		eventCount := len(capturedEvents)
		eventMutex.Unlock()

		if eventCount == 0 {
			t.Error("Expected discovery events to be emitted")
		}

		// Validate: Should have discovered the plugin
		if len(results) != 1 {
			t.Errorf("Expected 1 plugin, found %d", len(results))
		}

		t.Logf("✅ Event notification working - received %d events for %d plugins",
			eventCount, len(results))
	})
}

// Helper Functions

func createTestDiscoveryConfig(searchPaths []string) ExtendedDiscoveryConfig {
	return ExtendedDiscoveryConfig{
		DiscoveryConfig: DiscoveryConfig{
			Enabled:     true,
			Directories: searchPaths,
			Patterns:    []string{"*.json"},
		},
		SearchPaths:       searchPaths,
		FilePatterns:      []string{"*.json"},
		MaxDepth:          10,
		ValidateManifests: true,
		DiscoveryTimeout:  30 * time.Second,
	}
}

func createValidManifest(name, version string) PluginManifest {
	return PluginManifest{
		Name:         name,
		Version:      version,
		Transport:    TransportExecutable,
		Endpoint:     fmt.Sprintf("/usr/local/bin/%s", name),
		Description:  fmt.Sprintf("Test plugin: %s", name),
		Author:       "test-suite@example.com",
		Capabilities: []string{"test", "validation"},
	}
}

func writeJSONManifest(t *testing.T, path string, manifest PluginManifest) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON manifest: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("Failed to write JSON manifest: %v", err)
	}
}

func writeYAMLManifest(t *testing.T, path string, manifest PluginManifest) {
	data, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatalf("Failed to marshal YAML manifest: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("Failed to write YAML manifest: %v", err)
	}
}

func writeInvalidJSON(t *testing.T, path string) {
	invalidJSON := `{"name": "invalid", "version": "1.0.0" // missing closing brace`
	if err := os.WriteFile(path, []byte(invalidJSON), 0644); err != nil {
		t.Fatalf("Failed to write invalid JSON: %v", err)
	}
}
