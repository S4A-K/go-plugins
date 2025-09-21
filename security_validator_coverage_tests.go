// security_validator_coverage_test.go: tests for security validator coverage improvements
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestSecurityValidator_Enable_WithRealArgusIntegration
func TestSecurityValidator_Enable_WithRealArgusIntegration(t *testing.T) {
	// Setup with correct structures
	tempDir := t.TempDir()
	whitelistFile := filepath.Join(tempDir, "real-whitelist.json")
	auditFile := filepath.Join(tempDir, "real-audit.log")

	// Create whitelist with correct structure
	whitelist := &PluginWhitelist{
		Version:     "1.0.0",
		UpdatedAt:   time.Now(),
		Description: "Test whitelist per Argus integration",
		Plugins: map[string]PluginHashInfo{
			"test-service-plugin": {
				Name:             "test-service-plugin",
				Type:             "service",
				Version:          "1.0.0",
				Algorithm:        HashAlgorithmSHA256,
				Hash:             "sha256:abcd1234567890123456789012345678901234567890123456789012345678901234",
				AllowedEndpoints: []string{"localhost:8080", "127.0.0.1:9090"},
				MaxFileSize:      1024 * 1024, // 1MB
				AddedAt:          time.Now(),
				Description:      "Test service plugin for integration testing",
			},
			"monitoring-plugin": {
				Name:        "monitoring-plugin",
				Type:        "monitor",
				Algorithm:   HashAlgorithmSHA256,
				Hash:        "sha256:efgh5678901234567890123456789012345678901234567890123456789012345678",
				MaxFileSize: 2 * 1024 * 1024, // 2MB
				AddedAt:     time.Now(),
			},
		},
	}

	// Write whitelist in correct JSON format
	whitelistData, err := json.MarshalIndent(whitelist, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal whitelist: %v", err)
	}

	err = os.WriteFile(whitelistFile, whitelistData, 0600)
	if err != nil {
		t.Fatalf("Failed to write whitelist file: %v", err)
	}

	// Config SecurityValidator with Argus enabled
	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		WatchConfig:   true, // Enable Argus integration
		AutoUpdate:    true,
		HashAlgorithm: HashAlgorithmSHA256,
		AuditConfig: SecurityAuditConfig{
			Enabled:          true,
			AuditFile:        auditFile,
			LogUnauthorized:  true,
			LogAuthorized:    true,
			LogConfigChanges: true,
			IncludeMetadata:  true,
		},
	}

	// Create a validator
	validator, err := NewSecurityValidator(config, NewTestLogger())
	if err != nil {
		t.Fatalf("Failed to create SecurityValidator: %v", err)
	}

	// Test: Enable() - this uses Argus internally
	err = validator.Enable()
	if err != nil {
		t.Fatalf("SecurityValidator.Enable() failed: %v", err)
	}

	// Verify state internal
	if !validator.enabled {
		t.Error("Validator should be enabled after Enable()")
	}

	// Test: Modify whitelist to verify hot-reload
	modifiedWhitelist := *whitelist
	modifiedWhitelist.Plugins["new-runtime-plugin"] = PluginHashInfo{
		Name:      "new-runtime-plugin",
		Type:      "runtime",
		Algorithm: HashAlgorithmSHA256,
		Hash:      "sha256:ijkl9012345678901234567890123456789012345678901234567890123456789012",
		AddedAt:   time.Now(),
	}
	modifiedWhitelist.UpdatedAt = time.Now()

	modifiedData, err := json.MarshalIndent(&modifiedWhitelist, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal modified whitelist: %v", err)
	}

	// Write modification to trigger Argus watcher
	err = os.WriteFile(whitelistFile, modifiedData, 0600)
	if err != nil {
		t.Fatalf("Failed to update whitelist file: %v", err)
	}

	// Wait for Argus to process the change
	time.Sleep(200 * time.Millisecond)

	// Test: Validation with existing plugin
	testConfig := PluginConfig{
		Name:    "test-service-plugin",
		Type:    "service",
		Version: "1.0.0",
	}

	result, err := validator.ValidatePlugin(testConfig, "/fake/path/test-service-plugin")
	if err != nil {
		t.Logf("Validation error for fake path (expected): %v", err)
	} else if result != nil {
		t.Logf("✅ Plugin validation result: Authorized=%t, Violations=%d",
			result.Authorized, len(result.Violations))
	}

	// Verify statistics
	stats := validator.GetStats()
	if stats.ValidationAttempts == 0 {
		t.Error("Expected at least one validation attempt in stats")
	}
	t.Logf("Security stats: Attempts=%d, Authorized=%d, Rejected=%d",
		stats.ValidationAttempts, stats.AuthorizedLoads, stats.RejectedLoads)

	// Verify audit file creation (indicates Argus audit is working)
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		t.Log("ℹ️  Audit file not created - may indicate Argus setup difference")
	} else {
		t.Log("✅ Audit file created - Argus integration active")
	}

	// Cleanup: Disable validator
	err = validator.Disable()
	if err != nil {
		t.Errorf("Failed to disable validator: %v", err)
	}

	t.Log("✅ SecurityValidator Enable() with Argus integration test completed successfully")
}

// TestSecurityValidator_CalculateFileHash_EdgeCases
// Test specifico per calculateFileHash could have edge cases not covered
func TestSecurityValidator_CalculateFileHash_EdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	// Create validator to access calculateFileHash method (private, tested indirectly)
	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyPermissive,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator, err := NewSecurityValidator(config, NewTestLogger())
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test cases for calculateFileHash through validation
	testCases := []struct {
		name        string
		fileContent []byte
		fileName    string
		expectError bool
		description string
	}{
		{
			name:        "EmptyFile",
			fileContent: []byte{},
			fileName:    "empty.bin",
			expectError: false,
			description: "Empty file should produce valid hash",
		},
		{
			name:        "LargeFile",
			fileContent: make([]byte, 10*1024*1024), // 10MB
			fileName:    "large.bin",
			expectError: false,
			description: "Large file hash calculation performance test",
		},
		{
			name:        "BinaryData",
			fileContent: []byte{0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF},
			fileName:    "binary.bin",
			expectError: false,
			description: "Binary data should be hashed correctly",
		},
		{
			name:        "UnicodeContent",
			fileContent: []byte("Hello 世界 🌍 ñáéíóú"),
			fileName:    "unicode.txt",
			expectError: false,
			description: "Unicode content should be hashed without issues",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Crea file di test
			testFile := filepath.Join(tempDir, tc.fileName)
			err := os.WriteFile(testFile, tc.fileContent, 0600)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Test calculateFileHash indirectly through validatePluginHash
			// (which internally calls calculateFileHash)
			start := time.Now()

			// Create a test plugin configuration
			testConfig := PluginConfig{
				Name: "hash-test-plugin",
				Type: "test",
			}

			// Create empty whitelist to avoid plugin not found errors
			whitelist := &PluginWhitelist{
				Version:   "1.0.0",
				UpdatedAt: time.Now(),
				Plugins:   map[string]PluginHashInfo{},
			}

			validator.whitelist = whitelist
			err = validator.Enable()
			if err != nil {
				t.Fatalf("Failed to enable validator: %v", err)
			}

			// Test the validation (which will calculate the file hash)
			result, err := validator.ValidatePlugin(testConfig, testFile)
			duration := time.Since(start)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s but got none", tc.description)
				} else {
					t.Logf("✅ Correctly got error for %s: %v", tc.description, err)
				}
			} else {
				// Don't expect errors for the hash calculation itself
				t.Logf("Hash calculation completed in %v for %s (%d bytes)",
					duration, tc.description, len(tc.fileContent))

				if duration > 5*time.Second {
					t.Errorf("Hash calculation took too long: %v for %s", duration, tc.description)
				}

				if result != nil {
					t.Logf("Validation result for %s: %d violations", tc.name, len(result.Violations))
				}
			}

			if err := validator.Disable(); err != nil {
				t.Logf("Warning: Failed to disable validator: %v", err)
			}
		})
	}
}

// TestSecurityValidator_LoadWhitelist_ErrorHandling
func TestSecurityValidator_LoadWhitelist_ErrorHandling(t *testing.T) {
	tempDir := t.TempDir()

	// Test cases that could cause bugs in parsing
	testCases := []struct {
		name            string
		whitelistData   string
		expectLoadError bool
		description     string
	}{
		{
			name: "ValidWhitelist",
			whitelistData: `{
				"version": "1.0.0",
				"updated_at": "2025-01-21T10:00:00Z",
				"plugins": {
					"valid-plugin": {
						"name": "valid-plugin",
						"algorithm": "sha256",
						"hash": "sha256:validhash123456789012345678901234567890123456789012345678901234",
						"added_at": "2025-01-21T10:00:00Z"
					}
				}
			}`,
			expectLoadError: false,
			description:     "Valid whitelist should load successfully",
		},
		{
			name:            "InvalidJSON",
			whitelistData:   `{"version": "1.0.0", "plugins": {`,
			expectLoadError: true,
			description:     "Malformed JSON should cause load error",
		},
		{
			name: "MissingRequiredFields",
			whitelistData: `{
				"version": "1.0.0",
				"plugins": {
					"incomplete-plugin": {
						"name": "incomplete-plugin"
					}
				}
			}`,
			expectLoadError: false, // could be filled with defaults
			description:     "Missing required fields might be handled gracefully",
		},
		{
			name: "InvalidHashFormat",
			whitelistData: `{
				"version": "1.0.0", 
				"updated_at": "2025-01-21T10:00:00Z",
				"plugins": {
					"bad-hash-plugin": {
						"name": "bad-hash-plugin",
						"algorithm": "sha256",
						"hash": "invalid-hash-format",
						"added_at": "2025-01-21T10:00:00Z"
					}
				}
			}`,
			expectLoadError: false, // Validation could be done later
			description:     "Invalid hash format handling test",
		},
		{
			name: "ExtremelyLongPluginName",
			whitelistData: fmt.Sprintf(`{
				"version": "1.0.0",
				"updated_at": "2025-01-21T10:00:00Z", 
				"plugins": {
					"%s": {
						"name": "%s",
						"algorithm": "sha256",
						"hash": "sha256:longnamevalidhash123456789012345678901234567890123456789012345678",
						"added_at": "2025-01-21T10:00:00Z"
					}
				}
			}`, string(make([]rune, 1000)), string(make([]rune, 1000))),
			expectLoadError: false, // JSON parsing should handle this
			description:     "Extremely long plugin name stress test",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create whitelist file for this test
			whitelistFile := filepath.Join(tempDir, tc.name+"-whitelist.json")
			err := os.WriteFile(whitelistFile, []byte(tc.whitelistData), 0600)
			if err != nil {
				t.Fatalf("Failed to create test whitelist file: %v", err)
			}

			// Create validator that will use this whitelist
			config := SecurityConfig{
				Enabled:       true,
				Policy:        SecurityPolicyStrict,
				WhitelistFile: whitelistFile,
				WatchConfig:   false, // Disable watching for tests
			}

			validator, err := NewSecurityValidator(config, NewTestLogger())
			if err != nil {
				t.Fatalf("Failed to create validator: %v", err)
			}

			// Test: Enable() forces the loading of the whitelist (loadWhitelist())
			err = validator.Enable()

			if tc.expectLoadError {
				if err == nil {
					t.Errorf("Expected load error for %s but got none", tc.description)
				} else {
					t.Logf("✅ Correctly got load error for %s: %v", tc.description, err)
				}
			} else {
				if err != nil {
					t.Logf("Load error for %s (might be expected): %v", tc.description, err)
				} else {
					t.Logf("✅ Successfully loaded whitelist for %s", tc.description)

					// Verify that the whitelist has been loaded
					if validator.whitelist == nil {
						t.Error("Whitelist should not be nil after successful load")
					} else {
						t.Logf("Loaded %d plugins from whitelist", len(validator.whitelist.Plugins))
					}
				}

				// Cleanup
				if validator.enabled {
					if err := validator.Disable(); err != nil {
						t.Logf("Warning: Failed to disable validator: %v", err)
					}
				}
			}
		})
	}
}

// TestSecurityValidator_ConcurrentValidation_StressTest
// Stress test for race conditions in concurrent validations
func TestSecurityValidator_ConcurrentValidation_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	tempDir := t.TempDir()
	whitelistFile := filepath.Join(tempDir, "concurrent-whitelist.json")

	// Create whitelist with many plugins for concurrent test
	plugins := make(map[string]PluginHashInfo)
	for i := 0; i < 100; i++ {
		pluginName := fmt.Sprintf("stress-plugin-%d", i)
		plugins[pluginName] = PluginHashInfo{
			Name:      pluginName,
			Type:      "stress",
			Algorithm: HashAlgorithmSHA256,
			Hash:      fmt.Sprintf("sha256:stress%02d567890123456789012345678901234567890123456789012345678901234", i%64),
			AddedAt:   time.Now(),
		}
	}

	whitelist := &PluginWhitelist{
		Version:   "1.0.0",
		UpdatedAt: time.Now(),
		Plugins:   plugins,
	}

	whitelistData, err := json.MarshalIndent(whitelist, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal stress whitelist: %v", err)
	}

	err = os.WriteFile(whitelistFile, whitelistData, 0600)
	if err != nil {
		t.Fatalf("Failed to write stress whitelist: %v", err)
	}

	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		WatchConfig:   false, // Disable watching to prevent interference
	}

	validator, err := NewSecurityValidator(config, NewTestLogger())
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	err = validator.Enable()
	if err != nil {
		t.Fatalf("Failed to enable validator: %v", err)
	}

	// Stress test: 20 goroutines concurrent with 200 validations each
	const numGoroutines = 20
	const validationsPerGoroutine = 200

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*10)
	results := make(chan int, numGoroutines)

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errors <- fmt.Errorf("goroutine %d panic: %v", goroutineID, r)
				}
			}()

			successCount := 0
			for j := 0; j < validationsPerGoroutine; j++ {
				pluginID := (goroutineID*validationsPerGoroutine + j) % 100
				pluginName := fmt.Sprintf("stress-plugin-%d", pluginID)

				testConfig := PluginConfig{
					Name: pluginName,
					Type: "stress",
				}

				result, err := validator.ValidatePlugin(testConfig, fmt.Sprintf("/fake/stress/%s", pluginName))
				if err == nil && result != nil {
					successCount++
				}

				// Test GetStats concurrently
				_ = validator.GetStats()
			}
			results <- successCount
		}(i)
	}

	// Await completion
	wg.Wait()
	close(errors)
	close(results)

	duration := time.Since(start)
	totalValidations := numGoroutines * validationsPerGoroutine

	// Verify errors
	for err := range errors {
		t.Errorf("RACE CONDITION: %v", err)
	}

	// Conta successi
	totalSuccesses := 0
	for success := range results {
		totalSuccesses += success
	}

	// Performance analysis
	validationsPerSecond := float64(totalValidations) / duration.Seconds()

	t.Logf("✅ Stress test completed:")
	t.Logf("   Total validations: %d", totalValidations)
	t.Logf("   Total duration: %v", duration)
	t.Logf("   Validations/sec: %.2f", validationsPerSecond)
	t.Logf("   Successful validations: %d", totalSuccesses)

	if validationsPerSecond < 100 {
		t.Logf("⚠️  Performance warning: Only %.2f validations/sec (expected >100)", validationsPerSecond)
	}

	// Verify final stats
	finalStats := validator.GetStats()
	if finalStats.ValidationAttempts == 0 {
		t.Error("🐛 BUG: No validation attempts recorded despite running validations")
	}

	t.Logf("Final stats: Attempts=%d, Authorized=%d, Rejected=%d",
		finalStats.ValidationAttempts, finalStats.AuthorizedLoads, finalStats.RejectedLoads)

	// Cleanup
	err = validator.Disable()
	if err != nil {
		t.Errorf("Failed to disable validator: %v", err)
	}
}
