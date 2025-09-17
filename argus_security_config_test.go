// library_config_security_test.go: Tests for unified SecurityConfig integration
//
// This test file validates that the SecurityConfig integration within LibraryConfig
// works correctly including hot reload, validation, and configuration processing.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLibraryConfigWithSecurityConfig tests the unified configuration with SecurityConfig
func TestLibraryConfigWithSecurityConfig(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "unified_config.json")

	// Create minimal valid configuration focusing on SecurityConfig
	configJSON := `{
		"logging": {
			"level": "info",
			"format": "json"
		},
		"observability": {
			"metrics_enabled": true,
			"metrics_interval": 5000000000
		},
		"default_policies": {
			"retry": {
				"max_attempts": 3,
				"initial_delay": 1000000000,
				"multiplier": 2.0
			},
			"circuit_breaker": {
				"failure_threshold": 5,
				"timeout": 30000000000
			},
			"health_check": {
				"enabled": true,
				"interval": 10000000000,
				"timeout": 5000000000,
				"max_failures": 3,
				"failure_limit": 5
			},
			"connection": {
				"timeout": 30000000000
			},
			"rate_limit": {
				"enabled": false
			}
		},
		"security": {
			"enabled": true,
			"policy": 2,
			"whitelist_file": "` + filepath.Join(tempDir, "whitelist.json") + `",
			"auto_update": true,
			"hash_algorithm": "sha256",
			"validate_on_start": true,
			"max_file_size": 1048576,
			"allowed_types": [".so", ".dll", ".dylib"],
			"forbidden_paths": ["/tmp", "/var/tmp"],
			"audit": {
				"enabled": true,
				"audit_file": "` + filepath.Join(tempDir, "security.log") + `",
				"log_unauthorized": true,
				"log_authorized": false,
				"log_config_changes": true
			},
			"watch_config": true,
			"reload_delay": 100000000
		},
		"performance": {
			"watcher_poll_interval": 1000000000,
			"max_concurrent_health_checks": 5,
			"optimization_enabled": true
		}
	}`

	// Write config to file
	if err := os.WriteFile(configFile, []byte(configJSON), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a simple manager for testing
	manager := &Manager[string, string]{}

	// Create library config watcher
	options := LibraryConfigOptions{
		PollInterval:        100 * time.Millisecond,
		EnableEnvExpansion:  true,
		ValidateBeforeApply: true,
		RollbackOnFailure:   true,
	}
	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, nil)
	if err != nil {
		t.Fatalf("Failed to create library config watcher: %v", err)
	}

	// Start the watcher
	ctx := context.Background()
	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Errorf("Failed to stop watcher: %v", err)
		}
	}()

	// Wait for initial config load
	time.Sleep(200 * time.Millisecond)

	// Verify that the configuration was loaded correctly
	currentConfig := watcher.GetCurrentConfig()

	// Check security configuration
	if !currentConfig.Security.Enabled {
		t.Error("Security should be enabled")
	}

	if currentConfig.Security.Policy != SecurityPolicyStrict {
		t.Errorf("Expected SecurityPolicyStrict, got %v", currentConfig.Security.Policy)
	}

	if currentConfig.Security.HashAlgorithm != HashAlgorithmSHA256 {
		t.Errorf("Expected HashAlgorithmSHA256, got %v", currentConfig.Security.HashAlgorithm)
	}

	if currentConfig.Security.MaxFileSize != 1024*1024 {
		t.Errorf("Expected MaxFileSize 1MB, got %d", currentConfig.Security.MaxFileSize)
	}

	if len(currentConfig.Security.AllowedTypes) != 3 {
		t.Errorf("Expected 3 allowed types, got %d", len(currentConfig.Security.AllowedTypes))
	}

	if len(currentConfig.Security.ForbiddenPaths) != 2 {
		t.Errorf("Expected 2 forbidden paths, got %d", len(currentConfig.Security.ForbiddenPaths))
	}

	// Check audit configuration
	if !currentConfig.Security.AuditConfig.Enabled {
		t.Error("Security audit should be enabled")
	}

	if !currentConfig.Security.AuditConfig.LogUnauthorized {
		t.Error("LogUnauthorized should be enabled")
	}

	if currentConfig.Security.AuditConfig.LogAuthorized {
		t.Error("LogAuthorized should be disabled")
	}

	t.Logf("✅ Unified SecurityConfig integration test passed")
}

// TestSecurityConfigValidation tests the validateSecurityConfig function
func TestSecurityConfigValidation(t *testing.T) {
	tempDir := t.TempDir()
	manager := &Manager[string, string]{}

	// Create a watcher for testing (we need it to access the validation method)
	configFile := filepath.Join(tempDir, "test.json")
	if err := os.WriteFile(configFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	options := LibraryConfigOptions{
		ValidateBeforeApply: true,
	}
	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, nil)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	tests := []struct {
		name      string
		config    SecurityConfig
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_config",
			config: SecurityConfig{
				Enabled:        true,
				Policy:         SecurityPolicyStrict,
				WhitelistFile:  "/absolute/path/whitelist.json",
				HashAlgorithm:  HashAlgorithmSHA256,
				MaxFileSize:    1024 * 1024,
				AllowedTypes:   []string{".so", ".dll"},
				ForbiddenPaths: []string{"/tmp"},
				AuditConfig: SecurityAuditConfig{
					Enabled:   true,
					AuditFile: "/absolute/path/audit.log",
				},
				ReloadDelay: 100 * time.Millisecond,
			},
			expectErr: false,
		},
		{
			name: "invalid_policy",
			config: SecurityConfig{
				Policy: SecurityPolicy(999), // Invalid policy
			},
			expectErr: true,
			errMsg:    "invalid security policy",
		},
		{
			name: "relative_whitelist_path",
			config: SecurityConfig{
				WhitelistFile: "relative/path.json", // Should be absolute
			},
			expectErr: true,
			errMsg:    "whitelist file path must be absolute",
		},
		{
			name: "invalid_hash_algorithm",
			config: SecurityConfig{
				HashAlgorithm: "md5", // Invalid algorithm
			},
			expectErr: true,
			errMsg:    "invalid hash algorithm",
		},
		{
			name: "negative_max_file_size",
			config: SecurityConfig{
				MaxFileSize: -1, // Negative size
			},
			expectErr: true,
			errMsg:    "max file size cannot be negative",
		},
		{
			name: "empty_allowed_type",
			config: SecurityConfig{
				AllowedTypes: []string{".so", ""}, // Empty type
			},
			expectErr: true,
			errMsg:    "allowed type at index 1 cannot be empty",
		},
		{
			name: "relative_forbidden_path",
			config: SecurityConfig{
				ForbiddenPaths: []string{"relative/path"}, // Should be absolute
			},
			expectErr: true,
			errMsg:    "forbidden path at index 0 must be absolute",
		},
		{
			name: "relative_audit_file",
			config: SecurityConfig{
				AuditConfig: SecurityAuditConfig{
					Enabled:   true,
					AuditFile: "relative/audit.log", // Should be absolute
				},
			},
			expectErr: true,
			errMsg:    "audit file path must be absolute",
		},
		{
			name: "negative_reload_delay",
			config: SecurityConfig{
				ReloadDelay: -1 * time.Second, // Negative delay
			},
			expectErr: true,
			errMsg:    "reload delay cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := watcher.validateSecurityConfig(tt.config)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %s", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %s", err.Error())
				}
			}
		})
	}

	t.Logf("✅ Security config validation tests passed")
}

// TestSecurityConfigHotReload tests hot reloading of security configuration
func TestSecurityConfigHotReload(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "hot_reload_config.json")

	// Initial configuration - use JSON to avoid complex struct initialization
	initialConfigJSON := `{
		"logging": {
			"level": "info",
			"format": "json"
		},
		"observability": {
			"metrics_enabled": false,
			"metrics_interval": 1000000000
		},
		"default_policies": {
			"retry": {
				"max_attempts": 3,
				"initial_delay": 1000000000,
				"multiplier": 2.0
			},
			"circuit_breaker": {
				"failure_threshold": 5,
				"timeout": 30000000000
			},
			"health_check": {
				"enabled": true,
				"interval": 10000000000,
				"timeout": 5000000000,
				"max_failures": 3,
				"failure_limit": 5
			},
			"connection": {
				"timeout": 30000000000
			},
			"rate_limit": {
				"enabled": false
			}
		},
		"security": {
			"enabled": false,
			"policy": 1,
			"max_file_size": 524288
		},
		"performance": {
			"watcher_poll_interval": 1000000000,
			"max_concurrent_health_checks": 3,
			"optimization_enabled": false
		}
	}`

	// Write initial config
	if err := os.WriteFile(configFile, []byte(initialConfigJSON), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	// Create watcher
	manager := &Manager[string, string]{}
	options := LibraryConfigOptions{
		PollInterval:        50 * time.Millisecond,
		ValidateBeforeApply: true,
		RollbackOnFailure:   true,
	}
	watcher, err := NewLibraryConfigWatcher(manager, configFile, options, nil)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	ctx := context.Background()
	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Wait for initial load
	time.Sleep(200 * time.Millisecond)

	// Verify initial state
	config1 := watcher.GetCurrentConfig()
	if config1.Security.Enabled {
		t.Error("Security should initially be disabled")
	}
	if config1.Security.Policy != SecurityPolicyPermissive {
		t.Error("Policy should initially be permissive")
	}

	// Update configuration with security enabled
	updatedConfigJSON := `{
		"logging": {
			"level": "info",
			"format": "json"
		},
		"observability": {
			"metrics_enabled": true,
			"metrics_interval": 2000000000
		},
		"default_policies": {
			"retry": {
				"max_attempts": 3,
				"initial_delay": 1000000000,
				"multiplier": 2.0
			},
			"circuit_breaker": {
				"failure_threshold": 5,
				"timeout": 30000000000
			},
			"health_check": {
				"enabled": true,
				"interval": 10000000000,
				"timeout": 5000000000,
				"max_failures": 3,
				"failure_limit": 5
			},
			"connection": {
				"timeout": 30000000000
			},
			"rate_limit": {
				"enabled": false
			}
		},
		"security": {
			"enabled": true,
			"policy": 2,
			"max_file_size": 1048576,
			"hash_algorithm": "sha256",
			"allowed_types": [".so"]
		},
		"performance": {
			"watcher_poll_interval": 1000000000,
			"max_concurrent_health_checks": 10,
			"optimization_enabled": true
		}
	}`

	// Write updated config
	if err := os.WriteFile(configFile, []byte(updatedConfigJSON), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	// Wait for hot reload
	time.Sleep(500 * time.Millisecond)

	// Verify updated state
	config2 := watcher.GetCurrentConfig()
	if !config2.Security.Enabled {
		t.Error("Security should be enabled after update")
	}
	if config2.Security.Policy != SecurityPolicyStrict {
		t.Error("Policy should be strict after update")
	}
	if config2.Security.MaxFileSize != 1024*1024 {
		t.Errorf("MaxFileSize should be 1MB after update, got %d", config2.Security.MaxFileSize)
	}
	if config2.Security.HashAlgorithm != HashAlgorithmSHA256 {
		t.Error("HashAlgorithm should be SHA256 after update")
	}
	if len(config2.Security.AllowedTypes) != 1 || config2.Security.AllowedTypes[0] != ".so" {
		t.Error("AllowedTypes should contain only .so after update")
	}

	t.Logf("✅ Security config hot reload test passed")
}
