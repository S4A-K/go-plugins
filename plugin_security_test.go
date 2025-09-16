// plugin_security_test.go: Test suite for plugin security system
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityValidator_Basic tests basic security validator functionality
func TestSecurityValidator_Basic(t *testing.T) {
	logger := NewLogger(nil)

	// Test default config
	config := DefaultSecurityConfig()
	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security validator: %v", err)
	}

	// Should be disabled by default
	if validator.IsEnabled() {
		t.Error("Security validator should be disabled by default")
	}

	// Test enabling
	config.Enabled = true
	err = validator.UpdateConfig(config)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	err = validator.Enable()
	if err != nil {
		t.Fatalf("Failed to enable validator: %v", err)
	}

	if !validator.IsEnabled() {
		t.Error("Security validator should be enabled")
	}

	// Test stats
	stats := validator.GetStats()
	if stats.ValidationAttempts != 0 {
		t.Error("Initial validation attempts should be 0")
	}
}

// TestSecurityValidator_WhitelistValidation tests whitelist-based validation
func TestSecurityValidator_WhitelistValidation(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "goplugins_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create sample whitelist
	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	err = CreateSampleWhitelist(whitelistFile)
	if err != nil {
		t.Fatalf("Failed to create sample whitelist: %v", err)
	}

	logger := NewLogger(nil)
	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
		AuditConfig: SecurityAuditConfig{
			Enabled:         true,
			AuditFile:       filepath.Join(tempDir, "audit.jsonl"),
			LogUnauthorized: true,
			LogAuthorized:   true,
		},
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security validator: %v", err)
	}

	err = validator.Enable()
	if err != nil && !strings.Contains(err.Error(), "already enabled") {
		t.Fatalf("Failed to enable validator: %v", err)
	}

	// Test validating authorized plugin
	pluginConfig := PluginConfig{
		Name: "auth-service",
		Type: "http",
	}

	result, err := validator.ValidatePlugin(pluginConfig, "")
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Authorized {
		t.Error("Plugin should be authorized according to whitelist")
	}

	// Test validating unauthorized plugin
	unauthorizedConfig := PluginConfig{
		Name: "malicious-plugin",
		Type: "http",
	}

	result, err = validator.ValidatePlugin(unauthorizedConfig, "")
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if result.Authorized {
		t.Error("Plugin should not be authorized")
	}

	if len(result.Violations) == 0 {
		t.Error("Should have security violations")
	}

	// Check stats
	stats := validator.GetStats()
	if stats.ValidationAttempts != 2 {
		t.Errorf("Expected 2 validation attempts, got %d", stats.ValidationAttempts)
	}

	if stats.AuthorizedLoads != 1 {
		t.Errorf("Expected 1 authorized load, got %d", stats.AuthorizedLoads)
	}

	if stats.RejectedLoads != 1 {
		t.Errorf("Expected 1 rejected load, got %d", stats.RejectedLoads)
	}
}

// TestSecurityValidator_Policies tests different security policies
func TestSecurityValidator_Policies(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "goplugins_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	err = CreateSampleWhitelist(whitelistFile)
	if err != nil {
		t.Fatalf("Failed to create sample whitelist: %v", err)
	}

	logger := NewLogger(nil)

	// Test disabled policy
	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyDisabled,
		WhitelistFile: whitelistFile,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security validator: %v", err)
	}

	_ = validator.Enable() // Ignore error for test

	pluginConfig := PluginConfig{
		Name: "unknown-plugin",
		Type: "http",
	}

	result, err := validator.ValidatePlugin(pluginConfig, "")
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Authorized {
		t.Error("Plugin should be authorized in disabled mode")
	}

	// Test permissive policy
	config.Policy = SecurityPolicyPermissive
	_ = validator.UpdateConfig(config) // Ignore error for test

	result, err = validator.ValidatePlugin(pluginConfig, "")
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Authorized {
		t.Error("Plugin should be authorized in permissive mode")
	}

	if len(result.Violations) == 0 {
		t.Error("Should still record violations in permissive mode")
	}

	// Test audit-only policy
	config.Policy = SecurityPolicyAuditOnly
	_ = validator.UpdateConfig(config) // Ignore error for test

	result, err = validator.ValidatePlugin(pluginConfig, "")
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Authorized {
		t.Error("Plugin should be authorized in audit-only mode")
	}
}

// TestSecurityValidator_ArgusIntegration tests Argus integration
func TestSecurityValidator_ArgusIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "goplugins_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	auditFile := filepath.Join(tempDir, "audit.jsonl")

	err = CreateSampleWhitelist(whitelistFile)
	if err != nil {
		t.Fatalf("Failed to create sample whitelist: %v", err)
	}

	logger := NewLogger(nil)
	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		WatchConfig:   true,
		AuditConfig: SecurityAuditConfig{
			Enabled:   true,
			AuditFile: auditFile,
		},
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security validator: %v", err)
	}

	err = validator.Enable()
	if err != nil && !strings.Contains(err.Error(), "already enabled") {
		t.Fatalf("Failed to enable validator: %v", err)
	}

	// Check Argus integration info
	argusInfo := validator.GetArgusIntegrationInfo()
	enabled, ok := argusInfo["enabled"].(bool)
	if !ok {
		t.Log("Argus integration info not available, skipping integration test")
		return
	}

	if !enabled {
		t.Log("Argus integration not enabled in test environment (expected)")
		return
	}

	watchedFiles, ok := argusInfo["watched_files"].([]string)
	if !ok {
		t.Log("Watched files info not available")
		return
	}

	if len(watchedFiles) > 0 && watchedFiles[0] != whitelistFile {
		t.Errorf("Should be watching %s, got %s", whitelistFile, watchedFiles[0])
	}

	// Test force reload (may fail if Argus is not running, which is expected in tests)
	err = validator.ForceReloadWhitelist()
	if err != nil {
		t.Logf("Force reload failed (expected in test environment): %v", err)
	}

	// Check that audit file was created
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		t.Error("Audit file should have been created")
	}
}

// TestSecurityValidator_HashValidation tests hash-based validation
func TestSecurityValidator_HashValidation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "goplugins_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create a test plugin file
	testPluginFile := filepath.Join(tempDir, "test_plugin.so")
	testContent := "fake plugin binary content"
	err = os.WriteFile(testPluginFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test plugin file: %v", err)
	}

	logger := NewLogger(nil)
	validator, err := NewSecurityValidator(DefaultSecurityConfig(), logger)
	if err != nil {
		t.Fatalf("Failed to create security validator: %v", err)
	}

	// Calculate hash of the test file
	hash, err := validator.calculateFileHash(testPluginFile)
	if err != nil {
		t.Fatalf("Failed to calculate hash: %v", err)
	}

	if hash == "" {
		t.Error("Hash should not be empty")
	}

	// Verify hash is SHA-256 (64 hex characters)
	if len(hash) != 64 {
		t.Errorf("SHA-256 hash should be 64 characters, got %d", len(hash))
	}

	t.Logf("Calculated hash: %s", hash)
}

// BenchmarkSecurityValidator tests performance of security validation
func BenchmarkSecurityValidator(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "goplugins_security_bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	err = CreateSampleWhitelist(whitelistFile)
	if err != nil {
		b.Fatalf("Failed to create sample whitelist: %v", err)
	}

	logger := NewLogger(nil)
	config := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
	}

	validator, err := NewSecurityValidator(config, logger)
	if err != nil {
		b.Fatalf("Failed to create security validator: %v", err)
	}

	_ = validator.Enable() // Ignore error for benchmark

	pluginConfig := PluginConfig{
		Name: "auth-service",
		Type: "http",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := validator.ValidatePlugin(pluginConfig, "")
		if err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// TestManager_SecurityIntegration tests security integration with manager
func TestManager_SecurityIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "goplugins_manager_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	whitelistFile := filepath.Join(tempDir, "whitelist.json")
	err = CreateSampleWhitelist(whitelistFile)
	if err != nil {
		t.Fatalf("Failed to create sample whitelist: %v", err)
	}

	logger := NewLogger(nil)
	manager := NewManager[TestRequest, TestResponse](logger)

	// Enable security
	securityConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		AuditConfig: SecurityAuditConfig{
			Enabled:   true,
			AuditFile: filepath.Join(tempDir, "manager_audit.jsonl"),
		},
	}

	err = manager.EnablePluginSecurity(securityConfig)
	if err != nil {
		t.Fatalf("Failed to enable security: %v", err)
	}

	if !manager.IsPluginSecurityEnabled() {
		t.Error("Security should be enabled")
	}

	// Test security stats
	stats, err := manager.GetPluginSecurityStats()
	if err != nil {
		t.Fatalf("Failed to get security stats: %v", err)
	}

	if stats.ValidationAttempts != 0 {
		t.Error("Initial validation attempts should be 0")
	}

	// Test whitelist info
	whitelistInfo, err := manager.GetPluginWhitelistInfo()
	if err != nil {
		t.Fatalf("Failed to get whitelist info: %v", err)
	}

	loaded, ok := whitelistInfo["loaded"].(bool)
	if !ok || !loaded {
		t.Error("Whitelist should be loaded")
	}

	// Test config retrieval
	config, err := manager.GetPluginSecurityConfig()
	if err != nil {
		t.Fatalf("Failed to get security config: %v", err)
	}

	if config.Policy != SecurityPolicyStrict {
		t.Error("Policy should be strict")
	}
}
