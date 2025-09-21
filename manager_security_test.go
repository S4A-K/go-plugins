// manager_security_test.go: Tests for Plugin Manager Security
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
	"sync"
	"testing"
	"time"
)

// TestManager_SecurityRaceConditions testa race conditions nelle operazioni di sicurezza
func TestManager_SecurityRaceConditions(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Setup whitelist file
	whitelistFile := filepath.Join(tempDir, "test_whitelist.json")
	testWhitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins: map[string]PluginHashInfo{
			"test-plugin": {
				Name:      "test-plugin",
				Type:      "http",
				Algorithm: HashAlgorithmSHA256,
				Hash:      "dummy-hash-for-race-test",
				AddedAt:   time.Now(),
				UpdatedAt: time.Now(),
			},
		},
	}
	whitelistData, err := json.Marshal(testWhitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager[TestRequest, TestResponse](logger)

	// Security config
	securityConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	// Test concurrent security operations
	concurrency := 20
	var wg sync.WaitGroup
	errors := make([]error, concurrency*4) // 4 operations per goroutine

	// Launch concurrent operations
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			baseIdx := index * 4

			// Operation 1: Enable security
			errors[baseIdx] = manager.EnablePluginSecurity(securityConfig)

			// Operation 2: Check if enabled
			_ = manager.IsPluginSecurityEnabled()

			// Operation 3: Get stats (might fail if not enabled)
			_, errors[baseIdx+1] = manager.GetPluginSecurityStats()

			// Operation 4: Validate plugin
			pluginConfig := PluginConfig{Name: "test-plugin", Type: "http"}
			_, errors[baseIdx+2] = manager.ValidatePluginSecurity(pluginConfig, "")

			// Operation 5: Disable security (might fail if not enabled)
			errors[baseIdx+3] = manager.DisablePluginSecurity()
		}(i)
	}

	wg.Wait()

	// Analyze results - we don't expect crashes, but some operations may fail due to state
	crashCount := 0
	for _, err := range errors {
		if err != nil && (err.Error() == "runtime error" || err.Error() == "panic") {
			crashCount++
		}
	}

	if crashCount > 0 {
		t.Errorf("RACE CONDITION BUG: %d operations crashed during concurrent access", crashCount)
	}

	// Final state should be consistent
	finalEnabled := manager.IsPluginSecurityEnabled()
	t.Logf("Final security state: enabled=%v (this should be deterministic)", finalEnabled)
}

// TestManager_ShutdownRaceConditions testa race conditions durante shutdown
func TestManager_ShutdownRaceConditions(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Setup whitelist
	whitelistFile := filepath.Join(tempDir, "shutdown_whitelist.json")
	testWhitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins:       make(map[string]PluginHashInfo),
	}
	whitelistData, err := json.Marshal(testWhitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager[TestRequest, TestResponse](logger)

	securityConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	// Enable security first
	if err := manager.EnablePluginSecurity(securityConfig); err != nil {
		t.Fatal(err)
	}

	// Launch security operations concurrent with shutdown
	var wg sync.WaitGroup
	shutdownComplete := make(chan bool)
	operationResults := make([]error, 5)

	// Start shutdown immediately
	go func() {
		ctx := context.Background()
		_ = manager.Shutdown(ctx)
		shutdownComplete <- true
	}()

	// Small delay to ensure shutdown starts
	time.Sleep(5 * time.Millisecond)

	// Launch operations that should fail after shutdown
	operations := []func() error{
		func() error { return manager.EnablePluginSecurity(securityConfig) },
		func() error { return manager.DisablePluginSecurity() },
		func() error { return manager.ReloadPluginWhitelist() },
		func() error {
			_, err := manager.ValidatePluginSecurity(PluginConfig{Name: "test"}, "")
			return err
		},
		func() error {
			_, err := manager.GetPluginSecurityStats()
			return err
		},
	}

	for i, op := range operations {
		wg.Add(1)
		go func(index int, operation func() error) {
			defer wg.Done()
			// Try operation - should fail immediately since shutdown already happened
			err := operation()
			operationResults[index] = err
		}(i, op)
	}

	wg.Wait()
	<-shutdownComplete

	// All operations should eventually fail with "manager is shut down"
	shutdownErrorCount := 0
	for i, err := range operationResults {
		if err != nil && err.Error() == "manager is shut down" {
			shutdownErrorCount++
		} else if err == nil {
			t.Logf("Operation %d succeeded during shutdown (possible race)", i)
		} else {
			t.Logf("Operation %d failed with: %v", i, err)
		}
	}

	if shutdownErrorCount == 0 {
		t.Errorf("SHUTDOWN RACE BUG: No operations were properly rejected after shutdown")
	}
}

// TestManager_SecurityStateManagement testa la gestione dello stato security
func TestManager_SecurityStateManagement(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Setup whitelist
	whitelistFile := filepath.Join(tempDir, "state_whitelist.json")
	testWhitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins:       make(map[string]PluginHashInfo),
	}
	whitelistData, err := json.Marshal(testWhitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager[TestRequest, TestResponse](logger)

	securityConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	// Test initial state
	if manager.IsPluginSecurityEnabled() {
		t.Errorf("Security should not be enabled initially")
	}

	// Test operations with disabled security (since validator is always initialized now)
	disabledSecurityTests := []struct {
		name string
		op   func() error
	}{
		{"disable_when_disabled", func() error { return manager.DisablePluginSecurity() }},
		{"stats_when_disabled", func() error { _, err := manager.GetPluginSecurityStats(); return err }},
		{"config_when_disabled", func() error { _, err := manager.GetPluginSecurityConfig(); return err }},
		{"reload_when_disabled", func() error { return manager.ReloadPluginWhitelist() }},
		{"validate_when_disabled", func() error { _, err := manager.ValidatePluginSecurity(PluginConfig{}, ""); return err }},
		{"whitelist_info_when_disabled", func() error { _, err := manager.GetPluginWhitelistInfo(); return err }},
		{"argus_info_when_disabled", func() error { _, err := manager.GetArgusIntegrationInfo(); return err }},
	}

	for _, tt := range disabledSecurityTests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.op()
			// Most operations should work even when security is disabled, but some might have specific behaviors
			if tt.name == "disable_when_disabled" && err != nil {
				// DisableSecurity might fail if already disabled - this is acceptable
				t.Logf("Got expected error when disabling already disabled security: %v", err)
			}
		})
	}

	// Test successful enable
	if err := manager.EnablePluginSecurity(securityConfig); err != nil {
		t.Fatal(err)
	}

	if !manager.IsPluginSecurityEnabled() {
		t.Errorf("Security should be enabled after EnablePluginSecurity")
	}

	// Test double enable (should update config, not error)
	newConfig := securityConfig
	newConfig.Policy = SecurityPolicyPermissive
	if err := manager.EnablePluginSecurity(newConfig); err != nil {
		t.Errorf("Double enable should update config, not error: %v", err)
	}

	// Verify config was updated
	currentConfig, err := manager.GetPluginSecurityConfig()
	if err != nil {
		t.Errorf("Failed to get current config: %v", err)
	}
	if currentConfig.Policy != SecurityPolicyPermissive {
		t.Errorf("Config not updated: expected permissive, got %v", currentConfig.Policy)
	}

	// Test stats after enable
	stats, err := manager.GetPluginSecurityStats()
	if err != nil {
		t.Errorf("Failed to get stats: %v", err)
	}
	if stats.ValidationAttempts < 0 {
		t.Errorf("Invalid stats: %+v", stats)
	}

	// Test disable
	if err := manager.DisablePluginSecurity(); err != nil {
		t.Errorf("Failed to disable security: %v", err)
	}

	if manager.IsPluginSecurityEnabled() {
		t.Errorf("Security should be disabled after DisablePluginSecurity")
	}

	// Test double disable (should error)
	if err := manager.DisablePluginSecurity(); err == nil {
		t.Errorf("Double disable should error")
	}
}

// TestManager_SecurityValidationBypass testa possibili bypass della validazione
func TestManager_SecurityValidationBypass(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Create malicious plugin file
	maliciousFile := filepath.Join(tempDir, "malicious.so")
	maliciousContent := []byte("malicious backdoor code")
	if err := os.WriteFile(maliciousFile, maliciousContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Setup EMPTY whitelist (no plugins authorized)
	whitelistFile := filepath.Join(tempDir, "empty_whitelist.json")
	emptyWhitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins:       make(map[string]PluginHashInfo), // EMPTY - no authorized plugins
	}
	whitelistData, err := json.Marshal(emptyWhitelist)
	if err != nil {
		t.Fatalf("Failed to marshal empty whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager[TestRequest, TestResponse](logger)

	// Test validation without security enabled (potential bypass)
	maliciousConfig := PluginConfig{
		Name: "backdoor-plugin",
		Type: "http",
	}

	result, err := manager.ValidatePluginSecurity(maliciousConfig, maliciousFile)
	if err == nil {
		t.Errorf("SECURITY BYPASS: Validation succeeded without security enabled! Result: %+v", result)
	}
	if result != nil {
		t.Errorf("SECURITY BYPASS: Got validation result without security enabled: %+v", result)
	}

	// Enable STRICT security
	strictConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	if err := manager.EnablePluginSecurity(strictConfig); err != nil {
		t.Fatal(err)
	}

	// Now validation should BLOCK the malicious plugin
	result, err = manager.ValidatePluginSecurity(maliciousConfig, maliciousFile)
	if err != nil {
		t.Errorf("Validation error: %v", err)
		return
	}

	if result.Authorized {
		t.Errorf("CRITICAL SECURITY BUG: Malicious plugin was authorized in STRICT mode!")
	}

	if len(result.Violations) == 0 {
		t.Errorf("Expected security violations for unauthorized plugin")
	}

	// Verify violation type
	foundUnauthorized := false
	for _, violation := range result.Violations {
		if violation.Type == "plugin_not_whitelisted" {
			foundUnauthorized = true
			t.Logf("Good: Unauthorized plugin properly detected")
			break
		}
	}
	if !foundUnauthorized {
		t.Errorf("Expected 'plugin_not_whitelisted' violation, got: %+v", result.Violations)
	}
}

// TestManager_SecurityNilPointerSafety testa la sicurezza contro nil pointer dereference
func TestManager_SecurityNilPointerSafety(t *testing.T) {
	logger := &testLogger{t: t}
	manager := NewManager[TestRequest, TestResponse](logger)

	// Force nil security validator (simulate corruption)
	manager.mu.Lock()
	manager.securityValidator = nil
	manager.mu.Unlock()

	// Test all operations that could cause nil pointer dereference
	panicTests := []struct {
		name string
		op   func()
	}{
		{
			"is_enabled_nil_check",
			func() { _ = manager.IsPluginSecurityEnabled() },
		},
		{
			"get_stats_nil_check",
			func() { _, _ = manager.GetPluginSecurityStats() },
		},
		{
			"get_config_nil_check",
			func() { _, _ = manager.GetPluginSecurityConfig() },
		},
		{
			"reload_whitelist_nil_check",
			func() { _ = manager.ReloadPluginWhitelist() },
		},
		{
			"validate_plugin_nil_check",
			func() { _, _ = manager.ValidatePluginSecurity(PluginConfig{}, "") },
		},
		{
			"whitelist_info_nil_check",
			func() { _, _ = manager.GetPluginWhitelistInfo() },
		},
		{
			"argus_info_nil_check",
			func() { _, _ = manager.GetArgusIntegrationInfo() },
		},
	}

	for _, tt := range panicTests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("NIL POINTER PANIC BUG: %s caused panic: %v", tt.name, r)
				}
			}()

			tt.op() // Should not panic, should return error gracefully
		})
	}
}

// TestManager_SecurityConcurrentEnableDisable testa enable/disable concurrent
func TestManager_SecurityConcurrentEnableDisable(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Setup whitelist
	whitelistFile := filepath.Join(tempDir, "concurrent_whitelist.json")
	testWhitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins:       make(map[string]PluginHashInfo),
	}
	whitelistData, err := json.Marshal(testWhitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager[TestRequest, TestResponse](logger)

	securityConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	// Run concurrent enable/disable operations
	concurrency := 20
	var wg sync.WaitGroup
	results := make([]bool, concurrency*2) // enable + disable per goroutine

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Try enable
			err1 := manager.EnablePluginSecurity(securityConfig)
			results[index*2] = (err1 == nil)

			// Try disable
			err2 := manager.DisablePluginSecurity()
			results[index*2+1] = (err2 == nil)
		}(i)
	}

	wg.Wait()

	// Analyze results - should have consistent final state
	finalEnabled := manager.IsPluginSecurityEnabled()
	enableCount := 0
	disableCount := 0

	for i := 0; i < len(results); i += 2 {
		if results[i] {
			enableCount++
		}
		if results[i+1] {
			disableCount++
		}
	}

	t.Logf("Concurrent operations: %d enables succeeded, %d disables succeeded", enableCount, disableCount)
	t.Logf("Final state: enabled=%v", finalEnabled)

	// The final state should be deterministic based on the last successful operation
	// We don't enforce a specific final state since it depends on timing,
	// but the manager should not crash or be in an inconsistent state

	// Test that the manager is still functional
	if finalEnabled {
		if _, err := manager.GetPluginSecurityStats(); err != nil {
			t.Errorf("Manager in inconsistent state: enabled=true but stats failed: %v", err)
		}
	} else {
		if _, err := manager.GetPluginSecurityStats(); err == nil {
			t.Errorf("Manager in inconsistent state: enabled=false but stats succeeded")
		}
	}
}

// TestManager_PostShutdownStateCheck tests if manager accepts operations after shutdown
func TestManager_PostShutdownStateCheck(t *testing.T) {
	tempDir := t.TempDir()
	logger := &testLogger{t: t}

	// Setup whitelist
	whitelistFile := filepath.Join(tempDir, "shutdown_state_whitelist.json")
	testWhitelist := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins:       make(map[string]PluginHashInfo),
	}
	whitelistData, err := json.Marshal(testWhitelist)
	if err != nil {
		t.Fatalf("Failed to marshal whitelist data: %v", err)
	}
	if err := os.WriteFile(whitelistFile, whitelistData, 0644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager[TestRequest, TestResponse](logger)

	// Initial security config - enable security
	securityConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	// Configure security
	if err := manager.EnablePluginSecurity(securityConfig); err != nil {
		t.Fatal(err)
	}

	// Verify manager is working before shutdown
	t.Log("Testing manager before shutdown...")
	if !manager.IsPluginSecurityEnabled() {
		t.Fatal("Security should be enabled before shutdown")
	}

	// Shutdown the manager
	t.Log("Shutting down manager...")
	_ = manager.Shutdown(context.Background())

	// CRITICAL TEST: Try to enable security after shutdown
	t.Log("Testing EnablePluginSecurity after shutdown (should fail)...")

	newSecurityConfig := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyPermissive,
		WhitelistFile: whitelistFile,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	err = manager.EnablePluginSecurity(newSecurityConfig)
	if err == nil {
		t.Error("CRITICAL SHUTDOWN BUG: EnablePluginSecurity succeeded after shutdown - manager should reject all operations")
	} else {
		t.Logf("Good: EnablePluginSecurity properly rejected after shutdown: %v", err)
	}

	// Test plugin validation after shutdown
	t.Log("Testing ValidatePluginSecurity after shutdown (should fail)...")
	pluginConfig := PluginConfig{Name: "test-plugin", Type: "http"}
	_, validationErr := manager.ValidatePluginSecurity(pluginConfig, "")
	if validationErr == nil {
		t.Error("CRITICAL SHUTDOWN BUG: ValidatePluginSecurity succeeded after shutdown")
	} else {
		t.Logf("Good: ValidatePluginSecurity properly rejected after shutdown: %v", validationErr)
	}

	// Test other operations after shutdown
	t.Log("Testing other security operations after shutdown...")

	if disableErr := manager.DisablePluginSecurity(); disableErr == nil {
		t.Error("SHUTDOWN BUG: DisablePluginSecurity succeeded after shutdown")
	}

	if reloadErr := manager.ReloadPluginWhitelist(); reloadErr == nil {
		t.Error("SHUTDOWN BUG: ReloadPluginWhitelist succeeded after shutdown")
	}

	if _, statsErr := manager.GetPluginSecurityStats(); statsErr == nil {
		t.Error("SHUTDOWN BUG: GetPluginSecurityStats succeeded after shutdown")
	}

	t.Log("Post-shutdown state check completed")
}
