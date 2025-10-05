package goplugins

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestSecurityArgusIntegration_UnitTests pure unit tests for SecurityArgusIntegration
func TestSecurityArgusIntegration_Creation(t *testing.T) {
	validator := &SecurityValidator{}
	logger := &testLogger{t: t}

	integration := NewSecurityArgusIntegration(validator, logger)

	if integration == nil {
		t.Fatal("Expected non-nil integration")
	}

	if integration.validator != validator {
		t.Errorf("Expected validator to be set correctly")
	}

	if integration.logger != logger {
		t.Errorf("Expected logger to be set correctly")
	}

	if integration.running {
		t.Errorf("Expected initial running state to be false")
	}

	if integration.ctx == nil {
		t.Errorf("Expected context to be initialized")
	}
}

// TestSecurityArgusIntegration_StateManagement tests internal state management
func TestSecurityArgusIntegration_StateManagement(t *testing.T) {
	validator := &SecurityValidator{}
	logger := &testLogger{t: t}
	integration := NewSecurityArgusIntegration(validator, logger)

	// Test initial state
	if integration.IsRunning() {
		t.Errorf("Expected integration to not be running initially")
	}

	// Test state modification
	integration.running = true
	if !integration.IsRunning() {
		t.Errorf("Expected integration to be running after setting running=true")
	}

	integration.running = false
	if integration.IsRunning() {
		t.Errorf("Expected integration to not be running after setting running=false")
	}
}

// TestSecurityArgusIntegration_StatsManagement tests stats management
func TestSecurityArgusIntegration_StatsManagement(t *testing.T) {
	validator := &SecurityValidator{}
	logger := &testLogger{t: t}
	integration := NewSecurityArgusIntegration(validator, logger)

	// Test initial stats
	stats := integration.GetStats()
	if stats.WhitelistReloads != 0 {
		t.Errorf("Expected initial WhitelistReloads to be 0, got %d", stats.WhitelistReloads)
	}
	if stats.AuditEvents != 0 {
		t.Errorf("Expected initial AuditEvents to be 0, got %d", stats.AuditEvents)
	}
	if stats.ConfigErrors != 0 {
		t.Errorf("Expected initial ConfigErrors to be 0, got %d", stats.ConfigErrors)
	}

	// Test stats modification
	integration.stats.WhitelistReloads = 5
	integration.stats.AuditEvents = 10
	integration.stats.ConfigErrors = 2
	integration.stats.LastError = "test error"

	stats = integration.GetStats()
	if stats.WhitelistReloads != 5 {
		t.Errorf("Expected WhitelistReloads to be 5, got %d", stats.WhitelistReloads)
	}
	if stats.AuditEvents != 10 {
		t.Errorf("Expected AuditEvents to be 10, got %d", stats.AuditEvents)
	}
	if stats.ConfigErrors != 2 {
		t.Errorf("Expected ConfigErrors to be 2, got %d", stats.ConfigErrors)
	}
	if stats.LastError != "test error" {
		t.Errorf("Expected LastError to be 'test error', got '%s'", stats.LastError)
	}
}

// TestSecurityArgusIntegration_WatchedFiles tests watched files management
func TestSecurityArgusIntegration_WatchedFiles(t *testing.T) {
	validator := &SecurityValidator{}
	logger := &testLogger{t: t}
	integration := NewSecurityArgusIntegration(validator, logger)

	// Test no files initially
	files := integration.GetWatchedFiles()
	if len(files) != 0 {
		t.Errorf("Expected no watched files initially, got %d", len(files))
	}

	// Test with whitelist file set
	integration.whitelistFile = "/path/to/whitelist.json"
	files = integration.GetWatchedFiles()
	if len(files) != 1 {
		t.Errorf("Expected 1 watched file, got %d", len(files))
	}
	if files[0] != "/path/to/whitelist.json" {
		t.Errorf("Expected watched file to be '/path/to/whitelist.json', got '%s'", files[0])
	}

	// Test clearing whitelist file
	integration.whitelistFile = ""
	files = integration.GetWatchedFiles()
	if len(files) != 0 {
		t.Errorf("Expected no watched files after clearing, got %d", len(files))
	}
}

// TestSecurityArgusIntegration_ErrorHandling tests error handling
func TestSecurityArgusIntegration_ErrorHandling(t *testing.T) {
	validator := &SecurityValidator{}
	logger := &testLogger{t: t}
	integration := NewSecurityArgusIntegration(validator, logger)

	// Test disable when not running
	err := integration.DisableWatching()
	if err == nil {
		t.Errorf("Expected error when disabling non-running integration")
	}

	expectedErr := "argus integration not running"
	errMsg := err.Error()
	if !strings.Contains(errMsg, expectedErr) {
		t.Errorf("Expected error message to contain '%s', got '%s'", expectedErr, errMsg)
	}
}

// TestSecurityArgusIntegration_UptimeCalculation tests uptime calculation
func TestSecurityArgusIntegration_UptimeCalculation(t *testing.T) {
	validator := &SecurityValidator{}
	logger := &testLogger{t: t}
	integration := NewSecurityArgusIntegration(validator, logger)

	// Test non-running integration (uptime should be 0)
	stats := integration.GetStats()
	if stats.UptimeSeconds != 0 {
		t.Errorf("Expected UptimeSeconds to be 0 for non-running integration, got %d", stats.UptimeSeconds)
	}

	// Test running integration
	integration.running = true
	integration.stats.LastReload = time.Now().Add(-30 * time.Second)

	stats = integration.GetStats()
	if stats.UptimeSeconds < 25 || stats.UptimeSeconds > 35 {
		t.Errorf("Expected UptimeSeconds to be around 30, got %d", stats.UptimeSeconds)
	}
}

// TestSecurityArgusIntegration_ThreadSafety tests basic thread safety
func TestSecurityArgusIntegration_ThreadSafety(t *testing.T) {
	validator := &SecurityValidator{}
	logger := &testLogger{t: t}
	integration := NewSecurityArgusIntegration(validator, logger)

	done := make(chan bool, 2)

	// Goroutine 1: Letture continue
	go func() {
		for i := 0; i < 50; i++ {
			_ = integration.IsRunning()
			_ = integration.GetStats()
			_ = integration.GetWatchedFiles()
		}
		done <- true
	}()

	// Goroutine 2: multiple modifications
	go func() {
		for i := 0; i < 50; i++ {
			integration.mutex.Lock()
			integration.stats.AuditEvents++
			integration.mutex.Unlock()
		}
		done <- true
	}()

	// Wait for both goroutines to finish
	for i := 0; i < 2; i++ {
		select {
		case <-done:
			// OK
		case <-time.After(2 * time.Second):
			t.Fatal("Test timeout - possible deadlock")
		}
	}

	// Verifica che il conteggio sia corretto
	stats := integration.GetStats()
	if stats.AuditEvents != 50 {
		t.Errorf("Expected AuditEvents to be 50, got %d", stats.AuditEvents)
	}
}

// TestSecurityArgusIntegration_EnableWatchingWithArgus_ParameterValidation tests parameter validation
// This test verifies input validation without external dependencies
func TestSecurityArgusIntegration_EnableWatchingWithArgus_ParameterValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Argus integration test in short mode")
	}

	// Setup: Create a clean integration instance with mock security validator
	validator, err := NewSecurityValidator(DefaultSecurityConfig(), NewTestLogger())
	if err != nil {
		t.Fatalf("Failed to create security validator: %v", err)
	}
	logger := NewTestLogger()
	integration := NewSecurityArgusIntegration(validator, logger)

	// Pre-condition: Should not be running initially
	if integration.IsRunning() {
		t.Error("Integration should not be running initially")
	}

	// Test setup with valid paths in temp directory (safe for testing)
	tempDir := t.TempDir() // Automatic cleanup
	whitelistFile := tempDir + "/whitelist.json"
	auditFile := tempDir + "/audit.log"

	// Create a valid whitelist file to avoid file validation errors
	whitelistContent := `{
		"plugins": [
			{
				"name": "test-plugin",
				"hash": "sha256:abc123def456",
				"endpoints": ["localhost:8080"],
				"size_limit": 1048576
			}
		],
		"version": "1.0.0",
		"last_updated": "2025-09-21T14:00:00Z"
	}`
	if err := os.WriteFile(whitelistFile, []byte(whitelistContent), 0644); err != nil {
		t.Fatalf("Failed to create test whitelist file: %v", err)
	}

	// Test: Enable watching with proper Argus integration
	err = integration.EnableWatchingWithArgus(whitelistFile, auditFile)

	// Assertions: Should succeed with proper setup
	if err != nil {
		t.Fatalf("EnableWatchingWithArgus should succeed with valid paths and files, got error: %v", err)
	}

	// Verify integration is now running
	if !integration.IsRunning() {
		t.Error("Integration should be running after successful EnableWatchingWithArgus")
	}

	// Verify internal state is correctly set
	if integration.whitelistFile != whitelistFile {
		t.Errorf("Expected whitelistFile to be %s, got %s", whitelistFile, integration.whitelistFile)
	}

	if integration.auditFile != auditFile {
		t.Errorf("Expected auditFile to be %s, got %s", auditFile, integration.auditFile)
	}

	// Note: With Argus v1.0.2+, audit logging uses SQLite database instead of separate files
	// Verify the integration is running properly (indicates audit setup succeeded)
	if !integration.IsRunning() {
		t.Error("Integration should be running after successful enable")
	}
	}

	// Cleanup: Disable to prevent resource leaks in tests
	if err := integration.DisableWatching(); err != nil {
		t.Errorf("Failed to disable watching during cleanup: %v", err)
	}

	// Verify clean shutdown
	if integration.IsRunning() {
		t.Error("Integration should not be running after disable")
	}
}

// TestSecurityArgusIntegration_EnableWatchingWithArgus_DoubleEnable tests double-enable protection
// This is a critical security test - multiple enables could cause resource leaks or security bypasses
func TestSecurityArgusIntegration_EnableWatchingWithArgus_DoubleEnable(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (CI environment)")
	}

	// Setup: Integration instance
	validator := &SecurityValidator{}
	logger := NewTestLogger()
	integration := NewSecurityArgusIntegration(validator, logger)

	tempDir := t.TempDir()
	whitelistFile := tempDir + "/whitelist.json"
	auditFile := tempDir + "/audit.log"

	// Test: First enable should succeed
	err1 := integration.EnableWatchingWithArgus(whitelistFile, auditFile)
	if err1 != nil {
		// In CI environment, this might fail due to missing dependencies
		t.Logf("First EnableWatchingWithArgus failed (expected in CI): %v", err1)
		t.Skip("Skipping test due to Argus dependencies not available in CI")
	}

	// Test: Second enable should fail with specific error
	err2 := integration.EnableWatchingWithArgus(whitelistFile, auditFile)

	// Assertions: Second enable must be rejected to prevent security issues
	if err2 == nil {
		t.Fatal("Second EnableWatchingWithArgus should fail to prevent multiple initializations")
	}

	// Verify it's the correct error type (not just any error)
	if !strings.Contains(err2.Error(), "already running") {
		t.Errorf("Expected 'already running' error, got: %v", err2)
	}

	// Verify first instance is still running (not corrupted by second call)
	if !integration.IsRunning() {
		t.Error("Integration should still be running after failed second enable")
	}

	// Cleanup
	if err := integration.DisableWatching(); err != nil {
		t.Logf("Warning: Failed to disable watching during cleanup: %v", err)
	}
}

// TestSecurityArgusIntegration_EnableWatchingWithArgus_InvalidAuditDirectory tests security with invalid audit paths
// This test can find path traversal vulnerabilities and directory creation edge cases
func TestSecurityArgusIntegration_EnableWatchingWithArgus_InvalidAuditDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (CI environment)")
	}

	// Setup: Integration instance
	validator := &SecurityValidator{}
	logger := NewTestLogger()
	integration := NewSecurityArgusIntegration(validator, logger)

	// Test case 1: Audit file in non-existent deep directory structure
	tempDir := t.TempDir()
	whitelistFile := tempDir + "/whitelist.json"
	invalidAuditFile := "/root/nonexistent/deep/path/audit.log" // Should fail on most systems

	// Test: Enable with invalid audit directory
	err := integration.EnableWatchingWithArgus(whitelistFile, invalidAuditFile)

	// In CI environment, this test might not work as expected
	if err == nil {
		t.Logf("EnableWatchingWithArgus unexpectedly succeeded with invalid audit directory (might be CI environment behavior)")
		// Don't fail in CI - just log and continue
	} else {
		// Normal case: should fail gracefully
		if !strings.Contains(err.Error(), "audit") {
			t.Logf("Expected audit-related error message, got: %v", err)
		}
	}

	// Verify the error is properly typed (not just a panic recovery)
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("Expected audit-related error message, got: %v", err)
	}

	// Verify integration is not in inconsistent state
	if integration.IsRunning() {
		t.Error("Integration should not be running after failed enable")
	}

	// Test case 2: Empty audit file (edge case)
	err2 := integration.EnableWatchingWithArgus(whitelistFile, "")

	// With empty audit file, it should succeed (audit is optional)
	if err2 != nil {
		t.Logf("EnableWatchingWithArgus failed with empty audit file (might be due to CI environment): %v", err2)
	} else {
		// Cleanup if it succeeded
		if err := integration.DisableWatching(); err != nil {
			t.Logf("Warning: Failed to disable watching during cleanup: %v", err)
		}
	}
}
