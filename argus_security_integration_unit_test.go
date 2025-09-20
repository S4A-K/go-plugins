package goplugins

import (
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
