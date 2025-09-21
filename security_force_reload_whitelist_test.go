// security_force_reload_whitelist_test.go: tests for force reload functionality in security validation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"os"
	"sync"
	"testing"
	"time"
)

// TestForceReloadWhitelist_IntegrationLayer_NilValidation verifies handling of nil Argus integration
func TestForceReloadWhitelist_IntegrationLayer_NilValidation(t *testing.T) {
	// Setup: SecurityValidator without Argus integration
	config := SecurityConfig{
		Enabled:       true,
		HashAlgorithm: HashAlgorithmSHA256,
		Policy:        SecurityPolicyStrict,
	}

	validator := &SecurityValidator{
		config:           config,
		mutex:            sync.RWMutex{},
		argusIntegration: nil, // Important: nil integration
		logger:           &testLogger{t: t},
		stats:            SecurityStats{},
	}

	t.Run("NilArgusIntegration_ErrorHandling", func(t *testing.T) {
		// ForceReloadWhitelist should fail gracefully with nil integration
		err := validator.ForceReloadWhitelist()

		if err == nil {
			t.Error("ForceReloadWhitelist should fail when argusIntegration is nil")
		}

		// Verifies that error indicates integration not initialized
		expectedMsg := "argus integration not initialized"
		if err != nil && !containsErrorMessage(err, expectedMsg) {
			t.Errorf("Error should indicate integration not initialized, got: %v", err)
		}
	})

	t.Run("MutexSafety_WithNilIntegration", func(t *testing.T) {
		// Test that mutex is handled correctly even with nil integration
		done := make(chan error, 1)

		// Goroutine that calls ForceReloadWhitelist
		go func() {
			err := validator.ForceReloadWhitelist()
			done <- err
		}()

		// Should complete quickly without deadlock
		select {
		case err := <-done:
			if err == nil {
				t.Error("Expected error with nil integration")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ForceReloadWhitelist timed out - possible deadlock with mutex")
		}
	})
}

// TestForceReloadWhitelist_IntegrationDelegation_ValidFlow verifies correct delegation
func TestForceReloadWhitelist_IntegrationDelegation_ValidFlow(t *testing.T) {
	// Setup: crea file whitelist valido per Argus integration
	validFile, err := os.CreateTemp("", "delegation_whitelist_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(validFile.Name()); err != nil {
			t.Logf("Warning: Failed to remove temp file %s: %v", validFile.Name(), err)
		}
	}()

	validContent := `{
		"plugins": {
			"test-plugin": {
				"name": "test-plugin",
				"hash": "sha256:abc123def456",
				"endpoints": ["localhost:8080"],
				"size_limit": 1048576
			}
		},
		"version": "1.0.0",
		"updated_at": "2025-09-21T14:00:00Z",
		"hash_algorithm": "sha256"
	}`

	if _, err := validFile.WriteString(validContent); err != nil {
		t.Fatalf("Failed to write valid content: %v", err)
	}
	if err := validFile.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}

	// Setup: SecurityValidator with valid Argus integration
	config := SecurityConfig{
		Enabled:       true,
		WhitelistFile: validFile.Name(),
		HashAlgorithm: HashAlgorithmSHA256,
		Policy:        SecurityPolicyStrict,
	}

	validator, err := NewSecurityValidator(config, &testLogger{t: t})
	if err != nil {
		t.Fatalf("Failed to create SecurityValidator: %v", err)
	}

	t.Run("ValidDelegation_Success", func(t *testing.T) {
		// Setup: manually activate integration to avoid deadlock in EnableWatchingWithArgus
		validator.argusIntegration.mutex.Lock()
		validator.argusIntegration.running = true
		validator.argusIntegration.whitelistFile = validFile.Name()
		validator.argusIntegration.mutex.Unlock()

		// ForceReloadWhitelist should delegate correctly to Argus integration
		err := validator.ForceReloadWhitelist()

		if err != nil {
			t.Errorf("ForceReloadWhitelist should succeed with running integration: %v", err)
		}

		// Verifies that stats are updated after reload
		validator.mutex.RLock()
		configReloads := validator.stats.ConfigReloads
		validator.mutex.RUnlock()

		if configReloads == 0 {
			t.Error("ConfigReloads should be incremented after successful reload")
		}

		// Cleanup: deactivate integration
		validator.argusIntegration.mutex.Lock()
		validator.argusIntegration.running = false
		validator.argusIntegration.mutex.Unlock()
	})

	t.Run("NotRunningIntegration_ErrorHandling", func(t *testing.T) {
		// Test that ForceReloadWhitelist fails when integration is not running
		// (we don't call EnableWatchingWithArgus, so it remains not running)
		err := validator.ForceReloadWhitelist()
		if err == nil {
			t.Error("ForceReloadWhitelist should fail when integration is not running")
		}

		// Verifies that error indicates integration not running
		expectedMsg := "not running"
		if err != nil && !containsErrorMessage(err, expectedMsg) {
			t.Errorf("Error should indicate integration not running, got: %v", err)
		}
	})
}

// TestForceReloadWhitelist_ConcurrentAccess_RaceConditions verifies thread safety delegation
func TestForceReloadWhitelist_ConcurrentAccess_RaceConditions(t *testing.T) {
	// Setup: SecurityValidator with valid integration
	validFile, err := os.CreateTemp("", "concurrent_whitelist_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(validFile.Name()); err != nil {
			t.Logf("Warning: Failed to remove temp file %s: %v", validFile.Name(), err)
		}
	}()

	validContent := `{
		"plugins": {
			"concurrent-plugin": {
				"name": "concurrent-plugin",
				"hash": "sha256:def789abc123",
				"endpoints": ["localhost:8081"],
				"size_limit": 2097152
			}
		},
		"version": "1.1.0",
		"updated_at": "2025-09-21T15:00:00Z",
		"hash_algorithm": "sha256"
	}`

	if _, err := validFile.WriteString(validContent); err != nil {
		t.Fatalf("Failed to write content: %v", err)
	}
	if err := validFile.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}

	config := SecurityConfig{
		Enabled:       true,
		WhitelistFile: validFile.Name(),
		HashAlgorithm: HashAlgorithmSHA256,
		Policy:        SecurityPolicyStrict,
	}

	validator, err := NewSecurityValidator(config, &testLogger{t: t})
	if err != nil {
		t.Fatalf("Failed to create SecurityValidator: %v", err)
	}

	t.Run("ConcurrentReloads_ThreadSafety", func(t *testing.T) {
		// Create isolated validator instance for this subtest to avoid race conditions
		isolatedValidator, err := NewSecurityValidator(config, &testLogger{t: t})
		if err != nil {
			t.Fatalf("Failed to create isolated SecurityValidator: %v", err)
		}

		// Setup: attiva Argus integration per test concurrency
		auditFile := validFile.Name() + ".audit"
		err = isolatedValidator.argusIntegration.EnableWatchingWithArgus(validFile.Name(), auditFile)
		if err != nil {
			t.Fatalf("Failed to enable integration: %v", err)
		}
		defer func() {
			if err := os.Remove(auditFile); err != nil {
				t.Logf("Warning: Failed to remove audit file %s: %v", auditFile, err)
			}
		}()

		numGoroutines := 8
		done := make(chan error, numGoroutines)

		// Lancia reload simultanei tramite SecurityValidator
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				err := isolatedValidator.ForceReloadWhitelist()
				done <- err
			}(i)
		}

		// Get results
		var errors []error
		for i := 0; i < numGoroutines; i++ {
			select {
			case err := <-done:
				if err != nil {
					errors = append(errors, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout waiting for concurrent ForceReloadWhitelist operations")
			}
		}

		// Should complete without deadlock (some may fail due to race conditions)
		if len(errors) == numGoroutines {
			t.Errorf("All %d ForceReloadWhitelist operations failed, possible deadlock: %v", numGoroutines, errors[0])
		}
	})

	t.Run("MutexChain_NoDeadlock", func(t *testing.T) {
		// Test mutex chain without activating integration (will test error path)
		stopTest := make(chan bool)
		errorCount := make(chan int, 1)

		// Goroutine that performs continuous reloads for 1 second (shorter for consistent errors)
		go func() {
			errors := 0
			for {
				select {
				case <-stopTest:
					errorCount <- errors
					return
				default:
					if err := validator.ForceReloadWhitelist(); err != nil {
						errors++
					}
					time.Sleep(time.Millisecond) // Breve pausa tra reload
				}
			}
		}()

		// Let it run for 1 second
		time.Sleep(1 * time.Second)
		close(stopTest)

		// Verify that operation did not get stuck
		select {
		case errors := <-errorCount:
			t.Logf("Completed continuous reload test with %d errors", errors)
			// The important thing is that it did not get stuck in deadlock
			// With integration nil, it could have 0 errors (no-op operation) or errors (depends on implementation)
		case <-time.After(5 * time.Second):
			t.Fatal("Continuous reload test timed out - possible mutex deadlock")
		}
	})
}

// Utility function for checking error messages
func containsErrorMessage(err error, expected string) bool {
	if err == nil {
		return false
	}
	errorMsg := err.Error()
	return len(expected) > 0 && len(errorMsg) >= len(expected) &&
		func() bool {
			for i := 0; i <= len(errorMsg)-len(expected); i++ {
				if errorMsg[i:i+len(expected)] == expected {
					return true
				}
			}
			return false
		}()
}
