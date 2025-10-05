// security_force_reload_test.go: tests for force reload functionality in security validation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestForceReload_StateValidation_NotRunning verifies behavior of ForceReload when integration is not running
func TestForceReload_StateValidation_NotRunning(t *testing.T) {
	// Setup: create integration NOT running
	integration := &SecurityArgusIntegration{
		logger:  &testLogger{t: t},
		mutex:   sync.RWMutex{},
		running: false, // Not initialized
	}

	t.Run("ForceReloadWhenNotRunning", func(t *testing.T) {
		// ForceReload should fail when integration is not running
		err := integration.ForceReload()

		if err == nil {
			t.Error("ForceReload should fail when integration is not running")
		}

		// Verify that the error indicates integration not running
		if err != nil && !strings.Contains(err.Error(), "not running") {
			t.Errorf("Error should indicate integration not running, got: %v", err)
		}
	})

	t.Run("StateConsistencyAfterFailedReload", func(t *testing.T) {
		// Verify that state remains consistent after failed reload
		initialRunning := integration.running

		err := integration.ForceReload()
		if err == nil {
			t.Error("Expected ForceReload to fail")
		}

		// Running state should not change after failed reload
		integration.mutex.RLock()
		currentRunning := integration.running
		integration.mutex.RUnlock()

		if currentRunning != initialRunning {
			t.Errorf("Running state changed after failed reload: before=%v, after=%v", initialRunning, currentRunning)
		}
	})
}

// TestForceReload_IntegrityValidation_CorruptedWhitelist verifies handling of corrupted whitelists
// Potential bug: reload of corrupted files, inconsistent state after error
func TestForceReload_IntegrityValidation_CorruptedWhitelist(t *testing.T) {
	// Setup: create initially valid whitelist file
	validFile, err := os.CreateTemp("", "valid_whitelist_*.json")
	if err != nil {
		t.Fatalf("Failed to create valid file: %v", err)
	}
	defer func() {
		if err := os.Remove(validFile.Name()); err != nil {
			t.Logf("Warning: Failed to remove temp file %s: %v", validFile.Name(), err)
		}
	}()

	// Write initial valid content (correct format)
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
		t.Fatalf("Failed to close valid file: %v", err)
	}

	// Setup validator with valid file
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

	integration := &SecurityArgusIntegration{
		logger:        &testLogger{t: t},
		mutex:         sync.RWMutex{},
		running:       true,
		whitelistFile: validFile.Name(),
		validator:     validator,
		stats:         SecurityArgusStats{},
	}

	t.Run("CorruptedWhitelistReload", func(t *testing.T) {
		// Now corrupt the file after the validator has been created
		corruptedContent := `{"plugins": [{"name": "test"` // JSON incompleto
		err := os.WriteFile(validFile.Name(), []byte(corruptedContent), 0644)
		if err != nil {
			t.Fatalf("Failed to corrupt file: %v", err)
		}

		// ForceReload should fail with corrupted file
		err = integration.ForceReload()

		if err == nil {
			t.Error("ForceReload should fail with corrupted whitelist file")
		}

		// Verify that stats reflect the error
		integration.mutex.RLock()
		configErrors := integration.stats.ConfigErrors
		lastError := integration.stats.LastError
		integration.mutex.RUnlock()

		if configErrors == 0 {
			t.Error("ConfigErrors should be incremented after failed reload")
		}
		if lastError == "" {
			t.Error("LastError should be set after failed reload")
		}

		// Restore valid file for next tests
		err = os.WriteFile(validFile.Name(), []byte(validContent), 0644)
		if err != nil {
			t.Fatalf("Failed to restore valid file: %v", err)
		}
	})

	t.Run("FileTooBig_IntegrityCheck", func(t *testing.T) {
		// Create file too large for integrity check
		bigFile, err := os.CreateTemp("", "big_whitelist_*.json")
		if err != nil {
			t.Fatalf("Failed to create big file: %v", err)
		}
		defer func() {
			if err := os.Remove(bigFile.Name()); err != nil {
				t.Logf("Warning: Failed to remove temp file %s: %v", bigFile.Name(), err)
			}
		}()

		// 15MB file (exceeds 10MB limit of ValidateWhitelistIntegrity)
		if err := createFileWithSize(bigFile.Name(), 15*1024*1024); err != nil {
			t.Fatalf("Failed to create big file: %v", err)
		}

		// Update integration to use oversized file
		integration.whitelistFile = bigFile.Name()

		// Update validator config for new file
		newConfig := integration.validator.GetConfig()
		newConfig.WhitelistFile = bigFile.Name()
		if err := integration.validator.UpdateConfig(newConfig); err != nil {
			t.Fatalf("Failed to update validator config: %v", err)
		}

		err = integration.ForceReload()
		if err == nil {
			t.Error("ForceReload should fail for file exceeding size limit")
		}

		// Verify that error indicates integrity/size problem
		errorMsg := err.Error()
		if err != nil && !strings.Contains(errorMsg, "too large") && !strings.Contains(errorMsg, "size") && !strings.Contains(errorMsg, "integrity") {
			t.Errorf("Error should indicate size/integrity problem, got: %v", err)
		}
	})
}

// TestForceReload_ConcurrencyControl_RaceConditions verifies thread safety
// Potential bug: race conditions, data corruption, deadlock during simultaneous reloads
func TestForceReload_ConcurrencyControl_RaceConditions(t *testing.T) {
	// Setup: create valid whitelist file
	validFile, err := os.CreateTemp("", "valid_whitelist_*.json")
	if err != nil {
		t.Fatalf("Failed to create valid file: %v", err)
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
		t.Fatalf("Failed to close valid file: %v", err)
	}

	// Setup validator with valid file
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

	integration := &SecurityArgusIntegration{
		logger:        &testLogger{t: t},
		mutex:         sync.RWMutex{},
		running:       true,
		whitelistFile: validFile.Name(),
		validator:     validator,
		stats:         SecurityArgusStats{},
	}

	t.Run("ConcurrentForceReloads", func(t *testing.T) {
		numGoroutines := 10
		done := make(chan error, numGoroutines)

		// Launch simultaneous reloads
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				err := integration.ForceReload()
				done <- err
			}(i)
		}

		// Collect results
		var errors []error
		for i := 0; i < numGoroutines; i++ {
			select {
			case err := <-done:
				if err != nil {
					errors = append(errors, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout waiting for concurrent ForceReload operations")
			}
		}

		// Some may fail but there shouldn't be deadlock or corruption
		if len(errors) == numGoroutines {
			t.Errorf("All %d ForceReload operations failed, possible deadlock: %v", numGoroutines, errors[0])
		}
	})

	t.Run("ReloadDuringStatsRead", func(t *testing.T) {
		// Test reads stats while reload is in progress
		stopReads := make(chan bool)
		readErrors := make(chan error, 1)

		// Goroutine that continuously reads stats
		go func() {
			for {
				select {
				case <-stopReads:
					return
				default:
					integration.mutex.RLock()
					_ = integration.stats.ConfigErrors
					_ = integration.stats.LastError
					integration.mutex.RUnlock()

					sleepDuration := time.Microsecond
					if testing.Short() {
						// Longer sleep to reduce contention under race detection
						sleepDuration = time.Millisecond
					}
					time.Sleep(sleepDuration)
				}
			}
		}()

		// Execute multiple reloads while reads are ongoing
		reloadCount := 50
		sleepDuration := time.Microsecond

		if testing.Short() {
			// Reduce load for race detection and CI environments
			reloadCount = 10
			sleepDuration = time.Millisecond
		}

		for i := 0; i < reloadCount; i++ {
			_ = integration.ForceReload()
			time.Sleep(sleepDuration)
		}

		// Ferma letture
		close(stopReads)

		// There shouldn't be any race conditions or corruption
		select {
		case err := <-readErrors:
			t.Errorf("Stats read failed during concurrent reload: %v", err)
		case <-time.After(100 * time.Millisecond):
			// OK, no errors
		}
	})
}
