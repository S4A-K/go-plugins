// security_race_conditions_test.go: tests for race conditions in security validation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestUpdateSecurityValidator_MemorySafety_NilValidator verifiieses safe handling of nil updates
// Potential bug: panic on nil pointer dereference if validator is used after update
func TestUpdateSecurityValidator_MemorySafety_NilValidator(t *testing.T) {
	integration := &SecurityArgusIntegration{
		logger: &testLogger{t: t},
		mutex:  sync.RWMutex{},
	}

	// Test Case: Update nil validator
	t.Run("NilValidatorUpdate", func(t *testing.T) {
		// Should not panic even with nil validator
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("UpdateSecurityValidator panicked with nil validator: %v", r)
			}
		}()

		integration.UpdateSecurityValidator(nil)

		// Verify that validator is actually nil after update
		integration.mutex.RLock()
		validator := integration.validator
		integration.mutex.RUnlock()

		if validator != nil {
			t.Error("Expected validator to be nil after nil update")
		}
	})
}

// TestUpdateSecurityValidator_RaceCondition_ConcurrentUpdates verifies thread safety
// Potential bug: data race or corruption during simultaneous updates
func TestUpdateSecurityValidator_RaceCondition_ConcurrentUpdates(t *testing.T) {
	integration := &SecurityArgusIntegration{
		logger: &testLogger{t: t},
		mutex:  sync.RWMutex{},
	}

	// Setup: create test validator
	config := SecurityConfig{
		Enabled:       true,
		HashAlgorithm: HashAlgorithmSHA256,
		Policy:        SecurityPolicyStrict,
	}

	validator1, err := NewSecurityValidator(config, &testLogger{t: t})
	if err != nil {
		t.Fatalf("Failed to create validator1: %v", err)
	}

	validator2, err := NewSecurityValidator(config, &testLogger{t: t})
	if err != nil {
		t.Fatalf("Failed to create validator2: %v", err)
	}

	t.Run("ConcurrentUpdates_RaceDetection", func(t *testing.T) {
		numGoroutines := 10
		done := make(chan bool, numGoroutines)

		// Launch concurrent goroutines that update the validator
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				// Alternate between validator1 and validator2 to maximize race condition
				if id%2 == 0 {
					integration.UpdateSecurityValidator(validator1)
				} else {
					integration.UpdateSecurityValidator(validator2)
				}
			}(i)
		}

		// Wait for all goroutines to finish
		for i := 0; i < numGoroutines; i++ {
			select {
			case <-done:
				// OK
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for concurrent updates to complete")
			}
		}

		// Verify that final validator is one of the two (not corrupted)
		integration.mutex.RLock()
		finalValidator := integration.validator
		integration.mutex.RUnlock()

		if finalValidator != validator1 && finalValidator != validator2 {
			t.Error("Final validator is neither validator1 nor validator2 - possible corruption")
		}
	})

	t.Run("ReadWhileUpdate_NoCorruption", func(t *testing.T) {
		// Test reading the validator while updates are in progress
		stopUpdates := make(chan bool)
		updateErrors := make(chan error, 1)

		// Goroutine that continuously updates
		go func() {
			defer func() {
				if r := recover(); r != nil {
					updateErrors <- fmt.Errorf("update panic: %v", r)
				}
			}()

			for {
				select {
				case <-stopUpdates:
					return
				default:
					integration.UpdateSecurityValidator(validator1)
					time.Sleep(time.Microsecond) // Breve pausa per permettere race
					integration.UpdateSecurityValidator(validator2)
					time.Sleep(time.Microsecond)
				}
			}
		}()

		// Read validator multiple times while updates are in progress
		for i := 0; i < 100; i++ {
			integration.mutex.RLock()
			currentValidator := integration.validator
			integration.mutex.RUnlock()

			// Validator must always be one of the two or nil (never corrupted)
			if currentValidator != nil && currentValidator != validator1 && currentValidator != validator2 {
				t.Errorf("Read corrupted validator at iteration %d", i)
				break
			}
		}

		// Stop updates
		close(stopUpdates)

		// Check for errors in updates
		select {
		case err := <-updateErrors:
			t.Errorf("Update goroutine failed: %v", err)
		case <-time.After(100 * time.Millisecond):
			// OK, no error
		}
	})
}

// TestUpdateSecurityValidator_StateCorruption_ValidatorSwitch verifies consistency of state
// Potential bug: inconsistent state when validator changes during operations
func TestUpdateSecurityValidator_StateCorruption_ValidatorSwitch(t *testing.T) {
	integration := &SecurityArgusIntegration{
		logger:  &testLogger{t: t},
		mutex:   sync.RWMutex{},
		running: true, // Simulate active integration
	}

	// Setup: create two validators with different configurations
	config1 := SecurityConfig{
		Enabled:       true,
		Policy:        SecurityPolicyStrict,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	config2 := SecurityConfig{
		Enabled:       false, // Different from config1
		Policy:        SecurityPolicyPermissive,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	validator1, err := NewSecurityValidator(config1, &testLogger{t: t})
	if err != nil {
		t.Fatalf("Failed to create validator1: %v", err)
	}

	validator2, err := NewSecurityValidator(config2, &testLogger{t: t})
	if err != nil {
		t.Fatalf("Failed to create validator2: %v", err)
	}

	t.Run("ValidatorSwitchCoherence", func(t *testing.T) {
		// Set initial validator to validator1
		integration.UpdateSecurityValidator(validator1)

		// Verify initial state
		integration.mutex.RLock()
		initialValidator := integration.validator
		integration.mutex.RUnlock()

		if initialValidator != validator1 {
			t.Error("Initial validator not set correctly")
		}

		// Change to validator2
		integration.UpdateSecurityValidator(validator2)

		// Verify that the switch is atomic and complete
		integration.mutex.RLock()
		newValidator := integration.validator
		integration.mutex.RUnlock()

		if newValidator != validator2 {
			t.Error("Validator switch not atomic - state corruption possible")
		}

		// Verify that there are no references to the old validator
		if newValidator == validator1 {
			t.Error("Old validator still referenced after update")
		}
	})
}
