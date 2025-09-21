// library_config_watcher_stop_test.go: tests for LibraryConfigWatcher.Stop() function
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"sync"
	"testing"
	"time"

	"github.com/agilira/argus"
)

// Test file per LibraryConfigWatcher.Stop() function - critical shutdown testing
// Red team approach - cercare race conditions, deadlock, state corruption

func TestStop_ValidWatcher_ProperShutdown(t *testing.T) {
	// Test dello stop normale con watcher running
	watcher := createTestLibraryConfigWatcher()

	// Simula che il watcher sia running
	watcher.enabled.Store(true)
	watcher.stopped.Store(false)

	// Build a real Argus watcher to test stop
	config := argus.Config{
		PollInterval:    100 * time.Millisecond,
		MaxWatchedFiles: 10,
	}
	argusWatcher := argus.New(config)

	// CRITICAL: Start Argus watcher before stopping it (simulate real behavior)
	startErr := argusWatcher.Start()
	if startErr != nil {
		t.Fatalf("Failed to start Argus watcher: %v", startErr)
	}

	watcher.watcher = argusWatcher

	err := watcher.Stop()

	// Verify that there is no error
	if err != nil {
		t.Errorf("Stop() returned error: %v", err)
	}

	// Verify that the state has changed correctly
	if watcher.enabled.Load() {
		t.Error("Watcher should be disabled after Stop()")
	}

	if !watcher.stopped.Load() {
		t.Error("Watcher should be marked as stopped")
	}
}

func TestStop_AlreadyStopped_FastPath(t *testing.T) {
	// Test the fast path when already stopped
	watcher := createTestLibraryConfigWatcher()

	// Create a real Argus watcher
	config := argus.Config{PollInterval: 100 * time.Millisecond}
	watcher.watcher = argus.New(config)

	// Pre-mark as stopped (simulating previous stop)
	watcher.stopped.Store(true)
	watcher.enabled.Store(false)

	err := watcher.Stop()

	// Should return specific error
	if err == nil {
		t.Error("Stop() should return error when already stopped")
	}

	// Verify the error type
	if !contains(err.Error(), "already stopped") {
		t.Errorf("Expected 'already stopped' error, got: %v", err)
	}
}

func TestStop_NotRunning_StateError(t *testing.T) {
	// Test when the watcher is not running but not stopped
	watcher := createTestLibraryConfigWatcher()

	// Create a real Argus watcher
	config := argus.Config{PollInterval: 100 * time.Millisecond}
	watcher.watcher = argus.New(config)

	// Simulate state where enabled=false but stopped=false (intermediate state)
	watcher.enabled.Store(false)
	watcher.stopped.Store(false)

	err := watcher.Stop()

	// Should return error "not running"
	if err == nil {
		t.Error("Stop() should return error when not running")
	}

	if !contains(err.Error(), "not running") {
		t.Errorf("Expected 'not running' error, got: %v", err)
	}
}

func TestStop_ConcurrentCalls_SyncOnceGuard(t *testing.T) {
	// Test concurrency: only the first Stop() call should succeed, others should fail
	watcher := createTestLibraryConfigWatcher()

	// Setup running state
	watcher.enabled.Store(true)
	watcher.stopped.Store(false)

	// Create a real Argus watcher and start it
	config := argus.Config{PollInterval: 100 * time.Millisecond}
	argusWatcher := argus.New(config)

	// CRITICAL: Start Argus to allow Stop
	startErr := argusWatcher.Start()
	if startErr != nil {
		t.Fatalf("Failed to start Argus watcher: %v", startErr)
	}

	watcher.watcher = argusWatcher

	// Launch multiple concurrent Stop() calls
	const goroutines = 10
	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			errors <- watcher.Stop()
		}()
	}

	// Collect results
	var successCount, errorCount int
	for i := 0; i < goroutines; i++ {
		err := <-errors
		if err == nil {
			successCount++
		} else {
			errorCount++
		}
	}

	// Only one call should succeed (the first one), others should fail
	if successCount != 1 {
		t.Errorf("Expected exactly 1 success, got %d successes and %d errors", successCount, errorCount)
		// Log errors for debugging
		for i := 0; i < goroutines; i++ {
			select {
			case err := <-errors:
				if err != nil {
					t.Logf("Concurrent Stop error: %v", err)
				}
			default:
			}
		}
	}

	// Verify final consistent state
	if watcher.enabled.Load() {
		t.Error("Watcher should be disabled after concurrent stops")
	}

	if !watcher.stopped.Load() {
		t.Error("Watcher should be stopped after concurrent stops")
	}
}

func TestStop_WithAuditLogger_ProperCleanup(t *testing.T) {
	// Test that the audit logger is properly closed
	watcher := createTestLibraryConfigWatcher()

	// Setup with running state
	watcher.enabled.Store(true)
	watcher.stopped.Store(false)

	// Create a real Argus watcher and start it
	config := argus.Config{PollInterval: 100 * time.Millisecond}
	argusWatcher := argus.New(config)

	// CRITICAL: Start Argus before Stop
	startErr := argusWatcher.Start()
	if startErr != nil {
		t.Fatalf("Failed to start Argus watcher: %v", startErr)
	}

	watcher.watcher = argusWatcher

	// For the real audit logger test, create a real AuditLogger
	auditConfig := argus.AuditConfig{
		Enabled: true,
	}
	auditLogger, auditErr := argus.NewAuditLogger(auditConfig)
	if auditErr != nil {
		t.Skipf("Could not create audit logger: %v", auditErr)
		return
	}
	watcher.auditLogger = auditLogger

	err := watcher.Stop()

	if err != nil {
		t.Errorf("Stop() should succeed with audit logger: %v", err)
	}

	// Verifica stato finale
	if watcher.enabled.Load() {
		t.Error("Watcher should be disabled after Stop()")
	}

	if !watcher.stopped.Load() {
		t.Error("Watcher should be marked as stopped")
	}
}

func TestStop_ArgusFailure_StateRestoration(t *testing.T) {
	// Test critical: what happens if Argus.Stop() fails?
	// This tests the state recovery path lines 606-607
	watcher := createTestLibraryConfigWatcher()

	// Setup running state
	watcher.enabled.Store(true)
	watcher.stopped.Store(false)

	// Create an Argus watcher and start it normally
	config := argus.Config{PollInterval: 100 * time.Millisecond}
	argusWatcher := argus.New(config)

	// Start normally
	startErr := argusWatcher.Start()
	if startErr != nil {
		t.Fatalf("Failed to start Argus watcher: %v", startErr)
	}

	// CRITICAL: Force Argus to be already stopped to simulate failure
	// Call Stop() twice to force error on second Stop()
	firstStopErr := argusWatcher.Stop()
	if firstStopErr != nil {
		t.Fatalf("First Argus stop failed unexpectedly: %v", firstStopErr)
	}

	// Now argusWatcher is stopped, but our LibraryConfigWatcher is not
	watcher.watcher = argusWatcher

	err := watcher.Stop()

	// Should return error (Argus already stopped)
	if err == nil {
		t.Error("Stop() should return error when Argus is already stopped")
	}

	// CRITICAL CHECK of state restoration (lines 606-607)
	// stopped should remain true (permanent operation)
	if !watcher.stopped.Load() {
		t.Error("stopped should remain true even when Argus fails")
	}

	// enabled should be restored to true (potential bug!)
	if !watcher.enabled.Load() {
		t.Error("enabled should be restored when Argus stop fails (per current implementation)")
	}

	// Log for visibility of behavior
	t.Logf("State after Argus failure - enabled: %v, stopped: %v, error: %v",
		watcher.enabled.Load(), watcher.stopped.Load(), err)
}

// Helper functions for tests

func createTestLibraryConfigWatcher() *LibraryConfigWatcher[string, string] {
	// Create a minimal LibraryConfigWatcher for tests
	return &LibraryConfigWatcher[string, string]{
		mutex:    sync.Mutex{},
		stopOnce: sync.Once{},
		logger:   &mockLogger{},
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
