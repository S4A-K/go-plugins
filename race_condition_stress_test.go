// race_condition_stress_test.go : stress tests
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRaceConditionStressTest runs intensive concurrent tests to detect race conditions
func TestRaceConditionStressTest(t *testing.T) {
	t.Run("RequestTracker_HighConcurrency", func(t *testing.T) {
		tracker := NewRequestTracker()

		const numGoroutines = 1000
		const numOperationsPerGoroutine = 100

		var wg sync.WaitGroup
		var totalOperations atomic.Int64

		// Create context with cancellation for each plugin
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start multiple goroutines doing concurrent operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(pluginID int) {
				defer wg.Done()

				pluginName := "test-plugin-" + strconv.Itoa(pluginID%10)

				for j := 0; j < numOperationsPerGoroutine; j++ {
					// Start request
					tracker.StartRequest(pluginName, ctx)
					totalOperations.Add(1)

					// Simulate some work
					time.Sleep(time.Microsecond)

					// End request
					tracker.EndRequest(pluginName, ctx)

					// Occasionally check active count
					if j%10 == 0 {
						tracker.GetActiveRequestCount(pluginName)
						tracker.GetAllActiveRequests()
					}
				}
			}(i)
		}

		// Wait for all operations to complete
		wg.Wait()

		// Verify final state
		allRequests := tracker.GetAllActiveRequests()
		for pluginName, count := range allRequests {
			if count != 0 {
				t.Errorf("Plugin %s has non-zero active requests: %d", pluginName, count)
			}
		}

		t.Logf("Completed %d total operations successfully", totalOperations.Load())
	})

	t.Run("AtomicOperations_Consistency", func(t *testing.T) {
		// Test atomic operations consistency under high concurrency
		const numGoroutines = 500
		const numOperations = 1000

		var counter atomic.Int64
		var wg sync.WaitGroup

		// Multiple goroutines incrementing counter
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					counter.Add(1)
				}
			}()
		}

		wg.Wait()

		expected := int64(numGoroutines * numOperations)
		actual := counter.Load()

		if actual != expected {
			t.Errorf("Atomic counter inconsistency: expected %d, got %d", expected, actual)
		}
	})

	t.Run("Mutex_DeadlockPrevention", func(t *testing.T) {
		// Test potential deadlock scenarios with multiple mutexes
		var mu1, mu2 sync.Mutex
		var wg sync.WaitGroup
		var operations atomic.Int64

		// Goroutine 1: acquires mu1 then mu2
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				mu1.Lock()
				time.Sleep(time.Microsecond)
				mu2.Lock()
				operations.Add(1)
				mu2.Unlock()
				mu1.Unlock()
			}
		}()

		// Goroutine 2: acquires mu1 then mu2 (same order - no deadlock)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				mu1.Lock()
				time.Sleep(time.Microsecond)
				mu2.Lock()
				operations.Add(1)
				mu2.Unlock()
				mu1.Unlock()
			}
		}()

		// Wait with timeout to detect potential deadlocks
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			t.Logf("Completed %d operations without deadlock", operations.Load())
		case <-time.After(5 * time.Second):
			t.Error("Potential deadlock detected - operations did not complete within timeout")
		}
	})
}
