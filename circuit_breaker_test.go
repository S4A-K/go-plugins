// circuit_breaker_comprehensive_test.go: Comprehensive tests for circuit breaker resilience patterns
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"testing"
	"time"
) // TestCircuitBreakerState_String tests state string representation
func TestCircuitBreakerState_String(t *testing.T) {
	assert := NewTestAssertions(t)

	testCases := []struct {
		state    CircuitBreakerState
		expected string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{CircuitBreakerState(99), "unknown"}, // Invalid state
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			actual := tc.state.String()
			assert.AssertEqual(tc.expected, actual, "state string representation")
		})
	}
}

// TestCircuitBreaker_GetStats_Accuracy tests statistics accuracy
func TestCircuitBreaker_GetStats_Accuracy(t *testing.T) {
	assert := NewTestAssertions(t)

	config := CircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    10,
		RecoveryTimeout:     1 * time.Second,
		MinRequestThreshold: 5,
		SuccessThreshold:    3,
	}

	cb := NewCircuitBreaker(config)

	// Initial stats
	stats := cb.GetStats()
	assert.AssertEqual(int64(0), stats.RequestCount, "initial request count")
	assert.AssertEqual(int64(0), stats.SuccessCount, "initial success count")
	assert.AssertEqual(int64(0), stats.FailureCount, "initial failure count")

	// Record successes
	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordSuccess()

	stats = cb.GetStats()
	assert.AssertEqual(int64(3), stats.RequestCount, "request count after 3 successes")
	assert.AssertEqual(int64(3), stats.SuccessCount, "success count")
	assert.AssertEqual(int64(0), stats.FailureCount, "failure count should be 0")

	// Record failures
	cb.RecordFailure()
	cb.RecordFailure()

	stats = cb.GetStats()
	assert.AssertEqual(int64(5), stats.RequestCount, "request count after 3 successes + 2 failures")
	assert.AssertEqual(int64(3), stats.SuccessCount, "success count should remain 3")
	assert.AssertEqual(int64(2), stats.FailureCount, "failure count")
}

// TestCircuitBreaker_Reset_Functionality tests circuit breaker reset functionality
func TestCircuitBreaker_Reset_Functionality(t *testing.T) {
	assert := NewTestAssertions(t)

	config := CircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    3,
		RecoveryTimeout:     1 * time.Second,
		MinRequestThreshold: 2,
		SuccessThreshold:    2,
	}

	cb := NewCircuitBreaker(config)

	// Generate some activity
	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure() // Should trigger open state

	// Verify state before reset
	assert.AssertEqual(StateOpen, cb.GetState(), "should be open before reset")

	stats := cb.GetStats()
	assert.AssertTrue(stats.RequestCount > 0, "should have recorded requests")
	assert.AssertTrue(stats.FailureCount > 0, "should have recorded failures")

	// Reset the circuit breaker
	cb.Reset()

	// Verify state after reset
	assert.AssertEqual(StateClosed, cb.GetState(), "should be closed after reset")
	assert.AssertTrue(cb.AllowRequest(), "should allow requests after reset")

	// Verify stats are cleared
	stats = cb.GetStats()
	assert.AssertEqual(int64(0), stats.RequestCount, "request count should be reset")
	assert.AssertEqual(int64(0), stats.SuccessCount, "success count should be reset")
	assert.AssertEqual(int64(0), stats.FailureCount, "failure count should be reset")
}

// TestCircuitBreaker_DisabledBehavior tests circuit breaker when disabled
func TestCircuitBreaker_DisabledBehavior(t *testing.T) {
	assert := NewTestAssertions(t)

	config := CircuitBreakerConfig{
		Enabled: false, // Disabled circuit breaker
	}

	cb := NewCircuitBreaker(config)

	// Should always allow requests when disabled
	assert.AssertTrue(cb.AllowRequest(), "disabled circuit breaker should always allow requests")

	// Record many failures - should not affect behavior
	for i := 0; i < 10; i++ {
		cb.RecordFailure()
		assert.AssertTrue(cb.AllowRequest(), "should continue allowing requests despite failures")
	}

	// State should remain closed
	assert.AssertEqual(StateClosed, cb.GetState(), "disabled circuit breaker should always be closed")

	// Stats should NOT be tracked when disabled
	stats := cb.GetStats()
	assert.AssertEqual(int64(0), stats.FailureCount, "failures should NOT be counted when disabled")
}
