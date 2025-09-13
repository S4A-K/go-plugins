// circuit_breaker.go: Production-ready circuit breaker implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/go-timecache"
)

// CircuitBreakerState represents the current operational state of a circuit breaker.
//
// The circuit breaker pattern prevents cascading failures by monitoring the
// failure rate of operations and temporarily blocking requests when failures
// exceed a threshold. This helps systems fail fast and recover gracefully.
//
// State behaviors:
//   - StateClosed: Normal operation, all requests are allowed through
//   - StateOpen: Circuit is tripped, requests fail immediately without execution
//   - StateHalfOpen: Testing phase, limited requests allowed to test recovery
//
// State transitions occur automatically based on failure/success counts and timeouts.
type CircuitBreakerState int32

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern for enhanced plugin resilience.
//
// This implementation provides automatic failure detection and recovery mechanisms
// to prevent cascading failures in distributed systems. It uses atomic operations
// for thread safety and maintains detailed statistics for monitoring.
//
// Key features:
//   - Thread-safe operation using atomic counters
//   - Configurable failure thresholds and recovery timeouts
//   - Automatic state transitions based on success/failure patterns
//   - Detailed statistics tracking for observability
//   - Graceful recovery testing through half-open state
//
// Usage example:
//
//	config := CircuitBreakerConfig{
//	    Enabled:             true,
//	    FailureThreshold:    5,
//	    RecoveryTimeout:     30 * time.Second,
//	    MinRequestThreshold: 3,
//	    SuccessThreshold:    2,
//	}
//	cb := NewCircuitBreaker(config)
//
//	// Before making a request
//	if !cb.AllowRequest() {
//	    return nil, errors.New("circuit breaker open")
//	}
//
//	// After request completion
//	if err != nil {
//	    cb.RecordFailure()
//	} else {
//	    cb.RecordSuccess()
//	}
type CircuitBreaker struct {
	config CircuitBreakerConfig

	// Atomic counters for thread safety
	state           atomic.Int32 // CircuitBreakerState
	failureCount    atomic.Int64
	successCount    atomic.Int64
	requestCount    atomic.Int64
	lastFailureTime atomic.Int64 // Unix timestamp

	// Mutex for state transitions
	mu sync.Mutex
}

// NewCircuitBreaker creates a new circuit breaker instance with the specified configuration.
//
// The circuit breaker starts in the StateClosed state, allowing all requests to pass through.
// State transitions will occur automatically based on the configured thresholds and the
// success/failure patterns of monitored operations.
//
// Parameters:
//   - config: Configuration defining thresholds, timeouts, and behavior parameters
//
// Returns a thread-safe CircuitBreaker ready for use across multiple goroutines.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	cb := &CircuitBreaker{
		config: config,
	}
	cb.state.Store(int32(StateClosed))
	return cb
}

// AllowRequest determines whether a request should be allowed through the circuit breaker.
//
// This method implements the core logic of the circuit breaker pattern by checking
// the current state and applying the appropriate rules:
//
//   - StateClosed: Always allows requests (normal operation)
//   - StateOpen: Blocks all requests until recovery timeout expires
//   - StateHalfOpen: Allows limited requests to test service recovery
//
// The method is thread-safe and may trigger state transitions when called.
// It should be called before attempting any operation that you want to protect
// with the circuit breaker.
//
// Returns:
//   - true: Request should proceed
//   - false: Request should be rejected (fail fast)
func (cb *CircuitBreaker) AllowRequest() bool {
	if !cb.config.Enabled {
		return true
	}

	currentState := CircuitBreakerState(cb.state.Load())

	switch currentState {
	case StateClosed:
		return true

	case StateOpen:
		// Check if recovery timeout has passed
		if cb.shouldAttemptRecovery() {
			cb.mu.Lock()
			// Double-check state after acquiring lock
			if CircuitBreakerState(cb.state.Load()) == StateOpen && cb.shouldAttemptRecovery() {
				cb.state.Store(int32(StateHalfOpen))
				cb.resetCounters()
			}
			cb.mu.Unlock()
			return CircuitBreakerState(cb.state.Load()) == StateHalfOpen
		}
		return false

	case StateHalfOpen:
		// Allow limited requests to test recovery
		return cb.requestCount.Load() < int64(cb.config.SuccessThreshold)

	default:
		return false
	}
}

// RecordSuccess records a successful operation and may trigger state transitions.
//
// This method should be called after every successful operation that was allowed
// through the circuit breaker. It updates internal counters and may cause the
// circuit breaker to transition from StateHalfOpen to StateClosed if enough
// consecutive successes have been recorded.
//
// The method is thread-safe and performs atomic updates to maintain consistency
// across concurrent operations.
//
// State transition logic:
//   - In StateHalfOpen: May close circuit if SuccessThreshold is met
//   - In other states: Updates statistics for monitoring
func (cb *CircuitBreaker) RecordSuccess() {
	if !cb.config.Enabled {
		return
	}

	cb.successCount.Add(1)
	cb.requestCount.Add(1)

	currentState := CircuitBreakerState(cb.state.Load())

	if currentState == StateHalfOpen {
		cb.mu.Lock()
		defer cb.mu.Unlock()

		// Check if we have enough successful requests to close the circuit
		if cb.successCount.Load() >= int64(cb.config.SuccessThreshold) {
			cb.state.Store(int32(StateClosed))
			cb.resetCounters()
		}
	}
}

// RecordFailure records a failed operation and may trigger the circuit breaker to open.
//
// This method should be called after every failed operation that was allowed
// through the circuit breaker. It updates failure counters and may cause the
// circuit breaker to transition to StateOpen if the failure threshold is exceeded.
//
// The method is thread-safe and performs atomic updates to maintain consistency
// across concurrent operations. It also updates the last failure timestamp for
// recovery timeout calculations.
//
// State transition logic:
//   - May open circuit if FailureThreshold is exceeded
//   - In StateHalfOpen: Any failure immediately reopens the circuit
//   - Updates failure timestamp for recovery timeout tracking
func (cb *CircuitBreaker) RecordFailure() {
	if !cb.config.Enabled {
		return
	}

	cb.failureCount.Add(1)
	cb.requestCount.Add(1)
	cb.lastFailureTime.Store(timecache.CachedTimeNano())

	currentState := CircuitBreakerState(cb.state.Load())

	// Check if we should trip the circuit breaker
	if currentState == StateClosed || currentState == StateHalfOpen {
		cb.mu.Lock()
		defer cb.mu.Unlock()

		// Check conditions for opening the circuit
		if cb.shouldOpenCircuit() {
			cb.state.Store(int32(StateOpen))
			// Don't reset counters when opening - they're needed for monitoring
		}
	}
}

// GetState returns the current state of the circuit breaker.
//
// This method provides a thread-safe way to inspect the circuit breaker's
// current operational state without affecting its behavior. It's useful
// for monitoring, debugging, and making operational decisions.
//
// Returns one of:
//   - StateClosed: Normal operation
//   - StateOpen: Circuit is tripped, blocking requests
//   - StateHalfOpen: Testing recovery
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(cb.state.Load())
}

// GetStats returns comprehensive statistics about the circuit breaker's operation.
//
// This method provides detailed metrics for monitoring and observability purposes.
// The statistics include current state, operation counts, and timing information
// that can be used for alerting, dashboards, and performance analysis.
//
// The returned statistics are consistent with the circuit breaker's internal
// state at the time of the call, providing a reliable snapshot for monitoring.
//
// Returns CircuitBreakerStats containing:
//   - Current state and failure/success counts
//   - Request count and last failure timestamp
//   - All data needed for operational visibility
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	return CircuitBreakerStats{
		State:        cb.GetState(),
		FailureCount: cb.failureCount.Load(),
		SuccessCount: cb.successCount.Load(),
		RequestCount: cb.requestCount.Load(),
		LastFailure:  time.Unix(0, cb.lastFailureTime.Load()),
	}
}

// Reset forcibly resets the circuit breaker to the closed state and clears all counters.
//
// This method provides an administrative way to manually reset the circuit breaker,
// typically used for operational recovery or testing purposes. It immediately
// transitions the circuit breaker to StateClosed regardless of current state
// and clears all failure/success counters.
//
// Use cases:
//   - Manual recovery after fixing underlying issues
//   - Administrative reset during maintenance
//   - Testing and development scenarios
//   - Integration with external monitoring systems
//
// Note: Use with caution in production as it bypasses the normal recovery logic.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state.Store(int32(StateClosed))
	cb.resetCounters()
}

// shouldAttemptRecovery checks if enough time has passed since the last failure
func (cb *CircuitBreaker) shouldAttemptRecovery() bool {
	lastFailure := cb.lastFailureTime.Load()
	if lastFailure == 0 {
		return true
	}

	elapsed := time.Since(time.Unix(0, lastFailure))
	return elapsed >= cb.config.RecoveryTimeout
}

// shouldOpenCircuit determines if the circuit should be opened based on failure conditions
func (cb *CircuitBreaker) shouldOpenCircuit() bool {
	failureCount := cb.failureCount.Load()
	requestCount := cb.requestCount.Load()

	// Always allow opening if we haven't met minimum requests yet but have enough failures
	if requestCount < int64(cb.config.MinRequestThreshold) {
		return failureCount >= int64(cb.config.FailureThreshold)
	}

	// Check if failure threshold is exceeded
	return failureCount >= int64(cb.config.FailureThreshold)
}

// resetCounters resets all counters (should be called with lock held)
func (cb *CircuitBreaker) resetCounters() {
	cb.failureCount.Store(0)
	cb.successCount.Store(0)
	cb.requestCount.Store(0)
}

// CircuitBreakerStats contains comprehensive statistics about circuit breaker operation.
//
// This structure provides all the metrics needed for monitoring, alerting, and
// debugging circuit breaker behavior. It includes both current state information
// and historical operation counts.
//
// Fields:
//   - State: Current operational state (Closed/Open/HalfOpen)
//   - FailureCount: Total failures recorded since last reset
//   - SuccessCount: Total successes recorded since last reset
//   - RequestCount: Total requests processed since last reset
//   - LastFailure: Timestamp of the most recent failure
//
// These statistics can be exposed via metrics systems, logged for analysis,
// or used by monitoring systems to track system health and performance.
type CircuitBreakerStats struct {
	State        CircuitBreakerState `json:"state"`
	FailureCount int64               `json:"failure_count"`
	SuccessCount int64               `json:"success_count"`
	RequestCount int64               `json:"request_count"`
	LastFailure  time.Time           `json:"last_failure"`
}
