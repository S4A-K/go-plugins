// panic_recovery.go: Standardized panic recovery utilities with stack trace support
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"runtime"
	"time"
)

// RecoveryHandler defines the signature for panic recovery handlers.
type RecoveryHandler func(recovered interface{}, stack []byte)

// WithStackRecover returns a panic recovery function that logs panic details
// including full stack trace. This provides comprehensive debugging information
// when goroutines panic in event handlers or other async operations.
//
// Example usage:
//
//	go func() {
//	    defer withStackRecover(logger)()
//	    // potentially panicking code
//	}()
//
// The returned function should be called with defer to ensure proper recovery.
func withStackRecover(logger Logger) func() {
	return func() {
		if r := recover(); r != nil {
			// Capture stack trace with reasonable buffer size
			buf := make([]byte, 64<<10) // 64KB should be sufficient for most cases
			n := runtime.Stack(buf, false)

			// Log the panic with full context
			logger.Error("Panic recovered in goroutine",
				"panic", r,
				"stack", string(buf[:n]))
		}
	}
}

// WithCustomRecoveryHandler returns a panic recovery function that calls
// a custom handler when a panic occurs. This allows for application-specific
// panic handling while still capturing stack traces.
//
// Example usage:
//
//	handler := func(recovered interface{}, stack []byte) {
//	    // Custom panic handling logic
//	    metrics.IncrementPanicCounter()
//	    alert.SendPanicAlert(recovered, stack)
//	}
//
//	go func() {
//	    defer withCustomRecoveryHandler(handler)()
//	    // potentially panicking code
//	}()
func withCustomRecoveryHandler(handler RecoveryHandler) func() {
	return func() {
		if r := recover(); r != nil {
			// Capture stack trace
			buf := make([]byte, 64<<10)
			n := runtime.Stack(buf, false)

			// Call custom handler with panic details
			handler(r, buf[:n])
		}
	}
}

// SafeGo executes a function in a new goroutine with automatic panic recovery.
// This is a convenience function that combines goroutine creation with panic
// recovery, reducing boilerplate code.
//
// Example usage:
//
//	SafeGo(logger, func() {
//	    // potentially panicking code
//	})
//
// If the function panics, the panic will be logged and the goroutine will
// terminate gracefully without crashing the application.
func SafeGo(logger Logger, fn func()) {
	go func() {
		defer withStackRecover(logger)()
		fn()
	}()
}

// SafeGoWithHandler executes a function in a new goroutine with custom panic recovery.
// This variant allows for application-specific panic handling.
//
// Example usage:
//
//	handler := func(recovered interface{}, stack []byte) {
//	    // Custom handling
//	}
//
//	SafeGoWithHandler(handler, func() {
//	    // potentially panicking code
//	})
func SafeGoWithHandler(handler RecoveryHandler, fn func()) {
	go func() {
		defer withCustomRecoveryHandler(handler)()
		fn()
	}()
}

// RecoveryMetrics provides metrics about panic recovery operations.
type RecoveryMetrics struct {
	TotalPanicsRecovered int64            `json:"total_panics_recovered"`
	LastPanicTime        int64            `json:"last_panic_time_unix"`
	PanicsByComponent    map[string]int64 `json:"panics_by_component"`
}

// MetricsRecoveryHandler creates a recovery handler that tracks panic metrics.
// This is useful for monitoring and alerting on panic frequency.
func MetricsRecoveryHandler(logger Logger, metrics *RecoveryMetrics, component string) RecoveryHandler {
	return func(recovered interface{}, stack []byte) {
		// Update metrics
		metrics.TotalPanicsRecovered++
		metrics.LastPanicTime = time.Now().Unix()

		if metrics.PanicsByComponent == nil {
			metrics.PanicsByComponent = make(map[string]int64)
		}
		metrics.PanicsByComponent[component]++

		// Log with component context
		logger.Error("Panic recovered with metrics tracking",
			"panic", recovered,
			"component", component,
			"total_panics", metrics.TotalPanicsRecovered,
			"stack", string(stack))
	}
}
