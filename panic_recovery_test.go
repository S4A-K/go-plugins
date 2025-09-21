// panic_recovery_test.go: panic recovery tests with logging and custom handlers
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPanicRecovery_WithStackRecover tests basic panic recovery with logging
// Covers: withStackRecover() function and stack trace capture
func TestPanicRecovery_WithStackRecover(t *testing.T) {
	t.Run("RecoversPanic_WithStackTrace", func(t *testing.T) {
		// Setup: Create test logger to capture panic messages
		logger := NewTestLogger()

		// Execute: Function that panics with known message
		func() {
			defer withStackRecover(logger)()
			panic("test panic message")
		}()

		// Verify: Panic was recovered and logged
		if len(logger.Messages) != 1 {
			t.Fatalf("Expected 1 log message, got %d", len(logger.Messages))
		}

		logMsg := logger.Messages[0]

		// Verify: Log level is ERROR
		if logMsg.Level != "ERROR" {
			t.Errorf("Expected ERROR level, got %s", logMsg.Level)
		}

		// Verify: Log message contains panic recovery info
		if logMsg.Message != "Panic recovered in goroutine" {
			t.Errorf("Expected 'Panic recovered in goroutine', got %s", logMsg.Message)
		}

		// Verify: Args contain panic details
		if len(logMsg.Args) < 4 { // panic, recovered_value, stack, trace
			t.Fatalf("Expected at least 4 args, got %d", len(logMsg.Args))
		}

		// Find panic value in args
		var panicValue interface{}
		var stackTrace string
		for i := 0; i < len(logMsg.Args)-1; i += 2 {
			key, ok := logMsg.Args[i].(string)
			if !ok {
				continue
			}

			switch key {
			case "panic":
				panicValue = logMsg.Args[i+1]
			case "stack":
				if stackStr, ok := logMsg.Args[i+1].(string); ok {
					stackTrace = stackStr
				}
			}
		} // Verify: Panic value was captured correctly
		if panicValue != "test panic message" {
			t.Errorf("Expected panic value 'test panic message', got %v", panicValue)
		}

		// Verify: Stack trace contains function information
		if stackTrace == "" {
			t.Error("Expected non-empty stack trace")
		}

		// Verify: Stack trace contains this test function
		if !strings.Contains(stackTrace, "TestPanicRecovery_WithStackRecover") {
			t.Error("Expected stack trace to contain test function name")
		}
	})

	t.Run("NoPanic_NoLogging", func(t *testing.T) {
		// Setup: Create test logger
		logger := NewTestLogger()

		// Execute: Function that doesn't panic
		func() {
			defer withStackRecover(logger)()
			// Normal execution, no panic
		}()

		// Verify: No messages logged when no panic occurs
		if len(logger.Messages) != 0 {
			t.Errorf("Expected 0 log messages when no panic, got %d", len(logger.Messages))
		}
	})
}

// TestPanicRecovery_CustomHandler tests custom recovery handler functionality
// Covers: withCustomRecoveryHandler() and custom handler execution
func TestPanicRecovery_CustomHandler(t *testing.T) {
	t.Run("CustomHandler_ReceivesPanicDetails", func(t *testing.T) {
		// Setup: Variables to capture handler calls
		var handlerCalled bool
		var recoveredValue interface{}
		var capturedStack []byte

		// Create custom handler
		customHandler := func(recovered interface{}, stack []byte) {
			handlerCalled = true
			recoveredValue = recovered
			capturedStack = make([]byte, len(stack))
			copy(capturedStack, stack)
		}

		// Execute: Function that panics
		func() {
			defer withCustomRecoveryHandler(customHandler)()
			panic("custom handler test panic")
		}()

		// Verify: Custom handler was called
		if !handlerCalled {
			t.Fatal("Expected custom handler to be called")
		}

		// Verify: Panic value was passed correctly
		if recoveredValue != "custom handler test panic" {
			t.Errorf("Expected panic value 'custom handler test panic', got %v", recoveredValue)
		}

		// Verify: Stack trace was captured
		if len(capturedStack) == 0 {
			t.Error("Expected non-empty stack trace")
		}

		// Verify: Stack trace contains meaningful information
		stackStr := string(capturedStack)
		if !strings.Contains(stackStr, "TestPanicRecovery_CustomHandler") {
			t.Error("Expected stack trace to contain test function name")
		}
	})

	t.Run("CustomHandler_NoPanic_NotCalled", func(t *testing.T) {
		// Setup: Handler call tracker
		var handlerCalled bool

		customHandler := func(recovered interface{}, stack []byte) {
			handlerCalled = true
		}

		// Execute: Function that doesn't panic
		func() {
			defer withCustomRecoveryHandler(customHandler)()
			// Normal execution
		}()

		// Verify: Handler was not called when no panic
		if handlerCalled {
			t.Error("Expected custom handler NOT to be called when no panic occurs")
		}
	})

	t.Run("CustomHandler_NilHandler_PanicsAreIgnored", func(t *testing.T) {
		// Execute: Function with nil handler (edge case)
		func() {
			defer withCustomRecoveryHandler(nil)()
			panic("panic with nil handler")
		}()

		// Verify: Test completes without crashing (nil handler handled gracefully)
		// If we reach this point, the nil handler didn't cause a crash
	})
}

// TestPanicRecovery_SafeGo tests SafeGo goroutine execution with panic recovery
// Covers: SafeGo() convenience function and goroutine safety
func TestPanicRecovery_SafeGo(t *testing.T) {
	t.Run("SafeGo_PanicRecovered", func(t *testing.T) {
		// Setup: Create test logger and synchronization
		logger := NewTestLogger()
		var wg sync.WaitGroup
		wg.Add(1)

		// Execute: SafeGo with panicking function
		SafeGo(logger, func() {
			defer wg.Done()
			panic("SafeGo test panic")
		})

		// Wait for goroutine completion with timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Goroutine completed successfully
		case <-time.After(500 * time.Millisecond):
			t.Fatal("SafeGo goroutine did not complete within timeout")
		}

		// Add small delay to ensure logger write completes
		time.Sleep(10 * time.Millisecond)

		// Verify: Panic was logged (thread-safe access)
		logger.mu.RLock()
		messageCount := len(logger.Messages)
		var logMsg TestLogMessage
		if messageCount > 0 {
			logMsg = logger.Messages[0]
		}
		logger.mu.RUnlock()

		if messageCount != 1 {
			t.Fatalf("Expected 1 log message, got %d", messageCount)
		}
		if logMsg.Level != "ERROR" {
			t.Errorf("Expected ERROR level, got %s", logMsg.Level)
		}

		// Find panic value in log args
		var panicValue interface{}
		for i := 0; i < len(logMsg.Args)-1; i += 2 {
			if key, ok := logMsg.Args[i].(string); ok && key == "panic" {
				panicValue = logMsg.Args[i+1]
				break
			}
		}

		if panicValue != "SafeGo test panic" {
			t.Errorf("Expected panic value 'SafeGo test panic', got %v", panicValue)
		}
	})

	t.Run("SafeGo_NormalExecution", func(t *testing.T) {
		// Setup: Test logger and completion tracking
		logger := NewTestLogger()
		var wg sync.WaitGroup
		var executionCompleted bool

		wg.Add(1)

		// Execute: SafeGo with normal function
		SafeGo(logger, func() {
			defer wg.Done()
			executionCompleted = true
		})

		// Wait for completion
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(100 * time.Millisecond):
			t.Fatal("SafeGo goroutine did not complete within timeout")
		}

		// Verify: Function executed normally
		if !executionCompleted {
			t.Error("Expected function to complete execution")
		}

		// Verify: No panic logs when no panic occurs
		if len(logger.Messages) != 0 {
			t.Errorf("Expected 0 log messages when no panic, got %d", len(logger.Messages))
		}
	})
}

// TestPanicRecovery_SafeGoWithHandler tests SafeGoWithHandler and metrics functionality
// Covers: SafeGoWithHandler(), MetricsRecoveryHandler(), RecoveryMetrics
func TestPanicRecovery_SafeGoWithHandler(t *testing.T) {
	t.Run("SafeGoWithHandler_CustomHandlerCalled", func(t *testing.T) {
		// Setup: Thread-safe custom handler tracking
		var mu sync.Mutex
		var handlerCalled bool
		var recoveredValue interface{}
		var wg sync.WaitGroup

		customHandler := func(recovered interface{}, stack []byte) {
			mu.Lock()
			handlerCalled = true
			recoveredValue = recovered
			mu.Unlock()
		}

		wg.Add(1)

		// Execute: SafeGoWithHandler with panicking function
		SafeGoWithHandler(customHandler, func() {
			defer wg.Done()
			panic("SafeGoWithHandler test")
		})

		// Wait for completion
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(500 * time.Millisecond):
			t.Fatal("SafeGoWithHandler goroutine did not complete within timeout")
		}

		// Add small delay to ensure handler completes
		time.Sleep(10 * time.Millisecond)

		// Verify: Custom handler was called (thread-safe read)
		mu.Lock()
		wasCalled := handlerCalled
		recovered := recoveredValue
		mu.Unlock()

		if !wasCalled {
			t.Error("Expected custom handler to be called")
		}

		// Verify recovered value
		if recovered != "SafeGoWithHandler test" {
			t.Errorf("Expected recovered value 'SafeGoWithHandler test', got %v", recovered)
		}

		if recoveredValue != "SafeGoWithHandler test" {
			t.Errorf("Expected panic value 'SafeGoWithHandler test', got %v", recoveredValue)
		}
	})

	t.Run("MetricsRecoveryHandler_TracksMetrics", func(t *testing.T) {
		// Setup: Logger and metrics
		logger := NewTestLogger()
		metrics := &RecoveryMetrics{}
		component := "test-component"

		// Create metrics handler
		handler := MetricsRecoveryHandler(logger, metrics, component)

		// Execute: Simulate panic recovery
		handler("test panic for metrics", []byte("mock stack trace"))

		// Verify: Metrics were updated
		if metrics.TotalPanicsRecovered != 1 {
			t.Errorf("Expected TotalPanicsRecovered=1, got %d", metrics.TotalPanicsRecovered)
		}

		if metrics.LastPanicTime == 0 {
			t.Error("Expected LastPanicTime to be set")
		}

		if metrics.PanicsByComponent == nil {
			t.Fatal("Expected PanicsByComponent to be initialized")
		}

		if metrics.PanicsByComponent[component] != 1 {
			t.Errorf("Expected component panic count=1, got %d", metrics.PanicsByComponent[component])
		}

		// Verify: Logger received panic message
		if len(logger.Messages) != 1 {
			t.Fatalf("Expected 1 log message, got %d", len(logger.Messages))
		}

		logMsg := logger.Messages[0]
		if logMsg.Level != "ERROR" {
			t.Errorf("Expected ERROR level, got %s", logMsg.Level)
		}

		if logMsg.Message != "Panic recovered with metrics tracking" {
			t.Errorf("Expected metrics tracking message, got %s", logMsg.Message)
		}

		// Test multiple panics increase counter
		handler("second panic", []byte("second stack trace"))

		if metrics.TotalPanicsRecovered != 2 {
			t.Errorf("Expected TotalPanicsRecovered=2 after second panic, got %d", metrics.TotalPanicsRecovered)
		}

		if metrics.PanicsByComponent[component] != 2 {
			t.Errorf("Expected component panic count=2 after second panic, got %d", metrics.PanicsByComponent[component])
		}
	})
}
