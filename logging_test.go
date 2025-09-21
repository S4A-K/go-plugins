// logging_test.go: logging interface tests
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"sync"
	"testing"
)

// TestLogger_BasicMessageCapture tests the core logging functionality
// Covers: Debug(), Info(), Warn(), Error() message capture
func TestLogger_BasicMessageCapture(t *testing.T) {
	tests := []struct {
		name    string
		logFunc func(*TestLogger, string, ...any)
		level   string
		message string
		args    []any
	}{
		{
			name:    "Debug_SimpleMessage",
			logFunc: (*TestLogger).Debug,
			level:   "DEBUG",
			message: "debug message",
			args:    nil,
		},
		{
			name:    "Info_SimpleMessage",
			logFunc: (*TestLogger).Info,
			level:   "INFO",
			message: "info message",
			args:    nil,
		},
		{
			name:    "Warn_SimpleMessage",
			logFunc: (*TestLogger).Warn,
			level:   "WARN",
			message: "warn message",
			args:    nil,
		},
		{
			name:    "Error_SimpleMessage",
			logFunc: (*TestLogger).Error,
			level:   "ERROR",
			message: "error message",
			args:    nil,
		},
		{
			name:    "Info_WithStructuredArgs",
			logFunc: (*TestLogger).Info,
			level:   "INFO",
			message: "operation completed",
			args:    []any{"duration", "150ms", "plugin", "test-plugin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: Create fresh TestLogger
			logger := NewTestLogger()

			// Execute: Log message
			tt.logFunc(logger, tt.message, tt.args...)

			// Verify: Message was captured correctly
			if len(logger.Messages) != 1 {
				t.Fatalf("Expected 1 message, got %d", len(logger.Messages))
			}

			msg := logger.Messages[0]
			if msg.Level != tt.level {
				t.Errorf("Expected level %s, got %s", tt.level, msg.Level)
			}

			if msg.Message != tt.message {
				t.Errorf("Expected message %s, got %s", tt.message, msg.Message)
			}

			// Verify structured args if provided
			if tt.args != nil {
				if len(msg.Args) != len(tt.args) {
					t.Errorf("Expected %d args, got %d", len(tt.args), len(msg.Args))
				}

				for i, arg := range tt.args {
					if msg.Args[i] != arg {
						t.Errorf("Arg[%d]: expected %v, got %v", i, arg, msg.Args[i])
					}
				}
			}
		})
	}
}

// TestLogger_TestUtilities tests HasMessage() and Clear() functionality
// Covers: HasMessage(), Clear() methods for testing utilities
func TestLogger_TestUtilities(t *testing.T) {
	t.Run("HasMessage_MessageExistsAndMissing", func(t *testing.T) {
		// Setup: Create logger and log some messages
		logger := NewTestLogger()
		logger.Info("user login", "user_id", "12345")
		logger.Error("database connection failed")
		logger.Debug("cache hit", "key", "user:12345")

		// Test: HasMessage finds existing messages
		if !logger.HasMessage("INFO", "user login") {
			t.Error("Expected to find INFO message 'user login'")
		}

		if !logger.HasMessage("ERROR", "database connection failed") {
			t.Error("Expected to find ERROR message 'database connection failed'")
		}

		if !logger.HasMessage("DEBUG", "cache hit") {
			t.Error("Expected to find DEBUG message 'cache hit'")
		}

		// Test: HasMessage correctly identifies missing messages
		if logger.HasMessage("INFO", "nonexistent message") {
			t.Error("Expected NOT to find nonexistent message")
		}

		if logger.HasMessage("WARN", "user login") {
			t.Error("Expected NOT to find INFO message with WARN level")
		}

		if logger.HasMessage("INFO", "user logout") {
			t.Error("Expected NOT to find different message text")
		}
	})

	t.Run("Clear_RemovesAllMessages", func(t *testing.T) {
		// Setup: Create logger with multiple messages
		logger := NewTestLogger()
		logger.Info("message 1")
		logger.Warn("message 2")
		logger.Error("message 3")

		// Verify: Messages exist before clear
		if len(logger.Messages) != 3 {
			t.Fatalf("Expected 3 messages before clear, got %d", len(logger.Messages))
		}

		// Execute: Clear all messages
		logger.Clear()

		// Verify: All messages removed
		if len(logger.Messages) != 0 {
			t.Errorf("Expected 0 messages after clear, got %d", len(logger.Messages))
		}

		// Verify: HasMessage returns false after clear
		if logger.HasMessage("INFO", "message 1") {
			t.Error("Expected HasMessage to return false after clear")
		}
	})
}

// TestLogger_WithMethod tests the With() context chaining functionality
// Covers: With() method for creating contextual loggers
func TestLogger_WithMethod(t *testing.T) {
	t.Run("With_ReturnsNewLoggerInstance", func(t *testing.T) {
		// Setup: Create original logger with some messages
		originalLogger := NewTestLogger()
		originalLogger.Info("original message")

		// Execute: Create new logger with With()
		contextLogger := originalLogger.With("component", "auth", "request_id", "req-123")

		// Verify: With() returns new Logger interface instance
		if contextLogger == nil {
			t.Fatal("With() should return a Logger instance")
		}

		// Verify: Original logger remains unchanged
		if len(originalLogger.Messages) != 1 {
			t.Errorf("Expected original logger to have 1 message, got %d", len(originalLogger.Messages))
		}

		// Verify: New logger is separate instance (TestLogger specific behavior)
		contextTestLogger, ok := contextLogger.(*TestLogger)
		if !ok {
			t.Fatal("Expected With() to return *TestLogger for testing")
		}

		// Verify: New logger has copied messages (TestLogger implementation)
		if len(contextTestLogger.Messages) != 1 {
			t.Errorf("Expected context logger to have 1 copied message, got %d", len(contextTestLogger.Messages))
		}

		// Test: New logger can log independently
		contextLogger.Info("context message")

		// Verify: Context logger has additional message
		if len(contextTestLogger.Messages) != 2 {
			t.Errorf("Expected context logger to have 2 messages after logging, got %d", len(contextTestLogger.Messages))
		}

		// Verify: Original logger unchanged by context logger's logging
		if len(originalLogger.Messages) != 1 {
			t.Errorf("Expected original logger to remain at 1 message, got %d", len(originalLogger.Messages))
		}
	})

	t.Run("With_EmptyArgsHandledCorrectly", func(t *testing.T) {
		// Setup: Create logger
		logger := NewTestLogger()

		// Execute: Call With() with no args
		contextLogger := logger.With()

		// Verify: With() handles empty args gracefully
		if contextLogger == nil {
			t.Error("With() should handle empty args gracefully")
		}

		// Test: Context logger still functions normally
		contextLogger.Info("test message")

		contextTestLogger := contextLogger.(*TestLogger)
		if len(contextTestLogger.Messages) != 1 {
			t.Errorf("Expected 1 message in context logger, got %d", len(contextTestLogger.Messages))
		}
	})
}

// TestLogger_ContextIntegration tests context-based logger functions
// Covers: LoggerFromContext(), ContextWithLogger() for context propagation
func TestLogger_ContextIntegration(t *testing.T) {
	t.Run("ContextWithLogger_AndLoggerFromContext", func(t *testing.T) {
		// Setup: Create test logger and context
		testLogger := NewTestLogger()
		ctx := context.Background()

		// Execute: Add logger to context
		ctxWithLogger := ContextWithLogger(ctx, testLogger)

		// Verify: Context is different from original
		if ctxWithLogger == ctx {
			t.Error("ContextWithLogger should return new context")
		}

		// Execute: Extract logger from context
		extractedLogger := LoggerFromContext(ctxWithLogger)

		// Verify: Extracted logger is the same instance
		if extractedLogger != testLogger {
			t.Error("LoggerFromContext should return the same logger instance")
		}

		// Test: Use extracted logger for logging
		extractedLogger.Info("context propagated message")

		// Verify: Message was logged to original test logger
		if len(testLogger.Messages) != 1 {
			t.Errorf("Expected 1 message in original logger, got %d", len(testLogger.Messages))
		}

		if !testLogger.HasMessage("INFO", "context propagated message") {
			t.Error("Expected to find context propagated message")
		}
	})

	t.Run("LoggerFromContext_FallsBackToDefault", func(t *testing.T) {
		// Setup: Context without logger
		ctx := context.Background()

		// Execute: Extract logger from context without logger
		logger := LoggerFromContext(ctx)

		// Verify: Returns default logger (should be NoOpLogger)
		if logger == nil {
			t.Error("LoggerFromContext should never return nil")
		}

		// Verify: Logger is default logger (NoOpLogger)
		defaultLogger := DefaultLogger()

		// Both should be NoOpLogger instances (can't compare directly, test behavior)
		// Test that both behave as no-op loggers (no panics, graceful handling)
		logger.Info("test message")        // Should not panic
		defaultLogger.Info("test message") // Should not panic
	})

	t.Run("ContextWithLogger_NilLoggerHandledCorrectly", func(t *testing.T) {
		// Setup: Context and nil logger
		ctx := context.Background()

		// Execute: Add nil logger to context (should be handled gracefully)
		ctxWithLogger := ContextWithLogger(ctx, nil)

		// Execute: Extract logger from context
		extractedLogger := LoggerFromContext(ctxWithLogger)

		// Verify: Should get nil from context, but LoggerFromContext handles it
		if extractedLogger == nil {
			t.Error("LoggerFromContext should handle nil gracefully")
		}
	})
}

// TestLogger_FactoryAndNoOp tests factory functions and NoOpLogger behavior
// Covers: NewLogger(), DefaultLogger(), DiscardLogger(), NoOpLogger methods
func TestLogger_FactoryAndNoOp(t *testing.T) {
	t.Run("NewLogger_HandlesSupportedTypes", func(t *testing.T) {
		// Test: Logger interface type
		testLogger := NewTestLogger()
		logger1 := NewLogger(testLogger)
		if logger1 != testLogger {
			t.Error("NewLogger should return same instance for Logger interface")
		}

		// Test: Nil input returns NoOpLogger
		logger2 := NewLogger(nil)
		if logger2 == nil {
			t.Error("NewLogger should return NoOpLogger for nil input")
		}

		// Test: NoOpLogger methods don't panic
		logger2.Debug("test")
		logger2.Info("test")
		logger2.Warn("test")
		logger2.Error("test")

		contextLogger := logger2.With("key", "value")
		if contextLogger == nil {
			t.Error("NoOpLogger.With() should return non-nil logger")
		}
	})

	t.Run("DefaultLogger_ReturnsNoOpLogger", func(t *testing.T) {
		// Execute: Get default logger
		logger := DefaultLogger()

		// Verify: Returns non-nil logger
		if logger == nil {
			t.Error("DefaultLogger should return non-nil logger")
		}

		// Test: Default logger methods don't panic
		logger.Debug("debug message")
		logger.Info("info message")
		logger.Warn("warn message")
		logger.Error("error message")

		contextLogger := logger.With("component", "default")
		if contextLogger == nil {
			t.Error("DefaultLogger.With() should return non-nil logger")
		}
	})

	t.Run("DiscardLogger_ReturnsNoOpLogger", func(t *testing.T) {
		// Execute: Get discard logger
		logger := DiscardLogger()

		// Verify: Returns non-nil logger
		if logger == nil {
			t.Error("DiscardLogger should return non-nil logger")
		}

		// Test: Discard logger methods don't panic
		logger.Debug("debug message")
		logger.Info("info message")
		logger.Warn("warn message")
		logger.Error("error message")

		contextLogger := logger.With("component", "discard")
		if contextLogger == nil {
			t.Error("DiscardLogger.With() should return non-nil logger")
		}
	})
}

// TestLogger_ThreadSafety tests concurrent access to TestLogger
// Covers: Thread-safe message capture with concurrent goroutines
func TestLogger_ThreadSafety(t *testing.T) {
	t.Run("ConcurrentLogging_ThreadSafe", func(t *testing.T) {
		// Setup: Create logger for concurrent access
		logger := NewTestLogger()
		numGoroutines := 50
		messagesPerGoroutine := 20
		expectedTotalMessages := numGoroutines * messagesPerGoroutine

		var wg sync.WaitGroup

		// Execute: Concurrent logging from multiple goroutines
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()

				for j := 0; j < messagesPerGoroutine; j++ {
					// Mix different log levels
					switch j % 4 {
					case 0:
						logger.Debug("debug message", "goroutine", goroutineID, "iteration", j)
					case 1:
						logger.Info("info message", "goroutine", goroutineID, "iteration", j)
					case 2:
						logger.Warn("warn message", "goroutine", goroutineID, "iteration", j)
					case 3:
						logger.Error("error message", "goroutine", goroutineID, "iteration", j)
					}
				}
			}(i)
		}

		// Wait for all goroutines to complete
		wg.Wait()

		// Verify: All messages captured without data races
		if len(logger.Messages) != expectedTotalMessages {
			t.Errorf("Expected %d total messages, got %d", expectedTotalMessages, len(logger.Messages))
		}

		// Verify: Messages have expected levels (count each level)
		levelCounts := make(map[string]int)
		for _, msg := range logger.Messages {
			levelCounts[msg.Level]++
		}

		expectedPerLevel := expectedTotalMessages / 4
		if levelCounts["DEBUG"] != expectedPerLevel {
			t.Errorf("Expected %d DEBUG messages, got %d", expectedPerLevel, levelCounts["DEBUG"])
		}
		if levelCounts["INFO"] != expectedPerLevel {
			t.Errorf("Expected %d INFO messages, got %d", expectedPerLevel, levelCounts["INFO"])
		}
		if levelCounts["WARN"] != expectedPerLevel {
			t.Errorf("Expected %d WARN messages, got %d", expectedPerLevel, levelCounts["WARN"])
		}
		if levelCounts["ERROR"] != expectedPerLevel {
			t.Errorf("Expected %d ERROR messages, got %d", expectedPerLevel, levelCounts["ERROR"])
		}
	})
}

// TestLogger_UnsupportedTypesPanic tests NewLogger panic behavior
func TestLogger_UnsupportedTypesPanic(t *testing.T) {
	t.Run("NewLogger_PanicsOnUnsupportedType", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("NewLogger should panic for unsupported type")
			}

			expectedMsg := "unsupported logger type: expected Logger interface or nil"
			if r != expectedMsg {
				t.Errorf("Expected panic message '%s', got '%v'", expectedMsg, r)
			}
		}()

		// Should panic
		NewLogger("unsupported string type")
	})

	t.Run("NewLogger_PanicsOnIntType", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("NewLogger should panic for int type")
			}
		}()

		// Should panic
		NewLogger(42)
	})

	t.Run("NewLogger_PanicsOnStructType", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("NewLogger should panic for struct type")
			}
		}()

		// Should panic
		NewLogger(struct{ Name string }{Name: "test"})
	})
}

// TestNoOpLogger_Behavior tests NoOpLogger specific behavior
func TestNoOpLogger_Behavior(t *testing.T) {
	t.Run("NewNoOpLogger_Creation", func(t *testing.T) {
		logger := NewNoOpLogger()
		if logger == nil {
			t.Fatal("NewNoOpLogger() should not return nil")
		}
	})

	t.Run("NoOpLogger_AllMethods", func(t *testing.T) {
		logger := NewNoOpLogger()

		// Should not panic
		logger.Debug("debug message", "key", "value")
		logger.Info("info message", "key", "value")
		logger.Warn("warn message", "key", "value")
		logger.Error("error message", "key", "value")
	})

	t.Run("NoOpLogger_WithReturnsSelf", func(t *testing.T) {
		logger := NewNoOpLogger()
		withLogger := logger.With("key", "value")

		if withLogger != logger {
			t.Error("NoOpLogger.With() should return same instance")
		}
	})

	t.Run("NoOpLogger_WithEmptyArgs", func(t *testing.T) {
		logger := NewNoOpLogger()
		withLogger := logger.With()

		if withLogger != logger {
			t.Error("NoOpLogger.With() should return same instance for empty args")
		}
	})

	t.Run("NoOpLogger_WithMultipleCalls", func(t *testing.T) {
		logger := NewNoOpLogger()

		// Multiple With() calls should all return same instance
		with1 := logger.With("key1", "value1")
		with2 := with1.With("key2", "value2")
		with3 := with2.With("key3", "value3")

		if with1 != logger || with2 != logger || with3 != logger {
			t.Error("All NoOpLogger.With() calls should return same instance")
		}
	})
}

// TestTestLogger_EdgeCases tests TestLogger edge cases and error conditions
func TestTestLogger_EdgeCases(t *testing.T) {
	t.Run("TestLogger_EmptyMessages", func(t *testing.T) {
		logger := NewTestLogger()

		logger.Debug("")
		logger.Info("")
		logger.Warn("")
		logger.Error("")

		if len(logger.Messages) != 4 {
			t.Errorf("Expected 4 messages, got %d", len(logger.Messages))
		}

		for i, msg := range logger.Messages {
			if msg.Message != "" {
				t.Errorf("Message %d should be empty, got '%s'", i, msg.Message)
			}
		}
	})

	t.Run("TestLogger_NoArgs", func(t *testing.T) {
		logger := NewTestLogger()

		logger.Info("message without args")

		if len(logger.Messages) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(logger.Messages))
		}

		if len(logger.Messages[0].Args) != 0 {
			t.Errorf("Expected 0 args, got %d", len(logger.Messages[0].Args))
		}
	})

	t.Run("TestLogger_ManyArgs", func(t *testing.T) {
		logger := NewTestLogger()

		// Create 100 args
		args := make([]any, 200) // 100 key-value pairs
		for i := 0; i < 200; i += 2 {
			args[i] = "key" + string(rune('0'+i/2))
			args[i+1] = "value" + string(rune('0'+i/2))
		}

		logger.Info("message with many args", args...)

		if len(logger.Messages[0].Args) != 200 {
			t.Errorf("Expected 200 args, got %d", len(logger.Messages[0].Args))
		}
	})

	t.Run("TestLogger_NilArgs", func(t *testing.T) {
		logger := NewTestLogger()

		logger.Info("message with nil args", "key1", nil, "key2", nil)

		msg := logger.Messages[0]
		if len(msg.Args) != 4 {
			t.Errorf("Expected 4 args, got %d", len(msg.Args))
		}

		if msg.Args[1] != nil || msg.Args[3] != nil {
			t.Error("Expected nil values to be preserved")
		}
	})

	t.Run("TestLogger_MixedArgTypes", func(t *testing.T) {
		logger := NewTestLogger()

		logger.Info("mixed types", "string", "value", "int", 42, "bool", true, "float", 3.14)

		msg := logger.Messages[0]
		if len(msg.Args) != 8 {
			t.Errorf("Expected 8 args, got %d", len(msg.Args))
		}

		// Verify types are preserved
		if msg.Args[1] != "value" {
			t.Errorf("Expected string 'value', got %v", msg.Args[1])
		}
		if msg.Args[3] != 42 {
			t.Errorf("Expected int 42, got %v", msg.Args[3])
		}
		if msg.Args[5] != true {
			t.Errorf("Expected bool true, got %v", msg.Args[5])
		}
		if msg.Args[7] != 3.14 {
			t.Errorf("Expected float 3.14, got %v", msg.Args[7])
		}
	})
}

// TestLoggerProvider_EdgeCases tests LoggerProvider edge cases
func TestLoggerProvider_EdgeCases(t *testing.T) {
	t.Run("NewLogger_NilHandling", func(t *testing.T) {
		logger := NewLogger(nil)

		if logger == nil {
			t.Fatal("NewLogger(nil) should not return nil")
		}

		// Should behave like NoOpLogger
		logger.Debug("test")
		logger.Info("test")
		logger.Warn("test")
		logger.Error("test")

		withLogger := logger.With("key", "value")
		if withLogger == nil {
			t.Error("With() should not return nil")
		}
	})

	t.Run("NewLogger_AlreadyLoggerInterface", func(t *testing.T) {
		testLogger := NewTestLogger()
		result := NewLogger(testLogger)

		if result != testLogger {
			t.Error("NewLogger should return exact same instance for Logger interface")
		}

		// Verify it still works
		result.Info("test message")
		if !testLogger.HasMessage("INFO", "test message") {
			t.Error("Logger should still function after NewLogger processing")
		}
	})
}

// TestDefaultAndDiscardLoggers_Behavior tests default logger creation functions
func TestDefaultAndDiscardLoggers_Behavior(t *testing.T) {
	t.Run("DefaultLogger_BehavesLikeNoOp", func(t *testing.T) {
		logger := DefaultLogger()

		// Should not panic and should behave like NoOpLogger
		logger.Debug("test debug")
		logger.Info("test info")
		logger.Warn("test warn")
		logger.Error("test error")

		withLogger := logger.With("component", "test")
		if withLogger == nil {
			t.Error("DefaultLogger.With() should not return nil")
		}

		withLogger.Info("test with context")
	})

	t.Run("DiscardLogger_BehavesLikeNoOp", func(t *testing.T) {
		logger := DiscardLogger()

		// Should not panic and should behave like NoOpLogger
		logger.Debug("test debug")
		logger.Info("test info")
		logger.Warn("test warn")
		logger.Error("test error")

		withLogger := logger.With("component", "test")
		if withLogger == nil {
			t.Error("DiscardLogger.With() should not return nil")
		}

		withLogger.Info("test with context")
	})

	t.Run("DefaultAndDiscardAreDifferentInstances", func(t *testing.T) {
		default1 := DefaultLogger()
		default2 := DefaultLogger()
		discard1 := DiscardLogger()
		discard2 := DiscardLogger()

		// Each call should return a new instance
		if default1 == default2 {
			t.Error("DefaultLogger calls should return different instances")
		}

		if discard1 == discard2 {
			t.Error("DiscardLogger calls should return different instances")
		}

		if default1 == discard1 {
			t.Error("DefaultLogger and DiscardLogger should be different instances")
		}
	})
}

// TestContextIntegration_EdgeCases tests context integration edge cases
func TestContextIntegration_EdgeCases(t *testing.T) {
	t.Run("LoggerFromContext_EmptyContext", func(t *testing.T) {
		ctx := context.Background()
		logger := LoggerFromContext(ctx)

		if logger == nil {
			t.Fatal("LoggerFromContext should never return nil")
		}

		// Should work like default logger
		logger.Info("test message")
	})

	t.Run("ContextWithLogger_MultipleLoggers", func(t *testing.T) {
		ctx := context.Background()

		logger1 := NewTestLogger()
		ctx1 := ContextWithLogger(ctx, logger1)

		logger2 := NewTestLogger()
		ctx2 := ContextWithLogger(ctx1, logger2) // Override with new logger

		retrieved := LoggerFromContext(ctx2)

		// Should get the most recent logger (logger2)
		if retrieved != logger2 {
			t.Error("Should get most recently set logger from context")
		}

		// Test that it works
		retrieved.Info("context test")
		if !logger2.HasMessage("INFO", "context test") {
			t.Error("Retrieved logger should work correctly")
		}

		// Original logger should not have the message
		if logger1.HasMessage("INFO", "context test") {
			t.Error("Original logger should not receive message intended for new logger")
		}
	})

	t.Run("ContextWithLogger_NilLogger", func(t *testing.T) {
		ctx := context.Background()
		ctxWithNil := ContextWithLogger(ctx, nil)

		logger := LoggerFromContext(ctxWithNil)

		// Should fall back to default logger when nil is in context
		if logger == nil {
			t.Fatal("LoggerFromContext should fall back to default when context contains nil")
		}

		// Should work without panicking
		logger.Info("test with nil logger in context")
	})
}

// TestLoggerInterface_Compliance tests that all implementations correctly implement Logger interface
func TestLoggerInterface_Compliance(t *testing.T) {
	t.Run("NoOpLogger_ImplementsLogger", func(t *testing.T) {
		var logger Logger = NewNoOpLogger()

		// Compile-time check that NoOpLogger implements Logger
		logger.Debug("test")
		logger.Info("test")
		logger.Warn("test")
		logger.Error("test")
		_ = logger.With("key", "value")
	})

	t.Run("TestLogger_ImplementsLogger", func(t *testing.T) {
		var logger Logger = NewTestLogger()

		// Compile-time check that TestLogger implements Logger
		logger.Debug("test")
		logger.Info("test")
		logger.Warn("test")
		logger.Error("test")
		_ = logger.With("key", "value")
	})

	t.Run("Interface_PolymorphicUsage", func(t *testing.T) {
		loggers := []Logger{
			NewNoOpLogger(),
			NewTestLogger(),
		}

		for i, logger := range loggers {
			// All should work polymorphically
			logger.Debug("debug", "logger", i)
			logger.Info("info", "logger", i)
			logger.Warn("warn", "logger", i)
			logger.Error("error", "logger", i)

			withLogger := logger.With("context", "test")
			if withLogger == nil {
				t.Errorf("Logger %d With() returned nil", i)
			}
		}
	})
}
