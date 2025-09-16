// logging.go: Pluggable logging system with automatic adapter detection
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"sync"
)

// loggerContextKey is a custom type for context keys to avoid collisions
type loggerContextKey string

const (
	// Context keys for logger storage
	loggerKey loggerContextKey = "logger"
)

// Logger defines the pluggable logging interface for the go-plugins library.
//
// This interface enables users to integrate any logging framework (zap, logrus,
// zerolog, custom loggers) without external dependencies. Users must provide
// their own Logger implementation.
//
// Design principles:
//   - Zero dependencies: Interface has no external logging dependencies
//   - Performance friendly: Supports structured logging with minimal allocations
//   - Contextual logging: With() method for adding persistent context
//   - Level-based: Standard log levels (Debug, Info, Warn, Error)
//   - Structured args: Key-value pairs for structured logging
//
// Example implementations:
//   - ZapAdapter: Wraps *zap.Logger
//   - LogrusAdapter: Wraps *logrus.Logger
//   - NoOpLogger: Silent logger for testing
//
// Example usage:
//
//	// Interface-based logger
//	zapLogger := NewZapAdapter(zap.NewDevelopment())
//	manager := NewManager[Req, Resp](zapLogger)
//
//	// Custom logger implementation
//	customLogger := &MyCustomLogger{}
//	manager := NewManager[Req, Resp](customLogger)
type Logger interface {
	// Debug logs a debug message with optional key-value pairs
	Debug(msg string, args ...any)

	// Info logs an info message with optional key-value pairs
	Info(msg string, args ...any)

	// Warn logs a warning message with optional key-value pairs
	Warn(msg string, args ...any)

	// Error logs an error message with optional key-value pairs
	Error(msg string, args ...any)

	// With returns a new logger with persistent context key-value pairs
	// The returned logger should include all provided context in subsequent log calls
	With(args ...any) Logger
}

// LoggerProvider creates Logger instances from various input types.
//
// This is the core of the intelligent logging system that automatically
// detects and adapts different logger types without breaking existing code.
// It enables gradual migration from concrete types to interfaces.
type LoggerProvider struct{}

// NewLogger creates a Logger from supported logger types.
//
// Supported types:
//   - Logger interface: Used directly
//   - nil: Returns NoOpLogger for silent operation
//   - Unsupported types: Panic with descriptive message
func NewLogger(logger any) Logger {
	switch l := logger.(type) {
	case Logger:
		return l // Already implements our interface
	case nil:
		return NewNoOpLogger() // Silent logger
	default:
		panic("unsupported logger type: expected Logger interface or nil")
	}
}

// NoOpLogger provides a silent logger implementation for testing and minimal setups.
//
// This logger discards all log messages and is useful for:
//   - Testing environments where log output is not desired
//   - Production setups that use external logging systems
//   - Minimal overhead scenarios where logging is disabled
type NoOpLogger struct{}

// NewNoOpLogger creates a new no-operation logger.
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

// Debug implements Logger interface (no-op)
func (n *NoOpLogger) Debug(msg string, args ...any) {}

// Info implements Logger interface (no-op)
func (n *NoOpLogger) Info(msg string, args ...any) {}

// Warn implements Logger interface (no-op)
func (n *NoOpLogger) Warn(msg string, args ...any) {}

// Error implements Logger interface (no-op)
func (n *NoOpLogger) Error(msg string, args ...any) {}

// With implements Logger interface (no-op)
func (n *NoOpLogger) With(args ...any) Logger {
	return n // Return same instance since it's stateless
}

// TestLogger for testing - captures log messages
type TestLogger struct {
	mu       sync.RWMutex     `json:"-"`
	Messages []TestLogMessage `json:"messages"`
}

// TestLogMessage represents a captured log message for testing.
type TestLogMessage struct {
	Level   string
	Message string
	Args    []any
}

// NewTestLogger creates a new test logger.
func NewTestLogger() *TestLogger {
	return &TestLogger{
		Messages: make([]TestLogMessage, 0),
	}
}

// Debug implements Logger interface (captures message)
func (t *TestLogger) Debug(msg string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Messages = append(t.Messages, TestLogMessage{
		Level:   "DEBUG",
		Message: msg,
		Args:    args,
	})
}

// Info implements Logger interface (captures message)
func (t *TestLogger) Info(msg string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Messages = append(t.Messages, TestLogMessage{
		Level:   "INFO",
		Message: msg,
		Args:    args,
	})
}

// Warn implements Logger interface (captures message)
func (t *TestLogger) Warn(msg string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Messages = append(t.Messages, TestLogMessage{
		Level:   "WARN",
		Message: msg,
		Args:    args,
	})
}

// Error implements Logger interface (captures message)
func (t *TestLogger) Error(msg string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Messages = append(t.Messages, TestLogMessage{
		Level:   "ERROR",
		Message: msg,
		Args:    args,
	})
}

// With implements Logger interface (returns new logger with fields)
func (t *TestLogger) With(args ...any) Logger {
	// For testing, we don't need to implement context chaining
	// Return a new instance to avoid sharing state
	t.mu.RLock()
	messages := make([]TestLogMessage, len(t.Messages))
	copy(messages, t.Messages)
	t.mu.RUnlock()

	return &TestLogger{Messages: messages}
}

// HasMessage checks if the logger captured a message containing the given text.
func (t *TestLogger) HasMessage(level, message string) bool {
	for _, msg := range t.Messages {
		if msg.Level == level && msg.Message == message {
			return true
		}
	}
	return false
}

// Clear removes all captured messages.
func (t *TestLogger) Clear() {
	t.Messages = t.Messages[:0]
}

// DefaultLogger creates a reasonable default logger for the library.
//
// Returns NoOpLogger since we removed slog dependency.
// Users should provide their own Logger implementation.
func DefaultLogger() Logger {
	return NewNoOpLogger()
}

// DiscardLogger creates a logger that discards all output.
//
// Same as DefaultLogger - returns NoOpLogger.
func DiscardLogger() Logger {
	return NewNoOpLogger()
}

// LoggerFromContext extracts a logger from context if available.
//
// This function enables context-based logger propagation through
// the application stack. Falls back to DefaultLogger if no logger
// is found in the context.
func LoggerFromContext(ctx context.Context) Logger {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger
	}

	return DefaultLogger()
}

// ContextWithLogger adds a logger to the context.
func ContextWithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}
