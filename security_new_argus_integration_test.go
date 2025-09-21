// security_new_argus_integration_test.go: tests for NewSecurityArgusIntegration function
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"testing"
	"time"
)

// Test file per NewSecurityArgusIntegration function - constructor testing

func TestNewSecurityArgusIntegration_ValidInputs_ProperInitialization(t *testing.T) {
	// Test del constructor with valid inputs
	validator := setupBasicValidator()
	logger := &mockLogger{}

	// Build the integration
	integration := NewSecurityArgusIntegration(validator, logger)

	// Verify that the object was created correctly
	if integration == nil {
		t.Fatal("NewSecurityArgusIntegration returned nil")
	}

	// Verify that the basic fields were initialized
	if integration.validator != validator {
		t.Error("Validator not properly set")
	}

	if integration.logger == nil {
		t.Error("Logger not properly set")
	}

	// Verify that the context was created
	if integration.ctx == nil {
		t.Error("Context not initialized")
	}

	if integration.cancel == nil {
		t.Error("Cancel function not initialized")
	}

	// Verify that it is not running initially
	if integration.running {
		t.Error("Integration should not be running initially")
	}

	// Verify that the stats were initialized empty
	if integration.stats.WhitelistReloads != 0 {
		t.Error("Stats WhitelistReloads should be 0 initially")
	}

	// Cleanup
	if integration.cancel != nil {
		integration.cancel()
	}
}

func TestNewSecurityArgusIntegration_NilValidator_HandlesGracefully(t *testing.T) {
	// Test constructor with validator nil
	logger := &mockLogger{}

	// Create the integration with nil validator
	integration := NewSecurityArgusIntegration(nil, logger)

	// Verify that the object was created
	if integration == nil {
		t.Fatal("NewSecurityArgusIntegration returned nil with nil validator")
	}

	// Verify that validator is nil but other fields are ok
	if integration.validator != nil {
		t.Error("Expected validator to be nil")
	}

	if integration.logger == nil {
		t.Error("Logger not properly set")
	}

	// Context should be valid even with nil validator
	if integration.ctx == nil {
		t.Error("Context not initialized")
	}

	// Cleanup
	if integration.cancel != nil {
		integration.cancel()
	}
}

func TestNewSecurityArgusIntegration_NilLogger_HandlesGracefully(t *testing.T) {
	// Test constructor with logger nil
	validator := setupBasicValidator()

	// Create the integration with nil logger
	integration := NewSecurityArgusIntegration(validator, nil)

	// Verify that the object was created
	if integration == nil {
		t.Fatal("NewSecurityArgusIntegration returned nil with nil logger")
	}

	// Verify that logger is nil but other fields are ok
	if integration.validator != validator {
		t.Error("Validator not properly set")
	}

	if integration.logger != nil {
		t.Error("Expected logger to be nil")
	}

	// Context should be valid even with nil logger
	if integration.ctx == nil {
		t.Error("Context not initialized")
	}

	// Cleanup
	if integration.cancel != nil {
		integration.cancel()
	}
}

func TestNewSecurityArgusIntegration_BothNil_StillCreatesValidObject(t *testing.T) {
	// Test constructor with both nil - edge case
	integration := NewSecurityArgusIntegration(nil, nil)

	// Should still create a valid object
	if integration == nil {
		t.Fatal("NewSecurityArgusIntegration returned nil with both parameters nil")
	}

	// Verify that the nils were preserved
	if integration.validator != nil {
		t.Error("Expected validator to be nil")
	}

	if integration.logger != nil {
		t.Error("Expected logger to be nil")
	}

	// Context should be valid even with nil parameters
	if integration.ctx == nil {
		t.Error("Context not initialized even with nil parameters")
	}

	if integration.cancel == nil {
		t.Error("Cancel function not initialized")
	}

	// Verify that the context is cancellable
	select {
	case <-integration.ctx.Done():
		t.Error("Context is already cancelled")
	default:
		// Ok, context is not cancelled
	}

	// Test cancellation
	integration.cancel()

	// Now it should be cancelled
	select {
	case <-integration.ctx.Done():
		// Ok, context was cancelled
	case <-time.After(100 * time.Millisecond):
		t.Error("Context was not cancelled after calling cancel()")
	}
}

func TestNewSecurityArgusIntegration_ContextHierarchy_ProperSetup(t *testing.T) {
	// Test that the context is created correctly
	validator := setupBasicValidator()
	logger := &mockLogger{}

	integration := NewSecurityArgusIntegration(validator, logger)

	// Verify that the context is derived from background
	if integration.ctx == nil {
		t.Fatal("Context is nil")
	}

	// The context should be cancellable
	if integration.ctx.Err() != nil {
		t.Error("Context has error before cancellation")
	}

	// Test cancellation propagation
	done := make(chan bool)
	go func() {
		select {
		case <-integration.ctx.Done():
			done <- true
		case <-time.After(200 * time.Millisecond):
			done <- false
		}
	}()

	// Trigger cancellation
	time.Sleep(50 * time.Millisecond)
	integration.cancel()

	// Verify that cancellation was propagated
	cancelled := <-done
	if !cancelled {
		t.Error("Context cancellation was not propagated properly")
	}

	// Verify that the context has the correct error
	if integration.ctx.Err() != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", integration.ctx.Err())
	}
}

func TestNewSecurityArgusIntegration_MultipleInstances_IndependentContexts(t *testing.T) {
	// Test that multiple instances have independent contexts
	validator := setupBasicValidator()
	logger := &mockLogger{}

	integration1 := NewSecurityArgusIntegration(validator, logger)
	integration2 := NewSecurityArgusIntegration(validator, logger)

	// Verify that they have different contexts
	if integration1.ctx == integration2.ctx {
		t.Error("Multiple instances share the same context")
	}

	// Cancel only the first
	integration1.cancel()

	// The first should be cancelled
	select {
	case <-integration1.ctx.Done():
		// Ok
	case <-time.After(100 * time.Millisecond):
		t.Error("First context was not cancelled")
	}

	// The second should still be active
	select {
	case <-integration2.ctx.Done():
		t.Error("Second context was cancelled unexpectedly")
	case <-time.After(100 * time.Millisecond):
		// Ok, still active
	}

	// Cleanup
	integration2.cancel()
}

// Utility function to create a simple validator
func setupBasicValidator() *SecurityValidator {
	// Manually create a simple SecurityValidator for testing
	return &SecurityValidator{}
}

// Mock logger for testing
type mockLogger struct{}

func (ml *mockLogger) Info(msg string, args ...any)  {}
func (ml *mockLogger) Error(msg string, args ...any) {}
func (ml *mockLogger) Debug(msg string, args ...any) {}
func (ml *mockLogger) Warn(msg string, args ...any)  {}
func (ml *mockLogger) With(args ...any) Logger       { return ml }
