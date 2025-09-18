// types_test.go: Tests for common data types
//
// This file contains unit tests for the data types defined in types.go,
// ensuring that the type definitions work correctly after the refactoring
// from plugin.go to types.go.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPluginStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   PluginStatus
		expected string
	}{
		{
			name:     "StatusHealthy",
			status:   StatusHealthy,
			expected: "healthy",
		},
		{
			name:     "StatusDegraded",
			status:   StatusDegraded,
			expected: "degraded",
		},
		{
			name:     "StatusUnhealthy",
			status:   StatusUnhealthy,
			expected: "unhealthy",
		},
		{
			name:     "StatusOffline",
			status:   StatusOffline,
			expected: "offline",
		},
		{
			name:     "StatusUnknown",
			status:   StatusUnknown,
			expected: "unknown",
		},
		{
			name:     "InvalidStatus",
			status:   PluginStatus(999),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.status.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHealthStatus_Creation(t *testing.T) {
	now := time.Now()
	responseTime := 100 * time.Millisecond

	health := HealthStatus{
		Status:       StatusHealthy,
		Message:      "Plugin is working correctly",
		LastCheck:    now,
		ResponseTime: responseTime,
		Metadata: map[string]string{
			"version":     "1.0.0",
			"plugin_type": "test",
		},
	}

	assert.Equal(t, StatusHealthy, health.Status)
	assert.Equal(t, "Plugin is working correctly", health.Message)
	assert.Equal(t, now, health.LastCheck)
	assert.Equal(t, responseTime, health.ResponseTime)
	assert.Equal(t, "1.0.0", health.Metadata["version"])
	assert.Equal(t, "test", health.Metadata["plugin_type"])
}

func TestPluginInfo_Creation(t *testing.T) {
	info := PluginInfo{
		Name:        "test-plugin",
		Version:     "2.1.0",
		Description: "A test plugin for demonstration",
		Author:      "Test Developer",
		Capabilities: []string{
			"process_data",
			"health_check",
			"metrics",
		},
		Metadata: map[string]string{
			"runtime":     "go",
			"environment": "test",
		},
	}

	assert.Equal(t, "test-plugin", info.Name)
	assert.Equal(t, "2.1.0", info.Version)
	assert.Equal(t, "A test plugin for demonstration", info.Description)
	assert.Equal(t, "Test Developer", info.Author)
	assert.Contains(t, info.Capabilities, "process_data")
	assert.Contains(t, info.Capabilities, "health_check")
	assert.Contains(t, info.Capabilities, "metrics")
	assert.Equal(t, "go", info.Metadata["runtime"])
	assert.Equal(t, "test", info.Metadata["environment"])
}

func TestExecutionContext_Creation(t *testing.T) {
	timeout := 30 * time.Second

	execCtx := ExecutionContext{
		RequestID:  "req-abc123",
		Timeout:    timeout,
		MaxRetries: 3,
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"Content-Type":  "application/json",
		},
		Metadata: map[string]string{
			"user_id":    "user456",
			"session_id": "session789",
		},
	}

	assert.Equal(t, "req-abc123", execCtx.RequestID)
	assert.Equal(t, timeout, execCtx.Timeout)
	assert.Equal(t, 3, execCtx.MaxRetries)
	assert.Equal(t, "Bearer token123", execCtx.Headers["Authorization"])
	assert.Equal(t, "application/json", execCtx.Headers["Content-Type"])
	assert.Equal(t, "user456", execCtx.Metadata["user_id"])
	assert.Equal(t, "session789", execCtx.Metadata["session_id"])
}

func TestTypesCompatibilityAfterRefactoring(t *testing.T) {
	// This test ensures that all types are properly accessible after refactoring
	// and that the types can be used together as before

	// Create a health status
	health := HealthStatus{
		Status:       StatusHealthy,
		Message:      "All systems operational",
		LastCheck:    time.Now(),
		ResponseTime: 50 * time.Millisecond,
	}

	// Create plugin info
	info := PluginInfo{
		Name:         "refactored-test-plugin",
		Version:      "1.0.0",
		Description:  "Testing refactored types",
		Capabilities: []string{"test"},
	}

	// Create execution context
	execCtx := ExecutionContext{
		RequestID:  "test-refactor-001",
		Timeout:    10 * time.Second,
		MaxRetries: 2,
	}

	// Verify all types work together
	assert.NotNil(t, health)
	assert.NotNil(t, info)
	assert.NotNil(t, execCtx)

	// Verify status enums work
	assert.Equal(t, "healthy", StatusHealthy.String())
	assert.Equal(t, "degraded", StatusDegraded.String())
	assert.Equal(t, "unhealthy", StatusUnhealthy.String())
	assert.Equal(t, "offline", StatusOffline.String())
	assert.Equal(t, "unknown", StatusUnknown.String())

	// Verify they can be used in composite structures (like before)
	testData := struct {
		Health HealthStatus
		Info   PluginInfo
		Ctx    ExecutionContext
	}{
		Health: health,
		Info:   info,
		Ctx:    execCtx,
	}

	assert.Equal(t, StatusHealthy, testData.Health.Status)
	assert.Equal(t, "refactored-test-plugin", testData.Info.Name)
	assert.Equal(t, "test-refactor-001", testData.Ctx.RequestID)
}

// BenchmarkPluginStatus_String benchmarks the String method performance
func BenchmarkPluginStatus_String(b *testing.B) {
	status := StatusHealthy

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = status.String()
	}
}

// TestPluginStatus_Constants verifies that status constants have expected values
func TestPluginStatus_Constants(t *testing.T) {
	assert.Equal(t, PluginStatus(0), StatusUnknown)
	assert.Equal(t, PluginStatus(1), StatusHealthy)
	assert.Equal(t, PluginStatus(2), StatusDegraded)
	assert.Equal(t, PluginStatus(3), StatusUnhealthy)
	assert.Equal(t, PluginStatus(4), StatusOffline)
}

// Example demonstrates how to use the refactored types
func ExamplePluginStatus() {
	// Create and use a plugin status
	status := StatusHealthy
	_ = status.String() // Just verify it works

	// Create a health status using the types
	health := HealthStatus{
		Status:       StatusHealthy,
		Message:      "Plugin operational",
		LastCheck:    time.Now(),
		ResponseTime: 10 * time.Millisecond,
	}

	if health.Status == StatusHealthy {
		// Use the fields to avoid unused write warnings
		_ = health.Message
		_ = health.LastCheck
		_ = health.ResponseTime
	}

	// Output:
}
