// types.go: Common data types and structures for the plugin system
//
// This file contains all shared data type definitions used throughout the plugin
// system. These types represent the common data models and enumerations that are
// used by plugins, managers, and other components. The separation of these types
// from the interface definitions improves code organization and maintainability.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"time"
)

// PluginStatus represents the current operational status of a plugin instance.
//
// Status levels indicate the plugin's ability to handle requests and its overall health:
//   - StatusUnknown: Initial state or status cannot be determined
//   - StatusHealthy: Plugin is fully operational and handling requests normally
//   - StatusDegraded: Plugin is operational but performance may be impacted
//   - StatusUnhealthy: Plugin has issues but may still handle some requests
//   - StatusOffline: Plugin is not responding and should not receive requests
//
// These statuses are used by circuit breakers and health monitoring systems
// to make routing and recovery decisions.
type PluginStatus int

const (
	StatusUnknown PluginStatus = iota
	StatusHealthy
	StatusDegraded
	StatusUnhealthy
	StatusOffline
)

// String returns a human-readable representation of the plugin status.
func (s PluginStatus) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusDegraded:
		return "degraded"
	case StatusUnhealthy:
		return "unhealthy"
	case StatusOffline:
		return "offline"
	default:
		return "unknown"
	}
}

// HealthStatus contains comprehensive health information about a plugin instance.
//
// This structure provides detailed health assessment data used by monitoring
// systems and circuit breakers to make intelligent routing and recovery
// decisions. It includes both current status and historical
// timing information for trend analysis.
//
// Fields:
//   - Status: Current operational status (healthy, degraded, unhealthy, offline)
//   - Message: Human-readable description of the current status
//   - LastCheck: Timestamp of when this status was determined
//   - ResponseTime: How long the health check took to complete
//   - Metadata: Additional context-specific information (error codes, version info, etc.)
//
// Example usage:
//
//	health := plugin.Health(ctx)
//	if health.Status != StatusHealthy {
//	    log.Printf("Plugin %s unhealthy: %s (response time: %v)",
//	        pluginName, health.Message, health.ResponseTime)
//	}
type HealthStatus struct {
	Status       PluginStatus      `json:"status"`
	Message      string            `json:"message,omitempty"`
	LastCheck    time.Time         `json:"last_check"`
	ResponseTime time.Duration     `json:"response_time"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// PluginInfo contains comprehensive metadata about a plugin instance.
//
// This structure provides essential information about a plugin's identity,
// capabilities, and characteristics. It's used for plugin discovery, version
// management, capability matching, and operational visibility.
//
// Fields:
//   - Name: Unique identifier for the plugin instance
//   - Version: Plugin version for compatibility and update management
//   - Description: Human-readable description of plugin functionality
//   - Author: Plugin developer/maintainer information
//   - Capabilities: List of features or operations the plugin supports
//   - Metadata: Additional key-value pairs for custom plugin information
//
// Example:
//
//	info := plugin.Info()
//	fmt.Printf("Plugin: %s v%s by %s\n", info.Name, info.Version, info.Author)
//	fmt.Printf("Capabilities: %v\n", info.Capabilities)
type PluginInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description,omitempty"`
	Author       string            `json:"author,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ExecutionContext provides execution context and configuration to plugins.
//
// This structure carries request-specific metadata and execution parameters
// that plugins can use to customize their behavior, implement tracing,
// handle timeouts, and manage retries. It ensures consistent context
// propagation across different plugin types and transports.
//
// Fields:
//   - RequestID: Unique identifier for request tracing and correlation
//   - Timeout: Maximum execution time for this specific request
//   - MaxRetries: Number of retry attempts allowed for this request
//   - Headers: Transport-specific headers (HTTP headers, gRPC metadata, etc.)
//   - Metadata: Additional context data (user info, feature flags, etc.)
//
// Example usage:
//
//	execCtx := ExecutionContext{
//	    RequestID:  "req-12345",
//	    Timeout:    30 * time.Second,
//	    MaxRetries: 3,
//	    Headers:    map[string]string{"Authorization": "Bearer token"},
//	    Metadata:   map[string]string{"user_id": "user123"},
//	}
//	response, err := plugin.Execute(ctx, execCtx, request)
type ExecutionContext struct {
	RequestID  string            `json:"request_id"`
	Timeout    time.Duration     `json:"timeout"`
	MaxRetries int               `json:"max_retries"`
	Headers    map[string]string `json:"headers,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}
