// plugin.go: Core plugin interfaces and types
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
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
// These statuses are used by load balancers, circuit breakers, and health
// monitoring systems to make routing and recovery decisions.
type PluginStatus int

const (
	StatusUnknown PluginStatus = iota
	StatusHealthy
	StatusDegraded
	StatusUnhealthy
	StatusOffline
)

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
// systems, load balancers, and circuit breakers to make intelligent routing
// and recovery decisions. It includes both current status and historical
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

// ExecutionContext provides execution context and configuration to plugins
type ExecutionContext struct {
	RequestID  string            `json:"request_id"`
	Timeout    time.Duration     `json:"timeout"`
	MaxRetries int               `json:"max_retries"`
	Headers    map[string]string `json:"headers,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Plugin represents a generic plugin that can process requests of type Req and return responses of type Resp
// This interface is designed to be transport-agnostic and production-ready
type Plugin[Req, Resp any] interface {
	// Info returns metadata about the plugin
	Info() PluginInfo

	// Execute processes a request and returns a response
	// Context should be honored for timeouts and cancellation
	Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error)

	// Health performs a health check and returns detailed status
	Health(ctx context.Context) HealthStatus

	// Close gracefully shuts down the plugin and cleans up resources
	// Should be idempotent (safe to call multiple times)
	Close() error
}

// PluginManager manages a collection of plugins and provides load balancing,
// circuit breaking, and health monitoring
type PluginManager[Req, Resp any] interface {
	// Register adds a plugin to the manager
	Register(plugin Plugin[Req, Resp]) error

	// Unregister removes a plugin from the manager
	Unregister(name string) error

	// Execute routes a request to the appropriate plugin
	// Includes automatic retries, circuit breaking, and fallback handling
	Execute(ctx context.Context, pluginName string, request Req) (Resp, error)

	// ExecuteWithOptions executes with custom execution context
	ExecuteWithOptions(ctx context.Context, pluginName string, execCtx ExecutionContext, request Req) (Resp, error)

	// GetPlugin returns a specific plugin by name
	GetPlugin(name string) (Plugin[Req, Resp], error)

	// ListPlugins returns all registered plugin names and their health status
	ListPlugins() map[string]HealthStatus

	// LoadFromConfig loads plugins from a configuration file or object
	LoadFromConfig(config ManagerConfig) error

	// ReloadConfig hot-reloads configuration without stopping the manager
	ReloadConfig(config ManagerConfig) error

	// Health returns the overall health of all plugins
	Health() map[string]HealthStatus

	// Shutdown gracefully shuts down all plugins and cleans up resources
	Shutdown(ctx context.Context) error
}

// PluginFactory creates new plugin instances from configuration
type PluginFactory[Req, Resp any] interface {
	// CreatePlugin creates a new plugin instance from the given configuration
	CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error)

	// SupportedTransports returns the list of supported transport protocols
	SupportedTransports() []string

	// ValidateConfig validates a plugin configuration without creating the plugin
	ValidateConfig(config PluginConfig) error
}
