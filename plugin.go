// plugin.go: Core plugin interfaces and types
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
)

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

// PluginManager manages a collection of plugins and provides circuit breaking
// and health monitoring
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
