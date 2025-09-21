// Package goplugins provides a production-ready, type-safe plugin architecture
// for Go applications. It supports gRPC and subprocess transport protocols
// with built-in circuit breaking, health monitoring, authentication, and graceful degradation.
//
// Key Features:
//   - Type-safe plugin interfaces using Go generics
//   - Multiple transport protocols (gRPC, subprocess execution)
//   - Circuit breaker pattern for resilience
//   - Health monitoring and automatic recovery
//   - Authentication and authorization (API key, Bearer, mTLS, Basic, Custom)
//   - Advanced security system with plugin whitelisting and hash validation
//   - Hot-reloading of plugin configurations with active request monitoring
//   - Production-grade graceful draining with atomic request tracking
//   - Pluggable logging system supporting any framework
//   - Comprehensive observability with metrics exporters and distributed tracing
//   - Zero-downtime deployments and graceful shutdown
//   - Simple API with fluent builder pattern for common use cases
//
// Basic Usage:
//
//	// Define your plugin request/response types
//	type KeyRequest struct {
//		KeyID string `json:"key_id"`
//	}
//
//	type KeyResponse struct {
//		Key   []byte `json:"key"`
//		Error string `json:"error,omitempty"`
//	}
//
//	// Simple API - Recommended for most use cases
//	manager, err := goplugins.Production[KeyRequest, KeyResponse]().
//		WithPlugin("vault-provider", goplugins.Subprocess("./vault-plugin")).
//		WithSecurity("./plugins.whitelist").
//		WithMetrics().
//		Build()
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer manager.Shutdown(context.Background())
//
//	// Execute plugin operations
//	resp, err := manager.Execute(ctx, "vault-provider", KeyRequest{KeyID: "master"})
//
//	// Advanced API - For complex configurations
//	manager := goplugins.NewManager[KeyRequest, KeyResponse](logger)
//	config := goplugins.GetDefaultManagerConfig()
//	config.Plugins = []goplugins.PluginConfig{
//		{
//			Name:      "vault-provider",
//			Transport: goplugins.TransportExecutable,
//			Executable: "./vault-plugin",
//			Auth:      goplugins.AuthConfig{Method: goplugins.AuthAPIKey, APIKey: "secret"},
//		},
//	}
//	err = manager.LoadFromConfig(config)
//
// Active Request Monitoring:
// The library includes a sophisticated request tracking system that enables true zero-downtime
// deployments by monitoring active requests in real-time:
//
//   - Atomic request counters for lock-free performance (~50ns per operation)
//   - Context-based request tracking for selective cancellation
//   - Intelligent drain detection with 10ms precision (replaces time.Sleep)
//   - Configurable drain timeouts with fallback to force cancellation
//   - Real-time progress callbacks for operational visibility
//
// This eliminates the need for fixed timeout delays and provides precise control over
// graceful operations during hot reloads, plugin updates, and system shutdowns.
//
// Security System:
// The library implements a comprehensive security system with multiple layers:
//
//   - Plugin Whitelisting: SHA256 hash validation of plugin binaries
//   - Security Policies: Strict, Permissive, and Audit modes
//   - Authentication: mTLS, API key, Bearer token, Basic, and Custom methods
//   - Audit Logging: Comprehensive security event logging with rotation
//   - Path Traversal Protection: Prevents malicious path manipulation
//   - Hot-reload: Security configuration updates without restart
//   - Process Isolation: Subprocess plugins run in isolated processes
//
// Performance:
// Built-in connection pooling, intelligent caching, circuit breakers, optimized
// serialization, and atomic request tracking ensure high performance even under heavy load.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0
package goplugins
