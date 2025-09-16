// Package goplugins provides a production-ready, type-safe plugin architecture
// for Go applications. It supports multiple transport protocols (HTTP, gRPC, Unix sockets)
// with built-in circuit breaking, health monitoring, authentication, and graceful degradation.
//
// Key Features:
//   - Type-safe plugin interfaces using Go generics
//   - Multiple transport protocols (HTTP, gRPC, Unix sockets)
//   - Circuit breaker pattern for resilience
//   - Health monitoring and automatic recovery
//   - Authentication and authorization
//   - Hot-reloading of plugin configurations with active request monitoring
//   - Production-grade graceful draining (no more time.Sleep!)
//   - Pluggable logging system supporting any framework
//   - Comprehensive observability with metrics exporters
//   - Graceful shutdown with proper cleanup
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
//	// Create a plugin manager
//	manager := goplugins.NewManager[KeyRequest, KeyResponse]()
//
//	// Load plugins from configuration
//	err := manager.LoadFromConfig("plugins.yaml")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Execute plugin operations
//	resp, err := manager.Execute(ctx, "vault-provider", KeyRequest{KeyID: "master"})
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
// Security:
// The library implements multiple security layers including mTLS for transport security,
// API key authentication, request validation, rate limiting, and comprehensive audit logging.
//
// Performance:
// Built-in connection pooling, intelligent caching, circuit breakers, optimized
// serialization, and atomic request tracking ensure high performance even under heavy load.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0
package goplugins
