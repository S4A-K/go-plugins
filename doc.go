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
//   - Hot-reloading of plugin configurations
//   - Comprehensive metrics and structured logging
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
// Security:
// The library implements multiple security layers including mTLS for transport security,
// API key authentication, request validation, rate limiting, and comprehensive audit logging.
//
// Performance:
// Built-in connection pooling, intelligent caching, circuit breakers, and optimized
// serialization ensure high performance even under heavy load.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0
package goplugins
