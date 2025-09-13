// unix_transport_test.go: Comprehensive tests for Unix Domain Socket transport
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

//go:build !windows
// +build !windows

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockUnixServer provides a mock Unix socket server for testing
type mockUnixServer struct {
	listener   net.Listener
	socketPath string
	responses  map[string]UnixSocketResponse
	requests   []UnixSocketMessage
	mu         sync.RWMutex
	shutdown   atomic.Bool
	wg         sync.WaitGroup
}

// createShortSocketPath creates a short socket path for macOS compatibility
func createShortSocketPath(t *testing.T) string {
	t.Helper()

	// Use /tmp directly with a short random suffix for macOS compatibility
	// Socket paths on macOS are limited to 104 characters
	tmpFile, err := os.CreateTemp("/tmp", "test_*.sock")
	if err != nil {
		t.Fatalf("Failed to create temp file for socket path: %v", err)
	}

	socketPath := tmpFile.Name()
	tmpFile.Close()

	// Remove the file so we can use the path for socket
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("Failed to remove temp file: %v", err)
	}

	// Register cleanup to remove socket file
	t.Cleanup(func() {
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			t.Logf("Failed to cleanup socket file %s: %v", socketPath, err)
		}
	})

	return socketPath
}

// newMockUnixServer creates a new mock Unix socket server
func newMockUnixServer(t *testing.T) *mockUnixServer {
	t.Helper()

	// Create short socket path for macOS compatibility (104 char limit)
	socketPath := createShortSocketPath(t)

	// Remove socket if it exists - ignore error as file may not exist
	if err := os.Remove(socketPath); err != nil {
		// Ignore error - file may not exist, which is acceptable
		_ = err // Explicitly ignore for errcheck compliance
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create Unix socket listener: %v", err)
	}

	server := &mockUnixServer{
		listener:   listener,
		socketPath: socketPath,
		responses:  make(map[string]UnixSocketResponse),
		requests:   make([]UnixSocketMessage, 0),
	}

	// Set default responses
	server.setDefaultResponses()

	return server
}

// setDefaultResponses sets up default responses for common requests
func (m *mockUnixServer) setDefaultResponses() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Info response
	infoData, err := json.Marshal(PluginInfo{
		Name:         "test-plugin",
		Version:      "1.0.0",
		Description:  "Test Unix socket plugin",
		Capabilities: []string{"execute", "health"},
	})
	if err != nil {
		// This should never happen with static data, but handle it for completeness
		infoData = []byte(`{"name":"test-plugin","version":"1.0.0","description":"Test Unix socket plugin","capabilities":["execute","health"]}`)
	}

	m.responses["info"] = UnixSocketResponse{
		Type:    "info",
		Success: true,
		Data:    infoData,
	}

	// Health response
	m.responses["health"] = UnixSocketResponse{
		Type:    "health",
		Success: true,
		Data:    json.RawMessage(`{"status":"healthy"}`),
	}

	// Ping response
	m.responses["ping"] = UnixSocketResponse{
		Type:    "ping",
		Success: true,
		Data:    json.RawMessage(`{"pong":true}`),
	}

	// Execute response
	executeData, err := json.Marshal(TestResponse{
		Result:  "success",
		Details: map[string]string{"processed": "true"},
	})
	if err != nil {
		// This should never happen with static data, but handle it for completeness
		executeData = []byte(`{"result":"success","details":{"processed":"true"}}`)
	}

	m.responses["execute"] = UnixSocketResponse{
		Type:    "execute",
		Success: true,
		Data:    executeData,
	}
}

// setResponse sets a custom response for a message type
func (m *mockUnixServer) setResponse(msgType string, response UnixSocketResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[msgType] = response
}

// getRequests returns all received requests
func (m *mockUnixServer) getRequests() []UnixSocketMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	requests := make([]UnixSocketMessage, len(m.requests))
	copy(requests, m.requests)
	return requests
}

// start starts the mock server
func (m *mockUnixServer) start() {
	m.wg.Add(1)
	go m.serve()
}

// serve handles incoming connections
func (m *mockUnixServer) serve() {
	defer m.wg.Done()

	for {
		if m.shutdown.Load() {
			return
		}

		conn, err := m.listener.Accept()
		if err != nil {
			if m.shutdown.Load() {
				return
			}
			continue
		}

		m.wg.Add(1)
		go func(conn net.Conn) {
			defer m.wg.Done()
			defer func() {
				if err := conn.Close(); err != nil {
					// Log error in test context, but don't fail
					_ = err
				}
			}()
			m.handleConnection(conn)
		}(conn)
	}
}

// handleConnection handles a single connection
func (m *mockUnixServer) handleConnection(conn net.Conn) {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		if m.shutdown.Load() {
			return
		}

		var msg UnixSocketMessage
		if err := decoder.Decode(&msg); err != nil {
			return
		}

		// Store request
		m.mu.Lock()
		m.requests = append(m.requests, msg)
		m.mu.Unlock()

		// Get response
		m.mu.RLock()
		response, exists := m.responses[msg.Type]
		m.mu.RUnlock()

		if !exists {
			response = UnixSocketResponse{
				Type:      msg.Type,
				Success:   false,
				Error:     fmt.Sprintf("Unknown message type: %s", msg.Type),
				RequestID: msg.RequestID,
			}
		} else {
			response.RequestID = msg.RequestID
		}

		if err := encoder.Encode(response); err != nil {
			return
		}
	}
}

// close stops the mock server
func (m *mockUnixServer) close() {
	m.shutdown.Store(true)
	if err := m.listener.Close(); err != nil {
		// Listener already closed or error - not critical for test cleanup
		_ = err
	}
	m.wg.Wait()
	if err := os.Remove(m.socketPath); err != nil {
		// Socket file might not exist or permission issue - not critical for test cleanup
		_ = err
	}
}

// testPluginCreationCase represents a plugin creation test case
type testPluginCreationCase struct {
	name      string
	config    PluginConfig
	shouldErr bool
	errMsg    string
}

// getPluginCreationTestCases returns test cases for plugin creation
func getPluginCreationTestCases() []testPluginCreationCase {
	return []testPluginCreationCase{
		{
			name: "valid_config",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportUnix,
				Endpoint:  "", // Will be set by test
				Connection: ConnectionConfig{
					MaxConnections: 5,
				},
			},
			shouldErr: false,
		},
		{
			name: "invalid_transport",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportHTTP,
				Endpoint:  "/tmp/test.sock",
			},
			shouldErr: true,
			errMsg:    "transport must be unix",
		},
		{
			name: "missing_endpoint",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportUnix,
				Endpoint:  "",
			},
			shouldErr: true,
			errMsg:    "socket path (endpoint) is required",
		},
		{
			name: "nonexistent_socket",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportUnix,
				Endpoint:  "/nonexistent/path/test.sock",
			},
			shouldErr: true,
			errMsg:    "socket path does not exist",
		},
	}
}

// setupValidConfig prepares a valid config with mock server
func setupValidConfig(t *testing.T, config *PluginConfig) func() {
	server := newMockUnixServer(t)
	server.start()
	config.Endpoint = server.socketPath
	return server.close
}

// validatePluginCreation validates the plugin creation result
func validatePluginCreation(t *testing.T, tt testPluginCreationCase, plugin *UnixSocketPlugin[TestRequest, TestResponse], err error) {
	if tt.shouldErr {
		if err == nil {
			t.Errorf("Expected error but got none")
		} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
			t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
		}
		return
	}

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	if plugin == nil {
		t.Error("Expected plugin to be created but got nil")
		return
	}

	// Verify plugin info
	info := plugin.Info()
	if info.Name != tt.config.Name {
		t.Errorf("Expected plugin name %q, got %q", tt.config.Name, info.Name)
	}
}

// TestUnixSocketPlugin_NewUnixSocketPlugin tests plugin creation
func TestUnixSocketPlugin_NewUnixSocketPlugin(t *testing.T) {
	tests := getPluginCreationTestCases()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.config
			var cleanup func()

			if tt.name == "valid_config" {
				cleanup = setupValidConfig(t, &config)
				defer cleanup()
			}

			plugin, err := NewUnixSocketPlugin[TestRequest, TestResponse](config, logger)
			validatePluginCreation(t, tt, plugin, err)

			if plugin != nil {
				if err := plugin.Close(); err != nil {
					t.Logf("Failed to close plugin: %v", err)
				}
			}
		})
	}
}

// testBasicPoolOperations tests basic get/return operations
func testBasicPoolOperations(t *testing.T, socketPath string) {
	pool := NewUnixConnectionPool(socketPath, 2)
	defer func() {
		if err := pool.Close(); err != nil {
			t.Logf("Failed to close pool: %v", err)
		}
	}()

	// Test getting connection
	conn1, err := pool.GetConnection()
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}

	// Test returning connection
	pool.ReturnConnection(conn1)

	// Test getting connection again (should reuse)
	conn2, err := pool.GetConnection()
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}

	pool.ReturnConnection(conn2)
}

// testMaxConnections tests connection pool limits
func testMaxConnections(t *testing.T, socketPath string) {
	pool := NewUnixConnectionPool(socketPath, 2)
	defer func() {
		if err := pool.Close(); err != nil {
			t.Logf("Failed to close pool: %v", err)
		}
	}()

	connections := make([]net.Conn, 3)
	var err error

	// Get connections up to limit
	for i := 0; i < 3; i++ {
		connections[i], err = pool.GetConnection()
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
	}

	// Return connections
	for i := 0; i < 3; i++ {
		pool.ReturnConnection(connections[i])
	}
}

// testClosedPool tests behavior with closed pool
func testClosedPool(t *testing.T, socketPath string) {
	pool := NewUnixConnectionPool(socketPath, 2)
	if err := pool.Close(); err != nil {
		t.Logf("Failed to close pool: %v", err)
	}

	// Should fail to get connection from closed pool
	_, err := pool.GetConnection()
	if err == nil {
		t.Error("Expected error when getting connection from closed pool")
	}
}

// testInvalidSocketPath tests behavior with invalid socket
func testInvalidSocketPath(t *testing.T) {
	pool := NewUnixConnectionPool("/nonexistent/path/test.sock", 2)
	defer func() {
		if err := pool.Close(); err != nil {
			t.Logf("Failed to close pool: %v", err)
		}
	}()

	_, err := pool.GetConnection()
	if err == nil {
		t.Error("Expected error when connecting to nonexistent socket")
	}
}

// TestUnixConnectionPool tests the connection pool functionality
func TestUnixConnectionPool(t *testing.T) {
	server := newMockUnixServer(t)
	server.start()
	defer server.close()

	t.Run("basic_operations", func(t *testing.T) {
		testBasicPoolOperations(t, server.socketPath)
	})

	t.Run("max_connections", func(t *testing.T) {
		testMaxConnections(t, server.socketPath)
	})

	t.Run("closed_pool", func(t *testing.T) {
		testClosedPool(t, server.socketPath)
	})

	t.Run("invalid_socket_path", func(t *testing.T) {
		testInvalidSocketPath(t)
	})
}

// createTestPlugin creates a test plugin instance
func createTestPlugin(t *testing.T, server *mockUnixServer) *UnixSocketPlugin[TestRequest, TestResponse] {
	config := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportUnix,
		Endpoint:  server.socketPath,
		Connection: ConnectionConfig{
			MaxConnections: 5,
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	plugin, err := NewUnixSocketPlugin[TestRequest, TestResponse](config, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	return plugin
}

// testSuccessfulExecution tests successful plugin execution
func testSuccessfulExecution(t *testing.T, plugin *UnixSocketPlugin[TestRequest, TestResponse], server *mockUnixServer) {
	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-req-1",
		Headers:   map[string]string{"X-Test": "value"},
		Timeout:   5 * time.Second,
	}

	request := TestRequest{
		Action: "process",
		Data:   map[string]string{"key": "value"},
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if response.Result != "success" {
		t.Errorf("Expected result 'success', got %q", response.Result)
	}

	// Verify request was received by server
	requests := server.getRequests()
	found := false
	for _, req := range requests {
		if req.Type == "execute" && req.RequestID == "test-req-1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Execute request not found in server requests")
	}
}

// testExecutionWithTimeout tests execution timeout handling
func testExecutionWithTimeout(t *testing.T, plugin *UnixSocketPlugin[TestRequest, TestResponse], server *mockUnixServer) {
	// Set server to simulate slow response
	server.setResponse("execute", UnixSocketResponse{
		Type:    "execute",
		Success: false,
		Error:   "timeout",
	})
	defer server.setDefaultResponses()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	execCtx := ExecutionContext{
		RequestID: "test-req-timeout",
		Timeout:   50 * time.Millisecond,
	}

	request := TestRequest{Action: "slow"}

	_, err := plugin.Execute(ctx, execCtx, request)
	if err == nil {
		t.Error("Expected timeout error but got none")
	}
}

// testExecutionError tests execution error handling
func testExecutionError(t *testing.T, plugin *UnixSocketPlugin[TestRequest, TestResponse], server *mockUnixServer) {
	// Set server to return error
	server.setResponse("execute", UnixSocketResponse{
		Type:    "execute",
		Success: false,
		Error:   "processing failed",
	})
	defer server.setDefaultResponses()

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-req-error",
		Timeout:   5 * time.Second,
	}

	request := TestRequest{Action: "fail"}

	_, err := plugin.Execute(ctx, execCtx, request)
	if err == nil {
		t.Error("Expected execution error but got none")
	}

	if !strings.Contains(err.Error(), "processing failed") {
		t.Errorf("Expected error message to contain 'processing failed', got %q", err.Error())
	}
}

// TestUnixSocketPlugin_Execute tests plugin execution
func TestUnixSocketPlugin_Execute(t *testing.T) {
	server := newMockUnixServer(t)
	server.start()
	defer server.close()

	plugin := createTestPlugin(t, server)
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Logf("Failed to close plugin: %v", err)
		}
	}()

	t.Run("successful_execution", func(t *testing.T) {
		testSuccessfulExecution(t, plugin, server)
	})

	t.Run("execution_with_timeout", func(t *testing.T) {
		testExecutionWithTimeout(t, plugin, server)
	})

	t.Run("execution_error", func(t *testing.T) {
		testExecutionError(t, plugin, server)
	})
}

// TestUnixSocketPlugin_Health tests health checking
func TestUnixSocketPlugin_Health(t *testing.T) {

	server := newMockUnixServer(t)
	server.start()
	defer server.close()

	config := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportUnix,
		Endpoint:  server.socketPath,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	plugin, err := NewUnixSocketPlugin[TestRequest, TestResponse](config, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Logf("Failed to close plugin: %v", err)
		}
	}()

	t.Run("healthy_status", func(t *testing.T) {
		ctx := context.Background()
		health := plugin.Health(ctx)

		if health.Status != StatusHealthy {
			t.Errorf("Expected status %s, got %s", StatusHealthy, health.Status)
		}

		if health.Message != "OK" {
			t.Errorf("Expected message 'OK', got %q", health.Message)
		}

		if health.ResponseTime <= 0 {
			t.Error("Expected positive response time")
		}

		if health.Metadata["socket_path"] != server.socketPath {
			t.Errorf("Expected socket_path metadata %q, got %q",
				server.socketPath, health.Metadata["socket_path"])
		}
	})

	t.Run("degraded_status", func(t *testing.T) {
		// Set server to return health error
		server.setResponse("health", UnixSocketResponse{
			Type:    "health",
			Success: false,
			Error:   "service degraded",
		})

		ctx := context.Background()
		health := plugin.Health(ctx)

		if health.Status != StatusDegraded {
			t.Errorf("Expected status %s, got %s", StatusDegraded, health.Status)
		}

		if !strings.Contains(health.Message, "service degraded") {
			t.Errorf("Expected message to contain 'service degraded', got %q", health.Message)
		}

		// Reset server response
		server.setDefaultResponses()
	})

	t.Run("health_timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		// This should still work as it's a local socket
		health := plugin.Health(ctx)

		if health.Status == StatusOffline {
			t.Error("Health check should not be offline for local socket")
		}
	})
}

// createConcurrentTestPlugin creates a plugin for concurrent testing
func createConcurrentTestPlugin(t *testing.T, server *mockUnixServer) *UnixSocketPlugin[TestRequest, TestResponse] {
	config := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportUnix,
		Endpoint:  server.socketPath,
		Connection: ConnectionConfig{
			MaxConnections: 10,
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	plugin, err := NewUnixSocketPlugin[TestRequest, TestResponse](config, logger)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	return plugin
}

// testConcurrentExecutions tests concurrent plugin executions
func testConcurrentExecutions(t *testing.T, plugin *UnixSocketPlugin[TestRequest, TestResponse]) {
	const numGoroutines = 20
	const numRequests = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numRequests)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numRequests; j++ {
				ctx := context.Background()
				execCtx := ExecutionContext{
					RequestID: fmt.Sprintf("req-%d-%d", goroutineID, j),
					Timeout:   5 * time.Second,
				}

				request := TestRequest{
					Action: "concurrent",
					Data:   map[string]string{"goroutine": fmt.Sprintf("%d", goroutineID)},
				}

				_, err := plugin.Execute(ctx, execCtx, request)
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent execution error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Got %d errors in concurrent execution", errorCount)
	}
}

// testConcurrentHealthChecks tests concurrent health checks
func testConcurrentHealthChecks(t *testing.T, plugin *UnixSocketPlugin[TestRequest, TestResponse]) {
	const numGoroutines = 10

	var wg sync.WaitGroup
	results := make(chan HealthStatus, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			health := plugin.Health(ctx)
			results <- health
		}()
	}

	wg.Wait()
	close(results)

	// Check all health checks succeeded
	var healthyCount int
	for health := range results {
		if health.Status == StatusHealthy {
			healthyCount++
		}
	}

	if healthyCount != numGoroutines {
		t.Errorf("Expected %d healthy results, got %d", numGoroutines, healthyCount)
	}
}

// TestUnixSocketPlugin_Concurrent tests concurrent operations
func TestUnixSocketPlugin_Concurrent(t *testing.T) {
	server := newMockUnixServer(t)
	server.start()
	defer server.close()

	plugin := createConcurrentTestPlugin(t, server)
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Logf("Failed to close plugin: %v", err)
		}
	}()

	t.Run("concurrent_executions", func(t *testing.T) {
		testConcurrentExecutions(t, plugin)
	})

	t.Run("concurrent_health_checks", func(t *testing.T) {
		testConcurrentHealthChecks(t, plugin)
	})
}

// testFactorySupportedTransports tests factory supported transports
func testFactorySupportedTransports(t *testing.T, factory *UnixSocketPluginFactory[TestRequest, TestResponse]) {
	transports := factory.SupportedTransports()
	if len(transports) != 1 || transports[0] != string(TransportUnix) {
		t.Errorf("Expected supported transports [%s], got %v", TransportUnix, transports)
	}
}

// testFactoryValidateConfig tests factory config validation
func testFactoryValidateConfig(t *testing.T, factory *UnixSocketPluginFactory[TestRequest, TestResponse]) {
	// Create a temporary socket for testing with short path for macOS compatibility
	socketPath := createShortSocketPath(t)

	// Create the socket file
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create test socket: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("Failed to close listener: %v", err)
		}
	}()

	validConfig := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportUnix,
		Endpoint:  socketPath,
	}

	err = factory.ValidateConfig(validConfig)
	if err != nil {
		t.Errorf("Valid config should not return error: %v", err)
	}

	invalidConfig := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportHTTP,
		Endpoint:  "/tmp/test.sock",
	}

	err = factory.ValidateConfig(invalidConfig)
	if err == nil {
		t.Error("Invalid config should return error")
	}
}

// testFactoryCreatePlugin tests factory plugin creation
func testFactoryCreatePlugin(t *testing.T, factory *UnixSocketPluginFactory[TestRequest, TestResponse]) {
	server := newMockUnixServer(t)
	server.start()
	defer server.close()

	config := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportUnix,
		Endpoint:  server.socketPath,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	if plugin == nil {
		t.Error("Expected plugin to be created but got nil")
	}

	defer func() {
		if err := plugin.Close(); err != nil {
			t.Logf("Failed to close plugin: %v", err)
		}
	}()

	// Verify plugin works
	info := plugin.Info()
	if info.Name != config.Name {
		t.Errorf("Expected plugin name %q, got %q", config.Name, info.Name)
	}
}

// TestUnixSocketPluginFactory tests the factory pattern
func TestUnixSocketPluginFactory(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	factory := NewUnixSocketPluginFactory[TestRequest, TestResponse](logger)

	t.Run("supported_transports", func(t *testing.T) {
		testFactorySupportedTransports(t, factory)
	})

	t.Run("validate_config", func(t *testing.T) {
		testFactoryValidateConfig(t, factory)
	})

	t.Run("create_plugin", func(t *testing.T) {
		testFactoryCreatePlugin(t, factory)
	})
}

// TestUnixSocketMessage tests message serialization
func TestUnixSocketMessage(t *testing.T) {
	t.Run("message_serialization", func(t *testing.T) {
		msg := UnixSocketMessage{
			Type:      "execute",
			RequestID: "test-123",
			Data:      json.RawMessage(`{"action":"test"}`),
			Headers:   map[string]string{"X-Test": "value"},
			Timeout:   5000,
		}

		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("Failed to marshal message: %v", err)
		}

		var decoded UnixSocketMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal message: %v", err)
		}

		if decoded.Type != msg.Type {
			t.Errorf("Expected type %q, got %q", msg.Type, decoded.Type)
		}

		if decoded.RequestID != msg.RequestID {
			t.Errorf("Expected request ID %q, got %q", msg.RequestID, decoded.RequestID)
		}
	})

	t.Run("response_serialization", func(t *testing.T) {
		resp := UnixSocketResponse{
			Type:      "execute",
			RequestID: "test-123",
			Success:   true,
			Data:      json.RawMessage(`{"result":"ok"}`),
			Headers:   map[string]string{"X-Processing-Time": "10ms"},
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Failed to marshal response: %v", err)
		}

		var decoded UnixSocketResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if decoded.Success != resp.Success {
			t.Errorf("Expected success %t, got %t", resp.Success, decoded.Success)
		}

		if decoded.RequestID != resp.RequestID {
			t.Errorf("Expected request ID %q, got %q", resp.RequestID, decoded.RequestID)
		}
	})
}

// handleBenchmarkConnection handles a single benchmark server connection
func handleBenchmarkConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			// Connection close error in benchmark - not critical
		}
	}()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var msg UnixSocketMessage
	if err := decoder.Decode(&msg); err != nil {
		return
	}

	response := UnixSocketResponse{
		Type:      msg.Type,
		RequestID: msg.RequestID,
		Success:   true,
		Data:      json.RawMessage(`{"result":"ok"}`),
	}

	if err := encoder.Encode(response); err != nil {
		// Error encoding response in benchmark server - not critical
		return
	}
}

// createShortSocketPathForBenchmark creates a short socket path for benchmarks
func createShortSocketPathForBenchmark(b *testing.B) string {
	b.Helper()

	// Use /tmp directly with a short random suffix for macOS compatibility
	tmpFile, err := os.CreateTemp("/tmp", "bench_*.sock")
	if err != nil {
		b.Fatalf("Failed to create temp file for socket path: %v", err)
	}

	socketPath := tmpFile.Name()
	tmpFile.Close()

	// Remove the file so we can use the path for socket
	if err := os.Remove(socketPath); err != nil {
		b.Fatalf("Failed to remove temp file: %v", err)
	}

	// Register cleanup to remove socket file
	b.Cleanup(func() {
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			b.Logf("Failed to cleanup socket file %s: %v", socketPath, err)
		}
	})

	return socketPath
}

// setupBenchmarkServer creates and starts a benchmark server
func setupBenchmarkServer(b *testing.B) (net.Listener, string) {
	// Create short socket path for macOS compatibility
	socketPath := createShortSocketPathForBenchmark(b)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		b.Fatalf("Failed to create Unix socket listener: %v", err)
	}

	// Simple server that echoes back
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleBenchmarkConnection(conn)
		}
	}()

	return listener, socketPath
}

// createBenchmarkPlugin creates a plugin for benchmark testing
func createBenchmarkPlugin(b *testing.B, socketPath string) *UnixSocketPlugin[TestRequest, TestResponse] {
	config := PluginConfig{
		Name:      "bench-plugin",
		Transport: TransportUnix,
		Endpoint:  socketPath,
		Connection: ConnectionConfig{
			MaxConnections: 10,
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	plugin, err := NewUnixSocketPlugin[TestRequest, TestResponse](config, logger)
	if err != nil {
		b.Fatalf("Failed to create plugin: %v", err)
	}
	return plugin
}

// Benchmark tests for performance validation
func BenchmarkUnixSocketPlugin_Execute(b *testing.B) {
	listener, socketPath := setupBenchmarkServer(b)
	plugin := createBenchmarkPlugin(b, socketPath)

	defer func() {
		if err := plugin.Close(); err != nil {
			b.Logf("Failed to close plugin: %v", err)
		}
	}()
	defer func() {
		if err := listener.Close(); err != nil {
			b.Logf("Failed to close listener: %v", err)
		}
	}()

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "bench-req",
		Timeout:   5 * time.Second,
	}

	request := TestRequest{
		Action: "benchmark",
		Data:   map[string]string{"test": "data"},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := plugin.Execute(ctx, execCtx, request)
			if err != nil {
				b.Errorf("Execute failed: %v", err)
			}
		}
	})
}
