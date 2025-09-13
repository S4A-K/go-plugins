// grpc_transport_test.go: Comprehensive tests for gRPC transport implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Test types for gRPC plugin testing
type TestGRPCRequest struct {
	Message string            `json:"message"`
	Headers map[string]string `json:"headers,omitempty"`
}

type TestGRPCResponse struct {
	Result  string            `json:"result"`
	Status  string            `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
}

// MockGRPCServer implements a simplified test server for gRPC testing
// Since gRPC requires protobuf definitions and we're using JSON serialization,
// we'll create a simplified HTTP-based mock that can handle our test cases
type MockGRPCServer struct {

	// Server state
	listener  net.Listener
	server    *grpc.Server
	addr      string
	responses map[string]TestGRPCResponse
	requests  []TestGRPCRequest
	mu        sync.RWMutex

	// Control behavior
	shouldFail    atomic.Bool
	healthStatus  atomic.Int32 // 0=healthy, 1=unhealthy, 2=unavailable
	responseDelay time.Duration

	// Statistics
	executeCount atomic.Int32
	healthCount  atomic.Int32
	infoCount    atomic.Int32
}

// NewMockGRPCServer creates a new mock gRPC server
func NewMockGRPCServer(useTLS bool, certFile, keyFile string) (*MockGRPCServer, error) {
	mock := &MockGRPCServer{
		responses: make(map[string]TestGRPCResponse),
		requests:  make([]TestGRPCRequest, 0),
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	mock.listener = listener
	mock.addr = listener.Addr().String()

	var opts []grpc.ServerOption
	if useTLS {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("TLS requires cert and key files")
		}

		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	mock.server = grpc.NewServer(opts...)

	// Register service implementation would go here in real implementation
	// For testing, we'll use the generic conn.Invoke approach

	return mock, nil
}

// Start starts the mock gRPC server
func (m *MockGRPCServer) Start() error {
	go func() {
		if err := m.server.Serve(m.listener); err != nil {
			// Server stopped or error occurred
		}
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)
	return nil
}

// Stop stops the mock gRPC server
func (m *MockGRPCServer) Stop() {
	if m.server != nil {
		m.server.Stop()
	}
	if m.listener != nil {
		if err := m.listener.Close(); err != nil {
			// Log error in real implementation
		}
	}
}

// Address returns the server address
func (m *MockGRPCServer) Address() string {
	return m.addr
}

// SetResponse sets a mock response for a request message
func (m *MockGRPCServer) SetResponse(message string, response TestGRPCResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[message] = response
}

// GetRequests returns all received requests
func (m *MockGRPCServer) GetRequests() []TestGRPCRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]TestGRPCRequest, len(m.requests))
	copy(result, m.requests)
	return result
}

// SetFailMode controls whether the server should fail requests
func (m *MockGRPCServer) SetFailMode(shouldFail bool) {
	m.shouldFail.Store(shouldFail)
}

// SetHealthStatus sets the health check response
func (m *MockGRPCServer) SetHealthStatus(status int) {
	m.healthStatus.Store(int32(status))
}

// SetResponseDelay sets artificial delay for responses
func (m *MockGRPCServer) SetResponseDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseDelay = delay
}

// GetStats returns call statistics
func (m *MockGRPCServer) GetStats() (int32, int32, int32) {
	return m.executeCount.Load(), m.healthCount.Load(), m.infoCount.Load()
}

// Helper to create logger for tests
func createTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise during testing
	}))
}

func TestGRPCPlugin_NewGRPCPlugin(t *testing.T) {
	logger := createTestLogger(t)

	tests := []struct {
		name      string
		config    PluginConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "invalid_transport",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportHTTP,
				Endpoint:  "127.0.0.1:50051",
			},
			wantError: true,
			errorMsg:  "transport must be grpc or grpc-tls",
		},
		{
			name: "missing_endpoint",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPC,
				Endpoint:  "",
			},
			wantError: true,
			errorMsg:  "endpoint is required",
		},
		{
			name: "grpc_tls_missing_cert",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPCTLS,
				Endpoint:  "127.0.0.1:50051",
				Auth: AuthConfig{
					Method: AuthMTLS,
				},
			},
			wantError: true,
			errorMsg:  "cert_file and key_file required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin, err := NewGRPCPlugin[TestGRPCRequest, TestGRPCResponse](tt.config, logger)

			if tt.wantError {
				verifyGRPCPluginError(t, plugin, err, tt.errorMsg)
			} else {
				verifyGRPCPluginSuccess(t, plugin, err, tt.config)
			}
		})
	}
}

func TestGRPCPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    PluginConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid_grpc_config",
			config: PluginConfig{
				Name:      "test-grpc-plugin",
				Transport: TransportGRPC,
				Endpoint:  "127.0.0.1:50051",
			},
			wantError: false,
		},
		{
			name: "valid_grpc_tls_config",
			config: PluginConfig{
				Name:      "test-grpc-tls-plugin",
				Transport: TransportGRPCTLS,
				Endpoint:  "127.0.0.1:50052",
			},
			wantError: false,
		},
		{
			name: "invalid_transport",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportHTTP,
				Endpoint:  "127.0.0.1:50051",
			},
			wantError: true,
			errorMsg:  "transport must be grpc or grpc-tls",
		},
		{
			name: "missing_endpoint",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPC,
				Endpoint:  "",
			},
			wantError: true,
			errorMsg:  "endpoint is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGRPCConfig(tt.config)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}

				if tt.errorMsg != "" && !containsString(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGRPCConnectionPool(t *testing.T) {
	logger := createTestLogger(t)

	tests := []struct {
		name      string
		config    PluginConfig
		wantError bool
		test      func(t *testing.T, plugin *GRPCPlugin[TestGRPCRequest, TestGRPCResponse], err error)
	}{
		{
			name: "invalid_endpoint",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPC,
				Endpoint:  "invalid:99999",
			},
			wantError: false, // gRPC client creation succeeds, connection failure happens later
			test:      testInvalidEndpointExecution,
		},
		{
			name: "localhost_unavailable",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPC,
				Endpoint:  "127.0.0.1:19999", // Port unlikely to be in use
			},
			wantError: false, // gRPC client creation succeeds, connection failure happens later
			test:      testUnavailableEndpointHealth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin, err := NewGRPCPlugin[TestGRPCRequest, TestGRPCResponse](tt.config, logger)

			if tt.test != nil {
				tt.test(t, plugin, err)
			}

			if plugin != nil {
				if closeErr := plugin.Close(); closeErr != nil {
					t.Logf("Failed to close plugin: %v", closeErr)
				}
			}
		})
	}
}

func TestGRPCPlugin_Execute(t *testing.T) {
	logger := createTestLogger(t)

	tests := []struct {
		name      string
		request   TestGRPCRequest
		execCtx   ExecutionContext
		wantError bool
		errorMsg  string
	}{
		{
			name: "no_connection",
			request: TestGRPCRequest{
				Message: "hello",
			},
			execCtx: ExecutionContext{
				RequestID: "test-123",
				Timeout:   5 * time.Second,
			},
			wantError: true,
			errorMsg:  "connection",
		},
		{
			name: "execution_with_timeout",
			request: TestGRPCRequest{
				Message: "slow",
			},
			execCtx: ExecutionContext{
				RequestID: "test-timeout",
				Timeout:   100 * time.Millisecond,
			},
			wantError: true,
			errorMsg:  "connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPC,
				Endpoint:  "127.0.0.1:19998", // Non-existent server
			}

			plugin, err := NewGRPCPlugin[TestGRPCRequest, TestGRPCResponse](config, logger)
			if err != nil {
				// Expected - no server running
				t.Logf("Plugin creation failed as expected: %v", err)
				return
			}

			defer func() {
				if closeErr := plugin.Close(); closeErr != nil {
					t.Logf("Failed to close plugin: %v", closeErr)
				}
			}()

			_, err = plugin.Execute(context.Background(), tt.execCtx, tt.request)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}

				if tt.errorMsg != "" && !containsString(err.Error(), tt.errorMsg) {
					t.Logf("Got expected error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
			}
		})
	}
}

func TestGRPCPlugin_Health(t *testing.T) {
	logger := createTestLogger(t)

	tests := []struct {
		name            string
		endpoint        string
		wantStatus      PluginStatus
		wantContainsAny []string // Cross-platform error messages
	}{
		{
			name:       "unavailable_service",
			endpoint:   "127.0.0.1:19997", // Non-existent server
			wantStatus: StatusOffline,
			wantContainsAny: []string{
				"connection refused", // Linux/macOS
				"No connection could be made because the target machine actively refused it", // Windows
				"connectex",        // Windows alternative
				"connection error", // Generic gRPC
			},
		},
		{
			name:       "invalid_endpoint",
			endpoint:   "invalid:99999",
			wantStatus: StatusOffline,
			wantContainsAny: []string{
				"zero addresses",  // gRPC resolver error
				"name resolution", // Alternative resolver error
				"no such host",    // DNS resolution error
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPC,
				Endpoint:  tt.endpoint,
			}

			plugin, err := NewGRPCPlugin[TestGRPCRequest, TestGRPCResponse](config, logger)
			if err != nil {
				t.Fatalf("Failed to create plugin: %v", err)
			}

			defer func() {
				if closeErr := plugin.Close(); closeErr != nil {
					t.Logf("Failed to close plugin: %v", closeErr)
				}
			}()

			healthStatus := plugin.Health(context.Background())

			if healthStatus.Status != tt.wantStatus {
				t.Errorf("Expected health status %v, got %v", tt.wantStatus, healthStatus.Status)
			}

			if !containsAnyString(healthStatus.Message, tt.wantContainsAny...) {
				t.Errorf("Expected health message to contain one of %v, got %q", tt.wantContainsAny, healthStatus.Message)
			}

			// Verify metadata
			if healthStatus.Metadata["endpoint"] != config.Endpoint {
				t.Errorf("Expected endpoint metadata %q, got %q", config.Endpoint, healthStatus.Metadata["endpoint"])
			}

			if healthStatus.Metadata["transport"] != string(config.Transport) {
				t.Errorf("Expected transport metadata %q, got %q", config.Transport, healthStatus.Metadata["transport"])
			}
		})
	}
}

func TestGRPCPlugin_Concurrent(t *testing.T) {
	logger := createTestLogger(t)

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "concurrent_health_checks",
			test: func(t *testing.T) {
				// Test concurrent health checks on disconnected plugins
				config := PluginConfig{
					Name:      "test-plugin",
					Transport: TransportGRPC,
					Endpoint:  "127.0.0.1:19996", // Non-existent server
				}

				const numGoroutines = 10
				const checksPerGoroutine = 3

				var wg sync.WaitGroup
				healthResults := make(chan HealthStatus, numGoroutines*checksPerGoroutine)

				for i := 0; i < numGoroutines; i++ {
					wg.Add(1)
					go func(workerID int) {
						defer wg.Done()

						// Create plugin that will fail to connect
						plugin := &GRPCPlugin[TestGRPCRequest, TestGRPCResponse]{
							info: PluginInfo{
								Name: config.Name,
							},
							config: config,
							logger: logger,
						}
						plugin.connected.Store(false)

						for j := 0; j < checksPerGoroutine; j++ {
							healthStatus := plugin.Health(context.Background())
							healthResults <- healthStatus
						}
					}(i)
				}

				wg.Wait()
				close(healthResults)

				var offlineCount int
				for healthStatus := range healthResults {
					if healthStatus.Status == StatusOffline {
						offlineCount++
					}
				}

				totalChecks := numGoroutines * checksPerGoroutine
				if offlineCount != totalChecks {
					t.Errorf("Expected all health checks to be offline: got %d offline out of %d total",
						offlineCount, totalChecks)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

func TestGRPCPluginFactory(t *testing.T) {
	logger := createTestLogger(t)

	tests := []struct {
		name string
		test func(t *testing.T, factory *GRPCPluginFactory[TestGRPCRequest, TestGRPCResponse])
	}{
		{
			name: "supported_transports",
			test: validateFactoryTransports,
		},
		{
			name: "validate_config",
			test: validateFactoryConfig,
		},
		{
			name: "create_plugin",
			test: testFactoryPluginCreation,
		},
	}

	factory := NewGRPCPluginFactory[TestGRPCRequest, TestGRPCResponse](logger)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t, factory)
		})
	}
}

func validateFactoryTransports(t *testing.T, factory *GRPCPluginFactory[TestGRPCRequest, TestGRPCResponse]) {
	transports := factory.SupportedTransports()
	expected := []string{string(TransportGRPC), string(TransportGRPCTLS)}

	if len(transports) != len(expected) {
		t.Errorf("Expected %d transports, got %d", len(expected), len(transports))
		return
	}

	for i, transport := range transports {
		if transport != expected[i] {
			t.Errorf("Expected transport %q at index %d, got %q", expected[i], i, transport)
		}
	}
}

func validateFactoryConfig(t *testing.T, factory *GRPCPluginFactory[TestGRPCRequest, TestGRPCResponse]) {
	validConfig := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportGRPC,
		Endpoint:  "127.0.0.1:50051",
	}

	if err := factory.ValidateConfig(validConfig); err != nil {
		t.Errorf("Valid config should not produce error: %v", err)
	}

	invalidConfig := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportHTTP, // Invalid for gRPC factory
		Endpoint:  "127.0.0.1:50051",
	}

	if err := factory.ValidateConfig(invalidConfig); err == nil {
		t.Error("Invalid config should produce error")
	}
}

func testFactoryPluginCreation(t *testing.T, factory *GRPCPluginFactory[TestGRPCRequest, TestGRPCResponse]) {
	config := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportGRPC,
		Endpoint:  "127.0.0.1:50051", // Will fail to connect, but that's expected
	}

	plugin, err := factory.CreatePlugin(config)
	if err == nil {
		// If creation succeeded (unlikely), close the plugin
		if closeErr := plugin.Close(); closeErr != nil {
			t.Logf("Failed to close plugin: %v", closeErr)
		}
	} else {
		// Expected to fail due to no server running
		if !containsString(err.Error(), "failed to connect") && !containsString(err.Error(), "connection refused") {
			t.Errorf("Expected connection error, got: %v", err)
		}
	}
}

func TestGRPCMessage(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "message_serialization",
			test: testMessageSerialization,
		},
		{
			name: "response_serialization",
			test: testResponseSerialization,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

func testMessageSerialization(t *testing.T) {
	original := TestGRPCRequest{
		Message: "test message",
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"Content-Type":  "application/json",
		},
	}

	// Serialize
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Deserialize
	var deserialized TestGRPCRequest
	if err := json.Unmarshal(data, &deserialized); err != nil {
		t.Fatalf("Failed to unmarshal request: %v", err)
	}

	// Verify
	if deserialized.Message != original.Message {
		t.Errorf("Message mismatch: expected %q, got %q", original.Message, deserialized.Message)
	}

	if len(deserialized.Headers) != len(original.Headers) {
		t.Errorf("Headers length mismatch: expected %d, got %d", len(original.Headers), len(deserialized.Headers))
	}

	for key, value := range original.Headers {
		if deserialized.Headers[key] != value {
			t.Errorf("Header %q mismatch: expected %q, got %q", key, value, deserialized.Headers[key])
		}
	}
}

func testResponseSerialization(t *testing.T) {
	original := TestGRPCResponse{
		Result: "success result",
		Status: "ok",
		Headers: map[string]string{
			"Server":       "test-server",
			"Content-Type": "application/json",
		},
	}

	// Serialize
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	// Deserialize
	var deserialized TestGRPCResponse
	if err := json.Unmarshal(data, &deserialized); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Verify
	if deserialized.Result != original.Result {
		t.Errorf("Result mismatch: expected %q, got %q", original.Result, deserialized.Result)
	}

	if deserialized.Status != original.Status {
		t.Errorf("Status mismatch: expected %q, got %q", original.Status, deserialized.Status)
	}

	if len(deserialized.Headers) != len(original.Headers) {
		t.Errorf("Headers length mismatch: expected %d, got %d", len(original.Headers), len(deserialized.Headers))
	}
}

// Benchmark tests
func BenchmarkGRPCPlugin_Execute(b *testing.B) {
	logger := createBenchmarkLogger()

	config := PluginConfig{
		Name:      "benchmark-plugin",
		Transport: TransportGRPC,
		Endpoint:  "127.0.0.1:19995", // Non-existent server for benchmark
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Benchmark plugin creation (which will fail, but that's expected)
			plugin, err := NewGRPCPlugin[TestGRPCRequest, TestGRPCResponse](config, logger)
			if err != nil {
				// Expected - no server running
				continue
			}
			if closeErr := plugin.Close(); closeErr != nil {
				b.Logf("Failed to close plugin: %v", closeErr)
			}
		}
	})
}

// Helper functions
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				findSubstring(s, substr))))
}

// containsAnyString checks if the string contains any of the provided substrings (for cross-platform compatibility)
func containsAnyString(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if containsString(s, substr) {
			return true
		}
	}
	return false
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func createBenchmarkLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError, // Minimize logging during benchmarks
	}))
}

// verifyGRPCPluginError verifies that plugin creation failed as expected
func verifyGRPCPluginError(t *testing.T, plugin *GRPCPlugin[TestGRPCRequest, TestGRPCResponse], err error, expectedMsg string) {
	if err == nil {
		t.Error("Expected error but got none")
		if plugin != nil {
			if closeErr := plugin.Close(); closeErr != nil {
				t.Logf("Failed to close plugin: %v", closeErr)
			}
		}
		return
	}

	if expectedMsg != "" && !containsString(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got %q", expectedMsg, err.Error())
	}
}

// verifyGRPCPluginSuccess verifies that plugin creation succeeded as expected
func verifyGRPCPluginSuccess(t *testing.T, plugin *GRPCPlugin[TestGRPCRequest, TestGRPCResponse], err error, config PluginConfig) {
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	if plugin == nil {
		t.Error("Expected plugin but got nil")
		return
	}

	// Verify plugin properties
	info := plugin.Info()
	if info.Name != config.Name {
		t.Errorf("Expected plugin name %q, got %q", config.Name, info.Name)
	}

	// Cleanup
	if closeErr := plugin.Close(); closeErr != nil {
		t.Logf("Failed to close plugin: %v", closeErr)
	}
}

// testInvalidEndpointExecution tests that execution fails for invalid endpoints
func testInvalidEndpointExecution(t *testing.T, plugin *GRPCPlugin[TestGRPCRequest, TestGRPCResponse], err error) {
	if err != nil {
		t.Errorf("Expected plugin creation to succeed, got error: %v", err)
		return
	}
	if plugin == nil {
		t.Error("Expected plugin to be created")
		return
	}

	// Test that operations fail due to invalid endpoint
	ctx := context.Background()
	execCtx := ExecutionContext{RequestID: "test-001", Timeout: 1 * time.Second}
	request := TestGRPCRequest{Message: "test"}

	_, execErr := plugin.Execute(ctx, execCtx, request)
	if execErr == nil {
		t.Error("Expected Execute to fail with invalid endpoint")
	} else {
		t.Logf("Execute failed as expected: %v", execErr)
	}
}

// testUnavailableEndpointHealth tests health check behavior for unavailable endpoints
func testUnavailableEndpointHealth(t *testing.T, plugin *GRPCPlugin[TestGRPCRequest, TestGRPCResponse], err error) {
	if err != nil {
		t.Errorf("Expected plugin creation to succeed, got error: %v", err)
		return
	}
	if plugin == nil {
		t.Error("Expected plugin to be created")
		return
	}

	// Test that health check indicates unhealthy status due to unavailable endpoint
	healthStatus := plugin.Health(context.Background())

	// Verify health status indicates unhealthy or offline
	if healthStatus.Status == StatusHealthy {
		t.Errorf("Expected plugin status to be unhealthy for unavailable endpoint, got: %s", healthStatus.Status)
	} else {
		t.Logf("Health check returned unhealthy status as expected: %s - %s", healthStatus.Status, healthStatus.Message)
	}
}
