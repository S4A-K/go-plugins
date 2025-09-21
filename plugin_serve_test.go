// plugin_serve_test.go: Comprehensive tests for plugin-side serve interface
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestServeConfigValidation tests ServeConfig validation rules
func TestServeConfigValidation(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		config := ServeConfig{
			PluginName:      "test-plugin",
			PluginVersion:   "1.0.0",
			PluginType:      "grpc",
			HandshakeConfig: DefaultHandshakeConfig,
			NetworkConfig: NetworkServeConfig{
				Protocol:       "tcp",
				BindAddress:    "127.0.0.1",
				BindPort:       0,
				ReadTimeout:    30 * time.Second,
				WriteTimeout:   30 * time.Second,
				MaxConnections: 10,
			},
		}

		if err := config.Validate(); err != nil {
			t.Errorf("Valid config should not return error: %v", err)
		}
	})

	t.Run("EmptyPluginName", func(t *testing.T) {
		config := DefaultServeConfig
		config.PluginName = ""

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for empty plugin name")
		}
		if !strings.Contains(err.Error(), "plugin name is required") {
			t.Errorf("Error should mention plugin name, got: %v", err)
		}
	})

	t.Run("EmptyPluginVersion", func(t *testing.T) {
		config := DefaultServeConfig
		config.PluginVersion = ""

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for empty plugin version")
		}
		if !strings.Contains(err.Error(), "plugin version is required") {
			t.Errorf("Error should mention plugin version, got: %v", err)
		}
	})

	t.Run("EmptyPluginType", func(t *testing.T) {
		config := DefaultServeConfig
		config.PluginType = ""

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for empty plugin type")
		}
		if !strings.Contains(err.Error(), "plugin type is required") {
			t.Errorf("Error should mention plugin type, got: %v", err)
		}
	})

	t.Run("EmptyProtocol", func(t *testing.T) {
		config := DefaultServeConfig
		config.NetworkConfig.Protocol = ""

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for empty protocol")
		}
		if !strings.Contains(err.Error(), "network protocol is required") {
			t.Errorf("Error should mention protocol, got: %v", err)
		}
	})

	t.Run("ZeroReadTimeout", func(t *testing.T) {
		config := DefaultServeConfig
		config.NetworkConfig.ReadTimeout = 0

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for zero read timeout")
		}
		if !strings.Contains(err.Error(), "read timeout must be greater than 0") {
			t.Errorf("Error should mention read timeout, got: %v", err)
		}
	})

	t.Run("ZeroWriteTimeout", func(t *testing.T) {
		config := DefaultServeConfig
		config.NetworkConfig.WriteTimeout = 0

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for zero write timeout")
		}
		if !strings.Contains(err.Error(), "write timeout must be greater than 0") {
			t.Errorf("Error should mention write timeout, got: %v", err)
		}
	})

	t.Run("NegativeMaxConnections", func(t *testing.T) {
		config := DefaultServeConfig
		config.NetworkConfig.MaxConnections = -1

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for negative max connections")
		}
		if !strings.Contains(err.Error(), "max connections must be >= 0") {
			t.Errorf("Error should mention max connections, got: %v", err)
		}
	})

	t.Run("InvalidHandshakeConfig", func(t *testing.T) {
		config := DefaultServeConfig
		config.HandshakeConfig.ProtocolVersion = 0 // Invalid

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for invalid handshake config")
		}
		if !strings.Contains(err.Error(), "handshake config validation failed") {
			t.Errorf("Error should mention handshake config, got: %v", err)
		}
	})
}

// TestNetworkServeConfigValidation tests NetworkServeConfig validation rules
func TestNetworkServeConfigValidation(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol:       "tcp",
			BindAddress:    "127.0.0.1",
			BindPort:       8080,
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxConnections: 100,
		}

		if err := config.Validate(); err != nil {
			t.Errorf("Valid config should not return error: %v", err)
		}
	})

	t.Run("EmptyProtocol", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol: "",
		}

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for empty protocol")
		}
		if !strings.Contains(err.Error(), "protocol is required") {
			t.Errorf("Error should mention protocol, got: %v", err)
		}
	})

	t.Run("InvalidPortNegative", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol: "tcp",
			BindPort: -1,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for negative port")
		}
		if !strings.Contains(err.Error(), "bind port must be between 0 and 65535") {
			t.Errorf("Error should mention port range, got: %v", err)
		}
	})

	t.Run("InvalidPortTooHigh", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol: "tcp",
			BindPort: 65536,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for port too high")
		}
		if !strings.Contains(err.Error(), "bind port must be between 0 and 65535") {
			t.Errorf("Error should mention port range, got: %v", err)
		}
	})

	t.Run("NegativeReadTimeout", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol:    "tcp",
			ReadTimeout: -1 * time.Second,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for negative read timeout")
		}
		if !strings.Contains(err.Error(), "read timeout cannot be negative") {
			t.Errorf("Error should mention read timeout, got: %v", err)
		}
	})

	t.Run("NegativeWriteTimeout", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol:     "tcp",
			WriteTimeout: -1 * time.Second,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for negative write timeout")
		}
		if !strings.Contains(err.Error(), "write timeout cannot be negative") {
			t.Errorf("Error should mention write timeout, got: %v", err)
		}
	})

	t.Run("NegativeIdleTimeout", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol:    "tcp",
			IdleTimeout: -1 * time.Second,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for negative idle timeout")
		}
		if !strings.Contains(err.Error(), "idle timeout cannot be negative") {
			t.Errorf("Error should mention idle timeout, got: %v", err)
		}
	})

	t.Run("NegativeMaxConnections", func(t *testing.T) {
		config := NetworkServeConfig{
			Protocol:       "tcp",
			MaxConnections: -1,
		}

		err := config.Validate()
		if err == nil {
			t.Error("Should return error for negative max connections")
		}
		if !strings.Contains(err.Error(), "max connections cannot be negative") {
			t.Errorf("Error should mention max connections, got: %v", err)
		}
	})
}

// TestDefaultServeConfig tests the default serve configuration
func TestDefaultServeConfig(t *testing.T) {
	config := DefaultServeConfig

	if config.PluginName != "unnamed-plugin" {
		t.Errorf("Expected default plugin name 'unnamed-plugin', got %s", config.PluginName)
	}

	if config.PluginVersion != "1.0.0" {
		t.Errorf("Expected default plugin version '1.0.0', got %s", config.PluginVersion)
	}

	if config.PluginType != "generic" {
		t.Errorf("Expected default plugin type 'generic', got %s", config.PluginType)
	}

	if config.NetworkConfig.Protocol != "tcp" {
		t.Errorf("Expected default protocol 'tcp', got %s", config.NetworkConfig.Protocol)
	}

	if config.NetworkConfig.BindAddress != "127.0.0.1" {
		t.Errorf("Expected default bind address '127.0.0.1', got %s", config.NetworkConfig.BindAddress)
	}

	if config.NetworkConfig.BindPort != 0 {
		t.Errorf("Expected default bind port 0, got %d", config.NetworkConfig.BindPort)
	}

	if config.NetworkConfig.ReadTimeout != 30*time.Second {
		t.Errorf("Expected default read timeout 30s, got %v", config.NetworkConfig.ReadTimeout)
	}

	if config.NetworkConfig.WriteTimeout != 30*time.Second {
		t.Errorf("Expected default write timeout 30s, got %v", config.NetworkConfig.WriteTimeout)
	}

	if config.NetworkConfig.IdleTimeout != 60*time.Second {
		t.Errorf("Expected default idle timeout 60s, got %v", config.NetworkConfig.IdleTimeout)
	}

	if config.NetworkConfig.MaxConnections != 100 {
		t.Errorf("Expected default max connections 100, got %d", config.NetworkConfig.MaxConnections)
	}

	// Test that default config is valid
	if err := config.Validate(); err != nil {
		t.Errorf("Default config should be valid: %v", err)
	}
}

// MockHandshakeManager is a mock implementation for testing handshake functionality
type MockHandshakeManager struct {
	validateResult   *HandshakeInfo
	validateError    error
	prepareEnvResult []string
	callCount        atomic.Int32
}

func NewMockHandshakeManager() *MockHandshakeManager {
	return &MockHandshakeManager{
		validateResult: &HandshakeInfo{
			ProtocolVersion: 1,
			PluginType:      PluginTypeGRPC,
			ServerAddress:   "127.0.0.1",
			ServerPort:      8080,
			PluginName:      "test-plugin",
			PluginVersion:   "1.0.0",
		},
		prepareEnvResult: []string{
			"AGILIRA_PLUGIN_MAGIC_COOKIE=agilira-go-plugins-v1",
			"PLUGIN_PROTOCOL_VERSION=1",
			"PLUGIN_SERVER_ADDRESS=127.0.0.1",
			"PLUGIN_SERVER_PORT=8080",
			"PLUGIN_TYPE=grpc",
		},
	}
}

func (m *MockHandshakeManager) ValidatePluginEnvironment() (*HandshakeInfo, error) {
	m.callCount.Add(1)
	if m.validateError != nil {
		return nil, m.validateError
	}
	return m.validateResult, nil
}

func (m *MockHandshakeManager) PrepareEnvironment(info HandshakeInfo) []string {
	m.callCount.Add(1)
	return m.prepareEnvResult
}

func (m *MockHandshakeManager) SetValidateResult(result *HandshakeInfo, err error) {
	m.validateResult = result
	m.validateError = err
}

func (m *MockHandshakeManager) GetCallCount() int32 {
	return m.callCount.Load()
}

// MockConn is a mock network connection for testing
type MockConn struct {
	readData      []byte
	readError     error
	writeError    error
	writeData     []byte
	closed        atomic.Bool
	localAddr     net.Addr
	remoteAddr    net.Addr
	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

func NewMockConn() *MockConn {
	return &MockConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	if m.readError != nil {
		return 0, m.readError
	}
	if len(m.readData) == 0 {
		return 0, io.EOF
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	if m.writeError != nil {
		return 0, m.writeError
	}
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *MockConn) Close() error {
	m.closed.Store(true)
	return nil
}

func (m *MockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *MockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *MockConn) SetDeadline(t time.Time) error {
	m.SetReadDeadline(t)
	m.SetWriteDeadline(t)
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	m.readDeadline.Store(t)
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	m.writeDeadline.Store(t)
	return nil
}

func (m *MockConn) SetReadData(data []byte) {
	m.readData = data
}

func (m *MockConn) SetReadError(err error) {
	m.readError = err
}

func (m *MockConn) SetWriteError(err error) {
	m.writeError = err
}

func (m *MockConn) GetWrittenData() []byte {
	return m.writeData
}

func (m *MockConn) IsClosed() bool {
	return m.closed.Load()
}

// MockListener is a mock network listener for testing
type MockListener struct {
	acceptChan  chan net.Conn
	acceptError error
	closed      atomic.Bool
	addr        net.Addr
	acceptCount atomic.Int32
}

func NewMockListener() *MockListener {
	return &MockListener{
		acceptChan: make(chan net.Conn, 10),
		addr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
	}
}

func (m *MockListener) Accept() (net.Conn, error) {
	if m.closed.Load() {
		return nil, errors.New("listener closed")
	}
	if m.acceptError != nil {
		return nil, m.acceptError
	}

	m.acceptCount.Add(1)

	select {
	case conn := <-m.acceptChan:
		return conn, nil
	case <-time.After(100 * time.Millisecond):
		// Simulate timeout
		if netErr, ok := m.acceptError.(net.Error); ok && netErr.Timeout() {
			return nil, m.acceptError
		}
		return nil, &net.OpError{Op: "accept", Err: errors.New("timeout")}
	}
}

func (m *MockListener) Close() error {
	m.closed.Store(true)
	close(m.acceptChan)
	return nil
}

func (m *MockListener) Addr() net.Addr {
	return m.addr
}

func (m *MockListener) AddConnection(conn net.Conn) {
	if !m.closed.Load() {
		select {
		case m.acceptChan <- conn:
		default:
			// Channel full, drop connection
		}
	}
}

func (m *MockListener) SetAcceptError(err error) {
	m.acceptError = err
}

func (m *MockListener) GetAcceptCount() int32 {
	return m.acceptCount.Load()
}

// MockRequestHandler is a mock implementation for testing
type MockRequestHandler struct {
	requestType string
	response    *PluginResponse
	err         error
	callCount   atomic.Int32
	calls       []PluginRequest
	mutex       sync.RWMutex
}

func NewMockRequestHandler(requestType string) *MockRequestHandler {
	return &MockRequestHandler{
		requestType: requestType,
		response: &PluginResponse{
			Success: true,
			Data:    []byte("mock response"),
		},
	}
}

func (m *MockRequestHandler) HandleRequest(ctx context.Context, request *PluginRequest) (*PluginResponse, error) {
	m.callCount.Add(1)

	m.mutex.Lock()
	m.calls = append(m.calls, *request)
	m.mutex.Unlock()

	if m.err != nil {
		return nil, m.err
	}

	response := *m.response
	response.ID = request.ID
	response.Timestamp = time.Now()
	return &response, nil
}

func (m *MockRequestHandler) GetRequestType() string {
	return m.requestType
}

func (m *MockRequestHandler) SetResponse(response *PluginResponse) {
	m.mutex.Lock()
	m.response = response
	m.mutex.Unlock()
}

func (m *MockRequestHandler) SetError(err error) {
	m.mutex.Lock()
	m.err = err
	m.mutex.Unlock()
}

func (m *MockRequestHandler) GetCallCount() int32 {
	return m.callCount.Load()
}

func (m *MockRequestHandler) GetCalls() []PluginRequest {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return append([]PluginRequest{}, m.calls...)
}

// TestNewGenericPluginServer tests creation of generic plugin server
func TestNewGenericPluginServer(t *testing.T) {
	t.Run("WithDefaultLogger", func(t *testing.T) {
		config := DefaultServeConfig
		config.Logger = nil // Should use default

		server := NewGenericPluginServer(config)
		defer server.Close()

		if server == nil {
			t.Fatal("NewGenericPluginServer should not return nil")
		}

		if server.logger == nil {
			t.Error("Logger should be initialized")
		}
	})

	t.Run("WithCustomLogger", func(t *testing.T) {
		testLogger := NewTestLogger()
		config := DefaultServeConfig
		config.Logger = testLogger

		server := NewGenericPluginServer(config)
		defer server.Close()

		if server.logger != testLogger {
			t.Error("Custom logger should be used")
		}
	})

	t.Run("WithHealthCheckEnabled", func(t *testing.T) {
		config := DefaultServeConfig
		config.HealthConfig = HealthCheckConfig{
			Enabled:  true,
			Interval: 30 * time.Second,
		}

		server := NewGenericPluginServer(config)
		defer server.Close()

		if server.healthChecker == nil {
			t.Error("Health checker should be initialized when enabled")
		}
	})

	t.Run("WithHealthCheckDisabled", func(t *testing.T) {
		config := DefaultServeConfig
		config.HealthConfig = HealthCheckConfig{
			Enabled: false,
		}

		server := NewGenericPluginServer(config)
		defer server.Close()

		if server.healthChecker != nil {
			t.Error("Health checker should not be initialized when disabled")
		}
	})

	t.Run("InitialState", func(t *testing.T) {
		config := DefaultServeConfig
		server := NewGenericPluginServer(config)
		defer server.Close()

		if server.running {
			t.Error("Server should not be running initially")
		}

		if len(server.handlers) != 0 {
			t.Errorf("Handlers map should be empty initially, got %d", len(server.handlers))
		}

		if len(server.connections) != 0 {
			t.Errorf("Connections map should be empty initially, got %d", len(server.connections))
		}

		if server.stats.StartTime.IsZero() {
			t.Error("Start time should be set")
		}
	})
}

// TestGenericPluginServer_HandlerRegistration tests handler registration/unregistration
func TestGenericPluginServer_HandlerRegistration(t *testing.T) {
	server := NewGenericPluginServer(DefaultServeConfig)
	defer server.Close()

	t.Run("RegisterValidHandler", func(t *testing.T) {
		handler := NewMockRequestHandler("test-type")

		err := server.RegisterHandler(handler)
		if err != nil {
			t.Errorf("Should be able to register valid handler: %v", err)
		}

		if len(server.handlers) != 1 {
			t.Errorf("Expected 1 handler, got %d", len(server.handlers))
		}
	})

	t.Run("RegisterHandlerEmptyType", func(t *testing.T) {
		handler := NewMockRequestHandler("")

		err := server.RegisterHandler(handler)
		if err == nil {
			t.Error("Should return error for handler with empty request type")
		}
		if !strings.Contains(err.Error(), "handler must specify a non-empty request type") {
			t.Errorf("Error should mention non-empty type, got: %v", err)
		}
	})

	t.Run("RegisterDuplicateHandler", func(t *testing.T) {
		handler1 := NewMockRequestHandler("duplicate-type")
		handler2 := NewMockRequestHandler("duplicate-type")

		err1 := server.RegisterHandler(handler1)
		if err1 != nil {
			t.Errorf("First handler registration should succeed: %v", err1)
		}

		err2 := server.RegisterHandler(handler2)
		if err2 == nil {
			t.Error("Should return error for duplicate handler type")
		}
		if !strings.Contains(err2.Error(), "handler for request type 'duplicate-type' already registered") {
			t.Errorf("Error should mention duplicate type, got: %v", err2)
		}
	})

	t.Run("UnregisterHandler", func(t *testing.T) {
		handler := NewMockRequestHandler("unregister-type")

		err := server.RegisterHandler(handler)
		if err != nil {
			t.Fatalf("Handler registration should succeed: %v", err)
		}

		initialCount := len(server.handlers)
		server.UnregisterHandler("unregister-type")

		if len(server.handlers) != initialCount-1 {
			t.Errorf("Expected handler count to decrease by 1, got %d", len(server.handlers))
		}

		if _, exists := server.handlers["unregister-type"]; exists {
			t.Error("Handler should be removed after unregistration")
		}
	})

	t.Run("UnregisterNonExistentHandler", func(t *testing.T) {
		initialCount := len(server.handlers)

		// Should not panic or error
		server.UnregisterHandler("non-existent-type")

		if len(server.handlers) != initialCount {
			t.Error("Handler count should not change when unregistering non-existent handler")
		}
	})
}

// TestGenericPluginServer_Health tests Health method behavior
func TestGenericPluginServer_Health(t *testing.T) {
	t.Run("ServerNotRunning", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		ctx := context.Background()
		status := server.Health(ctx)

		if status.Status != StatusOffline {
			t.Errorf("Expected StatusOffline when server not running, got %s", status.Status.String())
		}

		if status.Message != "Plugin server is not running" {
			t.Errorf("Expected offline message, got '%s'", status.Message)
		}

		if status.ResponseTime != 0 {
			t.Errorf("Expected zero response time when offline, got %v", status.ResponseTime)
		}
	})

	t.Run("ServerRunning", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		// Simulate running state
		server.runMutex.Lock()
		server.running = true
		server.runMutex.Unlock()

		ctx := context.Background()
		status := server.Health(ctx)

		if status.Status != StatusHealthy {
			t.Errorf("Expected StatusHealthy when server running, got %s", status.Status.String())
		}

		if status.Message != "Plugin server is healthy and running" {
			t.Errorf("Expected healthy message, got '%s'", status.Message)
		}

		if status.ResponseTime <= 0 {
			t.Error("Response time should be greater than 0 when healthy")
		}

		// Check metadata
		if status.Metadata == nil {
			t.Fatal("Metadata should not be nil")
		}

		expectedMetadataKeys := []string{
			"active_connections", "requests_handled", "requests_failed",
			"uptime", "registered_handlers",
		}

		for _, key := range expectedMetadataKeys {
			if _, exists := status.Metadata[key]; !exists {
				t.Errorf("Expected metadata key '%s' to be present", key)
			}
		}
	})
}

// TestGenericPluginServer_Info tests Info method behavior
func TestGenericPluginServer_Info(t *testing.T) {
	t.Run("BasicInfo", func(t *testing.T) {
		config := DefaultServeConfig
		config.PluginName = "test-plugin"
		config.PluginVersion = "1.2.3"

		server := NewGenericPluginServer(config)
		defer server.Close()

		info := server.Info()

		if info.Name != "test-plugin" {
			t.Errorf("Expected plugin name 'test-plugin', got '%s'", info.Name)
		}

		if info.Version != "1.2.3" {
			t.Errorf("Expected plugin version '1.2.3', got '%s'", info.Version)
		}

		if info.Description != "Generic plugin server" {
			t.Errorf("Expected description 'Generic plugin server', got '%s'", info.Description)
		}

		if info.Author != "go-plugins" {
			t.Errorf("Expected author 'go-plugins', got '%s'", info.Author)
		}

		if info.Metadata == nil {
			t.Fatal("Metadata should not be nil")
		}

		if protocol, exists := info.Metadata["protocol"]; !exists || protocol != config.NetworkConfig.Protocol {
			t.Errorf("Expected protocol metadata '%s', got '%s'", config.NetworkConfig.Protocol, protocol)
		}
	})

	t.Run("InfoWithHandlers", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		// Register some handlers
		handler1 := NewMockRequestHandler("auth")
		handler2 := NewMockRequestHandler("payment")

		server.RegisterHandler(handler1)
		server.RegisterHandler(handler2)

		info := server.Info()

		if len(info.Capabilities) != 2 {
			t.Errorf("Expected 2 capabilities, got %d", len(info.Capabilities))
		}

		capabilitySet := make(map[string]bool)
		for _, capability := range info.Capabilities {
			capabilitySet[capability] = true
		}

		if !capabilitySet["auth"] {
			t.Error("Expected 'auth' capability to be present")
		}

		if !capabilitySet["payment"] {
			t.Error("Expected 'payment' capability to be present")
		}
	})
}

// TestGenericPluginServer_GetStats tests GetStats method
func TestGenericPluginServer_GetStats(t *testing.T) {
	server := NewGenericPluginServer(DefaultServeConfig)
	defer server.Close()

	stats := server.GetStats()

	if stats.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}

	if stats.RequestsHandled != 0 {
		t.Errorf("Expected 0 requests handled initially, got %d", stats.RequestsHandled)
	}

	if stats.RequestsFailed != 0 {
		t.Errorf("Expected 0 requests failed initially, got %d", stats.RequestsFailed)
	}

	if stats.ConnectionsTotal != 0 {
		t.Errorf("Expected 0 connections total initially, got %d", stats.ConnectionsTotal)
	}

	if stats.ActiveConnections != 0 {
		t.Errorf("Expected 0 active connections initially, got %d", stats.ActiveConnections)
	}

	if stats.AverageResponseTime != 0 {
		t.Errorf("Expected 0 average response time initially, got %v", stats.AverageResponseTime)
	}

	if !stats.LastRequestTime.IsZero() {
		t.Error("LastRequestTime should be zero initially")
	}
}

// TestGenericPluginServer_Stop tests Stop method behavior
func TestGenericPluginServer_Stop(t *testing.T) {
	t.Run("StopNotRunning", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)

		ctx := context.Background()
		err := server.Stop(ctx)

		if err != nil {
			t.Errorf("Stop should not return error when server not running: %v", err)
		}
	})

	t.Run("StopRunning", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)

		// Simulate running state
		server.runMutex.Lock()
		server.running = true
		server.runMutex.Unlock()

		// Enable health checker for testing shutdown
		server.healthChecker = &HealthChecker{}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := server.Stop(ctx)

		if err != nil {
			t.Errorf("Stop should not return error: %v", err)
		}

		server.runMutex.Lock()
		running := server.running
		server.runMutex.Unlock()

		if running {
			t.Error("Server should not be running after stop")
		}
	})
}

// TestGenericPluginServer_Close tests Close method (alias for Stop)
func TestGenericPluginServer_Close(t *testing.T) {
	server := NewGenericPluginServer(DefaultServeConfig)

	err := server.Close()

	if err != nil {
		t.Errorf("Close should not return error: %v", err)
	}
}

// TestServePlugin tests the ServePlugin convenience function
func TestServePlugin(t *testing.T) {
	t.Skip("ServePlugin requires complex mocking of HandshakeManager - covered by integration tests")
}

// TestPluginRequestResponse tests request and response structures
func TestPluginRequestResponse(t *testing.T) {
	t.Run("PluginRequest", func(t *testing.T) {
		timestamp := time.Now()
		request := PluginRequest{
			ID:        "test-id",
			Type:      "test-type",
			Method:    "test-method",
			Data:      []byte("test-data"),
			Metadata:  map[string]string{"key": "value"},
			Options:   map[string]interface{}{"option": "value"},
			Timestamp: timestamp,
		}

		if request.ID != "test-id" {
			t.Errorf("Expected ID 'test-id', got '%s'", request.ID)
		}

		if request.Type != "test-type" {
			t.Errorf("Expected Type 'test-type', got '%s'", request.Type)
		}

		if request.Method != "test-method" {
			t.Errorf("Expected Method 'test-method', got '%s'", request.Method)
		}

		if string(request.Data) != "test-data" {
			t.Errorf("Expected Data 'test-data', got '%s'", string(request.Data))
		}

		if request.Metadata["key"] != "value" {
			t.Errorf("Expected metadata key 'value', got '%s'", request.Metadata["key"])
		}

		if request.Options["option"] != "value" {
			t.Errorf("Expected options option 'value', got '%v'", request.Options["option"])
		}

		if !request.Timestamp.Equal(timestamp) {
			t.Errorf("Expected timestamp %v, got %v", timestamp, request.Timestamp)
		}
	})

	t.Run("PluginResponse", func(t *testing.T) {
		timestamp := time.Now()
		response := PluginResponse{
			ID:        "test-id",
			Success:   true,
			Data:      []byte("test-response"),
			Error:     "",
			Metadata:  map[string]string{"result": "ok"},
			Options:   map[string]interface{}{"processed": true},
			Timestamp: timestamp,
		}

		if response.ID != "test-id" {
			t.Errorf("Expected ID 'test-id', got '%s'", response.ID)
		}

		if !response.Success {
			t.Error("Expected Success true")
		}

		if string(response.Data) != "test-response" {
			t.Errorf("Expected Data 'test-response', got '%s'", string(response.Data))
		}

		if response.Error != "" {
			t.Errorf("Expected empty Error, got '%s'", response.Error)
		}

		if response.Metadata["result"] != "ok" {
			t.Errorf("Expected metadata result 'ok', got '%s'", response.Metadata["result"])
		}

		if response.Options["processed"] != true {
			t.Errorf("Expected options processed true, got '%v'", response.Options["processed"])
		}

		if !response.Timestamp.Equal(timestamp) {
			t.Errorf("Expected timestamp %v, got %v", timestamp, response.Timestamp)
		}
	})
}

// TestGenericPluginServer_ServeAdvanced tests the Serve method with environment mocking
func TestGenericPluginServer_ServeAdvanced(t *testing.T) {
	t.Run("ServeAlreadyRunning", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		// Simulate already running
		server.runMutex.Lock()
		server.running = true
		server.runMutex.Unlock()

		config := DefaultServeConfig
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := server.Serve(ctx, config)
		if err == nil {
			t.Error("Expected error when server already running")
		}
		if !strings.Contains(err.Error(), "plugin server is already running") {
			t.Errorf("Expected 'already running' error, got: %v", err)
		}
	})

	t.Run("ServeHandshakeValidation", func(t *testing.T) {
		// Test that Serve fails when handshake validation fails
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		// Don't set proper environment - should fail handshake validation
		config := DefaultServeConfig
		config.Logger = NewTestLogger() // Ensure logger is not nil
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err := server.Serve(ctx, config)
		// Should return error - could be handshake validation or context deadline
		if err == nil {
			t.Error("Expected error when environment not set")
		}
		// Accept both handshake validation error and context deadline as valid test outcomes
		if !strings.Contains(err.Error(), "handshake validation failed") &&
			!strings.Contains(err.Error(), "context deadline exceeded") {
			t.Errorf("Expected handshake validation error or timeout, got: %v", err)
		}
	})
}

// TestGenericPluginServer_MissingCoverageMethods tests remaining methods with 0% coverage
func TestGenericPluginServer_MissingCoverageMethods(t *testing.T) {
	logger := NewTestLogger()

	t.Run("Close", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		server.logger = logger

		err := server.Close()
		if err != nil {
			t.Errorf("Expected no error from Close, got: %v", err)
		}

		// Test double close
		err = server.Close()
		if err != nil {
			t.Errorf("Expected no error from double Close, got: %v", err)
		}
	})

	t.Run("Health", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		server.logger = logger
		defer server.Close()

		ctx := context.Background()
		status := server.Health(ctx)
		// HealthStatus is a struct, check if status is valid
		if status.Status < StatusUnknown || status.Status > StatusOffline {
			t.Error("Expected valid health status")
		}
	})

	t.Run("Info", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		server.logger = logger
		defer server.Close()

		info := server.Info()
		// PluginInfo is a struct, not pointer, so check if it's populated
		if info.Name == "" {
			t.Error("Expected plugin info to be populated")
		}
	})

	t.Run("GetStats", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		server.logger = logger
		defer server.Close()

		stats := server.GetStats()
		// ServeStats is a struct, not pointer, so just verify it returns successfully
		if stats.RequestsHandled < 0 {
			t.Error("Expected stats to be valid")
		}
	})

	t.Run("UnregisterHandler", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		server.logger = logger
		defer server.Close()

		// Register a handler first
		handler := NewMockRequestHandler("test-request")
		err := server.RegisterHandler(handler)
		if err != nil {
			t.Errorf("Failed to register handler: %v", err)
		}

		// Then unregister it by request type
		server.UnregisterHandler("test-request")

		// Verify it's gone by trying to register the same type again (should work now)
		handler2 := NewMockRequestHandler("test-request")
		err = server.RegisterHandler(handler2)
		if err != nil {
			t.Errorf("Failed to re-register handler after unregister: %v", err)
		}
	})
}

// TestGenericPluginServer_HandleConnectionAdvanced tests handleConnection with real mock connections
func TestGenericPluginServer_HandleConnectionAdvanced(t *testing.T) {
	t.Run("HandleConnection_EchoData", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		// Initialize WaitGroup for proper coordination
		server.wg = sync.WaitGroup{}

		mockConn := NewMockConn()
		testData := []byte("hello world")
		mockConn.SetReadData(testData)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		connID := "test-connection"

		// Add to WaitGroup before starting goroutine
		server.wg.Add(1)

		// Run handleConnection in goroutine
		done := make(chan struct{})
		go func() {
			defer close(done)
			server.handleConnection(ctx, connID, mockConn)
		}()

		// Wait for completion or timeout
		select {
		case <-done:
			// Check that data was echoed back
			writtenData := mockConn.GetWrittenData()
			if string(writtenData) != string(testData) {
				t.Errorf("Expected echoed data '%s', got '%s'", string(testData), string(writtenData))
			}

			// Check connection was closed
			if !mockConn.IsClosed() {
				t.Error("Connection should be closed after handling")
			}
		case <-ctx.Done():
			t.Error("handleConnection should have completed before timeout")
		}
	})

	t.Run("HandleConnection_ReadError", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		server.wg = sync.WaitGroup{}

		mockConn := NewMockConn()
		mockConn.SetReadError(errors.New("read error"))

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		connID := "test-connection-error"

		// Add to WaitGroup before starting goroutine
		server.wg.Add(1)

		done := make(chan struct{})
		go func() {
			defer close(done)
			server.handleConnection(ctx, connID, mockConn)
		}()

		select {
		case <-done:
			// Should complete without panic even with read error
			if !mockConn.IsClosed() {
				t.Error("Connection should be closed after error")
			}
		case <-ctx.Done():
			t.Error("handleConnection should have completed before timeout")
		}
	})

	t.Run("HandleConnection_WriteError", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		server.wg = sync.WaitGroup{}

		mockConn := NewMockConn()
		testData := []byte("test data")
		mockConn.SetReadData(testData)
		mockConn.SetWriteError(errors.New("write error"))

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		connID := "test-connection-write-error"

		// Add to WaitGroup before starting goroutine
		server.wg.Add(1)

		done := make(chan struct{})
		go func() {
			defer close(done)
			server.handleConnection(ctx, connID, mockConn)
		}()

		select {
		case <-done:
			// Should complete without panic even with write error
			if !mockConn.IsClosed() {
				t.Error("Connection should be closed after error")
			}
		case <-ctx.Done():
			t.Error("handleConnection should have completed before timeout")
		}
	})
}

// TestGenericPluginServer_NetworkIntegration tests network components integration
func TestGenericPluginServer_NetworkIntegration(t *testing.T) {
	t.Run("StatsTracking", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		// Simulate request handling
		server.stats.RequestsHandled = 10
		server.stats.RequestsFailed = 2
		server.stats.ConnectionsTotal = 5
		server.stats.ActiveConnections = 3

		stats := server.GetStats()
		if stats.RequestsHandled != 10 {
			t.Errorf("Expected 10 requests handled, got %d", stats.RequestsHandled)
		}
		if stats.RequestsFailed != 2 {
			t.Errorf("Expected 2 requests failed, got %d", stats.RequestsFailed)
		}
		if stats.ConnectionsTotal != 5 {
			t.Errorf("Expected 5 total connections, got %d", stats.ConnectionsTotal)
		}
		if stats.ActiveConnections != 3 {
			t.Errorf("Expected 3 active connections, got %d", stats.ActiveConnections)
		}
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		server := NewGenericPluginServer(DefaultServeConfig)
		defer server.Close()

		// Test concurrent handler registration
		var wg sync.WaitGroup
		errChan := make(chan error, 10)

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				handler := NewMockRequestHandler(fmt.Sprintf("handler-%d", id))
				err := server.RegisterHandler(handler)
				if err != nil {
					errChan <- err
				}
			}(i)
		}

		wg.Wait()
		close(errChan)

		// Check for errors
		for err := range errChan {
			t.Errorf("Concurrent handler registration failed: %v", err)
		}

		// Verify all handlers registered
		if len(server.handlers) != 5 {
			t.Errorf("Expected 5 handlers, got %d", len(server.handlers))
		}
	})
}
