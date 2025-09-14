// testing_helpers_test.go: Smart cross-platform test helper utilities
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestEnvironment provides cross-platform test utilities
type TestEnvironment struct {
	t           *testing.T
	tempDirs    []string
	mockServers []*httptest.Server
	tlsServers  []*httptest.Server
	unixSockets []string
	cleanup     []func()
	mu          sync.Mutex
}

// NewTestEnvironment creates a new test environment with automatic cleanup
func NewTestEnvironment(t *testing.T) *TestEnvironment {
	env := &TestEnvironment{
		t:           t,
		tempDirs:    make([]string, 0),
		mockServers: make([]*httptest.Server, 0),
		tlsServers:  make([]*httptest.Server, 0),
		unixSockets: make([]string, 0),
		cleanup:     make([]func(), 0),
	}

	// Register cleanup on test completion
	t.Cleanup(env.Cleanup)

	return env
}

// CreateTempDir creates a temporary directory for testing
func (te *TestEnvironment) CreateTempDir(pattern string) string {
	te.mu.Lock()
	defer te.mu.Unlock()

	tempDir, err := os.MkdirTemp("", pattern)
	if err != nil {
		te.t.Fatalf("Failed to create temp dir: %v", err)
	}

	te.tempDirs = append(te.tempDirs, tempDir)
	return tempDir
}

// TempDir returns the first temporary directory (for backward compatibility)
func (te *TestEnvironment) TempDir() string {
	te.mu.Lock()
	defer te.mu.Unlock()

	if len(te.tempDirs) == 0 {
		return te.CreateTempDir("go-plugins-test")
	}
	return te.tempDirs[0]
}

// CreateTempFile creates a temporary file with the given name and content
func (te *TestEnvironment) CreateTempFile(name, content string) string {
	tempDir := te.CreateTempDir("go-plugins-test")
	filePath := filepath.Join(tempDir, name)

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		te.t.Fatalf("Failed to create temp file %s: %v", filePath, err)
	}

	return filePath
}

// CreateTempFileWithContent creates a temporary file with the given name and content
func (te *TestEnvironment) CreateTempFileWithContent(name, content string) string {
	return te.CreateTempFile(name, content)
}

// CreateMockHTTPServer creates a mock HTTP server with request/response logging
func (te *TestEnvironment) CreateMockHTTPServer(handler http.HandlerFunc) *MockHTTPServer {
	te.mu.Lock()
	defer te.mu.Unlock()

	mockServer := &MockHTTPServer{
		requests:  make([]*http.Request, 0),
		responses: make(map[string]MockResponse),
		mu:        sync.RWMutex{},
	}

	// Wrap handler to log requests
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockServer.mu.Lock()
		mockServer.requests = append(mockServer.requests, r.Clone(context.Background()))
		mockServer.mu.Unlock()

		if handler != nil {
			handler(w, r)
		} else {
			mockServer.defaultHandler(w, r)
		}
	})

	server := httptest.NewServer(loggingHandler)
	mockServer.Server = server

	te.mockServers = append(te.mockServers, server)
	return mockServer
}

// CreateMockHTTPSServer creates a mock HTTPS server with TLS configuration
func (te *TestEnvironment) CreateMockHTTPSServer(handler http.HandlerFunc) *MockHTTPServer {
	te.mu.Lock()
	defer te.mu.Unlock()

	mockServer := &MockHTTPServer{
		requests:  make([]*http.Request, 0),
		responses: make(map[string]MockResponse),
		mu:        sync.RWMutex{},
	}

	// Wrap handler to log requests
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockServer.mu.Lock()
		mockServer.requests = append(mockServer.requests, r.Clone(context.Background()))
		mockServer.mu.Unlock()

		if handler != nil {
			handler(w, r)
		} else {
			mockServer.defaultHandler(w, r)
		}
	})

	server := httptest.NewTLSServer(loggingHandler)
	mockServer.Server = server

	te.tlsServers = append(te.tlsServers, server)
	return mockServer
}

// CreateUnixSocket creates a Unix domain socket for testing (Linux/macOS only)
func (te *TestEnvironment) CreateUnixSocket() string {
	if runtime.GOOS == "windows" {
		te.t.Skip("Unix sockets not supported on Windows")
	}

	te.mu.Lock()
	defer te.mu.Unlock()

	tempDir := te.CreateTempDir("unix_socket_test")
	socketPath := filepath.Join(tempDir, "test.sock")

	te.unixSockets = append(te.unixSockets, socketPath)
	return socketPath
}

// AddCleanupFunc adds a custom cleanup function
func (te *TestEnvironment) AddCleanupFunc(fn func()) {
	te.mu.Lock()
	defer te.mu.Unlock()
	te.cleanup = append(te.cleanup, fn)
}

// Cleanup cleans up all resources created during testing
func (te *TestEnvironment) Cleanup() {
	te.mu.Lock()
	defer te.mu.Unlock()

	// Run custom cleanup functions
	for _, fn := range te.cleanup {
		fn()
	}

	// Close mock servers
	for _, server := range te.mockServers {
		server.Close()
	}

	// Close TLS servers
	for _, server := range te.tlsServers {
		server.Close()
	}

	// Remove Unix sockets
	for _, socketPath := range te.unixSockets {
		if err := os.Remove(socketPath); err != nil {
			te.t.Logf("Warning: failed to remove socket %s: %v", socketPath, err)
		}
	}

	// Remove temp directories
	for _, tempDir := range te.tempDirs {
		if err := os.RemoveAll(tempDir); err != nil {
			te.t.Logf("Warning: failed to remove temp dir %s: %v", tempDir, err)
		}
	}
}

// MockHTTPServer provides advanced mocking capabilities for HTTP testing
type MockHTTPServer struct {
	*httptest.Server
	requests  []*http.Request
	responses map[string]MockResponse
	mu        sync.RWMutex
}

// MockResponse defines a mock HTTP response
type MockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       interface{}
	Delay      time.Duration
}

// SetResponse sets a mock response for a specific endpoint
func (ms *MockHTTPServer) SetResponse(method, path string, response MockResponse) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	key := fmt.Sprintf("%s %s", method, path)
	ms.responses[key] = response
}

// GetRequests returns all captured requests
func (ms *MockHTTPServer) GetRequests() []*http.Request {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	// Return a copy to prevent race conditions
	requests := make([]*http.Request, len(ms.requests))
	copy(requests, ms.requests)
	return requests
}

// GetRequestCount returns the number of requests received
func (ms *MockHTTPServer) GetRequestCount() int {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return len(ms.requests)
}

// ClearRequests clears the request history
func (ms *MockHTTPServer) ClearRequests() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.requests = ms.requests[:0]
}

// defaultHandler provides default behavior for mock server
func (ms *MockHTTPServer) defaultHandler(w http.ResponseWriter, r *http.Request) {
	ms.mu.RLock()
	key := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
	response, exists := ms.responses[key]
	ms.mu.RUnlock()

	if exists {
		ms.handleConfiguredResponse(w, response)
		return
	}

	ms.handleDefaultResponse(w, r)
}

// handleConfiguredResponse processes a pre-configured mock response
func (ms *MockHTTPServer) handleConfiguredResponse(w http.ResponseWriter, response MockResponse) {
	// Apply delay if specified
	if response.Delay > 0 {
		time.Sleep(response.Delay)
	}

	// Set headers
	for k, v := range response.Headers {
		w.Header().Set(k, v)
	}

	// Set status code
	if response.StatusCode != 0 {
		w.WriteHeader(response.StatusCode)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Write body
	ms.writeResponseBody(w, response.Body)
}

// handleDefaultResponse generates a default successful response
func (ms *MockHTTPServer) handleDefaultResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Return a generic response that works with both string and object types
	defaultResp := map[string]interface{}{
		"data":       "ok", // String data that can be unmarshaled to string
		"request_id": r.Header.Get("X-Request-ID"),
		"metadata":   map[string]string{"test": "true"},
	}
	if err := json.NewEncoder(w).Encode(defaultResp); err != nil {
		http.Error(w, "Failed to encode default response", http.StatusInternalServerError)
	}
}

// writeResponseBody writes the response body based on its type
func (ms *MockHTTPServer) writeResponseBody(w http.ResponseWriter, body interface{}) {
	if body != nil {
		if str, ok := body.(string); ok {
			if _, err := w.Write([]byte(str)); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
			}
		} else {
			if err := json.NewEncoder(w).Encode(body); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			}
		}
	}
}

// TestDataFactory provides factory methods for creating test data
type TestDataFactory struct{}

// CreateValidPluginConfig creates a valid plugin configuration for testing
func (tdf *TestDataFactory) CreateValidPluginConfig(name string) PluginConfig {
	return PluginConfig{
		Name:      name,
		Type:      "test",
		Transport: TransportHTTP,
		Endpoint:  "http://localhost:8080/api",
		Priority:  1,
		Enabled:   true,
		Auth: AuthConfig{
			Method: AuthNone,
		},
		Retry: RetryConfig{
			MaxRetries:      3,
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     5 * time.Second,
			Multiplier:      2.0,
		},
		CircuitBreaker: CircuitBreakerConfig{
			Enabled:             true,
			FailureThreshold:    5,
			RecoveryTimeout:     30 * time.Second,
			MinRequestThreshold: 3,
			SuccessThreshold:    2,
		},
		HealthCheck: HealthCheckConfig{
			Enabled:      true,
			Interval:     30 * time.Second,
			Timeout:      5 * time.Second,
			FailureLimit: 3,
		},
		Connection: ConnectionConfig{
			MaxConnections:     10,
			MaxIdleConnections: 5,
			IdleTimeout:        30 * time.Second,
			ConnectionTimeout:  10 * time.Second,
			RequestTimeout:     30 * time.Second,
			KeepAlive:          true,
		},
		RateLimit: RateLimitConfig{
			Enabled:           false,
			RequestsPerSecond: 10.0,
			BurstSize:         20,
			TimeWindow:        time.Second,
		},
	}
}

// CreateManagerConfig creates a valid manager configuration for testing
func (tdf *TestDataFactory) CreateManagerConfig(plugins ...PluginConfig) ManagerConfig {
	config := GetDefaultManagerConfig()
	config.Plugins = plugins
	return config
}

// CreateExecutionContext creates a valid execution context for testing
func (tdf *TestDataFactory) CreateExecutionContext() ExecutionContext {
	return ExecutionContext{
		RequestID:  "test-request-123",
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		Headers: map[string]string{
			"User-Agent": "test-client",
		},
		Metadata: map[string]string{
			"test": "true",
		},
	}
}

// AdvancedMockPlugin provides an enhanced mock implementation for complex testing scenarios
type AdvancedMockPlugin[Req, Resp any] struct {
	name             string
	executeFunc      func(context.Context, ExecutionContext, Req) (Resp, error)
	healthFunc       func(context.Context) HealthStatus
	infoFunc         func() PluginInfo
	closeFunc        func() error
	executionCount   atomic.Int64
	healthCheckCount atomic.Int64
	closed           atomic.Bool
	mu               sync.RWMutex
}

// NewAdvancedMockPlugin creates a new advanced mock plugin for testing
func NewAdvancedMockPlugin[Req, Resp any](name string) *AdvancedMockPlugin[Req, Resp] {
	return &AdvancedMockPlugin[Req, Resp]{
		name: name,
	}
}

// SetExecuteFunc sets the execute function for the mock
func (amp *AdvancedMockPlugin[Req, Resp]) SetExecuteFunc(fn func(context.Context, ExecutionContext, Req) (Resp, error)) {
	amp.mu.Lock()
	defer amp.mu.Unlock()
	amp.executeFunc = fn
}

// SetHealthFunc sets the health check function for the mock
func (amp *AdvancedMockPlugin[Req, Resp]) SetHealthFunc(fn func(context.Context) HealthStatus) {
	amp.mu.Lock()
	defer amp.mu.Unlock()
	amp.healthFunc = fn
}

// SetInfoFunc sets the info function for the mock
func (amp *AdvancedMockPlugin[Req, Resp]) SetInfoFunc(fn func() PluginInfo) {
	amp.mu.Lock()
	defer amp.mu.Unlock()
	amp.infoFunc = fn
}

// SetCloseFunc sets the close function for the mock
func (amp *AdvancedMockPlugin[Req, Resp]) SetCloseFunc(fn func() error) {
	amp.mu.Lock()
	defer amp.mu.Unlock()
	amp.closeFunc = fn
}

// Execute implements the Plugin interface Execute method
func (amp *AdvancedMockPlugin[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	amp.executionCount.Add(1)

	amp.mu.RLock()
	fn := amp.executeFunc
	amp.mu.RUnlock()

	if fn != nil {
		return fn(ctx, execCtx, request)
	}

	// Default implementation - create zero value response
	var resp Resp
	return resp, nil
}

// Health implements the Plugin interface Health method
func (amp *AdvancedMockPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	amp.healthCheckCount.Add(1)

	amp.mu.RLock()
	fn := amp.healthFunc
	amp.mu.RUnlock()

	if fn != nil {
		return fn(ctx)
	}

	// Default implementation
	return HealthStatus{
		Status:       StatusHealthy,
		Message:      "Mock plugin is healthy",
		LastCheck:    time.Now(),
		ResponseTime: 1 * time.Millisecond,
		Metadata: map[string]string{
			"plugin": amp.name,
			"mock":   "true",
		},
	}
}

// Info implements the Plugin interface Info method
func (amp *AdvancedMockPlugin[Req, Resp]) Info() PluginInfo {
	amp.mu.RLock()
	fn := amp.infoFunc
	amp.mu.RUnlock()

	if fn != nil {
		return fn()
	}

	// Default implementation
	return PluginInfo{
		Name:         amp.name,
		Version:      "1.0.0-mock",
		Description:  "Advanced mock plugin for testing",
		Author:       "go-plugins test suite",
		Capabilities: []string{"mock", "test"},
		Metadata: map[string]string{
			"transport": "http",
			"mock":      "true",
		},
	}
}

// Close implements the Plugin interface Close method
func (amp *AdvancedMockPlugin[Req, Resp]) Close() error {
	if amp.closed.CompareAndSwap(false, true) {
		amp.mu.RLock()
		fn := amp.closeFunc
		amp.mu.RUnlock()

		if fn != nil {
			return fn()
		}
	}
	return nil
}

// GetExecutionCount returns the number of times Execute was called
func (amp *AdvancedMockPlugin[Req, Resp]) GetExecutionCount() int64 {
	return amp.executionCount.Load()
}

// GetHealthCheckCount returns the number of times Health was called
func (amp *AdvancedMockPlugin[Req, Resp]) GetHealthCheckCount() int64 {
	return amp.healthCheckCount.Load()
}

// IsClosed returns true if the plugin has been closed
func (amp *AdvancedMockPlugin[Req, Resp]) IsClosed() bool {
	return amp.closed.Load()
}

// TestAssertions provides enhanced test assertion helpers
type TestAssertions struct {
	t *testing.T
}

// NewTestAssertions creates new test assertion helper
func NewTestAssertions(t *testing.T) *TestAssertions {
	return &TestAssertions{t: t}
}

// AssertNoError asserts that error is nil, with context
func (ta *TestAssertions) AssertNoError(err error, context string) {
	ta.t.Helper()
	if err != nil {
		ta.t.Fatalf("Expected no error in %s, got: %v", context, err)
	}
}

// AssertError asserts that error is not nil, with context
func (ta *TestAssertions) AssertError(err error, context string) {
	ta.t.Helper()
	if err == nil {
		ta.t.Fatalf("Expected error in %s, got nil", context)
	}
}

// AssertEqual asserts that two values are equal
func (ta *TestAssertions) AssertEqual(expected, actual interface{}, context string) {
	ta.t.Helper()
	if expected != actual {
		ta.t.Fatalf("Expected %v in %s, got %v", expected, context, actual)
	}
}

// AssertTrue asserts that condition is true
func (ta *TestAssertions) AssertTrue(condition bool, context string) {
	ta.t.Helper()
	if !condition {
		ta.t.Fatalf("Expected true condition in %s", context)
	}
}

// AssertFalse asserts that condition is false
func (ta *TestAssertions) AssertFalse(condition bool, context string) {
	ta.t.Helper()
	if condition {
		ta.t.Fatalf("Expected false condition in %s", context)
	}
}

// AssertNotNil asserts that value is not nil
func (ta *TestAssertions) AssertNotNil(value interface{}, context string) {
	ta.t.Helper()
	if value == nil {
		ta.t.Fatalf("Expected non-nil value in %s", context)
	}
}

// WaitForCondition waits for a condition to be true with timeout
func (ta *TestAssertions) WaitForCondition(condition func() bool, timeout time.Duration, message string) {
	ta.t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	ta.t.Fatalf("Condition not met within %v: %s", timeout, message)
}

// CrossPlatformHelpers provides OS-aware test utilities
type CrossPlatformHelpers struct{}

// IsWindows returns true if running on Windows
func (cph *CrossPlatformHelpers) IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsUnixLike returns true if running on Unix-like system (Linux/macOS)
func (cph *CrossPlatformHelpers) IsUnixLike() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

// GetValidSocketPath returns a valid socket path for the current OS
func (cph *CrossPlatformHelpers) GetValidSocketPath(tempDir string) string {
	if cph.IsWindows() {
		// Windows named pipe
		return `\\.\pipe\test_socket_` + fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// Unix socket
	return filepath.Join(tempDir, "test.sock")
}

// CreateTLSConfig creates a test TLS configuration
func (cph *CrossPlatformHelpers) CreateTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // Only for testing
		MinVersion:         tls.VersionTLS12,
	}
}

// GetFreePort returns a free port for testing
func (cph *CrossPlatformHelpers) GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := l.Close(); err != nil {
			// Log error but don't fail test since this is cleanup
		}
	}()

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("expected TCP address, got %T", l.Addr())
	}
	return addr.Port, nil
}

// TestRequest represents a test request structure shared across all test files
type TestRequest struct {
	Action string            `json:"action"`
	Data   map[string]string `json:"data"`
}

// TestResponse represents a test response structure shared across all test files
type TestResponse struct {
	Result  string            `json:"result"`
	Details map[string]string `json:"details"`
}

// Global helper instances
var (
	TestData      = &TestDataFactory{}
	CrossPlatform = &CrossPlatformHelpers{}
)
