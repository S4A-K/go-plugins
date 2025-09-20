// subprocess_integration_test.go: Integration tests for subprocess plugin functionality
//
// This file provides comprehensive integration testing for the subprocess plugin
// system, including mock servers, real process lifecycle management, and
// end-to-end communication scenarios.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Use existing TestRequest and TestResponse from observability_integration_test.go
// Extended for integration testing needs
type IntegrationTestRequest struct {
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Timestamp int64  `json:"timestamp"`
}

type IntegrationTestResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Timestamp int64  `json:"timestamp"`
}

// TestSubprocessIntegration_EndToEndCommunication tests complete subprocess
// plugin lifecycle with mock HTTP server communication.
func TestSubprocessIntegration_EndToEndCommunication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create professional subprocess plugin that implements the JSON protocol
	testExecutable := createSubprocessPluginExecutable(t)
	defer cleanupFile(t, testExecutable)

	factory := NewSubprocessPluginFactory[IntegrationTestRequest, IntegrationTestResponse](NewTestLogger())

	config := PluginConfig{
		Name:       "integration-test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
		Args:       []string{}, // No arguments needed for JSON protocol
		Env:        []string{"TEST_MODE=integration"},
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if closeErr := plugin.Close(); closeErr != nil {
			t.Logf("Warning: failed to close plugin: %v", closeErr)
		}
	}()

	// Test execution with mock server
	request := IntegrationTestRequest{
		Message:   "integration test message",
		RequestID: "test-123",
		Timestamp: time.Now().Unix(),
	}

	execCtx := ExecutionContext{
		RequestID: "exec-123",
		Timeout:   30 * time.Second,
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	if err != nil {
		t.Fatalf("Plugin execution failed: %v", err)
	}

	// Validate response from professional subprocess communication
	if response.Status != "success" {
		t.Errorf("Expected status 'success', got %s", response.Status)
	}

	if response.Message == "" {
		t.Error("Expected non-empty response message")
	}

	// Verify the response contains the processed request
	expectedMessage := "Processed: " + request.Message
	if response.Message != expectedMessage {
		t.Errorf("Expected message '%s', got '%s'", expectedMessage, response.Message)
	}

	// Verify request ID is preserved
	if response.RequestID != request.RequestID {
		t.Errorf("Expected request ID '%s', got '%s'", request.RequestID, response.RequestID)
	}
}

// TestSubprocessIntegration_ProcessLifecycleManagement tests the complete
// process lifecycle including startup, health monitoring, and graceful shutdown.
func TestSubprocessIntegration_ProcessLifecycleManagement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create professional subprocess plugin for lifecycle testing
	testExecutable := createSubprocessPluginExecutable(t)
	defer cleanupFile(t, testExecutable)

	factory := NewSubprocessPluginFactory[IntegrationTestRequest, IntegrationTestResponse](NewTestLogger())

	config := PluginConfig{
		Name:       "lifecycle-test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
		Args:       []string{}, // No arguments needed for JSON protocol
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	subprocessPlugin, ok := plugin.(*SubprocessPlugin[IntegrationTestRequest, IntegrationTestResponse])
	if !ok {
		t.Fatalf("Expected SubprocessPlugin, got %T", plugin)
	}

	// Test initial state
	initialHealth := subprocessPlugin.Health(ctx)
	if initialHealth.Status != StatusOffline {
		t.Errorf("Expected initial status %v, got %v", StatusOffline, initialHealth.Status)
	}

	// Start the process by executing a request
	request := IntegrationTestRequest{
		Message:   "startup test",
		RequestID: "startup-123",
	}

	execCtx := ExecutionContext{
		RequestID: "lifecycle-exec-123",
		Timeout:   10 * time.Second,
	}

	// This should trigger process startup
	_, err = subprocessPlugin.Execute(ctx, execCtx, request)

	// We expect this to fail since we don't have actual communication implementation,
	// but the process should start
	if err == nil {
		t.Log("Execution succeeded unexpectedly - communication may be implemented")
	} else {
		t.Logf("Execution failed as expected: %v", err)
	}

	// Verify process started
	processInfo := subprocessPlugin.GetInfo()
	if processInfo.Status == StatusStopped {
		t.Error("Process should have started")
	}

	if processInfo.PID == 0 {
		t.Error("Process should have valid PID")
	}

	// Test health after startup attempt
	healthAfterStart := subprocessPlugin.Health(ctx)
	if healthAfterStart.Status == StatusOffline {
		t.Log("Health check shows offline - expected if communication failed")
	}

	// Test graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 10*time.Second)
	defer shutdownCancel()

	err = subprocessPlugin.Stop(shutdownCtx)
	if err != nil {
		t.Errorf("Graceful shutdown failed: %v", err)
	}

	// Verify process stopped
	finalProcessInfo := subprocessPlugin.GetInfo()
	if finalProcessInfo.Status != StatusStopped {
		t.Errorf("Expected final status %v, got %v", StatusStopped, finalProcessInfo.Status)
	}
}

// Note: Removed TestSubprocessIntegration_ConcurrentExecution as it was testing
// HTTP client protocol instead of JSON stdin/stdout subprocess communication.
// The test was confusing and provided no real value. For proper concurrent
// JSON communication testing, see subprocess_json_communication_test.go

// TestSubprocessIntegration_ErrorRecovery tests error scenarios and recovery mechanisms.
func TestSubprocessIntegration_ErrorRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create professional subprocess plugin for error recovery testing
	testExecutable := createSubprocessPluginExecutable(t)
	defer cleanupFile(t, testExecutable)

	factory := NewSubprocessPluginFactory[IntegrationTestRequest, IntegrationTestResponse](NewTestLogger())

	config := PluginConfig{
		Name:       "error-recovery-test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
		Args:       []string{}, // No arguments needed for JSON protocol
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer func() {
		if closeErr := plugin.Close(); closeErr != nil {
			t.Logf("Warning: failed to close plugin: %v", closeErr)
		}
	}()

	subprocessPlugin, ok := plugin.(*SubprocessPlugin[IntegrationTestRequest, IntegrationTestResponse])
	if !ok {
		t.Fatalf("Expected SubprocessPlugin, got %T", plugin)
	}

	// Test multiple executions to trigger failure
	for i := 0; i < 5; i++ {
		request := IntegrationTestRequest{
			Message:   fmt.Sprintf("error test %d", i),
			RequestID: fmt.Sprintf("error-%d", i),
		}

		execCtx := ExecutionContext{
			RequestID: fmt.Sprintf("error-exec-%d", i),
			Timeout:   5 * time.Second,
		}

		_, err = plugin.Execute(ctx, execCtx, request)

		// We expect errors due to communication issues
		if err != nil {
			t.Logf("Execution %d failed as expected: %v", i, err)
		}

		// Check health after each execution
		health := subprocessPlugin.Health(ctx)
		t.Logf("Health after execution %d: %v - %s", i, health.Status, health.Message)
	}

	// Verify plugin can still be shut down gracefully even after errors
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err = subprocessPlugin.Stop(shutdownCtx)
	if err != nil {
		t.Errorf("Shutdown after errors failed: %v", err)
	}
}

// Mock HTTP server for subprocess communication testing
type MockPluginHTTPServer struct {
	server          *http.Server
	listener        net.Listener
	port            int
	requestReceived bool
	mutex           sync.RWMutex
	t               *testing.T
}

// NewMockPluginHTTPServer creates a new mock HTTP server for testing.
func NewMockPluginHTTPServer(t *testing.T) *MockPluginHTTPServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	mock := &MockPluginHTTPServer{
		listener: listener,
		port: func() int {
			if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
				return tcpAddr.Port
			}
			t.Fatalf("Expected TCP address, got %T", listener.Addr())
			return 0
		}(),
		t: t,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/execute", mock.handleExecute)
	mux.HandleFunc("/health", mock.handleHealth)

	mock.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := mock.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("Mock server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return mock
}

// Port returns the port the mock server is listening on.
func (m *MockPluginHTTPServer) Port() int {
	return m.port
}

// ReceivedRequest returns true if the server received at least one request.
func (m *MockPluginHTTPServer) ReceivedRequest() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.requestReceived
}

// Close shuts down the mock server.
func (m *MockPluginHTTPServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.server.Shutdown(ctx); err != nil {
		m.t.Logf("Mock server shutdown error: %v", err)
	}
}

// handleExecute handles plugin execution requests.
func (m *MockPluginHTTPServer) handleExecute(w http.ResponseWriter, r *http.Request) {
	m.mutex.Lock()
	m.requestReceived = true
	m.mutex.Unlock()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request IntegrationTestRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	response := IntegrationTestResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Processed: %s", request.Message),
		RequestID: request.RequestID,
		Timestamp: time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		m.t.Logf("Failed to encode response: %v", err)
	}
}

// handleHealth handles health check requests.
func (m *MockPluginHTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "healthy",
		"service": "mock-plugin-server",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		m.t.Logf("Failed to encode health response: %v", err)
	}
}

// createSubprocessPluginExecutable creates a professional test executable that implements the subprocess protocol.
func createSubprocessPluginExecutable(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "subprocess_plugin_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create a professional subprocess plugin that implements the JSON protocol
	goSourcePath := filepath.Join(tmpDir, "subprocess_plugin.go")
	goContent := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SubprocessRequest represents a request from the host
type SubprocessRequest struct {
	ID      string      ` + "`json:\"id\"`" + `
	Method  string      ` + "`json:\"method\"`" + `
	Payload interface{} ` + "`json:\"payload\"`" + `
	Context interface{} ` + "`json:\"context\"`" + `
}

// SubprocessResponse represents a response to the host
type SubprocessResponse struct {
	ID     string      ` + "`json:\"id\"`" + `
	Result interface{} ` + "`json:\"result,omitempty\"`" + `
	Error  *string     ` + "`json:\"error,omitempty\"`" + `
}

// IntegrationTestRequest represents the test request format
type IntegrationTestRequest struct {
	Message   string ` + "`json:\"message\"`" + `
	RequestID string ` + "`json:\"request_id\"`" + `
	Timestamp int64  ` + "`json:\"timestamp\"`" + `
}

// IntegrationTestResponse represents the test response format
type IntegrationTestResponse struct {
	Status    string ` + "`json:\"status\"`" + `
	Message   string ` + "`json:\"message\"`" + `
	RequestID string ` + "`json:\"request_id\"`" + `
	Timestamp int64  ` + "`json:\"timestamp\"`" + `
}

func main() {
	// Log to stderr so stdout is clean for JSON communication
	fmt.Fprintf(os.Stderr, "Professional subprocess plugin starting (PID: %d)\n", os.Getpid())

	// Create scanner for reading JSON requests from stdin
	scanner := bufio.NewScanner(os.Stdin)

	// Process requests in a loop
	for scanner.Scan() {
		line := scanner.Text()
		
		// Parse JSON request
		var request SubprocessRequest
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			sendError(request.ID, fmt.Sprintf("failed to parse request: %v", err))
			continue
		}

		// Process the request
		processRequest(request)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Subprocess plugin completed normally\n")
}

func processRequest(request SubprocessRequest) {
	switch request.Method {
	case "execute":
		handleExecuteRequest(request)
	default:
		sendError(request.ID, fmt.Sprintf("unknown method: %s", request.Method))
	}
}

func handleExecuteRequest(request SubprocessRequest) {
	// Parse the payload as IntegrationTestRequest
	payloadBytes, err := json.Marshal(request.Payload)
	if err != nil {
		sendError(request.ID, fmt.Sprintf("failed to marshal payload: %v", err))
		return
	}

	var testRequest IntegrationTestRequest
	if err := json.Unmarshal(payloadBytes, &testRequest); err != nil {
		sendError(request.ID, fmt.Sprintf("failed to parse test request: %v", err))
		return
	}

	// Create response
	response := IntegrationTestResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Processed: %s", testRequest.Message),
		RequestID: testRequest.RequestID,
		Timestamp: time.Now().Unix(),
	}

	// Send successful response
	sendSuccess(request.ID, response)
}

func sendSuccess(requestID string, result interface{}) {
	response := SubprocessResponse{
		ID:     requestID,
		Result: result,
	}
	
	sendResponse(response)
}

func sendError(requestID string, errorMsg string) {
	response := SubprocessResponse{
		ID:    requestID,
		Error: &errorMsg,
	}
	
	sendResponse(response)
}

func sendResponse(response SubprocessResponse) {
	// Serialize response to JSON
	responseBytes, err := json.Marshal(response)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal response: %v\n", err)
		return
	}

	// Send JSON response followed by newline (line-delimited JSON)
	fmt.Printf("%s\n", string(responseBytes))
	
	// Flush stdout to ensure immediate delivery
	os.Stdout.Sync()
}`

	err = os.WriteFile(goSourcePath, []byte(goContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create subprocess plugin Go source: %v", err)
	}

	// Compile the Go program
	executablePath := filepath.Join(tmpDir, "subprocess_plugin")
	if runtime.GOOS == "windows" {
		executablePath += ".exe"
	}

	if err := compileGoProgram(goSourcePath, executablePath); err != nil {
		t.Fatalf("Failed to compile subprocess plugin: %v", err)
	}

	return executablePath
}

// cleanupFile removes a file and logs any errors.
func cleanupFile(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Logf("Warning: failed to cleanup file %s: %v", path, err)
	}
}

// compileGoProgram compiles a Go source file to an executable
func compileGoProgram(sourcePath, executablePath string) error {
	// Initialize go module in the temp directory
	tempDir := filepath.Dir(sourcePath)

	// Create go.mod file
	goModPath := filepath.Join(tempDir, "go.mod")
	goModContent := `module testexecutable

go 1.21
`
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		return fmt.Errorf("failed to create go.mod: %v", err)
	}

	// Compile the program
	cmd := exec.Command("go", "build", "-o", executablePath, sourcePath)
	cmd.Dir = tempDir
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("compilation failed: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// Use existing TestLogger from logging.go
