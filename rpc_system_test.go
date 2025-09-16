// rpc_system.go: rpc system tests
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Mock implementation for testing
type mockRequestHandler struct {
	handlerType string
}

func (m *mockRequestHandler) HandleRequest(ctx context.Context, request *PluginRequest) (*PluginResponse, error) {
	// Echo back the request data with a prefix
	responseData := fmt.Sprintf("Handler %s processed: %s", m.handlerType, string(request.Data))

	return &PluginResponse{
		ID:        request.ID,
		Success:   true,
		Data:      []byte(responseData),
		Metadata:  request.Metadata,
		Timestamp: time.Now(),
	}, nil
}

func (m *mockRequestHandler) GetRequestType() string {
	return m.handlerType
}

func TestRPCProtocol_BasicCommunication(t *testing.T) {
	logger := NewTestLogger()

	// Create communication bridge
	config := DefaultBridgeConfig
	config.ListenPort = 0 // Let system choose port
	bridge := NewCommunicationBridge(config, logger)
	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Create RPC protocol instance
	rpcProtocol := NewRPCProtocol(logger, bridge)

	// Register a test handler
	testHandler := &mockRequestHandler{handlerType: "test"}
	err = rpcProtocol.RegisterHandler("test", testHandler)
	if err != nil {
		t.Fatalf("Failed to register handler: %v", err)
	}

	// Start RPC server
	ctx := context.Background()
	err = rpcProtocol.StartServer(ctx)
	if err != nil {
		t.Fatalf("Failed to start RPC server: %v", err)
	}
	defer func() {
		if err := rpcProtocol.Stop(); err != nil {
			t.Logf("Warning: failed to stop RPC protocol: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect client to RPC port (not bridge port)
	address := fmt.Sprintf("127.0.0.1:%d", rpcProtocol.GetRPCPort())
	err = rpcProtocol.ConnectClient(address)
	if err != nil {
		t.Fatalf("Failed to connect RPC client: %v", err)
	}

	// Test ping
	err = rpcProtocol.Ping()
	if err != nil {
		t.Errorf("Ping failed: %v", err)
	}

	// Debug: check if server is running
	if !rpcProtocol.IsRunning() {
		t.Errorf("RPC server should be running")
	}

	// Debug: print actual port
	t.Logf("RPC server running on port: %d", rpcProtocol.GetRPCPort())

	// Test remote method call
	testData := map[string]string{"message": "Hello RPC!"}
	result, err := rpcProtocol.CallRemoteMethod("test", "echo", testData)
	if err != nil {
		t.Errorf("Remote method call failed: %v", err)
	}

	// Verify result
	if result == nil {
		t.Errorf("Expected non-nil result")
	}

	// Test status
	status, err := rpcProtocol.GetRemoteStatus()
	if err != nil {
		t.Errorf("Failed to get remote status: %v", err)
	}

	if !status.Running {
		t.Errorf("Expected server to be running")
	}
}

func TestRPCProtocol_MultipleHandlers(t *testing.T) {
	logger := NewTestLogger()

	// Create communication bridge
	config := DefaultBridgeConfig
	config.ListenPort = 0 // Let system choose port
	bridge := NewCommunicationBridge(config, logger)
	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Create RPC protocol instance
	rpcProtocol := NewRPCProtocol(logger, bridge)

	// Register multiple handlers
	handlers := []string{"handler1", "handler2", "handler3"}
	for _, name := range handlers {
		handler := &mockRequestHandler{handlerType: name}
		err = rpcProtocol.RegisterHandler(name, handler)
		if err != nil {
			t.Fatalf("Failed to register handler %s: %v", name, err)
		}
	}

	// Start RPC server
	ctx := context.Background()
	err = rpcProtocol.StartServer(ctx)
	if err != nil {
		t.Fatalf("Failed to start RPC server: %v", err)
	}
	defer func() {
		if err := rpcProtocol.Stop(); err != nil {
			t.Logf("Warning: failed to stop RPC protocol: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect client to RPC port
	address := fmt.Sprintf("127.0.0.1:%d", rpcProtocol.GetRPCPort())
	err = rpcProtocol.ConnectClient(address)
	if err != nil {
		t.Fatalf("Failed to connect RPC client: %v", err)
	}

	// Test each handler
	for _, handlerName := range handlers {
		testData := map[string]string{"handler": handlerName}
		result, err := rpcProtocol.CallRemoteMethod(handlerName, "process", testData)
		if err != nil {
			t.Errorf("Call to %s failed: %v", handlerName, err)
			continue
		}

		if result == nil {
			t.Errorf("Expected non-nil result from %s", handlerName)
		}
	}

	// Verify stats
	stats := rpcProtocol.GetStats()
	if stats["registered_handlers"] != len(handlers) {
		t.Errorf("Expected %d registered handlers, got %v", len(handlers), stats["registered_handlers"])
	}
}

func TestRPCProtocol_ErrorHandling(t *testing.T) {
	logger := NewTestLogger()

	// Create communication bridge
	config := DefaultBridgeConfig
	config.ListenPort = 0 // Let system choose port
	bridge := NewCommunicationBridge(config, logger)
	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Create RPC protocol instance
	rpcProtocol := NewRPCProtocol(logger, bridge)

	// Start RPC server
	ctx := context.Background()
	err = rpcProtocol.StartServer(ctx)
	if err != nil {
		t.Fatalf("Failed to start RPC server: %v", err)
	}
	defer func() {
		if err := rpcProtocol.Stop(); err != nil {
			t.Logf("Warning: failed to stop RPC protocol: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect client to RPC port
	address := fmt.Sprintf("127.0.0.1:%d", rpcProtocol.GetRPCPort())
	err = rpcProtocol.ConnectClient(address)
	if err != nil {
		t.Fatalf("Failed to connect RPC client: %v", err)
	}

	// Test call to non-existent handler
	_, err = rpcProtocol.CallRemoteMethod("nonexistent", "method", nil)
	if err == nil {
		t.Errorf("Expected error when calling non-existent handler")
	}

	// Test duplicate handler registration
	testHandler := &mockRequestHandler{handlerType: "test"}
	err = rpcProtocol.RegisterHandler("test", testHandler)
	if err != nil {
		t.Fatalf("Failed to register first handler: %v", err)
	}

	err = rpcProtocol.RegisterHandler("test", testHandler)
	if err == nil {
		t.Errorf("Expected error when registering duplicate handler")
	}

	// Test double server start
	err = rpcProtocol.StartServer(ctx)
	if err == nil {
		t.Errorf("Expected error when starting server twice")
	}

	// Test client operations before connecting
	newRPC := NewRPCProtocol(logger, bridge)
	err = newRPC.Ping()
	if err == nil {
		t.Errorf("Expected error when pinging before connecting")
	}

	_, err = newRPC.CallRemoteMethod("test", "method", nil)
	if err == nil {
		t.Errorf("Expected error when calling method before connecting")
	}
}

func TestRPCProtocol_ConcurrentCalls(t *testing.T) {
	logger := NewTestLogger()

	// Create communication bridge
	config := DefaultBridgeConfig
	config.ListenPort = 0 // Let system choose port
	bridge := NewCommunicationBridge(config, logger)
	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Create RPC protocol instance
	rpcProtocol := NewRPCProtocol(logger, bridge)

	// Register handler
	testHandler := &mockRequestHandler{handlerType: "concurrent"}
	err = rpcProtocol.RegisterHandler("concurrent", testHandler)
	if err != nil {
		t.Fatalf("Failed to register handler: %v", err)
	}

	// Start RPC server
	ctx := context.Background()
	err = rpcProtocol.StartServer(ctx)
	if err != nil {
		t.Fatalf("Failed to start RPC server: %v", err)
	}
	defer func() {
		if err := rpcProtocol.Stop(); err != nil {
			t.Logf("Warning: failed to stop RPC protocol: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect client to RPC port
	address := fmt.Sprintf("127.0.0.1:%d", rpcProtocol.GetRPCPort())
	err = rpcProtocol.ConnectClient(address)
	if err != nil {
		t.Fatalf("Failed to connect RPC client: %v", err)
	}

	// Make concurrent calls
	numCalls := 10
	results := make(chan error, numCalls)

	for i := 0; i < numCalls; i++ {
		go func(callID int) {
			testData := map[string]interface{}{
				"call_id": callID,
				"message": fmt.Sprintf("Call %d", callID),
			}

			_, err := rpcProtocol.CallRemoteMethod("concurrent", "process", testData)
			results <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numCalls; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("Concurrent call %d failed: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("Concurrent call %d timed out", i)
		}
	}
}

func TestRPCProtocol_JSONSerialization(t *testing.T) {

	// Test RPCMethodCall serialization
	call := &RPCMethodCall{
		PluginName: "test-plugin",
		Method:     "test-method",
		Args:       json.RawMessage(`{"key": "value"}`),
		ID:         "test-id",
		Timeout:    30 * time.Second,
	}

	data, err := json.Marshal(call)
	if err != nil {
		t.Fatalf("Failed to marshal RPCMethodCall: %v", err)
	}

	var unmarshaledCall RPCMethodCall
	err = json.Unmarshal(data, &unmarshaledCall)
	if err != nil {
		t.Fatalf("Failed to unmarshal RPCMethodCall: %v", err)
	}

	if unmarshaledCall.PluginName != call.PluginName {
		t.Errorf("Expected plugin name %s, got %s", call.PluginName, unmarshaledCall.PluginName)
	}

	if unmarshaledCall.Method != call.Method {
		t.Errorf("Expected method %s, got %s", call.Method, unmarshaledCall.Method)
	}

	// Test RPCMethodResult serialization
	result := &RPCMethodResult{
		ID:      "test-id",
		Success: true,
		Result:  json.RawMessage(`{"result": "success"}`),
		Error:   "",
	}

	data, err = json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal RPCMethodResult: %v", err)
	}

	var unmarshaledResult RPCMethodResult
	err = json.Unmarshal(data, &unmarshaledResult)
	if err != nil {
		t.Fatalf("Failed to unmarshal RPCMethodResult: %v", err)
	}

	if unmarshaledResult.ID != result.ID {
		t.Errorf("Expected ID %s, got %s", result.ID, unmarshaledResult.ID)
	}

	if unmarshaledResult.Success != result.Success {
		t.Errorf("Expected success %v, got %v", result.Success, unmarshaledResult.Success)
	}
}

func TestRPCProtocol_Lifecycle(t *testing.T) {
	logger := NewTestLogger()

	// Create communication bridge
	config := DefaultBridgeConfig
	config.ListenPort = 0 // Let system choose port
	bridge := NewCommunicationBridge(config, logger)
	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Create RPC protocol instance
	rpcProtocol := NewRPCProtocol(logger, bridge)

	// Verify initial state
	if rpcProtocol.IsRunning() {
		t.Errorf("Expected RPC server not to be running initially")
	}

	if rpcProtocol.IsConnected() {
		t.Errorf("Expected RPC client not to be connected initially")
	}

	// Start server
	ctx := context.Background()
	err = rpcProtocol.StartServer(ctx)
	if err != nil {
		t.Fatalf("Failed to start RPC server: %v", err)
	}

	if !rpcProtocol.IsRunning() {
		t.Errorf("Expected RPC server to be running after start")
	}

	// Connect client to RPC port
	address := fmt.Sprintf("127.0.0.1:%d", rpcProtocol.GetRPCPort())
	err = rpcProtocol.ConnectClient(address)
	if err != nil {
		t.Fatalf("Failed to connect RPC client: %v", err)
	}

	if !rpcProtocol.IsConnected() {
		t.Errorf("Expected RPC client to be connected")
	}

	// Stop protocol
	err = rpcProtocol.Stop()
	if err != nil {
		t.Errorf("Failed to stop RPC protocol: %v", err)
	}

	if rpcProtocol.IsRunning() {
		t.Errorf("Expected RPC server not to be running after stop")
	}

	if rpcProtocol.IsConnected() {
		t.Errorf("Expected RPC client not to be connected after stop")
	}
}

// Benchmark RPC method calls
func BenchmarkRPCProtocol_MethodCall(b *testing.B) {
	logger := NewTestLogger()

	// Setup
	config := DefaultBridgeConfig
	config.ListenPort = 0 // Let system choose port
	bridge := NewCommunicationBridge(config, logger)
	err := bridge.Start()
	if err != nil {
		b.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			b.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	rpcProtocol := NewRPCProtocol(logger, bridge)
	testHandler := &mockRequestHandler{handlerType: "benchmark"}

	err = rpcProtocol.RegisterHandler("benchmark", testHandler)
	if err != nil {
		b.Fatalf("Failed to register handler: %v", err)
	}

	ctx := context.Background()
	err = rpcProtocol.StartServer(ctx)
	if err != nil {
		b.Fatalf("Failed to start RPC server: %v", err)
	}
	defer func() {
		if err := rpcProtocol.Stop(); err != nil {
			b.Logf("Warning: failed to stop RPC protocol: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	address := fmt.Sprintf("127.0.0.1:%d", rpcProtocol.GetRPCPort())
	err = rpcProtocol.ConnectClient(address)
	if err != nil {
		b.Fatalf("Failed to connect RPC client: %v", err)
	}

	testData := map[string]string{"data": "benchmark"}

	b.ResetTimer()

	// Benchmark
	for i := 0; i < b.N; i++ {
		_, err := rpcProtocol.CallRemoteMethod("benchmark", "process", testData)
		if err != nil {
			b.Errorf("Method call failed: %v", err)
		}
	}
}
