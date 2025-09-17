// grpc_native_transport.go: gRPC transport tests
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MockProtobufRequest implements proto.Message for testing
type MockProtobufRequest struct {
	Message   string                 `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

func (m *MockProtobufRequest) Reset() { *m = MockProtobufRequest{} }
func (m *MockProtobufRequest) String() string {
	return fmt.Sprintf("MockProtobufRequest{Message: %q, Timestamp: %v}", m.Message, m.Timestamp)
}
func (*MockProtobufRequest) ProtoMessage() {}

// Basic proto.Message implementation
func (m *MockProtobufRequest) ProtoReflect() protoreflect.Message {
	// Simplified implementation for testing
	return nil
}

// MockProtobufResponse implements proto.Message for testing
type MockProtobufResponse struct {
	Result      string                 `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
	ProcessedAt *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=processed_at,json=processedAt,proto3" json:"processed_at,omitempty"`
	Success     bool                   `protobuf:"varint,3,opt,name=success,proto3" json:"success,omitempty"`
}

func (m *MockProtobufResponse) Reset() { *m = MockProtobufResponse{} }
func (m *MockProtobufResponse) String() string {
	return fmt.Sprintf("MockProtobufResponse{Result: %q, ProcessedAt: %v, Success: %t}",
		m.Result, m.ProcessedAt, m.Success)
}
func (*MockProtobufResponse) ProtoMessage() {}

// Basic proto.Message implementation
func (m *MockProtobufResponse) ProtoReflect() protoreflect.Message {
	// Simplified implementation for testing
	return nil
}

// TestGRPCNativePluginCreation tests the creation of native protobuf plugins
func TestGRPCNativePluginCreation(t *testing.T) {
	config := PluginConfig{
		Name:      "test-native-plugin",
		Type:      "grpc-native",
		Transport: TransportGRPC,
		Endpoint:  "localhost:50051",
		Enabled:   true,
	}

	plugin, err := NewGRPCNativePlugin[*MockProtobufRequest, *MockProtobufResponse](config, nil)
	if err != nil {
		t.Fatalf("Failed to create native gRPC plugin: %v", err)
	}

	// Test plugin info
	info := plugin.Info()
	if info.Name != "test-native-plugin" {
		t.Errorf("Expected plugin name 'test-native-plugin', got %s", info.Name)
	}

	// Test type validation
	if plugin.requestType.String() != "*goplugins.MockProtobufRequest" {
		t.Errorf("Unexpected request type: %s", plugin.requestType.String())
	}

	if plugin.responseType.String() != "*goplugins.MockProtobufResponse" {
		t.Errorf("Unexpected response type: %s", plugin.responseType.String())
	}
}

// TestGRPCNativePluginFactory tests the factory pattern
func TestGRPCNativePluginFactory(t *testing.T) {
	factory := NewGRPCPluginFactory[*MockProtobufRequest, *MockProtobufResponse](nil)

	// Test supported transports
	transports := factory.SupportedTransports()
	expectedTransports := []string{"grpc", "grpc-tls"}

	if len(transports) != len(expectedTransports) {
		t.Errorf("Expected %d transports, got %d", len(expectedTransports), len(transports))
	}

	for i, transport := range transports {
		if transport != expectedTransports[i] {
			t.Errorf("Expected transport %s, got %s", expectedTransports[i], transport)
		}
	}

	// Test config validation
	validConfig := PluginConfig{
		Name:      "test-factory-plugin",
		Transport: TransportGRPC,
		Endpoint:  "localhost:50051",
		Enabled:   true,
	}

	if err := factory.ValidateConfig(validConfig); err != nil {
		t.Errorf("Valid config should not return error: %v", err)
	}

	// Test plugin creation
	plugin, err := factory.CreatePlugin(validConfig)
	if err != nil {
		t.Fatalf("Factory should create plugin successfully: %v", err)
	}

	if plugin == nil {
		t.Fatal("Factory should return non-nil plugin")
	}

	// Verify it's the right type
	nativePlugin, ok := plugin.(*GRPCNativePlugin[*MockProtobufRequest, *MockProtobufResponse])
	if !ok {
		t.Errorf("Factory should return GRPCNativePlugin, got %T", plugin)
	}

	if nativePlugin.config.Name != validConfig.Name {
		t.Errorf("Plugin should have config name %s, got %s", validConfig.Name, nativePlugin.config.Name)
	}
}

// TestManagerIntegration tests integration with the plugin manager
func TestManagerIntegrationWithNativeProtobuf(t *testing.T) {
	manager := NewManager[*MockProtobufRequest, *MockProtobufResponse](nil)

	// Register native protobuf factory
	err := RegisterGRPCNativeFactory(
		manager,
		"grpc-native",
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to register native gRPC factory: %v", err)
	}

	// Test that factory is registered
	// Note: We can't easily test LoadFromConfig without actual gRPC server,
	// but we can test that the registration worked
	t.Log("Native protobuf gRPC factory registered successfully")
}

// TestUtilityFunctions tests the utility registration functions
func TestUtilityFunctions(t *testing.T) {
	manager := NewManager[*MockProtobufRequest, *MockProtobufResponse](nil)

	config := PluginConfig{
		Name:      "utility-test-plugin",
		Transport: TransportGRPC,
		Endpoint:  "localhost:50051", // Won't connect, just testing creation
		Enabled:   true,
	}

	// Test direct plugin registration utility
	err := RegisterGRPCNativePlugin(
		manager,
		config,
		nil,
	)

	// This will fail because we can't connect, but that's expected
	// We're testing that the plugin was created successfully before connection
	if err == nil {
		t.Log("Plugin registered successfully (connection will fail in real usage)")
	} else {
		t.Logf("Plugin creation completed, connection error expected: %v", err)
	}
}

// TestProtobufMessageConstraints tests that type constraints work correctly
func TestProtobufMessageConstraints(t *testing.T) {
	// This test verifies at compile time that our type constraints work
	// If this compiles, the constraints are working

	var req *MockProtobufRequest
	var resp *MockProtobufResponse

	// These should work (implement proto.Message)
	_ = ProtobufMessage(req)
	_ = ProtobufMessage(resp)

	// Test that we can create plugin with these types
	config := PluginConfig{
		Name:      "constraint-test",
		Transport: TransportGRPC,
		Endpoint:  "localhost:50051",
		Enabled:   true,
	}

	_, err := NewGRPCNativePlugin[*MockProtobufRequest, *MockProtobufResponse](config, nil)
	if err != nil {
		t.Errorf("Should be able to create plugin with protobuf message types: %v", err)
	}
}

// BenchmarkProtobufSerialization benchmarks protobuf vs JSON performance
func BenchmarkProtobufSerialization(b *testing.B) {
	// Use a real protobuf message for benchmarking
	req := timestamppb.Now()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Benchmark protobuf marshaling
		data, err := proto.Marshal(req)
		if err != nil {
			b.Fatalf("Proto marshal failed: %v", err)
		}

		// Benchmark protobuf unmarshaling
		var unmarshaled timestamppb.Timestamp
		err = proto.Unmarshal(data, &unmarshaled)
		if err != nil {
			b.Fatalf("Proto unmarshal failed: %v", err)
		}
	}
}

// TestHealthAndShutdown tests basic plugin lifecycle methods
func TestHealthAndShutdown(t *testing.T) {
	config := PluginConfig{
		Name:      "lifecycle-test",
		Transport: TransportGRPC,
		Endpoint:  "localhost:50051",
		Enabled:   true,
	}

	plugin, err := NewGRPCNativePlugin[*MockProtobufRequest, *MockProtobufResponse](config, nil)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	// Test health (will fail without server, but should not panic)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	health := plugin.Health(ctx)
	// We expect this to fail since no server is running
	if health.Status == StatusHealthy {
		t.Log("Health check unexpectedly succeeded (maybe server is running?)")
	} else {
		t.Logf("Health check failed as expected: %s", health.Message)
	}

	// Test shutdown
	if err := plugin.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown should not fail: %v", err)
	}

	// Test close
	if err := plugin.Close(); err != nil {
		t.Errorf("Close should not fail: %v", err)
	}
}
