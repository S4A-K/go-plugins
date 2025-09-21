// factory_test.go: Comprehensive test suite for UnifiedPluginFactory implementation
//
// This test suite ensures proper plugin factory functionality including plugin creation,
// configuration validation, error handling, and extensibility through custom factories.
// Tests are designed to be deterministic and CI-friendly.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Mock plugin for testing - implements the Plugin interface
type mockPlugin struct {
	name   string
	config PluginConfig
}

func (m *mockPlugin) Execute(ctx context.Context, execCtx ExecutionContext, request TestRequest) (TestResponse, error) {
	if m.name == "error-plugin" {
		return TestResponse{}, errors.New("mock execution error")
	}
	return TestResponse{Result: "mock response"}, nil
}

func (m *mockPlugin) Health(ctx context.Context) HealthStatus {
	return HealthStatus{
		Status:    StatusHealthy,
		Message:   "Mock plugin is healthy",
		LastCheck: time.Now(),
	}
}

func (m *mockPlugin) Info() PluginInfo {
	return PluginInfo{
		Name:        m.name,
		Version:     "1.0.0",
		Description: "Mock plugin for testing",
	}
}

func (m *mockPlugin) Close() error {
	return nil
}

// Mock factory function for custom transport
func createMockPlugin(config PluginConfig) (Plugin[TestRequest, TestResponse], error) {
	if config.Name == "fail-create" {
		return nil, errors.New("mock creation failure")
	}

	return &mockPlugin{
		name:   config.Name,
		config: config,
	}, nil
}

// mockPluginFactory implements PluginFactory interface for testing
type mockPluginFactory struct {
	shouldFail bool
}

// CreatePlugin implements PluginFactory interface
func (mpf *mockPluginFactory) CreatePlugin(config PluginConfig) (Plugin[TestRequest, TestResponse], error) {
	if mpf.shouldFail {
		return nil, errors.New("mock factory failure")
	}
	return createMockPlugin(config)
}

// SupportedTransports implements PluginFactory interface
func (mpf *mockPluginFactory) SupportedTransports() []string {
	return []string{"mock"}
}

// ValidateConfig implements PluginFactory interface
func (mpf *mockPluginFactory) ValidateConfig(config PluginConfig) error {
	if config.Name == "invalid" {
		return errors.New("invalid config")
	}
	return nil
}

// TestUnifiedPluginFactory_CreationAndInitialization tests factory creation and basic setup
func TestUnifiedPluginFactory_CreationAndInitialization(t *testing.T) {
	t.Run("CreateWithNilLogger", func(t *testing.T) {
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)
		if factory == nil {
			t.Fatal("Expected factory to be created with nil logger")
		}

		if factory.logger == nil {
			t.Error("Expected factory to have initialized logger even with nil input")
		}
	})

	t.Run("CreateWithValidLogger", func(t *testing.T) {
		logger := NewLogger(nil)
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		if factory == nil {
			t.Fatal("Expected factory to be created with valid logger")
		}

		if factory.logger == nil {
			t.Error("Expected factory to have logger set")
		}
	})

	t.Run("SupportedTransports", func(t *testing.T) {
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)
		transports := factory.SupportedTransports()

		if len(transports) == 0 {
			t.Error("Expected factory to support at least one transport type")
		}

		// Should support subprocess transport
		hasSubprocess := false
		for _, transport := range transports {
			if transport == string(TransportExecutable) {
				hasSubprocess = true
				break
			}
		}

		if !hasSubprocess {
			t.Error("Expected factory to support subprocess transport")
		}
	})
}

// TestUnifiedPluginFactory_ConfigValidation tests configuration validation
func TestUnifiedPluginFactory_ConfigValidation(t *testing.T) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	t.Run("InvalidConfig_EmptyName", func(t *testing.T) {
		config := PluginConfig{
			Name:       "", // Invalid: empty name
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Executable: "/usr/bin/echo",
			Enabled:    true,
		}

		_, err := factory.CreatePlugin(config)
		if err == nil {
			t.Error("Expected error for empty plugin name")
		}

		// Should be a config validation error from our unified factory
		if !strings.Contains(err.Error(), "invalid plugin configuration") {
			t.Errorf("Expected config validation error, got: %v", err)
		}
	})

	t.Run("InvalidConfig_EmptyEndpoint", func(t *testing.T) {
		config := PluginConfig{
			Name:       "test-plugin",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Executable: "", // Invalid: empty executable
			Enabled:    true,
			Auth:       AuthConfig{Method: AuthNone},
		}

		_, err := factory.CreatePlugin(config)
		if err == nil {
			t.Error("Expected error for empty endpoint")
		}

		// Should be a plugin creation error (delegated to subprocess factory)
		if !strings.Contains(err.Error(), "failed to create exec plugin") {
			t.Errorf("Expected error about executable plugin creation, got: %v", err)
		}
	})

	t.Run("ValidConfig", func(t *testing.T) {
		config := PluginConfig{
			Name:       "test-plugin",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Executable: "/bin/echo", // Use a command that exists on most systems
			Enabled:    true,
			Auth:       AuthConfig{Method: AuthNone},
		}

		// This might fail due to subprocess creation, but config validation should pass
		_, err := factory.CreatePlugin(config)

		// We expect it might fail at subprocess creation, not config validation
		if err != nil && strings.Contains(err.Error(), "invalid plugin configuration") {
			t.Errorf("Config validation should pass for valid config, got: %v", err)
		}
	})
}

// TestUnifiedPluginFactory_UnsupportedTransport tests handling of unsupported transports
func TestUnifiedPluginFactory_UnsupportedTransport(t *testing.T) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	config := PluginConfig{
		Name:       "test-plugin",
		Type:       "subprocess",
		Transport:  "unsupported-transport", // Invalid transport
		Executable: "/usr/bin/echo",
		Enabled:    true,
		Auth:       AuthConfig{Method: AuthNone},
	}

	_, err := factory.CreatePlugin(config)
	if err == nil {
		t.Error("Expected error for unsupported transport type")
	}

	if !strings.Contains(err.Error(), "unsupported transport type") {
		t.Errorf("Expected error about unsupported transport, got: %v", err)
	}
}

// TestUnifiedPluginFactory_CustomFactoryRegistration tests custom factory registration
func TestUnifiedPluginFactory_CustomFactoryRegistration(t *testing.T) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	t.Run("RegisterValidCustomFactory", func(t *testing.T) {
		mockFactory := &mockPluginFactory{}
		err := factory.RegisterFactory("mock", mockFactory)
		if err != nil {
			t.Errorf("Expected no error registering custom factory, got: %v", err)
		}

		// Verify transport is now supported
		transports := factory.SupportedTransports()
		hasMock := false
		for _, transport := range transports {
			if transport == "mock" {
				hasMock = true
				break
			}
		}

		if !hasMock {
			t.Error("Expected mock transport to be supported after registration")
		}
	})

	t.Run("RegisterCustomFactory_EmptyTransportType", func(t *testing.T) {
		mockFactory := &mockPluginFactory{}
		err := factory.RegisterFactory("", mockFactory)
		if err == nil {
			t.Error("Expected error for empty transport type")
		}

		// Should be a config validation error
		if !strings.Contains(err.Error(), "transport type cannot be empty") {
			t.Errorf("Expected transport type error, got: %v", err)
		}
	})

	t.Run("RegisterCustomFactory_NilFactoryFunction", func(t *testing.T) {
		err := factory.RegisterFactory("invalid", nil)
		if err == nil {
			t.Error("Expected error for nil factory function")
		}

		// Should be a config validation error
		if !strings.Contains(err.Error(), "factory cannot be nil") {
			t.Errorf("Expected factory function error, got: %v", err)
		}
	})

	t.Run("UseCustomFactory", func(t *testing.T) {
		// First register the custom factory for executable transport (will override default)
		mockFactory := &mockPluginFactory{}
		err := factory.RegisterFactory(string(TransportExecutable), mockFactory)
		if err != nil {
			t.Fatalf("Failed to register custom factory: %v", err)
		}

		config := PluginConfig{
			Name:       "custom-plugin",
			Type:       "mock",
			Transport:  TransportExecutable, // Use valid transport, custom factory will override
			Executable: "not-used-by-mock",
			Enabled:    true,
			Auth:       AuthConfig{Method: AuthNone},
		}

		plugin, err := factory.CreatePlugin(config)
		if err != nil {
			t.Errorf("Expected successful plugin creation with custom factory, got: %v", err)
		}

		if plugin == nil {
			t.Error("Expected non-nil plugin from custom factory")
		}
	})
}

// TestUnifiedPluginFactory_CustomFactoryFailure tests custom factory error handling
func TestUnifiedPluginFactory_CustomFactoryFailure(t *testing.T) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	// Register custom factory that can fail
	failingFactory := &mockPluginFactory{shouldFail: true}
	err := factory.RegisterFactory("failing-mock", failingFactory)
	if err != nil {
		t.Fatalf("Failed to register custom factory: %v", err)
	}

	config := PluginConfig{
		Name:      "fail-create", // This name triggers failure in mock factory
		Type:      "mock",
		Transport: "failing-mock",
		Endpoint:  "not-used",
		Enabled:   true,
		Auth:      AuthConfig{Method: AuthNone},
	}

	_, err = factory.CreatePlugin(config)
	if err == nil {
		t.Error("Expected error from failing custom factory")
	}

	if !strings.Contains(err.Error(), "failed to create") {
		t.Errorf("Expected error about plugin creation failure, got: %v", err)
	}
}

// TestUnifiedPluginFactory_SubprocessPluginCreation tests subprocess plugin creation
func TestUnifiedPluginFactory_SubprocessPluginCreation(t *testing.T) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	t.Run("ValidSubprocessConfig", func(t *testing.T) {
		config := PluginConfig{
			Name:       "echo-plugin",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Executable: "/bin/echo", // Standard command available on most Unix systems
			Enabled:    true,
			Auth:       AuthConfig{Method: AuthNone},
			Options: map[string]interface{}{
				"args": []string{"test"},
			},
		}

		// This will likely fail at subprocess creation since /bin/echo isn't a proper plugin
		// but we're testing that the factory processes the config correctly
		_, err := factory.CreatePlugin(config)

		// We expect failure, but not due to config validation or factory setup
		if err != nil {
			// The error should be from subprocess creation, not factory logic
			if strings.Contains(err.Error(), "invalid plugin configuration") ||
				strings.Contains(err.Error(), "unsupported transport") {
				t.Errorf("Factory setup failed unexpectedly: %v", err)
			}
			// Other errors (subprocess creation, etc.) are expected in this test environment
		}
	})

	t.Run("SubprocessConfig_WithCustomOptions", func(t *testing.T) {
		config := PluginConfig{
			Name:       "custom-subprocess",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Executable: "/bin/sh",
			Enabled:    true,
			Auth:       AuthConfig{Method: AuthNone},
			Options: map[string]interface{}{
				"args": []string{"-c", "echo hello"},
				"env":  []string{"TEST=value"},
			},
		}

		// Test that options are processed without errors
		_, err := factory.CreatePlugin(config)

		// Similar to above - subprocess creation may fail, but factory logic should work
		if err != nil && (strings.Contains(err.Error(), "invalid plugin configuration") ||
			strings.Contains(err.Error(), "unsupported transport")) {
			t.Errorf("Factory configuration processing failed: %v", err)
		}
	})
}

// TestUnifiedPluginFactory_GRPCPluginCreation tests gRPC plugin creation
func TestUnifiedPluginFactory_GRPCPluginCreation(t *testing.T) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	t.Run("GRPCPlugin_NotImplemented", func(t *testing.T) {
		config := PluginConfig{
			Name:      "grpc-plugin",
			Type:      "grpc",
			Transport: TransportGRPC,
			Endpoint:  "localhost:50051",
			Enabled:   true,
			Auth:      AuthConfig{Method: AuthNone},
		}

		_, err := factory.CreatePlugin(config)
		if err == nil {
			t.Error("Expected error for gRPC plugin creation (types don't implement ProtobufMessage)")
		}

		// Should indicate unsupported transport since TestRequest/TestResponse don't implement ProtobufMessage
		if !strings.Contains(err.Error(), "unsupported transport type") {
			t.Errorf("Expected 'unsupported transport type' error, got: %v", err)
		}
	})
}

// TestFactoryBuilder_FluentInterface tests the builder pattern
func TestFactoryBuilder_FluentInterface(t *testing.T) {
	t.Run("BuilderWithoutCustomizations", func(t *testing.T) {
		builder := NewFactoryBuilder[TestRequest, TestResponse]()
		factory := builder.Build()

		if factory == nil {
			t.Fatal("Expected factory to be built successfully")
		}

		transports := factory.SupportedTransports()
		if len(transports) == 0 {
			t.Error("Expected built factory to support at least one transport")
		}
	})

	t.Run("BuilderWithLogger", func(t *testing.T) {
		logger := NewLogger(nil)
		builder := NewFactoryBuilder[TestRequest, TestResponse]()
		factory := builder.WithLogger(logger).Build()

		if factory == nil {
			t.Fatal("Expected factory to be built successfully with logger")
		}

		if factory.logger == nil {
			t.Error("Expected factory to have logger set")
		}
	})

	t.Run("BuilderWithCustomFactory", func(t *testing.T) {
		builder := NewFactoryBuilder[TestRequest, TestResponse]()
		mockFactory := &mockPluginFactory{}
		factory := builder.WithCustomFactory("builder-mock", mockFactory).Build()

		if factory == nil {
			t.Fatal("Expected factory to be built successfully with custom factory")
		}

		transports := factory.SupportedTransports()
		hasBuilderMock := false
		for _, transport := range transports {
			if transport == "builder-mock" {
				hasBuilderMock = true
				break
			}
		}

		if !hasBuilderMock {
			t.Error("Expected builder-mock transport to be supported")
		}
	})

	t.Run("BuilderChaining", func(t *testing.T) {
		logger := NewLogger(nil)
		builder := NewFactoryBuilder[TestRequest, TestResponse]()

		mockFactory1 := &mockPluginFactory{}
		mockFactory2 := &mockPluginFactory{}
		factory := builder.
			WithLogger(logger).
			WithCustomFactory("chain1", mockFactory1).
			WithCustomFactory("chain2", mockFactory2).
			Build()

		if factory == nil {
			t.Fatal("Expected factory to be built successfully with chained calls")
		}

		transports := factory.SupportedTransports()
		expectedCustom := []string{"chain1", "chain2"}

		for _, expected := range expectedCustom {
			found := false
			for _, transport := range transports {
				if transport == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected transport %s to be supported after chained builder", expected)
			}
		}
	})
}

// TestConvenienceFunctions tests the convenience factory creation functions
func TestConvenienceFunctions(t *testing.T) {
	t.Run("NewSimpleSubprocessFactory", func(t *testing.T) {
		factory := NewSimpleSubprocessFactory[TestRequest, TestResponse](nil)
		if factory == nil {
			t.Fatal("Expected subprocess factory to be created")
		}

		// This should be a subprocess-only factory
		// We can't easily test the specific type without reflection,
		// but we can test basic functionality
		config := PluginConfig{
			Name:       "simple-subprocess",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Executable: "/bin/echo",
			Enabled:    true,
		}

		_, err := factory.CreatePlugin(config)
		// Error expected due to subprocess creation, but should not be about unsupported transport
		if err != nil && strings.Contains(err.Error(), "unsupported transport") {
			t.Errorf("Subprocess factory should support executable transport, got: %v", err)
		}
	})

	t.Run("NewSimpleGRPCFactory", func(t *testing.T) {
		factory := NewSimpleGRPCFactory[TestRequest, TestResponse](nil)
		if factory == nil {
			t.Fatal("Expected gRPC factory to be created (or fallback to subprocess)")
		}

		// Since TestRequest/TestResponse don't implement ProtobufMessage,
		// this should fall back to subprocess factory
		config := PluginConfig{
			Name:       "simple-grpc-fallback",
			Type:       "subprocess",
			Transport:  TransportExecutable,
			Executable: "/bin/echo",
			Enabled:    true,
		}

		_, err := factory.CreatePlugin(config)
		// Should work as subprocess factory fallback
		if err != nil && strings.Contains(err.Error(), "unsupported transport") {
			t.Errorf("gRPC factory fallback should support subprocess, got: %v", err)
		}
	})

	t.Run("NewMultiTransportFactory", func(t *testing.T) {
		factory := NewMultiTransportFactory[TestRequest, TestResponse](nil)
		if factory == nil {
			t.Fatal("Expected multi-transport factory to be created")
		}

		transports := factory.SupportedTransports()
		if len(transports) == 0 {
			t.Error("Expected multi-transport factory to support at least one transport")
		}

		// Should support subprocess at minimum
		hasSubprocess := false
		for _, transport := range transports {
			if transport == string(TransportExecutable) {
				hasSubprocess = true
				break
			}
		}

		if !hasSubprocess {
			t.Error("Expected multi-transport factory to support subprocess transport")
		}
	})
}

// TestUnifiedPluginFactory_ErrorTypes tests proper error type returns
func TestUnifiedPluginFactory_ErrorTypes(t *testing.T) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	testCases := []struct {
		name        string
		config      PluginConfig
		expectedMsg string
		description string
	}{
		{
			name: "ConfigValidationError",
			config: PluginConfig{
				Name:       "", // Invalid
				Type:       "subprocess",
				Transport:  TransportExecutable,
				Executable: "/bin/echo",
				Enabled:    true,
				Auth:       AuthConfig{Method: AuthNone},
			},
			expectedMsg: "invalid plugin configuration",
			description: "Empty name should cause config validation error",
		},
		{
			name: "PluginCreationError_UnsupportedTransport",
			config: PluginConfig{
				Name:       "test-plugin",
				Type:       "subprocess",
				Transport:  "nonexistent-transport",
				Executable: "/bin/echo",
				Enabled:    true,
				Auth:       AuthConfig{Method: AuthNone},
			},
			expectedMsg: "unsupported transport type",
			description: "Unsupported transport should cause plugin creation error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := factory.CreatePlugin(tc.config)
			if err == nil {
				t.Errorf("Expected error for test case: %s", tc.description)
				return
			}

			if !strings.Contains(err.Error(), tc.expectedMsg) {
				t.Errorf("Expected error containing '%s' for %s, got: %v",
					tc.expectedMsg, tc.description, err)
			}
		})
	}
}

// BenchmarkUnifiedPluginFactory_CreatePlugin benchmarks plugin creation performance
func BenchmarkUnifiedPluginFactory_CreatePlugin(b *testing.B) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	// Register a fast mock factory
	mockFactory := &mockPluginFactory{}
	err := factory.RegisterFactory("benchmark-mock", mockFactory)
	if err != nil {
		b.Fatalf("Failed to register mock factory: %v", err)
	}

	config := PluginConfig{
		Name:      "benchmark-plugin",
		Type:      "mock",
		Transport: "benchmark-mock",
		Endpoint:  "mock-endpoint",
		Enabled:   true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := factory.CreatePlugin(config)
		if err != nil {
			b.Fatalf("Plugin creation failed: %v", err)
		}
	}
}

// BenchmarkUnifiedPluginFactory_RegisterCustomFactory benchmarks custom factory registration
func BenchmarkUnifiedPluginFactory_RegisterCustomFactory(b *testing.B) {
	factory := NewUnifiedPluginFactory[TestRequest, TestResponse](nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transportName := "benchmark-factory-" + string(rune(i))
		mockFactory := &mockPluginFactory{}
		err := factory.RegisterFactory(transportName, mockFactory)
		if err != nil {
			b.Fatalf("Factory registration failed: %v", err)
		}
	}
}

// TestUnifiedPluginFactoryCore tests core functionality of UnifiedPluginFactory
func TestUnifiedPluginFactoryCore(t *testing.T) {
	t.Run("NewUnifiedPluginFactory_Initialization", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		// Verify factory is properly initialized
		if factory == nil {
			t.Fatal("Expected factory to be initialized")
		}

		// Verify supported transports include defaults
		transports := factory.SupportedTransports()
		if len(transports) == 0 {
			t.Error("Expected factory to have default transports")
		}

		// Should have at least executable transport
		hasExecutable := false
		for _, transport := range transports {
			if transport == "exec" {
				hasExecutable = true
				break
			}
		}
		if !hasExecutable {
			t.Error("Expected factory to support executable transport by default")
		}
	})

	t.Run("CreatePlugin_ValidConfiguration", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		// Register mock factory for testing
		mockFactory := &mockPluginFactory{}
		err := factory.RegisterFactory("mock-transport", mockFactory)
		if err != nil {
			t.Fatalf("Failed to register mock factory: %v", err)
		}

		config := PluginConfig{
			Name:      "test-plugin",
			Type:      "service",
			Transport: "mock-transport",
			Endpoint:  "mock://endpoint",
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		plugin, err := factory.CreatePlugin(config)
		if err != nil {
			t.Fatalf("Failed to create plugin: %v", err)
		}

		if plugin == nil {
			t.Fatal("Expected plugin to be created")
		}

		// Verify plugin info
		info := plugin.Info()
		if info.Name != "test-plugin" {
			t.Errorf("Expected plugin name 'test-plugin', got %s", info.Name)
		}
	})

	t.Run("CreatePlugin_UnsupportedTransport", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		config := PluginConfig{
			Name:      "test-plugin",
			Type:      "service",
			Transport: "unsupported-transport",
			Endpoint:  "mock://endpoint",
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		_, err := factory.CreatePlugin(config)
		if err == nil {
			t.Fatal("Expected error for unsupported transport")
		}

		// Verify error message mentions transport
		if !strings.Contains(err.Error(), "unsupported transport") {
			t.Errorf("Expected error to mention unsupported transport, got: %v", err)
		}
	})

	t.Run("CreatePlugin_InvalidConfiguration", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		// Register mock factory
		mockFactory := &mockPluginFactory{}
		if regErr := factory.RegisterFactory("mock-transport", mockFactory); regErr != nil {
			t.Fatalf("Failed to register mock factory: %v", regErr)
		}

		// Invalid config - empty name
		config := PluginConfig{
			Name:      "", // Invalid empty name
			Type:      "service",
			Transport: "mock-transport",
			Endpoint:  "mock://endpoint",
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		_, err := factory.CreatePlugin(config)
		if err == nil {
			t.Fatal("Expected error for invalid configuration")
		}
	})

	t.Run("ValidateConfig_ValidConfiguration", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		// Register mock factory
		mockFactory := &mockPluginFactory{}
		if regErr := factory.RegisterFactory("mock-transport", mockFactory); regErr != nil {
			t.Fatalf("Failed to register mock factory: %v", regErr)
		}

		config := PluginConfig{
			Name:      "test-plugin",
			Type:      "service",
			Transport: "mock-transport",
			Endpoint:  "mock://endpoint",
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		err := factory.ValidateConfig(config)
		if err != nil {
			t.Errorf("Expected valid configuration, got error: %v", err)
		}
	})

	t.Run("ValidateConfig_UnsupportedTransport", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		config := PluginConfig{
			Name:      "test-plugin",
			Type:      "service",
			Transport: "unsupported-transport",
			Endpoint:  "mock://endpoint",
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		err := factory.ValidateConfig(config)
		if err == nil {
			t.Fatal("Expected error for unsupported transport")
		}
	})
}

// TestFactoryConvenienceFunctions tests the convenience factory functions
func TestFactoryConvenienceFunctions(t *testing.T) {
	t.Run("NewSimpleSubprocessFactory", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewSimpleSubprocessFactory[TestRequest, TestResponse](logger)

		if factory == nil {
			t.Fatal("Expected factory to be initialized")
		}

		// Verify it supports executable transport
		transports := factory.SupportedTransports()
		hasExecutable := false
		for _, transport := range transports {
			if transport == "exec" {
				hasExecutable = true
				break
			}
		}
		if !hasExecutable {
			t.Error("Expected subprocess factory to support executable transport")
		}
	})

	t.Run("NewSimpleGRPCFactory", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewSimpleGRPCFactory[TestRequest, TestResponse](logger)

		if factory == nil {
			t.Fatal("Expected factory to be initialized")
		}

		// Should fallback to subprocess since TestRequest/TestResponse don't implement ProtobufMessage
		transports := factory.SupportedTransports()
		if len(transports) == 0 {
			t.Error("Expected factory to have supported transports")
		}
	})

	t.Run("NewMultiTransportFactory", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewMultiTransportFactory[TestRequest, TestResponse](logger)

		if factory == nil {
			t.Fatal("Expected factory to be initialized")
		}

		transports := factory.SupportedTransports()
		if len(transports) == 0 {
			t.Error("Expected multi-transport factory to have supported transports")
		}
	})
}

// TestConfigurationValidation tests internal configuration validation
func TestConfigurationValidation(t *testing.T) {
	t.Run("ValidateConfiguration_ValidConfig", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		config := PluginConfig{
			Name:      "valid-plugin",
			Type:      "service",
			Transport: "exec",
			Endpoint:  "/path/to/binary",
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		// This should use validateConfiguration internally through CreatePlugin
		_, err := factory.CreatePlugin(config)
		// May fail at plugin creation but should pass validation
		if err != nil && strings.Contains(err.Error(), "validation") {
			t.Errorf("Configuration validation failed: %v", err)
		}
	})

	t.Run("ValidateConfiguration_EmptyName", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		config := PluginConfig{
			Name:      "", // Invalid empty name
			Type:      "service",
			Transport: "exec",
			Endpoint:  "/path/to/binary",
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		_, err := factory.CreatePlugin(config)
		if err == nil {
			t.Error("Expected validation error for empty name")
		}
	})

	t.Run("ValidateConfiguration_EmptyEndpoint", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		config := PluginConfig{
			Name:      "test-plugin",
			Type:      "service",
			Transport: "exec",
			Endpoint:  "", // Invalid empty endpoint
			Auth: AuthConfig{
				Method: AuthNone,
			},
		}

		_, err := factory.CreatePlugin(config)
		if err == nil {
			t.Error("Expected validation error for empty endpoint")
		}
	})

	t.Run("RegisterFactory_ErrorHandling", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		// Test empty transport type
		err := factory.RegisterFactory("", &mockPluginFactory{})
		if err == nil {
			t.Error("Expected error for empty transport type")
		}

		// Test nil factory
		err = factory.RegisterFactory("test-transport", nil)
		if err == nil {
			t.Error("Expected error for nil factory")
		}
	})
}

// TestFactoryRegistration tests factory registration and management
func TestFactoryRegistration(t *testing.T) {
	t.Run("RegisterFactory_Success", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		mockFactory := &mockPluginFactory{}
		err := factory.RegisterFactory("custom-transport", mockFactory)
		if err != nil {
			t.Errorf("Expected successful registration, got error: %v", err)
		}

		// Verify transport is now supported
		transports := factory.SupportedTransports()
		hasCustom := false
		for _, transport := range transports {
			if transport == "custom-transport" {
				hasCustom = true
				break
			}
		}
		if !hasCustom {
			t.Error("Expected custom transport to be supported after registration")
		}
	})

	t.Run("SupportedTransports_ReturnsAll", func(t *testing.T) {
		logger := NewTestLogger()
		factory := NewUnifiedPluginFactory[TestRequest, TestResponse](logger)

		// Register multiple custom factories
		for i := 0; i < 3; i++ {
			transportName := "custom-transport-" + strconv.Itoa(i)
			mockFactory := &mockPluginFactory{}
			if regErr := factory.RegisterFactory(transportName, mockFactory); regErr != nil {
				t.Fatalf("Failed to register factory %s: %v", transportName, regErr)
			}
		}

		transports := factory.SupportedTransports()

		// Should have at least default + 3 custom transports
		if len(transports) < 4 {
			t.Errorf("Expected at least 4 supported transports, got %d", len(transports))
		}
	})
}
