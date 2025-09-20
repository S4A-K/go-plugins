// factory_unified.go: Unified plugin factory patterns
//
// This file provides a simplified and unified approach to plugin factory
// creation, reducing boilerplate code and providing consistent patterns
// across different plugin types while maintaining flexibility.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
)

// UnifiedPluginFactory provides a registry-based approach to plugin creation.
//
// This factory acts as a registry that delegates to specialized factory implementations,
// eliminating code duplication and maintaining proper separation of concerns.
// It conforms to the standard PluginFactory interface while providing extensibility.
type UnifiedPluginFactory[Req, Resp any] struct {
	logger Logger

	// Registry of specialized factory implementations
	factories map[string]PluginFactory[Req, Resp]
}

// NewUnifiedPluginFactory creates a new unified plugin factory.
//
// This factory acts as a registry that delegates to specialized factories,
// eliminating redundancy while maintaining type safety and extensibility.
func NewUnifiedPluginFactory[Req, Resp any](logger any) *UnifiedPluginFactory[Req, Resp] {
	internalLogger := NewLogger(logger)

	factory := &UnifiedPluginFactory[Req, Resp]{
		logger:    internalLogger,
		factories: make(map[string]PluginFactory[Req, Resp]),
	}

	// Register default specialized factories
	factory.registerDefaultFactories()

	return factory
}

// CreatePlugin creates a plugin based on the configuration.
//
// This method validates configuration first, then delegates to the appropriate
// specialized factory, maintaining both validation and separation of concerns.
func (uf *UnifiedPluginFactory[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	// First validate basic configuration
	if err := uf.validateConfiguration(config); err != nil {
		return nil, NewPluginCreationError(fmt.Sprintf("invalid plugin configuration: %v", err), err)
	}

	// Find the appropriate factory for this transport
	factory, exists := uf.factories[string(config.Transport)]
	if !exists {
		return nil, NewPluginCreationError(
			fmt.Sprintf("unsupported transport type: %s", config.Transport), nil)
	}

	// Delegate to the specialized factory
	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		return nil, NewPluginCreationError(
			fmt.Sprintf("failed to create %s plugin", config.Transport), err)
	}

	uf.logger.Info("Plugin created successfully",
		"name", config.Name,
		"type", config.Type,
		"transport", config.Transport)

	return plugin, nil
}

// RegisterFactory registers a factory for a specific transport type.
//
// This method allows extending the unified factory with custom implementations
// while maintaining the standard PluginFactory interface contract.
func (uf *UnifiedPluginFactory[Req, Resp]) RegisterFactory(
	transportType string,
	factory PluginFactory[Req, Resp]) error {

	if transportType == "" {
		return NewConfigValidationError("transport type cannot be empty", nil)
	}

	if factory == nil {
		return NewConfigValidationError("factory cannot be nil", nil)
	}

	uf.factories[transportType] = factory
	uf.logger.Info("Factory registered", "transport_type", transportType)

	return nil
}

// SupportedTransports implements PluginFactory interface.
func (uf *UnifiedPluginFactory[Req, Resp]) SupportedTransports() []string {
	transports := make([]string, 0, len(uf.factories))
	for transportType := range uf.factories {
		transports = append(transports, transportType)
	}
	return transports
}

// ValidateConfig implements PluginFactory interface.
func (uf *UnifiedPluginFactory[Req, Resp]) ValidateConfig(config PluginConfig) error {
	// Validate basic configuration first
	if err := uf.validateConfiguration(config); err != nil {
		return err
	}

	// Find the appropriate factory for this transport
	factory, exists := uf.factories[string(config.Transport)]
	if !exists {
		return NewConfigValidationError(
			fmt.Sprintf("unsupported transport type: %s", config.Transport), nil)
	}

	// Delegate validation to the specialized factory
	return factory.ValidateConfig(config)
}

// validateConfiguration performs basic configuration validation
func (uf *UnifiedPluginFactory[Req, Resp]) validateConfiguration(config PluginConfig) error {
	// Validate basic config
	if err := config.validateBasicConfig(); err != nil {
		return err
	}

	// Validate authentication configuration
	if err := config.Auth.Validate(); err != nil {
		return NewAuthConfigValidationError(err)
	}

	return nil
}

// registerDefaultFactories registers the default specialized factories.
func (uf *UnifiedPluginFactory[Req, Resp]) registerDefaultFactories() {
	// Register subprocess factory for executable transport
	subprocessFactory := NewSubprocessPluginFactory[Req, Resp](uf.logger)
	uf.factories[string(TransportExecutable)] = subprocessFactory

	// Only register gRPC factory if types implement ProtobufMessage
	if uf.canUseGRPCFactory() {
		uf.registerGRPCFactory()
	}
}

// canUseGRPCFactory checks if Req and Resp types implement ProtobufMessage.
func (uf *UnifiedPluginFactory[Req, Resp]) canUseGRPCFactory() bool {
	var reqZero Req
	var respZero Resp

	_, reqOK := any(reqZero).(ProtobufMessage)
	_, respOK := any(respZero).(ProtobufMessage)

	return reqOK && respOK
}

// registerGRPCFactory safely registers gRPC factory with proper type constraints.
func (uf *UnifiedPluginFactory[Req, Resp]) registerGRPCFactory() {
	// This is safe because canUseGRPCFactory() verified the constraints
	if factory := uf.createGRPCFactoryAdapter(); factory != nil {
		uf.factories[string(TransportGRPC)] = factory
		uf.factories[string(TransportGRPCTLS)] = factory
	}
}

// createGRPCFactoryAdapter creates a type-safe adapter for gRPC factory.
func (uf *UnifiedPluginFactory[Req, Resp]) createGRPCFactoryAdapter() PluginFactory[Req, Resp] {
	// Create the specialized gRPC factory
	grpcFactory := NewGRPCPluginFactory[ProtobufMessage, ProtobufMessage](uf.logger)

	// Return an adapter that safely delegates to the gRPC factory
	return &grpcFactoryAdapter[Req, Resp]{
		grpcFactory: grpcFactory,
		logger:      uf.logger,
	}
}

// grpcFactoryAdapter adapts the specialized gRPC factory to work with any types
// that implement ProtobufMessage, providing type safety through runtime checks.
type grpcFactoryAdapter[Req, Resp any] struct {
	grpcFactory PluginFactory[ProtobufMessage, ProtobufMessage]
	logger      Logger
}

// CreatePlugin implements PluginFactory interface with type-safe delegation.
func (gfa *grpcFactoryAdapter[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	// Delegate to the specialized gRPC factory
	plugin, err := gfa.grpcFactory.CreatePlugin(config)
	if err != nil {
		return nil, err
	}

	// Safe cast - we verified types implement ProtobufMessage in canUseGRPCFactory()
	result, ok := any(plugin).(Plugin[Req, Resp])
	if !ok {
		return nil, NewPluginCreationError(
			"failed to cast gRPC plugin to expected type", nil)
	}

	return result, nil
}

// SupportedTransports implements PluginFactory interface.
func (gfa *grpcFactoryAdapter[Req, Resp]) SupportedTransports() []string {
	return gfa.grpcFactory.SupportedTransports()
}

// ValidateConfig implements PluginFactory interface.
func (gfa *grpcFactoryAdapter[Req, Resp]) ValidateConfig(config PluginConfig) error {
	return gfa.grpcFactory.ValidateConfig(config)
}

// FactoryBuilder provides a fluent interface for building unified factories.
//
// This builder pattern simplifies the creation of unified factories with
// specific configurations and custom factory implementations.
type FactoryBuilder[Req, Resp any] struct {
	logger          any
	customFactories map[string]PluginFactory[Req, Resp]
}

// NewFactoryBuilder creates a new factory builder.
func NewFactoryBuilder[Req, Resp any]() *FactoryBuilder[Req, Resp] {
	return &FactoryBuilder[Req, Resp]{
		customFactories: make(map[string]PluginFactory[Req, Resp]),
	}
}

// WithLogger sets the logger for the factory.
func (fb *FactoryBuilder[Req, Resp]) WithLogger(logger any) *FactoryBuilder[Req, Resp] {
	fb.logger = logger
	return fb
}

// WithCustomFactory adds a custom factory for a specific transport type.
func (fb *FactoryBuilder[Req, Resp]) WithCustomFactory(
	transportType string,
	factory PluginFactory[Req, Resp]) *FactoryBuilder[Req, Resp] {

	fb.customFactories[transportType] = factory
	return fb
}

// Build creates the unified factory with the specified configuration.
func (fb *FactoryBuilder[Req, Resp]) Build() *UnifiedPluginFactory[Req, Resp] {
	factory := NewUnifiedPluginFactory[Req, Resp](fb.logger)

	// Register custom factories
	for transportType, customFactory := range fb.customFactories {
		if err := factory.RegisterFactory(transportType, customFactory); err != nil {
			// Log error but continue with other factories
			// In a builder pattern, we don't want to fail completely
		}
	}

	return factory
}

// Convenience functions for common factory creation patterns

// NewSimpleSubprocessFactory creates a factory that only supports subprocess plugins.
//
// This is a convenience function for cases where only subprocess plugins are needed,
// reducing the complexity of factory setup.
func NewSimpleSubprocessFactory[Req, Resp any](logger any) PluginFactory[Req, Resp] {
	return NewSubprocessPluginFactory[Req, Resp](logger)
}

// NewSimpleGRPCFactory creates a factory that only supports gRPC plugins.
//
// This is a convenience function for cases where only gRPC plugins are needed.
// Note: This requires Req and Resp to implement ProtobufMessage interface.
func NewSimpleGRPCFactory[Req, Resp any](logger any) PluginFactory[Req, Resp] {
	// Check if Req and Resp implement ProtobufMessage interface at runtime
	// If not, fall back to subprocess factory for compatibility
	var reqZero Req
	var respZero Resp

	if _, reqOK := any(reqZero).(ProtobufMessage); reqOK {
		if _, respOK := any(respZero).(ProtobufMessage); respOK {
			// Both types implement ProtobufMessage, use gRPC factory
			// Cast is safe because we verified the interface implementation
			factory, ok := any(NewGRPCPluginFactory[ProtobufMessage, ProtobufMessage](logger)).(PluginFactory[Req, Resp])
			if !ok {
				// If cast fails, fallback to subprocess factory
				return NewSubprocessPluginFactory[Req, Resp](logger)
			}
			return factory
		}
	}

	// Fallback to subprocess factory if protobuf constraints not met
	return NewSubprocessPluginFactory[Req, Resp](logger)
}

// NewMultiTransportFactory creates a unified factory that supports both subprocess and gRPC plugins.
//
// This is the recommended factory for most use cases as it provides maximum flexibility
// while maintaining simplicity.
func NewMultiTransportFactory[Req, Resp any](logger any) *UnifiedPluginFactory[Req, Resp] {
	return NewUnifiedPluginFactory[Req, Resp](logger)
}
