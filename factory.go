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

// UnifiedPluginFactory provides a simplified interface for creating plugins.
//
// This factory consolidates common plugin creation patterns and reduces
// the amount of boilerplate code needed to create different types of plugins.
// It maintains compatibility with existing factory interfaces while providing
// a more streamlined creation process.
type UnifiedPluginFactory[Req, Resp any] struct {
	logger Logger

	// Factory functions for different plugin types
	subprocessFactory func(PluginConfig) (Plugin[Req, Resp], error)
	grpcFactory       func(PluginConfig) (Plugin[Req, Resp], error)
	customFactories   map[string]func(PluginConfig) (Plugin[Req, Resp], error)
}

// NewUnifiedPluginFactory creates a new unified plugin factory.
//
// This factory can handle multiple plugin types through a single interface,
// reducing the complexity of factory management while maintaining type safety.
func NewUnifiedPluginFactory[Req, Resp any](logger any) *UnifiedPluginFactory[Req, Resp] {
	internalLogger := NewLogger(logger)

	factory := &UnifiedPluginFactory[Req, Resp]{
		logger:          internalLogger,
		customFactories: make(map[string]func(PluginConfig) (Plugin[Req, Resp], error)),
	}

	// Initialize default factory functions
	factory.initializeDefaultFactories()

	return factory
}

// CreatePlugin creates a plugin based on the configuration.
//
// This method automatically determines the appropriate factory function
// based on the plugin configuration and delegates creation accordingly.
func (uf *UnifiedPluginFactory[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, NewPluginCreationError("invalid plugin configuration", err)
	}

	// Determine factory function based on transport type
	var factoryFunc func(PluginConfig) (Plugin[Req, Resp], error)

	switch config.Transport {
	case TransportExecutable:
		factoryFunc = uf.subprocessFactory
	case TransportGRPC, TransportGRPCTLS:
		factoryFunc = uf.grpcFactory
	default:
		// Check custom factories
		if customFunc, exists := uf.customFactories[string(config.Transport)]; exists {
			factoryFunc = customFunc
		} else {
			return nil, NewPluginCreationError(
				fmt.Sprintf("unsupported transport type: %s", config.Transport), nil)
		}
	}

	if factoryFunc == nil {
		return nil, NewPluginCreationError(
			fmt.Sprintf("no factory function available for transport: %s", config.Transport), nil)
	}

	// Create plugin using the appropriate factory
	plugin, err := factoryFunc(config)
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

// RegisterCustomFactory registers a custom factory function for a specific transport type.
//
// This method allows extending the unified factory with support for custom
// transport types without modifying the core factory code.
func (uf *UnifiedPluginFactory[Req, Resp]) RegisterCustomFactory(
	transportType string,
	factoryFunc func(PluginConfig) (Plugin[Req, Resp], error)) error {

	if transportType == "" {
		return NewConfigValidationError("transport type cannot be empty", nil)
	}

	if factoryFunc == nil {
		return NewConfigValidationError("factory function cannot be nil", nil)
	}

	uf.customFactories[transportType] = factoryFunc
	uf.logger.Info("Custom factory registered", "transport_type", transportType)

	return nil
}

// GetSupportedTransports returns a list of supported transport types.
func (uf *UnifiedPluginFactory[Req, Resp]) GetSupportedTransports() []string {
	transports := []string{}

	// Add built-in transports
	if uf.subprocessFactory != nil {
		transports = append(transports, string(TransportExecutable))
	}

	if uf.grpcFactory != nil {
		transports = append(transports, string(TransportGRPC), string(TransportGRPCTLS))
	}

	// Add custom transports
	for transportType := range uf.customFactories {
		transports = append(transports, transportType)
	}

	return transports
}

// initializeDefaultFactories sets up the default factory functions.
func (uf *UnifiedPluginFactory[Req, Resp]) initializeDefaultFactories() {
	// Subprocess factory
	uf.subprocessFactory = func(config PluginConfig) (Plugin[Req, Resp], error) {
		return uf.createSubprocessPlugin(config)
	}

	// gRPC factory
	uf.grpcFactory = func(config PluginConfig) (Plugin[Req, Resp], error) {
		return uf.createGRPCPlugin(config)
	}
}

// createSubprocessPlugin creates a subprocess plugin using the unified subprocess manager.
func (uf *UnifiedPluginFactory[Req, Resp]) createSubprocessPlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	if config.Endpoint == "" {
		return nil, NewConfigValidationError("executable path cannot be empty for subprocess transport", nil)
	}

	// Create unified subprocess manager configuration
	managerConfig := SubprocessManagerConfig{
		BaseConfig:     BaseConfig{}.WithDefaults(),
		ExecutablePath: config.Endpoint,
		Logger:         uf.logger.With("plugin", config.Name),
	}

	// Apply plugin-specific configuration
	if args, ok := config.Options["args"].([]string); ok {
		managerConfig.Args = args
	}

	if env, ok := config.Options["env"].([]string); ok {
		managerConfig.Env = env
	}

	// Apply component configurations from plugin options
	if handshakeConfig, ok := config.Options["handshake_config"].(HandshakeConfig); ok {
		managerConfig.HandshakeConfig = handshakeConfig
	} else {
		managerConfig.HandshakeConfig = DefaultHandshakeConfig
	}

	if streamConfig, ok := config.Options["stream_sync_config"].(StreamSyncConfig); ok {
		managerConfig.StreamConfig = streamConfig
	} else {
		managerConfig.StreamConfig = DefaultStreamSyncConfig
		// Disable stdout syncing for subprocess communication to avoid pipe conflicts
		managerConfig.StreamConfig.SyncStdout = false
	}

	if bridgeConfig, ok := config.Options["bridge_config"].(BridgeConfig); ok {
		managerConfig.BridgeConfig = bridgeConfig
	} else {
		managerConfig.BridgeConfig = DefaultBridgeConfig
	}

	// Apply defaults
	managerConfig.ApplyDefaults()

	// Validate configuration
	if err := managerConfig.Validate(); err != nil {
		return nil, err
	}

	// Create subprocess manager
	subprocessManager := NewSubprocessManager(managerConfig)

	// Create and return subprocess plugin with the unified manager
	return NewSubprocessPluginWithManager[Req, Resp](config, subprocessManager, uf.logger)
}

// createGRPCPlugin creates a gRPC plugin using existing gRPC factory logic.
func (uf *UnifiedPluginFactory[Req, Resp]) createGRPCPlugin(_ PluginConfig) (Plugin[Req, Resp], error) {
	// Note: gRPC plugin creation requires specific protobuf constraints
	// For now, we return an error indicating that gRPC plugins should be created
	// using the dedicated gRPC factory until we implement proper constraint handling
	return nil, NewPluginCreationError("gRPC plugin creation through unified factory not yet implemented", nil)
}

// FactoryBuilder provides a fluent interface for building unified factories.
//
// This builder pattern simplifies the creation of unified factories with
// specific configurations and custom factory functions.
type FactoryBuilder[Req, Resp any] struct {
	logger          any
	customFactories map[string]func(PluginConfig) (Plugin[Req, Resp], error)
}

// NewFactoryBuilder creates a new factory builder.
func NewFactoryBuilder[Req, Resp any]() *FactoryBuilder[Req, Resp] {
	return &FactoryBuilder[Req, Resp]{
		customFactories: make(map[string]func(PluginConfig) (Plugin[Req, Resp], error)),
	}
}

// WithLogger sets the logger for the factory.
func (fb *FactoryBuilder[Req, Resp]) WithLogger(logger any) *FactoryBuilder[Req, Resp] {
	fb.logger = logger
	return fb
}

// WithCustomFactory adds a custom factory function for a specific transport type.
func (fb *FactoryBuilder[Req, Resp]) WithCustomFactory(
	transportType string,
	factoryFunc func(PluginConfig) (Plugin[Req, Resp], error)) *FactoryBuilder[Req, Resp] {

	fb.customFactories[transportType] = factoryFunc
	return fb
}

// Build creates the unified factory with the specified configuration.
func (fb *FactoryBuilder[Req, Resp]) Build() *UnifiedPluginFactory[Req, Resp] {
	factory := NewUnifiedPluginFactory[Req, Resp](fb.logger)

	// Register custom factories
	for transportType, factoryFunc := range fb.customFactories {
		if err := factory.RegisterCustomFactory(transportType, factoryFunc); err != nil {
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
			return any(NewGRPCPluginFactory[ProtobufMessage, ProtobufMessage](logger)).(PluginFactory[Req, Resp])
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
