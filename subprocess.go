// subprocess_transport.go: go-plugins subprocess plugin execution
//
// This file implements subprocess-based plugin execution compatible with
// go-plugins architecture, supporting direct process execution
// with TCP-based IPC communication.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SubprocessPlugin represents a plugin that runs as a subprocess.
// This plugin type launches external executables as separate processes and
// communicates with them via TCP connections.
//
// After refactoring, this class focuses on orchestration and delegates
// specific responsibilities to dedicated components.
//
// Key features:
//   - Direct process execution via exec.Command
//   - TCP localhost IPC (not Unix sockets)
//   - Process lifecycle management via ProcessManager
//   - Standard subprocess handshake protocol via LifecycleManager
//   - Configuration parsing via ConfigParser
//   - Automatic cleanup on shutdown
type SubprocessPlugin[Req, Resp any] struct {
	// Core components (after refactoring)
	processManager   *ProcessManager
	configParser     *ConfigParser
	lifecycleManager *LifecycleManager

	// Legacy components (maintained for compatibility)
	handshakeManager *HandshakeManager
	streamSyncer     *StreamSyncer
	commBridge       *CommunicationBridge

	// Configuration
	handshakeConfig HandshakeConfig
	streamConfig    StreamSyncConfig
	bridgeConfig    BridgeConfig

	// State tracking
	mutex  sync.RWMutex
	logger Logger
}

// ProcessInfo contains information about the running subprocess.
type ProcessInfo struct {
	PID       int
	StartTime time.Time
	Status    ProcessStatus
}

// ProcessStatus represents the current status of a subprocess.
type ProcessStatus int

const (
	StatusStopped ProcessStatus = iota
	StatusStarting
	StatusRunning
	StatusStopping
	StatusFailed
)

// String implements fmt.Stringer for ProcessStatus.
func (s ProcessStatus) String() string {
	switch s {
	case StatusStopped:
		return "stopped"
	case StatusStarting:
		return "starting"
	case StatusRunning:
		return "running"
	case StatusStopping:
		return "stopping"
	case StatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// SubprocessPluginFactory creates subprocess plugin instances.
//
// This factory implements the standard subprocess model where plugins
// are external executables launched as separate processes.
type SubprocessPluginFactory[Req, Resp any] struct {
	logger Logger
}

// NewSubprocessPluginFactory creates a new subprocess plugin factory.
func NewSubprocessPluginFactory[Req, Resp any](logger any) *SubprocessPluginFactory[Req, Resp] {
	internalLogger := NewLogger(logger)

	return &SubprocessPluginFactory[Req, Resp]{
		logger: internalLogger,
	}
}

// CreatePlugin creates a new subprocess plugin instance.
//
// The endpoint should be the path to the executable to launch.
// Args can be passed via the PluginConfig.
func (f *SubprocessPluginFactory[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	if config.Endpoint == "" {
		return nil, NewConfigValidationError("executable path cannot be empty for subprocess transport", nil)
	}

	// Initialize handshake configuration
	handshakeConfig := DefaultHandshakeConfig
	if customConfig, ok := config.Options["handshake_config"].(HandshakeConfig); ok {
		handshakeConfig = customConfig
	}

	// Initialize stream sync configuration
	streamConfig := DefaultStreamSyncConfig
	if customStreamConfig, ok := config.Options["stream_sync_config"].(StreamSyncConfig); ok {
		streamConfig = customStreamConfig
	}

	// Customize prefix with plugin name
	if streamConfig.PrefixOutput && streamConfig.OutputPrefix == "[plugin]" {
		streamConfig.OutputPrefix = fmt.Sprintf("[%s]", config.Name)
	}

	// Initialize communication bridge configuration
	bridgeConfig := DefaultBridgeConfig
	if customBridgeConfig, ok := config.Options["bridge_config"].(BridgeConfig); ok {
		bridgeConfig = customBridgeConfig
	}

	logger := f.logger.With("plugin", config.Name, "executable", config.Endpoint)

	// Create configuration parser and parse config
	configParser := NewConfigParser(logger)
	parsedConfig, err := configParser.ParseConfig(config)
	if err != nil {
		return nil, err
	}

	// Create process manager
	processManager := NewProcessManager(ProcessManagerConfig{
		ExecutablePath: parsedConfig.ExecutablePath,
		Args:           parsedConfig.Args,
		Env:            parsedConfig.Env,
		Logger:         logger,
	})

	// Create legacy components for compatibility
	handshakeManager := NewHandshakeManager(handshakeConfig, logger)
	streamSyncer := NewStreamSyncer(streamConfig, logger)
	commBridge := NewCommunicationBridge(bridgeConfig, logger)

	// Create lifecycle manager
	lifecycleManager := NewLifecycleManager(LifecycleConfig{
		ProcessManager:      processManager,
		ConfigParser:        configParser,
		HandshakeManager:    handshakeManager,
		StreamSyncer:        streamSyncer,
		CommunicationBridge: commBridge,
		HandshakeConfig:     handshakeConfig,
		StreamConfig:        streamConfig,
		BridgeConfig:        bridgeConfig,
		Logger:              logger,
	})

	plugin := &SubprocessPlugin[Req, Resp]{
		processManager:   processManager,
		configParser:     configParser,
		lifecycleManager: lifecycleManager,
		handshakeManager: handshakeManager,
		streamSyncer:     streamSyncer,
		commBridge:       commBridge,
		handshakeConfig:  handshakeConfig,
		streamConfig:     streamConfig,
		bridgeConfig:     bridgeConfig,
		logger:           logger,
	}

	return plugin, nil
}

// SupportedTransports implements PluginFactory interface.
func (f *SubprocessPluginFactory[Req, Resp]) SupportedTransports() []string {
	return []string{string(TransportExecutable)}
}

// ValidateConfig implements PluginFactory interface.
func (f *SubprocessPluginFactory[Req, Resp]) ValidateConfig(config PluginConfig) error {
	if config.Endpoint == "" {
		return NewConfigValidationError("executable path cannot be empty for subprocess transport", nil)
	}

	if config.Transport != TransportExecutable {
		return NewConfigValidationError(fmt.Sprintf("subprocess factory only supports executable transport, got: %s", config.Transport), nil)
	}

	// Validate executable path exists and is executable
	if config.Executable == "" {
		return NewConfigValidationError("executable path is required", nil)
	}

	return nil
}

// Execute implements the Plugin interface for subprocess execution.
//
// This method launches the subprocess, establishes communication,
// sends the request, and returns the response.
func (sp *SubprocessPlugin[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp

	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	// Start subprocess if not already running
	if !sp.processManager.IsStarted() {
		if err := sp.startProcess(ctx); err != nil {
			return zero, NewProcessError("failed to start subprocess", err)
		}
	}

	// Communication infrastructure is ready - requires RPC implementation (Priority 5)
	if sp.commBridge == nil {
		return zero, NewCommunicationError("communication bridge not available", nil)
	}

	sp.logger.Debug("Executing subprocess request",
		"request_id", execCtx.RequestID,
		"timeout", execCtx.Timeout)

	return zero, NewRPCError("RPC communication protocol not implemented - will be completed in Priority 5", nil)
}

// startProcess launches the subprocess and establishes communication with handshake.
func (sp *SubprocessPlugin[Req, Resp]) startProcess(ctx context.Context) error {
	if sp.processManager.IsStarted() {
		return nil
	}

	sp.logger.Info("Starting subprocess plugin with lifecycle manager")

	// Use lifecycle manager for coordinated startup
	return sp.lifecycleManager.Startup(ctx)
}

// Stop gracefully stops the subprocess plugin.
func (sp *SubprocessPlugin[Req, Resp]) Stop(ctx context.Context) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if !sp.processManager.IsStarted() || sp.processManager.IsStopping() {
		return nil
	}

	processInfo := sp.processManager.GetProcessInfo()
	sp.logger.Info("Stopping subprocess plugin", "pid", processInfo.PID)

	// Use lifecycle manager for coordinated shutdown
	return sp.lifecycleManager.Shutdown(ctx)
}

// Health implements the Plugin interface - checks if the subprocess is healthy.
func (sp *SubprocessPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	now := time.Now()

	if !sp.processManager.IsStarted() {
		return HealthStatus{
			Status:       StatusOffline,
			Message:      "subprocess not started",
			LastCheck:    now,
			ResponseTime: 0,
		}
	}

	processInfo := sp.processManager.GetProcessInfo()
	if processInfo == nil {
		return HealthStatus{
			Status:       StatusUnhealthy,
			Message:      "no process information available",
			LastCheck:    now,
			ResponseTime: 0,
		}
	}

	if processInfo.Status != StatusRunning {
		return HealthStatus{
			Status:       StatusOffline,
			Message:      fmt.Sprintf("subprocess not running: %s", processInfo.Status),
			LastCheck:    now,
			ResponseTime: 0,
		}
	}

	start := time.Now()

	// Check if process is still alive using process manager
	if !sp.processManager.IsAlive() {
		return HealthStatus{
			Status:       StatusUnhealthy,
			Message:      "subprocess process check failed",
			LastCheck:    now,
			ResponseTime: time.Since(start),
		}
	}

	return HealthStatus{
		Status:       StatusHealthy,
		Message:      "subprocess running and responsive",
		LastCheck:    now,
		ResponseTime: time.Since(start),
	}
}

// GetInfo returns information about the subprocess.
func (sp *SubprocessPlugin[Req, Resp]) GetInfo() *ProcessInfo {
	return sp.processManager.GetProcessInfo()
}

// Close implements the Plugin interface - gracefully shuts down the subprocess.
func (sp *SubprocessPlugin[Req, Resp]) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return sp.Stop(ctx)
}

// Info implements the Plugin interface - returns plugin metadata.
func (sp *SubprocessPlugin[Req, Resp]) Info() PluginInfo {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	metadata := make(map[string]string)
	metadata["transport"] = string(TransportExecutable)

	// Get process information from process manager
	processInfo := sp.processManager.GetProcessInfo()
	if processInfo != nil {
		metadata["pid"] = fmt.Sprintf("%d", processInfo.PID)
		metadata["status"] = processInfo.Status.String()
		metadata["started_at"] = processInfo.StartTime.Format(time.RFC3339)
	}

	return PluginInfo{
		Name:         "subprocess-plugin",
		Version:      "1.0.0",
		Description:  "Subprocess plugin with refactored architecture",
		Author:       "AGILira go-plugins",
		Capabilities: []string{"subprocess", "process-management", "standard-protocol", "refactored-soc"},
		Metadata:     metadata,
	}
}
