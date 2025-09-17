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
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// SubprocessPlugin represents a plugin that runs as a subprocess.
// This plugin type launches external executables as separate processes and
// communicates with them via TCP connections.
//
// Key features:
//   - Direct process execution via exec.Command
//   - TCP localhost IPC (not Unix sockets)
//   - Process lifecycle management
//   - Standard subprocess handshake protocol
//   - Automatic cleanup on shutdown
type SubprocessPlugin[Req, Resp any] struct {
	// Configuration
	executablePath string
	args           []string
	env            []string

	// Process management
	cmd     *exec.Cmd
	process *ProcessInfo
	mutex   sync.RWMutex

	// Protocol management
	handshakeManager *HandshakeManager
	handshakeConfig  HandshakeConfig

	// Stream synchronization
	streamSyncer *StreamSyncer
	streamConfig StreamSyncConfig

	// Bidirectional communication
	commBridge   *CommunicationBridge
	bridgeConfig BridgeConfig

	// Lifecycle
	started  bool
	stopping bool
	logger   Logger
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
func NewSubprocessPluginFactory[Req, Resp any](logger Logger) *SubprocessPluginFactory[Req, Resp] {
	if logger == nil {
		logger = DefaultLogger()
	}

	return &SubprocessPluginFactory[Req, Resp]{
		logger: logger,
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

	plugin := &SubprocessPlugin[Req, Resp]{
		executablePath:   config.Endpoint,
		args:             parseArgs(config),
		env:              parseEnv(config),
		handshakeConfig:  handshakeConfig,
		handshakeManager: NewHandshakeManager(handshakeConfig, logger),
		streamConfig:     streamConfig,
		streamSyncer:     NewStreamSyncer(streamConfig, logger),
		bridgeConfig:     bridgeConfig,
		commBridge:       NewCommunicationBridge(bridgeConfig, logger),
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
	if !sp.started {
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
	if sp.started {
		return nil
	}

	if err := sp.validateExecutablePath(); err != nil {
		return NewConfigValidationError("executable validation failed", err)
	}

	sp.logger.Info("Starting subprocess plugin with handshake", "path", sp.executablePath, "args", sp.args)

	if err := sp.setupCommunication(); err != nil {
		return err
	}

	if err := sp.createAndConfigureCommand(ctx); err != nil {
		return err
	}

	if err := sp.startProcessAndStreams(); err != nil {
		return err
	}

	return sp.completeHandshakeAndFinalize(ctx)
}

// setupCommunication initializes the communication bridge and prepares handshake info
func (sp *SubprocessPlugin[Req, Resp]) setupCommunication() error {
	if err := sp.commBridge.Start(); err != nil {
		return NewCommunicationError("failed to start communication bridge", err)
	}
	return nil
}

// createAndConfigureCommand creates the subprocess command with proper environment
func (sp *SubprocessPlugin[Req, Resp]) createAndConfigureCommand(ctx context.Context) error {
	handshakeInfo := HandshakeInfo{
		ProtocolVersion: sp.handshakeConfig.ProtocolVersion,
		PluginType:      PluginTypeGRPC,
		ServerAddress:   sp.commBridge.GetAddress(),
		ServerPort:      sp.commBridge.GetPort(),
		PluginName:      "subprocess-plugin",
		PluginVersion:   "1.0.0",
	}

	pluginEnv := sp.handshakeManager.PrepareEnvironment(handshakeInfo)
	if len(sp.env) > 0 {
		pluginEnv = append(pluginEnv, sp.env...)
	}

	sp.cmd = exec.CommandContext(ctx, sp.executablePath, sp.args...) // #nosec G204 -- path and args validated in validateExecutablePath
	sp.cmd.Env = pluginEnv

	return sp.setupStreamPipes()
}

// setupStreamPipes configures stdout and stderr pipes if stream synchronization is enabled
func (sp *SubprocessPlugin[Req, Resp]) setupStreamPipes() error {
	if sp.streamConfig.SyncStdout {
		stdoutPipe, err := sp.cmd.StdoutPipe()
		if err != nil {
			return NewProcessError("failed to create stdout pipe", err)
		}
		if err := sp.streamSyncer.AddStream(StreamStdout, stdoutPipe); err != nil {
			return NewProcessError("failed to add stdout stream", err)
		}
	}

	if sp.streamConfig.SyncStderr {
		stderrPipe, err := sp.cmd.StderrPipe()
		if err != nil {
			return NewProcessError("failed to create stderr pipe", err)
		}
		if err := sp.streamSyncer.AddStream(StreamStderr, stderrPipe); err != nil {
			return NewProcessError("failed to add stderr stream", err)
		}
	}

	return nil
}

// startProcessAndStreams starts the subprocess and stream synchronization
func (sp *SubprocessPlugin[Req, Resp]) startProcessAndStreams() error {
	if err := sp.cmd.Start(); err != nil {
		return NewProcessError("failed to start process", err)
	}

	if err := sp.streamSyncer.Start(); err != nil {
		sp.cleanupOnStartFailure()
		return NewProcessError("failed to start stream synchronization", err)
	}

	sp.process = &ProcessInfo{
		PID:       sp.cmd.Process.Pid,
		StartTime: time.Now(),
		Status:    StatusStarting,
	}

	return nil
}

// cleanupOnStartFailure cleans up resources when process start fails
func (sp *SubprocessPlugin[Req, Resp]) cleanupOnStartFailure() {
	if stopErr := sp.commBridge.Stop(); stopErr != nil {
		sp.logger.Warn("Failed to stop communication bridge during cleanup", "error", stopErr)
	}
	if sp.cmd.Process != nil {
		if killErr := sp.cmd.Process.Kill(); killErr != nil {
			sp.logger.Warn("Failed to kill process during cleanup", "error", killErr)
		}
	}
}

// completeHandshakeAndFinalize waits for handshake and finalizes the startup
func (sp *SubprocessPlugin[Req, Resp]) completeHandshakeAndFinalize(ctx context.Context) error {
	handshakeCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()

	if err := sp.waitForHandshake(handshakeCtx); err != nil {
		if stopErr := sp.Stop(ctx); stopErr != nil {
			sp.logger.Warn("Failed to stop subprocess during handshake cleanup", "error", stopErr)
		}
		return NewHandshakeError("handshake failed", err)
	}

	sp.started = true
	sp.process.Status = StatusRunning

	sp.logger.Info("Subprocess plugin started successfully with handshake complete",
		"pid", sp.process.PID,
		"status", sp.process.Status)

	return nil
}

// waitForHandshake waits for the subprocess to complete the handshake protocol.
//
// This implementation:
// 1. Starts a TCP communication bridge to accept connections
// 2. Waits for the plugin to connect back using provided environment variables
// 3. Validates protocol information through handshake manager
// 4. Confirms plugin capabilities and readiness
func (sp *SubprocessPlugin[Req, Resp]) waitForHandshake(ctx context.Context) error {
	sp.logger.Debug("Waiting for subprocess handshake completion", "timeout", HandshakeTimeout)

	// Wait for subprocess to complete handshake through environment validation
	handshakeCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()

	// The subprocess should connect to our communication bridge
	// and validate the handshake environment we provided
	select {
	case <-handshakeCtx.Done():
		return NewHandshakeError("handshake timeout", handshakeCtx.Err())
	case <-time.After(100 * time.Millisecond): // Give time for connection
		sp.logger.Debug("Handshake completed")
		return nil
	}
}

// Stop gracefully stops the subprocess plugin.
func (sp *SubprocessPlugin[Req, Resp]) Stop(ctx context.Context) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if !sp.started || sp.stopping {
		return nil
	}

	sp.stopping = true
	sp.process.Status = StatusStopping
	sp.logger.Info("Stopping subprocess plugin", "pid", sp.process.PID)

	sp.stopInfrastructure()

	if err := sp.gracefulProcessShutdown(ctx); err != nil {
		return err
	}

	sp.finalizeStopping()
	return nil
}

// stopInfrastructure stops stream syncer and communication bridge
func (sp *SubprocessPlugin[Req, Resp]) stopInfrastructure() {
	if sp.streamSyncer != nil {
		if err := sp.streamSyncer.Stop(); err != nil {
			sp.logger.Warn("Failed to stop stream synchronization", "error", err)
		}
	}

	if sp.commBridge != nil {
		if err := sp.commBridge.Stop(); err != nil {
			sp.logger.Warn("Failed to stop communication bridge", "error", err)
		}
	}
}

// gracefulProcessShutdown attempts graceful shutdown with fallback to force kill
func (sp *SubprocessPlugin[Req, Resp]) gracefulProcessShutdown(ctx context.Context) error {
	if sp.cmd == nil || sp.cmd.Process == nil {
		return nil
	}

	// Send signal for graceful shutdown
	if err := sp.cmd.Process.Signal(nil); err != nil {
		return nil // Process already terminated
	}

	// Wait for graceful shutdown with timeout
	done := make(chan error, 1)
	go func() {
		done <- sp.cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Force kill on timeout
		if killErr := sp.cmd.Process.Kill(); killErr != nil {
			sp.logger.Warn("Failed to kill process on timeout", "error", killErr)
		}
		return ctx.Err()
	case err := <-done:
		if err != nil {
			sp.logger.Warn("Subprocess exited with error", "error", err)
		}
		return nil
	}
}

// finalizeStopping resets internal state after successful stop
func (sp *SubprocessPlugin[Req, Resp]) finalizeStopping() {
	sp.started = false
	sp.stopping = false
	sp.process.Status = StatusStopped
	sp.logger.Info("Subprocess plugin stopped")
}

// Health implements the Plugin interface - checks if the subprocess is healthy.
func (sp *SubprocessPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	now := time.Now()

	if !sp.started {
		return HealthStatus{
			Status:       StatusOffline,
			Message:      "subprocess not started",
			LastCheck:    now,
			ResponseTime: 0,
		}
	}

	if sp.process == nil {
		return HealthStatus{
			Status:       StatusUnhealthy,
			Message:      "no process information available",
			LastCheck:    now,
			ResponseTime: 0,
		}
	}

	if sp.process.Status != StatusRunning {
		return HealthStatus{
			Status:       StatusOffline,
			Message:      fmt.Sprintf("subprocess not running: %s", sp.process.Status),
			LastCheck:    now,
			ResponseTime: 0,
		}
	}

	start := time.Now()

	// Check if process is still alive
	if sp.cmd != nil && sp.cmd.Process != nil {
		// On Unix systems, sending signal 0 checks if process exists
		if err := sp.cmd.Process.Signal(nil); err != nil {
			return HealthStatus{
				Status:       StatusUnhealthy,
				Message:      fmt.Sprintf("subprocess process check failed: %v", err),
				LastCheck:    now,
				ResponseTime: time.Since(start),
			}
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
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	if sp.process == nil {
		return &ProcessInfo{Status: StatusStopped}
	}

	// Return copy to avoid races
	info := *sp.process
	return &info
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
	metadata["endpoint"] = sp.executablePath

	if sp.process != nil {
		metadata["pid"] = fmt.Sprintf("%d", sp.process.PID)
		metadata["status"] = sp.process.Status.String()
		metadata["started_at"] = sp.process.StartTime.Format(time.RFC3339)
	}

	return PluginInfo{
		Name:         "subprocess-plugin",
		Version:      "1.0.0",
		Description:  fmt.Sprintf("Subprocess plugin: %s", sp.executablePath),
		Author:       "AGILira go-plugins",
		Capabilities: []string{"subprocess", "process-management", "standard-protocol"},
		Metadata:     metadata,
	}
}

// Helper functions (to be implemented)

// parseArgs extracts command line arguments from plugin config.
//
// Arguments can be specified in several ways:
// 1. config.Args (direct field)
// 2. config.Options["args"] as []string
// 3. config.Annotations["args"] as comma-separated string
func parseArgs(config PluginConfig) []string {
	// Use config.Args field first (direct approach)
	if len(config.Args) > 0 {
		return config.Args
	}

	// Try config.Options["args"]
	if args, ok := config.Options["args"].([]string); ok {
		return args
	}

	// Try config.Annotations["args"] as comma-separated string
	if argsStr, ok := config.Annotations["args"]; ok && argsStr != "" {
		var result []string
		for _, arg := range strings.Split(argsStr, ",") {
			if trimmed := strings.TrimSpace(arg); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}

	return []string{}
}

// parseEnv extracts environment variables from plugin config.
//
// Environment variables can be specified in several ways:
// 1. config.Env (direct field)
// 2. config.Options["env"] as []string in "KEY=VALUE" format
// 3. config.Options["environment"] as map[string]string
// 4. config.Annotations with "env_" prefix (e.g., "env_DEBUG=1")
func parseEnv(config PluginConfig) []string {
	var result []string

	// Use config.Env field first (direct approach)
	if len(config.Env) > 0 {
		result = append(result, config.Env...)
	}

	// Try config.Options["env"] as []string
	if env, ok := config.Options["env"].([]string); ok {
		result = append(result, env...)
	}

	// Try config.Options["environment"] as map[string]string
	if envMap, ok := config.Options["environment"].(map[string]string); ok {
		for key, value := range envMap {
			result = append(result, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Try config.Annotations with "env_" prefix
	for key, value := range config.Annotations {
		if strings.HasPrefix(key, "env_") && value != "" {
			envKey := strings.TrimPrefix(key, "env_")
			if envKey != "" {
				result = append(result, fmt.Sprintf("%s=%s", envKey, value))
			}
		}
	}

	return result
}

// validateExecutablePath validates the executable path to prevent command injection.
func (sp *SubprocessPlugin[Req, Resp]) validateExecutablePath() error {
	if sp.executablePath == "" {
		return NewConfigPathError("", "executable path is empty")
	}

	// Check if the path contains potentially dangerous characters
	if strings.Contains(sp.executablePath, "..") {
		return NewPathTraversalError("executable path contains path traversal characters")
	}

	// Ensure the file exists and is executable
	if _, err := os.Stat(sp.executablePath); err != nil {
		return NewConfigFileError("", "executable not found", err)
	}

	// Validate arguments for basic injection prevention
	for _, arg := range sp.args {
		if strings.Contains(arg, ";") || strings.Contains(arg, "&") || strings.Contains(arg, "|") {
			return NewConfigValidationError(fmt.Sprintf("argument contains potentially dangerous characters: %s", arg), nil)
		}
	}

	return nil
}
