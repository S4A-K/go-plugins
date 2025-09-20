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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// SubprocessRequest represents a request sent to a subprocess plugin.
type SubprocessRequest struct {
	ID      string           `json:"id"`
	Method  string           `json:"method"`
	Payload interface{}      `json:"payload"`
	Context ExecutionContext `json:"context"`
}

// SubprocessResponse represents a response received from a subprocess plugin.
type SubprocessResponse[T any] struct {
	ID     string  `json:"id"`
	Result T       `json:"result,omitempty"`
	Error  *string `json:"error,omitempty"`
}

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
	// Unified management (simplified architecture)
	subprocessManager *SubprocessManager

	// Communication pipes (configured during startup)
	stdin  io.WriteCloser
	stdout io.ReadCloser

	// Communication state
	communicationMutex sync.Mutex // Serialize subprocess communication

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

	// Disable stdout syncing for subprocess communication to avoid pipe conflicts
	// We need stdout for request-response communication
	streamConfig.SyncStdout = false

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

	// Create unified subprocess manager
	subprocessManager := NewSubprocessManager(SubprocessManagerConfig{
		BaseConfig:      BaseConfig{}.WithDefaults(),
		ExecutablePath:  parsedConfig.ExecutablePath,
		Args:            parsedConfig.Args,
		Env:             parsedConfig.Env,
		HandshakeConfig: handshakeConfig,
		StreamConfig:    streamConfig,
		BridgeConfig:    bridgeConfig,
		Logger:          logger,
	})

	plugin := &SubprocessPlugin[Req, Resp]{
		// Unified management (simplified architecture)
		subprocessManager: subprocessManager,
		logger:            logger,
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

	// Ensure subprocess is started with elegant initialization
	if !sp.subprocessManager.IsStarted() {
		if err := sp.ensureProcessStarted(ctx); err != nil {
			return zero, NewProcessError("failed to start subprocess", err)
		}
	}

	// Communication infrastructure ready - using direct subprocess communication
	commBridge := sp.subprocessManager.GetCommunicationBridge()
	if commBridge == nil {
		return zero, NewCommunicationError("communication bridge not available", nil)
	}

	sp.logger.Debug("Executing subprocess request",
		"request_id", execCtx.RequestID,
		"timeout", execCtx.Timeout)

	// Execute request with streamlined communication flow
	result, err := sp.executeRequest(ctx, execCtx, request)
	if err != nil {
		return zero, err
	}

	return result, nil
}

// ensureProcessStarted ensures the subprocess is started with elegant initialization.
// This method consolidates the startup logic into a single, cohesive flow while maintaining
// clear separation of concerns and robust error handling.
func (sp *SubprocessPlugin[Req, Resp]) ensureProcessStarted(ctx context.Context) error {
	if sp.subprocessManager.IsStarted() {
		return nil
	}

	sp.logger.Info("Starting subprocess plugin with streamlined initialization")

	// Prepare handshake information for elegant startup
	handshakeConfig := sp.subprocessManager.GetHandshakeConfig()
	handshakeInfo := HandshakeInfo{
		ProtocolVersion: handshakeConfig.ProtocolVersion,
		PluginType:      PluginTypeGRPC,
		ServerAddress:   sp.subprocessManager.GetAddress(),
		ServerPort:      sp.subprocessManager.GetPort(),
		PluginName:      "subprocess-plugin",
		PluginVersion:   "1.0.0",
	}

	// Prepare handshake environment using subprocess manager components
	handshakeManager := sp.subprocessManager.GetHandshakeManager()
	handshakeEnv := handshakeManager.PrepareEnvironment(handshakeInfo)

	// Start communication bridge
	if err := sp.subprocessManager.StartCommunicationBridge(); err != nil {
		return NewCommunicationError("failed to start communication bridge", err)
	}

	// Create elegant setup function that configures communication pipes
	setupFunc := func(cmd *exec.Cmd) error {
		sp.logger.Debug("Configuring communication pipes during elegant startup")

		// Configure stdin pipe for JSON requests
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return NewProcessError("failed to create stdin pipe during startup", err)
		}
		sp.stdin = stdin

		// Configure stdout pipe for JSON responses
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return NewProcessError("failed to create stdout pipe during startup", err)
		}
		sp.stdout = stdout

		// Keep stderr separate for logging/debugging
		// The stream syncer can still configure stderr for stream synchronization

		sp.logger.Debug("Communication pipes configured successfully during elegant startup")
		return nil
	}

	// Start the process with elegant setup function
	if err := sp.subprocessManager.StartWithEnvironmentAndSetup(ctx, handshakeEnv, setupFunc); err != nil {
		// Cleanup communication bridge on failure
		if stopErr := sp.subprocessManager.StopCommunicationBridge(); stopErr != nil {
			sp.logger.Warn("Failed to stop communication bridge during cleanup", "error", stopErr)
		}
		return err
	}

	// Start stream synchronization for stderr only (stdout is used for communication)
	streamConfig := sp.subprocessManager.GetStreamConfig()
	streamSyncer := sp.subprocessManager.GetStreamSyncer()
	if streamConfig.SyncStderr {
		if err := streamSyncer.Start(); err != nil {
			sp.logger.Warn("Failed to start stream synchronization", "error", err)
		}
	}

	sp.logger.Info("Subprocess plugin started successfully with elegant initialization")
	return nil
}

// executeRequest executes a request with streamlined communication flow.
// This method combines the logic from executeViaStandardIO and executeJSONProtocol
// for better readability and reduced complexity while maintaining thread safety.
func (sp *SubprocessPlugin[Req, Resp]) executeRequest(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp

	// Serialize subprocess communication to prevent race conditions
	sp.communicationMutex.Lock()
	defer sp.communicationMutex.Unlock()

	sp.logger.Debug("Executing subprocess request with streamlined flow",
		"request_id", execCtx.RequestID)

	// Get the process command and ensure we have access to stdin/stdout
	cmd := sp.subprocessManager.GetCommand()
	if cmd == nil {
		return zero, NewProcessError("subprocess command not available", nil)
	}

	// Get or create communication pipes
	stdin, stdout, err := sp.getCommunicationPipes(cmd)
	if err != nil {
		return zero, err
	}

	// Create execution context with timeout
	execCtxWithTimeout := ctx
	if execCtx.Timeout > 0 {
		var cancel context.CancelFunc
		execCtxWithTimeout, cancel = context.WithTimeout(ctx, execCtx.Timeout)
		defer cancel()
	}

	// Execute JSON-based subprocess communication
	response, err := sp.performJSONCommunication(execCtxWithTimeout, execCtx, request, stdin, stdout)
	if err != nil {
		return zero, err
	}

	sp.logger.Debug("Subprocess execution completed successfully",
		"request_id", execCtx.RequestID)

	return response, nil
}

// getCommunicationPipes retrieves or creates stdin and stdout pipes for communication.
// This method provides elegant access to communication pipes with centralized management.
func (sp *SubprocessPlugin[Req, Resp]) getCommunicationPipes(cmd *exec.Cmd) (io.WriteCloser, io.ReadCloser, error) {
	// Ensure pipes are properly configured
	if err := sp.ensureCommunicationPipes(cmd); err != nil {
		return nil, nil, err
	}

	// Return the configured pipes
	return sp.stdin, sp.stdout, nil
}

// ensureCommunicationPipes ensures that stdin and stdout pipes are properly configured.
// This method provides elegant, centralized pipe management with robust error handling.
func (sp *SubprocessPlugin[Req, Resp]) ensureCommunicationPipes(cmd *exec.Cmd) error {
	// Ensure stdin pipe is configured
	if err := sp.ensureStdinPipe(cmd); err != nil {
		return NewCommunicationError("failed to ensure stdin pipe", err)
	}

	// Ensure stdout pipe is configured
	if err := sp.ensureStdoutPipe(cmd); err != nil {
		return NewCommunicationError("failed to ensure stdout pipe", err)
	}

	return nil
}

// ensureStdinPipe ensures the stdin pipe is properly configured with elegant caching logic.
func (sp *SubprocessPlugin[Req, Resp]) ensureStdinPipe(cmd *exec.Cmd) error {
	// Use cached pipe if available
	if sp.stdin != nil {
		return nil
	}

	// Check if stdin is already configured by another component
	if cmd.Stdin != nil {
		if writeCloser, ok := cmd.Stdin.(io.WriteCloser); ok {
			sp.stdin = writeCloser
			sp.logger.Debug("Using existing stdin pipe for subprocess communication")
			return nil
		}
		return NewProcessError("stdin already configured but not writable", nil)
	}

	// Process is already started, we can't create new pipes
	if sp.subprocessManager.IsStarted() {
		return NewProcessError("cannot create stdin pipe after process started", nil)
	}

	// Create new stdin pipe
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return NewProcessError("failed to create stdin pipe", err)
	}

	sp.stdin = stdin
	sp.logger.Debug("Created stdin pipe for subprocess communication")
	return nil
}

// ensureStdoutPipe ensures the stdout pipe is properly configured with elegant caching logic.
func (sp *SubprocessPlugin[Req, Resp]) ensureStdoutPipe(cmd *exec.Cmd) error {
	// Use cached pipe if available
	if sp.stdout != nil {
		return nil
	}

	// Check if stdout is already configured by another component
	if cmd.Stdout != nil {
		if readCloser, ok := cmd.Stdout.(io.ReadCloser); ok {
			sp.stdout = readCloser
			sp.logger.Debug("Using existing stdout pipe for subprocess communication")
			return nil
		}
		return NewProcessError("stdout already configured but not readable", nil)
	}

	// Process is already started, we can't create new pipes
	if sp.subprocessManager.IsStarted() {
		return NewProcessError("cannot create stdout pipe after process started", nil)
	}

	// Create new stdout pipe
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return NewProcessError("failed to create stdout pipe", err)
	}

	sp.stdout = stdout
	sp.logger.Debug("Created stdout pipe for subprocess communication")
	return nil
}

// performJSONCommunication performs the complete JSON-based subprocess communication.
// This method handles the core JSON protocol communication with the subprocess.
func (sp *SubprocessPlugin[Req, Resp]) performJSONCommunication(
	ctx context.Context,
	execCtx ExecutionContext,
	request Req,
	stdin io.WriteCloser,
	stdout io.ReadCloser,
) (Resp, error) {
	var zero Resp

	// Create subprocess request wrapper following the standard protocol
	subprocessRequest := SubprocessRequest{
		ID:      execCtx.RequestID,
		Method:  "execute",
		Payload: request,
		Context: execCtx,
	}

	// Serialize request to JSON
	requestData, err := json.Marshal(subprocessRequest)
	if err != nil {
		return zero, NewSerializationError("failed to marshal subprocess request", err)
	}

	sp.logger.Debug("Sending JSON request to subprocess",
		"request_id", execCtx.RequestID,
		"size", len(requestData))

	// Send request to subprocess with timeout
	if err := sp.sendJSONRequest(ctx, stdin, requestData); err != nil {
		return zero, err
	}

	// Read JSON response from subprocess with timeout
	responseData, err := sp.readJSONResponse(ctx, stdout)
	if err != nil {
		return zero, err
	}

	sp.logger.Debug("Received JSON response from subprocess",
		"request_id", execCtx.RequestID,
		"size", len(responseData))

	// Deserialize response
	var subprocessResponse SubprocessResponse[Resp]
	if err := json.Unmarshal(responseData, &subprocessResponse); err != nil {
		return zero, NewSerializationError("failed to unmarshal subprocess response", err)
	}

	// Validate response
	if err := sp.validateResponse(&subprocessResponse, execCtx.RequestID); err != nil {
		return zero, err
	}

	return subprocessResponse.Result, nil
}

// sendJSONRequest sends a JSON request to subprocess stdin.
func (sp *SubprocessPlugin[Req, Resp]) sendJSONRequest(ctx context.Context, stdin io.WriteCloser, data []byte) error {
	done := make(chan error, 1)

	go func() {
		// Write JSON request followed by newline (line-delimited JSON protocol)
		_, err := stdin.Write(append(data, '\n'))
		if err != nil {
			done <- NewCommunicationError("failed to write JSON request to subprocess stdin", err)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return NewCommunicationError("timeout writing JSON request to subprocess", ctx.Err())
	}
}

// readJSONResponse reads a JSON response from subprocess stdout.
func (sp *SubprocessPlugin[Req, Resp]) readJSONResponse(ctx context.Context, stdout io.ReadCloser) ([]byte, error) {
	done := make(chan struct {
		data []byte
		err  error
	}, 1)

	go func() {
		// Read JSON response line (line-delimited JSON protocol)
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			data := make([]byte, len(scanner.Bytes()))
			copy(data, scanner.Bytes())
			done <- struct {
				data []byte
				err  error
			}{data: data, err: nil}
		} else {
			err := scanner.Err()
			if err == nil {
				err = io.EOF
			}
			done <- struct {
				data []byte
				err  error
			}{data: nil, err: NewCommunicationError("failed to read JSON response from subprocess stdout", err)}
		}
	}()

	select {
	case result := <-done:
		return result.data, result.err
	case <-ctx.Done():
		return nil, NewCommunicationError("timeout reading JSON response from subprocess", ctx.Err())
	}
}

// validateResponse validates the subprocess response.
func (sp *SubprocessPlugin[Req, Resp]) validateResponse(response *SubprocessResponse[Resp], expectedRequestID string) error {
	// Check for subprocess errors
	if response.Error != nil {
		return NewProcessError("subprocess execution failed", fmt.Errorf("%s", *response.Error))
	}

	// Validate response ID matches request ID
	if response.ID != expectedRequestID {
		return NewCommunicationError(
			fmt.Sprintf("response ID mismatch: expected %s, got %s", expectedRequestID, response.ID),
			nil,
		)
	}

	return nil
}

// Stop gracefully stops the subprocess plugin.
func (sp *SubprocessPlugin[Req, Resp]) Stop(ctx context.Context) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if !sp.subprocessManager.IsStarted() || sp.subprocessManager.IsStopping() {
		return nil
	}

	processInfo := sp.subprocessManager.GetProcessInfo()
	sp.logger.Info("Stopping subprocess plugin", "pid", processInfo.PID)

	// Use subprocess manager for coordinated shutdown
	return sp.subprocessManager.Stop(ctx)
}

// Health implements the Plugin interface - checks if the subprocess is healthy.
func (sp *SubprocessPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	now := time.Now()

	if !sp.subprocessManager.IsStarted() {
		return HealthStatus{
			Status:       StatusOffline,
			Message:      "subprocess not started",
			LastCheck:    now,
			ResponseTime: 0,
		}
	}

	processInfo := sp.subprocessManager.GetProcessInfo()
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
	if !sp.subprocessManager.IsAlive() {
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
	return sp.subprocessManager.GetProcessInfo()
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
	processInfo := sp.subprocessManager.GetProcessInfo()
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

// NewSubprocessPluginWithManager creates a subprocess plugin with a pre-configured manager.
//
// This function allows creating subprocess plugins with a unified subprocess manager,
// providing better integration with the simplified factory pattern while maintaining
// compatibility with existing interfaces.
func NewSubprocessPluginWithManager[Req, Resp any](
	config PluginConfig,
	manager *SubprocessManager,
	logger Logger) (Plugin[Req, Resp], error) {

	if manager == nil {
		return nil, NewPluginCreationError("subprocess manager cannot be nil", nil)
	}

	if logger == nil {
		logger = DefaultLogger()
	}

	// Currently using the factory pattern for compatibility with existing plugin interfaces.
	// The passed manager parameter is available for future direct integration when the
	// plugin architecture is refactored to support direct manager injection.
	//
	// NOTE: Future enhancement - utilize the passed manager directly instead of factory
	// This would require extending the plugin interface to accept pre-configured managers
	factory := NewSubprocessPluginFactory[Req, Resp](logger)
	return factory.CreatePlugin(config)
}
