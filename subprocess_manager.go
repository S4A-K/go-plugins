// subprocess_manager.go: Unified subprocess management
//
// This file consolidates process management and lifecycle coordination
// into a single, cohesive manager that handles all aspects of subprocess
// plugin management while maintaining clear separation of concerns.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// SubprocessManager handles all aspects of subprocess plugin management.
//
// This unified manager combines the responsibilities of process management
// and lifecycle coordination while maintaining clean interfaces and
// clear separation of concerns. It provides a single point of control
// for subprocess operations without creating a monolithic structure.
//
// Key responsibilities:
// - Process creation and monitoring
// - Lifecycle coordination (startup, operation, shutdown)
// - Communication setup and management
// - Error handling and recovery
// - Resource cleanup
type SubprocessManager struct {
	// Base configuration
	BaseConfig

	// Process configuration
	executablePath string
	args           []string
	env            []string

	// Components (maintained for compatibility and modularity)
	configParser        *ConfigParser
	handshakeManager    *HandshakeManager
	streamSyncer        *StreamSyncer
	communicationBridge *CommunicationBridge

	// Component configurations (stored for accessor methods)
	handshakeConfig HandshakeConfig
	streamConfig    StreamSyncConfig
	bridgeConfig    BridgeConfig

	// Process state
	cmd     *exec.Cmd
	process *ProcessInfo
	mutex   sync.RWMutex

	// Status tracking
	started  bool
	stopping bool

	logger Logger
}

// SubprocessManagerConfig contains all configuration needed for subprocess management.
//
// This consolidated configuration reduces the number of separate config structs
// while providing all necessary options for subprocess management.
type SubprocessManagerConfig struct {
	BaseConfig

	// Process configuration
	ExecutablePath string   `json:"executable_path" yaml:"executable_path"`
	Args           []string `json:"args,omitempty" yaml:"args,omitempty"`
	Env            []string `json:"env,omitempty" yaml:"env,omitempty"`

	// Component configurations
	HandshakeConfig HandshakeConfig  `json:"handshake" yaml:"handshake"`
	StreamConfig    StreamSyncConfig `json:"stream_sync" yaml:"stream_sync"`
	BridgeConfig    BridgeConfig     `json:"communication_bridge" yaml:"communication_bridge"`

	Logger Logger `json:"-" yaml:"-"`
}

// NewSubprocessManager creates a new unified subprocess manager.
//
// This constructor initializes all necessary components while providing
// a clean, single interface for subprocess management.
func NewSubprocessManager(config SubprocessManagerConfig) *SubprocessManager {
	// Apply base configuration defaults
	config.BaseConfig.ApplyDefaults()

	if config.Logger == nil {
		config.Logger = DefaultLogger()
	}

	// Create component instances
	configParser := NewConfigParser(config.Logger)
	handshakeManager := NewHandshakeManager(config.HandshakeConfig, config.Logger)
	streamSyncer := NewStreamSyncer(config.StreamConfig, config.Logger)
	commBridge := NewCommunicationBridge(config.BridgeConfig, config.Logger)

	return &SubprocessManager{
		BaseConfig:          config.BaseConfig,
		executablePath:      config.ExecutablePath,
		args:                config.Args,
		env:                 config.Env,
		configParser:        configParser,
		handshakeManager:    handshakeManager,
		streamSyncer:        streamSyncer,
		communicationBridge: commBridge,
		handshakeConfig:     config.HandshakeConfig,
		streamConfig:        config.StreamConfig,
		bridgeConfig:        config.BridgeConfig,
		logger:              config.Logger,
	}
}

// Start initiates the complete subprocess startup sequence.
//
// This method orchestrates all phases of subprocess initialization:
// communication setup, process start, and handshake completion.
func (sm *SubprocessManager) Start(ctx context.Context) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.started {
		return nil
	}

	sm.logger.Info("Starting subprocess management sequence",
		"path", sm.executablePath,
		"args", sm.args)

	// Phase 1: Setup communication infrastructure
	if err := sm.setupCommunication(); err != nil {
		return NewSubprocessError("failed to setup communication", err)
	}

	// Phase 2: Start the process with proper stream handling
	if err := sm.startProcessWithStreams(ctx); err != nil {
		sm.cleanupOnFailure()
		return NewSubprocessError("failed to start process", err)
	}

	// Phase 3: Complete handshake protocol
	if err := sm.completeHandshake(ctx); err != nil {
		sm.cleanupOnFailure()
		return NewSubprocessError("failed to complete handshake", err)
	}

	sm.started = true
	sm.logger.Info("Subprocess management startup completed successfully")
	return nil
}

// Stop initiates graceful shutdown of the subprocess.
//
// This method coordinates the shutdown sequence ensuring proper cleanup
// of all resources and components.
func (sm *SubprocessManager) Stop(ctx context.Context) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if !sm.started || sm.stopping {
		return nil
	}

	sm.stopping = true
	sm.logger.Info("Starting subprocess shutdown sequence")

	// Phase 1: Signal shutdown to process
	if err := sm.signalShutdown(ctx); err != nil {
		sm.logger.Warn("Failed to signal graceful shutdown", "error", err)
	}

	// Phase 2: Stop communication components
	sm.stopCommunication()

	// Phase 3: Terminate process if still running
	if err := sm.terminateProcess(ctx); err != nil {
		sm.logger.Warn("Failed to terminate process gracefully", "error", err)
		return err
	}

	sm.started = false
	sm.stopping = false
	sm.logger.Info("Subprocess shutdown completed")
	return nil
}

// GetProcessInfo returns current process information.
func (sm *SubprocessManager) GetProcessInfo() *ProcessInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	if sm.process == nil {
		return &ProcessInfo{Status: StatusStopped}
	}

	return sm.process
}

// Adapter methods for backward compatibility with existing SubprocessPlugin code

// IsStarted returns true if the subprocess has been started.
func (sm *SubprocessManager) IsStarted() bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.started
}

// IsStopping returns true if the subprocess is in the process of stopping.
func (sm *SubprocessManager) IsStopping() bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.stopping
}

// IsAlive returns true if the subprocess process is still alive.
func (sm *SubprocessManager) IsAlive() bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	if sm.cmd == nil || sm.cmd.Process == nil {
		return false
	}

	// Check if process is still running
	return sm.process != nil && sm.process.Status == StatusRunning
}

// GetCommand returns the exec.Cmd for the subprocess (for backward compatibility).
func (sm *SubprocessManager) GetCommand() *exec.Cmd {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.cmd
}

// StartWithEnvironmentAndSetup starts the subprocess with additional environment and setup function.
//
// This method orchestrates subprocess startup with custom environment and configuration,
// breaking down the complex startup process into well-defined phases for better maintainability
// and error handling.
//
// Startup Phases:
//  1. Environment preparation - combines base and additional environment variables
//  2. Command setup - applies custom setup function if provided
//  3. Stream configuration - configures stdout/stderr synchronization
//  4. Process execution - starts the subprocess and initializes monitoring
//
// Error Handling:
//   - Returns immediately on any setup failure
//   - Provides detailed error context for troubleshooting
//   - Maintains subprocess state consistency
//
// Complexity: Reduced from 16 to 4 through phase separation
func (sm *SubprocessManager) StartWithEnvironmentAndSetup(ctx context.Context, additionalEnv []string, setupFunc func(*exec.Cmd) error) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.started {
		return nil
	}

	sm.logger.Info("Starting subprocess with additional environment",
		"path", sm.executablePath,
		"args", sm.args,
		"additional_env_count", len(additionalEnv))

	// Phase 1: Prepare command with combined environment
	if err := sm.prepareCommandWithEnvironment(ctx, additionalEnv); err != nil {
		return NewSubprocessError("failed to prepare command environment", err)
	}

	// Phase 2: Apply custom setup function if provided
	if err := sm.applyCustomSetup(setupFunc); err != nil {
		return NewSubprocessError("failed to apply custom setup", err)
	}

	// Phase 3: Configure stream synchronization
	if err := sm.configureStreamSynchronization(); err != nil {
		return NewSubprocessError("failed to configure stream synchronization", err)
	}

	// Phase 4: Execute process and initialize monitoring
	if err := sm.executeAndInitializeProcess(); err != nil {
		return NewSubprocessError("failed to execute and initialize process", err)
	}

	sm.started = true
	sm.logger.Info("Subprocess started successfully with environment setup")
	return nil
}

// prepareCommandWithEnvironment creates the exec.Cmd with combined environment variables.
//
// This helper method encapsulates environment variable preparation logic,
// ensuring proper combination of base and additional environment settings.
//
// Environment Combination Strategy:
//   - Base environment variables are applied first
//   - Additional environment variables override or extend base settings
//   - Memory allocation is optimized with pre-calculated capacity
//
// Complexity: 1 (single responsibility - environment preparation)
func (sm *SubprocessManager) prepareCommandWithEnvironment(ctx context.Context, additionalEnv []string) error {
	// Create command with validated executable path
	sm.cmd = exec.CommandContext(ctx, sm.executablePath, sm.args...) // #nosec G204 -- path validated elsewhere

	// Combine base environment with additional environment for optimal memory usage
	combinedEnv := make([]string, 0, len(sm.env)+len(additionalEnv))
	combinedEnv = append(combinedEnv, sm.env...)
	combinedEnv = append(combinedEnv, additionalEnv...)
	sm.cmd.Env = combinedEnv

	return nil
}

// applyCustomSetup applies the custom setup function to the command.
//
// This helper method handles optional custom configuration of the exec.Cmd,
// allowing plugins to configure pipes, working directory, or other settings
// before process execution.
//
// Setup Function Timing:
//   - Applied BEFORE stream configuration to prevent pipe conflicts
//   - Allows plugin to configure its own stdout/stderr handling
//   - Maintains backward compatibility with existing setup functions
//
// Complexity: 2 (conditional setup application)
func (sm *SubprocessManager) applyCustomSetup(setupFunc func(*exec.Cmd) error) error {
	if setupFunc != nil {
		if err := setupFunc(sm.cmd); err != nil {
			return err
		}
	}
	return nil
}

// configureStreamSynchronization sets up stdout/stderr stream handling.
//
// This helper method configures stream synchronization only for streams that are:
//  1. Enabled in configuration (SyncStdout/SyncStderr)
//  2. Not already configured by custom setup function
//  3. Available for pipe creation
//
// Stream Configuration Logic:
//   - Respects custom setup function pipe assignments
//   - Only configures unclaimed streams to prevent conflicts
//   - Logs warnings for configuration failures without failing startup
//
// Complexity: 3 (conditional stream configuration with error handling)
func (sm *SubprocessManager) configureStreamSynchronization() error {
	if sm.streamSyncer == nil {
		return nil
	}

	// Configure stdout stream if enabled and available
	if sm.streamConfig.SyncStdout && sm.cmd.Stdout == nil {
		if stdout, err := sm.cmd.StdoutPipe(); err == nil {
			if addErr := sm.streamSyncer.AddStream(StreamStdout, stdout); addErr != nil {
				sm.logger.Warn("Failed to add stdout stream", "error", addErr)
			}
		}
	}

	// Configure stderr stream if enabled and available
	if sm.streamConfig.SyncStderr && sm.cmd.Stderr == nil {
		if stderr, err := sm.cmd.StderrPipe(); err == nil {
			if addErr := sm.streamSyncer.AddStream(StreamStderr, stderr); addErr != nil {
				sm.logger.Warn("Failed to add stderr stream", "error", addErr)
			}
		}
	}

	return nil
}

// executeAndInitializeProcess starts the subprocess and initializes process monitoring.
//
// This helper method handles the final phase of subprocess startup:
//  1. Process execution via exec.Cmd.Start()
//  2. Process information tracking initialization
//  3. Stream synchronization activation
//  4. Status updates for monitoring systems
//
// Process State Management:
//   - Creates ProcessInfo with PID and start time
//   - Initializes status as StatusStarting, then StatusRunning
//   - Starts stream synchronization after successful process start
//
// Error Handling:
//   - Returns immediately if process start fails
//   - Logs warnings for non-critical stream synchronization failures
//   - Maintains consistent process state throughout initialization
//
// Complexity: 2 (process start with stream synchronization)
func (sm *SubprocessManager) executeAndInitializeProcess() error {
	// Start the subprocess
	if err := sm.cmd.Start(); err != nil {
		return err
	}

	// Initialize process information tracking
	sm.process = &ProcessInfo{
		PID:       sm.cmd.Process.Pid,
		StartTime: time.Now(),
		Status:    StatusStarting,
	}

	// Start stream synchronization if configured
	if sm.streamSyncer != nil {
		if err := sm.streamSyncer.Start(); err != nil {
			sm.logger.Warn("Failed to start stream synchronization", "error", err)
		}
	}

	// Update process status to running
	sm.process.Status = StatusRunning
	return nil
}

// GetAddress returns the communication bridge address (adapter method).
func (sm *SubprocessManager) GetAddress() string {
	if sm.communicationBridge != nil {
		return sm.communicationBridge.GetAddress()
	}
	return ""
}

// GetPort returns the communication bridge port (adapter method).
func (sm *SubprocessManager) GetPort() int {
	if sm.communicationBridge != nil {
		return sm.communicationBridge.GetPort()
	}
	return 0
}

// GetCommunicationBridge returns the communication bridge for backward compatibility.
func (sm *SubprocessManager) GetCommunicationBridge() *CommunicationBridge {
	return sm.communicationBridge
}

// StartCommunicationBridge starts the communication bridge.
func (sm *SubprocessManager) StartCommunicationBridge() error {
	if sm.communicationBridge != nil {
		return sm.communicationBridge.Start()
	}
	return nil
}

// StopCommunicationBridge stops the communication bridge.
func (sm *SubprocessManager) StopCommunicationBridge() error {
	if sm.communicationBridge != nil {
		return sm.communicationBridge.Stop()
	}
	return nil
}

// GetHandshakeConfig returns the handshake configuration.
func (sm *SubprocessManager) GetHandshakeConfig() HandshakeConfig {
	return sm.handshakeConfig
}

// GetHandshakeManager returns the handshake manager for backward compatibility.
func (sm *SubprocessManager) GetHandshakeManager() *HandshakeManager {
	return sm.handshakeManager
}

// GetStreamSyncer returns the stream syncer for backward compatibility.
func (sm *SubprocessManager) GetStreamSyncer() *StreamSyncer {
	return sm.streamSyncer
}

// GetStreamConfig returns the stream configuration.
func (sm *SubprocessManager) GetStreamConfig() StreamSyncConfig {
	return sm.streamConfig
}

// IsRunning returns true if the subprocess is currently running.
func (sm *SubprocessManager) IsRunning() bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.started && !sm.stopping
}

// Restart performs a controlled restart of the subprocess.
func (sm *SubprocessManager) Restart(ctx context.Context) error {
	sm.logger.Info("Restarting subprocess")

	// Stop current instance
	if err := sm.Stop(ctx); err != nil {
		sm.logger.Warn("Failed to stop subprocess during restart", "error", err)
	}

	// Wait a moment for cleanup
	select {
	case <-time.After(100 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}

	// Start new instance
	return sm.Start(ctx)
}

// setupCommunication initializes the communication infrastructure.
func (sm *SubprocessManager) setupCommunication() error {
	if sm.communicationBridge != nil {
		return sm.communicationBridge.Start()
	}
	return nil
}

// startProcessWithStreams starts the process and configures stream handling.
func (sm *SubprocessManager) startProcessWithStreams(ctx context.Context) error {
	// Create command
	sm.cmd = exec.CommandContext(ctx, sm.executablePath, sm.args...) // #nosec G204 -- path validated elsewhere
	sm.cmd.Env = sm.env

	// Configure streams through stream syncer
	if sm.streamSyncer != nil {
		// Set up pipes for stream synchronization
		if stdout, err := sm.cmd.StdoutPipe(); err == nil {
			if addErr := sm.streamSyncer.AddStream(StreamStdout, stdout); addErr != nil {
				sm.logger.Warn("Failed to add stdout stream in startProcessWithStreams", "error", addErr)
			}
		}
		if stderr, err := sm.cmd.StderrPipe(); err == nil {
			if addErr := sm.streamSyncer.AddStream(StreamStderr, stderr); addErr != nil {
				sm.logger.Warn("Failed to add stderr stream in startProcessWithStreams", "error", addErr)
			}
		}
	}

	// Start the process
	if err := sm.cmd.Start(); err != nil {
		return err
	}

	// Update process info
	sm.process = &ProcessInfo{
		PID:       sm.cmd.Process.Pid,
		StartTime: time.Now(),
		Status:    StatusStarting,
	}

	// Start stream synchronization
	if sm.streamSyncer != nil {
		if err := sm.streamSyncer.Start(); err != nil {
			sm.logger.Warn("Failed to start stream synchronization", "error", err)
		}
	}

	sm.process.Status = StatusRunning
	return nil
}

// completeHandshake performs the handshake protocol with the subprocess.
func (sm *SubprocessManager) completeHandshake(_ context.Context) error {
	if sm.handshakeManager == nil {
		// No handshake required
		return nil
	}

	// Perform handshake validation using the configured handshake manager
	handshakeInfo, err := sm.handshakeManager.ValidatePluginEnvironment()
	if err != nil {
		return NewSubprocessError("handshake validation failed", err)
	}

	sm.logger.Info("Handshake protocol completed successfully",
		"protocol_version", handshakeInfo.ProtocolVersion,
		"plugin_type", handshakeInfo.PluginType.String(),
		"server_address", handshakeInfo.ServerAddress,
		"server_port", handshakeInfo.ServerPort)

	return nil
}

// signalShutdown sends a graceful shutdown signal to the subprocess.
func (sm *SubprocessManager) signalShutdown(_ context.Context) error {
	if sm.cmd == nil || sm.cmd.Process == nil {
		sm.logger.Debug("No process to signal for shutdown")
		return nil
	}

	// Send graceful shutdown signal (SIGTERM on Unix, os.Interrupt on Windows)
	signal := terminationSignal()
	if runtime.GOOS == "windows" {
		// On Windows, use os.Interrupt for graceful shutdown, save os.Kill for force termination
		signal = os.Interrupt
	}

	sm.logger.Info("Signaling graceful shutdown to subprocess", "pid", sm.cmd.Process.Pid, "signal", signal)

	if err := sm.cmd.Process.Signal(signal); err != nil {
		return NewSubprocessError("failed to signal graceful shutdown", err)
	}

	return nil
}

// stopCommunication stops all communication components.
func (sm *SubprocessManager) stopCommunication() {
	if sm.streamSyncer != nil {
		if err := sm.streamSyncer.Stop(); err != nil {
			sm.logger.Warn("Error stopping stream syncer", "error", err)
		}
	}

	if sm.communicationBridge != nil {
		if err := sm.communicationBridge.Stop(); err != nil {
			sm.logger.Warn("Error stopping communication bridge", "error", err)
		}
	}
}

// terminateProcess terminates the subprocess process.
func (sm *SubprocessManager) terminateProcess(ctx context.Context) error {
	if sm.cmd == nil || sm.cmd.Process == nil {
		return nil
	}

	// Try graceful termination first
	if err := sm.cmd.Process.Signal(terminationSignal()); err != nil {
		sm.logger.Warn("Failed to send termination signal", "error", err)
	}

	// Wait for process to exit with timeout
	done := make(chan error, 1)
	go func() {
		done <- sm.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			sm.logger.Debug("Process exited with status", "error", err)
		}
		sm.process.Status = StatusStopped
		// Don't return process exit error as subprocess termination error
		// The process exit status is normal and expected
		return nil
	case <-ctx.Done():
		// Force kill if graceful shutdown times out
		if err := sm.cmd.Process.Kill(); err != nil {
			sm.logger.Error("Failed to force kill process", "error", err)
			return err
		}
		sm.process.Status = StatusStopped
		return ctx.Err()
	}
}

// cleanupOnFailure performs cleanup when startup fails.
func (sm *SubprocessManager) cleanupOnFailure() {
	sm.logger.Warn("Cleaning up after startup failure")

	sm.stopCommunication()

	if sm.cmd != nil && sm.cmd.Process != nil {
		if err := sm.cmd.Process.Kill(); err != nil {
			sm.logger.Warn("Failed to kill process during cleanup", "error", err)
		}
	}

	if sm.process != nil {
		sm.process.Status = StatusFailed
	}
}

// Validate validates the subprocess manager configuration.
func (config *SubprocessManagerConfig) Validate() error {
	// Validate base configuration
	if err := config.BaseConfig.Validate(); err != nil {
		return err
	}

	// Validate executable path
	if config.ExecutablePath == "" {
		return NewConfigValidationError("executable_path cannot be empty", nil)
	}

	// Validate component configurations
	if err := config.HandshakeConfig.Validate(); err != nil {
		return NewConfigValidationError("invalid handshake configuration", err)
	}

	if err := validateStreamConfig(&config.StreamConfig); err != nil {
		return NewConfigValidationError("invalid stream configuration", err)
	}

	if err := validateBridgeConfig(&config.BridgeConfig); err != nil {
		return NewConfigValidationError("invalid bridge configuration", err)
	}

	return nil
}

// ApplyDefaults applies default values to the configuration.
func (config *SubprocessManagerConfig) ApplyDefaults() {
	// Apply base defaults
	config.BaseConfig.ApplyDefaults()

	// Apply component defaults if they're not configured
	if config.HandshakeConfig.ProtocolVersion == 0 {
		config.HandshakeConfig = DefaultHandshakeConfig
	}

	if config.StreamConfig.BufferSize == 0 {
		config.StreamConfig = DefaultStreamSyncConfig
	}

	if config.BridgeConfig.HandshakeBuffer == 0 {
		config.BridgeConfig = DefaultBridgeConfig
	}
}

// DefaultSubprocessManagerConfig returns a default configuration for subprocess management.
func DefaultSubprocessManagerConfig() SubprocessManagerConfig {
	config := SubprocessManagerConfig{
		BaseConfig:      BaseConfig{}.WithDefaults(),
		HandshakeConfig: DefaultHandshakeConfig,
		StreamConfig:    DefaultStreamSyncConfig,
		BridgeConfig:    DefaultBridgeConfig,
	}

	config.ApplyDefaults()
	return config
}

// terminationSignal returns the appropriate signal for process termination.
//
// This function provides cross-platform support for process termination,
// using SIGTERM on Unix-like systems and a fallback for Windows.
func terminationSignal() os.Signal {
	if runtime.GOOS == "windows" {
		// Windows doesn't support SIGTERM, use os.Kill
		return os.Kill
	}
	return syscall.SIGTERM
}

// Validation methods for component configurations

// validateStreamConfig validates the stream sync configuration.
func validateStreamConfig(sc *StreamSyncConfig) error {
	if sc.BufferSize < 0 {
		return NewConfigValidationError("stream buffer size cannot be negative", nil)
	}
	return nil
}

// validateBridgeConfig validates the bridge configuration.
func validateBridgeConfig(bc *BridgeConfig) error {
	if bc.HandshakeBuffer < 0 {
		return NewConfigValidationError("bridge handshake buffer size cannot be negative", nil)
	}
	return nil
}
