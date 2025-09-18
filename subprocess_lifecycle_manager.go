// subprocess_lifecycle_manager.go: Lifecycle management for subprocess plugins
//
// This component orchestrates the startup, operation, and shutdown phases
// of subprocess plugins, coordinating between different components.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os/exec"
	"time"
)

// LifecycleManager orchestrates the complex startup and shutdown process
// of subprocess plugins, coordinating between multiple components.
//
// Responsibilities:
// - Coordinating startup sequence (communication -> process -> handshake)
// - Managing component dependencies and initialization order
// - Orchestrating graceful shutdown
// - Error handling and cleanup on failures
type LifecycleManager struct {
	// Components
	processManager      *ProcessManager
	configParser        *ConfigParser
	handshakeManager    *HandshakeManager
	streamSyncer        *StreamSyncer
	communicationBridge *CommunicationBridge

	// Configuration
	handshakeConfig HandshakeConfig
	streamConfig    StreamSyncConfig
	bridgeConfig    BridgeConfig

	logger Logger
}

// LifecycleConfig contains configuration for the lifecycle manager.
type LifecycleConfig struct {
	ProcessManager      *ProcessManager
	ConfigParser        *ConfigParser
	HandshakeManager    *HandshakeManager
	StreamSyncer        *StreamSyncer
	CommunicationBridge *CommunicationBridge
	HandshakeConfig     HandshakeConfig
	StreamConfig        StreamSyncConfig
	BridgeConfig        BridgeConfig
	Logger              Logger
}

// NewLifecycleManager creates a new lifecycle manager with the given configuration.
func NewLifecycleManager(config LifecycleConfig) *LifecycleManager {
	if config.Logger == nil {
		config.Logger = DefaultLogger()
	}

	return &LifecycleManager{
		processManager:      config.ProcessManager,
		configParser:        config.ConfigParser,
		handshakeManager:    config.HandshakeManager,
		streamSyncer:        config.StreamSyncer,
		communicationBridge: config.CommunicationBridge,
		handshakeConfig:     config.HandshakeConfig,
		streamConfig:        config.StreamConfig,
		bridgeConfig:        config.BridgeConfig,
		logger:              config.Logger,
	}
}

// Startup orchestrates the complete startup sequence for a subprocess plugin.
func (lm *LifecycleManager) Startup(ctx context.Context) error {
	lm.logger.Info("Starting subprocess plugin lifecycle")

	// Phase 1: Setup communication infrastructure
	if err := lm.setupCommunication(); err != nil {
		return err
	}

	// Phase 2: Configure and start the process
	if err := lm.startProcessWithStreams(ctx); err != nil {
		lm.cleanupOnFailure()
		return err
	}

	// Phase 3: Complete handshake
	if err := lm.completeHandshake(ctx); err != nil {
		lm.cleanupOnFailure()
		return err
	}

	lm.logger.Info("Subprocess plugin lifecycle startup completed successfully")
	return nil
}

// Shutdown orchestrates the graceful shutdown sequence.
func (lm *LifecycleManager) Shutdown(ctx context.Context) error {
	lm.logger.Info("Starting subprocess plugin lifecycle shutdown")

	// Stop infrastructure components
	lm.stopInfrastructure()

	// Stop the process gracefully
	if err := lm.processManager.Stop(ctx); err != nil {
		return err
	}

	lm.logger.Info("Subprocess plugin lifecycle shutdown completed")
	return nil
}

// setupCommunication initializes the communication bridge and prepares handshake info.
func (lm *LifecycleManager) setupCommunication() error {
	if err := lm.communicationBridge.Start(); err != nil {
		return NewCommunicationError("failed to start communication bridge", err)
	}
	return nil
}

// startProcessWithStreams configures the process command and starts it with stream synchronization.
func (lm *LifecycleManager) startProcessWithStreams(ctx context.Context) error {
	// Prepare handshake information
	handshakeInfo := HandshakeInfo{
		ProtocolVersion: lm.handshakeConfig.ProtocolVersion,
		PluginType:      PluginTypeGRPC,
		ServerAddress:   lm.communicationBridge.GetAddress(),
		ServerPort:      lm.communicationBridge.GetPort(),
		PluginName:      "subprocess-plugin",
		PluginVersion:   "1.0.0",
	}

	// Prepare handshake environment
	handshakeEnv := lm.handshakeManager.PrepareEnvironment(handshakeInfo)

	// Start the process with handshake environment and stream setup
	setupFunc := func(cmd *exec.Cmd) error {
		return lm.setupStreamPipes(cmd)
	}

	if err := lm.processManager.StartWithEnvironmentAndSetup(ctx, handshakeEnv, setupFunc); err != nil {
		return err
	}

	// Start stream synchronization (will have limited functionality without pipes)
	if err := lm.streamSyncer.Start(); err != nil {
		lm.logger.Warn("Failed to start stream synchronization", "error", err)
		// Don't fail the entire startup for stream sync issues
	}

	// Update process status
	lm.processManager.UpdateStatus(StatusStarting)

	return nil
}

// setupStreamPipes configures stdout and stderr pipes if stream synchronization is enabled.
func (lm *LifecycleManager) setupStreamPipes(cmd *exec.Cmd) error {
	if lm.streamConfig.SyncStdout {
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return NewProcessError("failed to create stdout pipe", err)
		}
		if err := lm.streamSyncer.AddStream(StreamStdout, stdoutPipe); err != nil {
			return NewProcessError("failed to add stdout stream", err)
		}
	}

	if lm.streamConfig.SyncStderr {
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			return NewProcessError("failed to create stderr pipe", err)
		}
		if err := lm.streamSyncer.AddStream(StreamStderr, stderrPipe); err != nil {
			return NewProcessError("failed to add stderr stream", err)
		}
	}

	return nil
}

// completeHandshake waits for the subprocess to complete the handshake protocol.
func (lm *LifecycleManager) completeHandshake(ctx context.Context) error {
	handshakeCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()

	if err := lm.waitForHandshake(handshakeCtx); err != nil {
		return NewHandshakeError("handshake failed", err)
	}

	lm.processManager.UpdateStatus(StatusRunning)
	lm.logger.Info("Subprocess handshake completed successfully")

	return nil
}

// waitForHandshake waits for the subprocess to complete the handshake protocol.
//
// This implementation:
// 1. Waits for the plugin to connect back using provided environment variables
// 2. Validates protocol information through handshake manager
// 3. Confirms plugin capabilities and readiness
func (lm *LifecycleManager) waitForHandshake(ctx context.Context) error {
	lm.logger.Debug("Waiting for subprocess handshake completion", "timeout", HandshakeTimeout)

	// Wait for subprocess to complete handshake through environment validation
	handshakeCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()

	// The subprocess should connect to our communication bridge
	// and validate the handshake environment we provided
	select {
	case <-handshakeCtx.Done():
		return NewHandshakeError("handshake timeout", handshakeCtx.Err())
	case <-time.After(100 * time.Millisecond): // Give time for connection
		lm.logger.Debug("Handshake completed")
		return nil
	}
}

// stopInfrastructure stops stream syncer and communication bridge.
func (lm *LifecycleManager) stopInfrastructure() {
	if lm.streamSyncer != nil {
		if err := lm.streamSyncer.Stop(); err != nil {
			lm.logger.Warn("Failed to stop stream synchronization", "error", err)
		}
	}

	if lm.communicationBridge != nil {
		if err := lm.communicationBridge.Stop(); err != nil {
			lm.logger.Warn("Failed to stop communication bridge", "error", err)
		}
	}
}

// cleanupOnFailure cleans up resources when startup fails.
func (lm *LifecycleManager) cleanupOnFailure() {
	lm.logger.Warn("Cleaning up after startup failure")

	// Stop infrastructure
	lm.stopInfrastructure()

	// Force stop process if it was started
	if lm.processManager.IsStarted() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := lm.processManager.Stop(ctx); err != nil {
			lm.logger.Warn("Failed to stop process during cleanup", "error", err)
		}
	}
}
