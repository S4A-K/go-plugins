// subprocess_process_manager.go: Dedicated process management for subprocess plugins
//
// This component handles the lifecycle and monitoring of subprocess processes,
// separating process management concerns from the main plugin logic.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// ProcessManager handles subprocess process lifecycle and monitoring.
//
// Responsibilities:
// - Process creation and execution
// - Process monitoring and health checks
// - Graceful shutdown and cleanup
// - Process status tracking
type ProcessManager struct {
	// Configuration
	executablePath string
	args           []string
	env            []string

	// Process state
	cmd     *exec.Cmd
	process *ProcessInfo
	mutex   sync.RWMutex

	// Status tracking
	started  bool
	stopping bool

	logger Logger
}

// ProcessManagerConfig contains configuration for the process manager.
type ProcessManagerConfig struct {
	ExecutablePath string
	Args           []string
	Env            []string
	Logger         Logger
}

// NewProcessManager creates a new process manager with the given configuration.
func NewProcessManager(config ProcessManagerConfig) *ProcessManager {
	if config.Logger == nil {
		config.Logger = DefaultLogger()
	}

	return &ProcessManager{
		executablePath: config.ExecutablePath,
		args:           config.Args,
		env:            config.Env,
		logger:         config.Logger,
	}
}

// Start starts the subprocess process.
func (pm *ProcessManager) Start(ctx context.Context) error {
	return pm.StartWithEnvironment(ctx, pm.env)
}

// StartWithEnvironment starts the subprocess process with additional environment variables.
func (pm *ProcessManager) StartWithEnvironment(ctx context.Context, additionalEnv []string) error {
	return pm.StartWithEnvironmentAndSetup(ctx, additionalEnv, nil)
}

// StartWithEnvironmentAndSetup starts the subprocess process with additional environment variables
// and allows setup configuration before starting the process.
func (pm *ProcessManager) StartWithEnvironmentAndSetup(ctx context.Context, additionalEnv []string, setupFunc func(*exec.Cmd) error) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.started {
		return nil
	}

	pm.logger.Info("Starting subprocess process", "path", pm.executablePath, "args", pm.args)

	// Create command
	pm.cmd = exec.CommandContext(ctx, pm.executablePath, pm.args...) // #nosec G204 -- path validated elsewhere

	// Combine base environment with additional environment
	combinedEnv := make([]string, 0, len(pm.env)+len(additionalEnv))
	combinedEnv = append(combinedEnv, pm.env...)
	combinedEnv = append(combinedEnv, additionalEnv...)
	pm.cmd.Env = combinedEnv

	// Apply setup function if provided
	if setupFunc != nil {
		if err := setupFunc(pm.cmd); err != nil {
			return NewProcessError("failed to setup command", err)
		}
	}

	// Start process
	if err := pm.cmd.Start(); err != nil {
		return NewProcessError("failed to start process", err)
	}

	// Initialize process info
	pm.process = &ProcessInfo{
		PID:       pm.cmd.Process.Pid,
		StartTime: time.Now(),
		Status:    StatusStarting,
	}

	pm.started = true
	pm.logger.Info("Subprocess process started successfully", "pid", pm.process.PID)

	return nil
}

// Stop gracefully stops the subprocess process.
func (pm *ProcessManager) Stop(ctx context.Context) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.started || pm.stopping {
		return nil
	}

	pm.stopping = true
	pm.updateStatus(StatusStopping)
	pm.logger.Info("Stopping subprocess process", "pid", pm.process.PID)

	if err := pm.gracefulShutdown(ctx); err != nil {
		return err
	}

	pm.finalizeStopping()
	return nil
}

// gracefulShutdown attempts graceful shutdown with fallback to force kill.
func (pm *ProcessManager) gracefulShutdown(ctx context.Context) error {
	if pm.cmd == nil || pm.cmd.Process == nil {
		return nil
	}

	// Send signal for graceful shutdown
	if err := pm.cmd.Process.Signal(nil); err != nil {
		return nil // Process already terminated
	}

	// Wait for graceful shutdown with timeout
	done := make(chan error, 1)
	go func() {
		done <- pm.cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Force kill on timeout
		if killErr := pm.cmd.Process.Kill(); killErr != nil {
			pm.logger.Warn("Failed to kill process on timeout", "error", killErr)
		}
		return ctx.Err()
	case err := <-done:
		if err != nil {
			pm.logger.Warn("Subprocess exited with error", "error", err)
		}
		return nil
	}
}

// finalizeStopping resets internal state after successful stop.
func (pm *ProcessManager) finalizeStopping() {
	pm.started = false
	pm.stopping = false
	pm.updateStatus(StatusStopped)
	pm.logger.Info("Subprocess process stopped")
}

// IsAlive checks if the process is currently running.
func (pm *ProcessManager) IsAlive() bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if !pm.started || pm.cmd == nil || pm.cmd.Process == nil {
		return false
	}

	// On Unix systems, sending signal 0 checks if process exists
	if err := pm.cmd.Process.Signal(nil); err != nil {
		return false
	}

	return true
}

// GetProcessInfo returns information about the current process.
func (pm *ProcessManager) GetProcessInfo() *ProcessInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if pm.process == nil {
		return &ProcessInfo{Status: StatusStopped}
	}

	// Return copy to avoid races
	info := *pm.process
	return &info
}

// UpdateStatus updates the process status.
func (pm *ProcessManager) UpdateStatus(status ProcessStatus) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.updateStatus(status)
}

// updateStatus updates the process status without locking (internal use).
func (pm *ProcessManager) updateStatus(status ProcessStatus) {
	if pm.process != nil {
		pm.process.Status = status
	}
}

// IsStarted returns whether the process has been started.
func (pm *ProcessManager) IsStarted() bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.started
}

// IsStopping returns whether the process is currently stopping.
func (pm *ProcessManager) IsStopping() bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.stopping
}

// GetCommand returns the underlying exec.Cmd (for advanced use cases like stream pipes).
// This should be used carefully and only during process startup.
func (pm *ProcessManager) GetCommand() *exec.Cmd {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.cmd
}

// SetCommand allows setting a configured command before starting.
// This is useful for adding pipes or other configuration.
func (pm *ProcessManager) SetCommand(cmd *exec.Cmd) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	if !pm.started {
		pm.cmd = cmd
	}
}
