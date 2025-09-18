// plugin_client.go: Individual plugin client management
//
// This file implements the PluginClient struct and all its related methods.
// The PluginClient manages a single plugin instance on the host side,
// handling communication, health checking, and providing a unified
// interface for making requests to the plugin.
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

// PluginClient manages a single plugin instance on the host side.
//
// Each PluginClient represents a connection to a subprocess plugin instance.
// It handles the communication, health checking, and provides a unified
// interface for making requests to the plugin.
type PluginClient struct {
	// Identity
	ID   string
	Name string
	Type string

	// Configuration
	config     PluginConfig
	executable string
	args       []string

	// Communication
	bridge     *CommunicationBridge
	subprocess *SubprocessPlugin[any, any]

	// State management
	status    PluginStatus
	startTime time.Time
	lastPing  time.Time
	mutex     sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	logger Logger

	// Health monitoring
	healthChecker *HealthChecker
}

// ClientStats provides statistics about a plugin client.
type ClientStats struct {
	Status       PluginStatus  `json:"status"`
	StartTime    time.Time     `json:"start_time"`
	LastPing     time.Time     `json:"last_ping"`
	Uptime       time.Duration `json:"uptime"`
	RequestCount int64         `json:"request_count"`
	ErrorCount   int64         `json:"error_count"`
	LastError    string        `json:"last_error,omitempty"`
}

// Start starts the plugin client.
func (pc *PluginClient) Start() error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.status != StatusOffline {
		return NewClientError("", "client is already running", nil)
	}

	pc.logger.Info("Starting plugin client", "name", pc.Name, "type", pc.Type)

	// Create subprocess for executable plugins
	if pc.config.Transport == TransportExecutable {
		if err := pc.startSubprocess(); err != nil {
			return NewProcessError("failed to start subprocess", err)
		}
	}

	pc.status = StatusHealthy
	pc.startTime = time.Now()
	pc.lastPing = time.Now()

	pc.logger.Info("Plugin client started", "name", pc.Name)
	return nil
}

// Stop stops the plugin client.
func (pc *PluginClient) Stop() error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.status == StatusOffline {
		return nil
	}

	pc.logger.Info("Stopping plugin client", "name", pc.Name)

	// Cancel context
	pc.cancel()

	// Stop health checker
	if pc.healthChecker != nil {
		pc.healthChecker.Stop()
	}

	// Stop communication bridge
	if pc.bridge != nil {
		if err := pc.bridge.Stop(); err != nil {
			pc.logger.Warn("Error stopping communication bridge",
				"name", pc.Name,
				"error", err)
		}
	}

	// Stop subprocess
	if pc.subprocess != nil {
		if err := pc.subprocess.Close(); err != nil {
			pc.logger.Warn("Error stopping subprocess",
				"name", pc.Name,
				"error", err)
		}
	}

	pc.status = StatusOffline
	pc.logger.Info("Plugin client stopped", "name", pc.Name)
	return nil
}

// Health returns the current health status (required by HealthChecker).
func (pc *PluginClient) Health(ctx context.Context) HealthStatus {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	return HealthStatus{
		Status:       pc.status,
		Message:      fmt.Sprintf("Plugin client %s is %s", pc.Name, pc.status),
		LastCheck:    time.Now(),
		ResponseTime: 0, // Could implement actual ping time
		Metadata: map[string]string{
			"plugin_name": pc.Name,
			"plugin_type": pc.Type,
			"uptime":      time.Since(pc.startTime).String(),
		},
	}
}

// Close closes the plugin client (required by HealthChecker).
func (pc *PluginClient) Close() error {
	return pc.Stop()
}

// Call makes a method call to the plugin via gRPC or subprocess with request tracking.
func (pc *PluginClient) Call(ctx context.Context, method string, args interface{}, tracker *RequestTracker) (interface{}, error) {
	pc.mutex.RLock()
	subprocess := pc.subprocess
	pc.mutex.RUnlock()

	if subprocess == nil {
		return nil, NewClientError("", "plugin client not initialized", nil)
	}

	if pc.status != StatusHealthy {
		return nil, NewClientError("", fmt.Sprintf("plugin client is not healthy: %s", pc.status), nil)
	}

	// Track request if tracker provided
	if tracker != nil {
		tracker.StartRequest(pc.Name, ctx)
		defer tracker.EndRequest(pc.Name, ctx)
	}

	// Create execution context for the call
	execCtx := ExecutionContext{
		RequestID: fmt.Sprintf("registry_%d", time.Now().UnixNano()),
		Timeout:   30 * time.Second,
		Metadata:  map[string]string{"method": method},
	}

	// Make call using subprocess plugin
	result, err := subprocess.Execute(ctx, execCtx, args)
	if err != nil {
		pc.logger.Error("Plugin call failed",
			"name", pc.Name,
			"method", method,
			"error", err)
		return nil, err
	}

	// Update last ping time
	pc.mutex.Lock()
	pc.lastPing = time.Now()
	pc.mutex.Unlock()

	return result, nil
}

// startSubprocess starts the subprocess for executable plugins.
func (pc *PluginClient) startSubprocess() error {
	if pc.executable == "" {
		return NewConfigValidationError("executable path not specified", nil)
	}

	// Create subprocess plugin config
	subprocessConfig := PluginConfig{
		Name:       pc.Name,
		Type:       pc.Type,
		Transport:  TransportExecutable,
		Executable: pc.executable,
		Args:       pc.args,
	}

	// Create subprocess plugin factory
	factory := &SubprocessPluginFactory[any, any]{}

	// Create subprocess plugin
	subprocess, err := factory.CreatePlugin(subprocessConfig)
	if err != nil {
		return NewProcessError("failed to create subprocess plugin", err)
	}

	// Type assert to subprocess plugin
	subprocessPlugin, ok := subprocess.(*SubprocessPlugin[any, any])
	if !ok {
		return NewFactoryError("subprocess", fmt.Sprintf("expected SubprocessPlugin, got %T", subprocess), nil)
	}
	pc.subprocess = subprocessPlugin

	// Create communication bridge
	bridgeConfig := BridgeConfig{
		ListenAddress:  "127.0.0.1",
		ListenPort:     0, // Auto-assign
		MaxChannels:    10,
		ChannelTimeout: 30 * time.Second,
		AcceptTimeout:  10 * time.Second,
	}

	bridge := NewCommunicationBridge(bridgeConfig, pc.logger)
	if err := bridge.Start(); err != nil {
		return NewCommunicationError("failed to start communication bridge", err)
	}

	pc.bridge = bridge

	// Note: RPC protocol removed - using gRPC/subprocess communication only

	pc.logger.Info("Subprocess started",
		"name", pc.Name,
		"executable", pc.executable,
		"bridge_port", bridge.GetPort())

	return nil
}
