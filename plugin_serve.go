// plugin_serve.go: Plugin-side serve interface for plugin registration and request handling
//
// This file implements the plugin-side interface that allows plugins to register
// themselves and serve requests from the host process. It complements the host-side
// plugin management system already implemented, providing a complete bidirectional
// plugin architecture using generic terminology.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// PluginServer represents a plugin that can serve requests from the host.
//
// This is the plugin-side counterpart to the host-side plugin management system.
// Plugins implement this interface to register themselves and handle requests.
type PluginServer interface {
	// Serve starts serving requests from the host process.
	// It blocks until the plugin is shut down or an error occurs.
	Serve(ctx context.Context, config ServeConfig) error

	// Stop gracefully shuts down the plugin server.
	Stop(ctx context.Context) error

	// Health returns the current health status of the plugin.
	Health(ctx context.Context) HealthStatus

	// Info returns information about the plugin.
	Info() PluginInfo
}

// ServeConfig configures how a plugin serves requests.
type ServeConfig struct {
	// Plugin information
	PluginName    string `json:"plugin_name" yaml:"plugin_name"`
	PluginVersion string `json:"plugin_version" yaml:"plugin_version"`
	PluginType    string `json:"plugin_type" yaml:"plugin_type"`

	// Communication configuration
	HandshakeConfig HandshakeConfig `json:"handshake" yaml:"handshake"`

	// Network configuration
	NetworkConfig NetworkServeConfig `json:"network" yaml:"network"`

	// Health monitoring configuration
	HealthConfig HealthCheckConfig `json:"health" yaml:"health"`

	// Logging configuration
	Logger Logger `json:"-" yaml:"-"`

	// Plugin-specific options
	Options map[string]interface{} `json:"options,omitempty" yaml:"options,omitempty"`
}

// NetworkServeConfig configures network serving options.
type NetworkServeConfig struct {
	// Protocol specifies the communication protocol (tcp, grpc, etc.)
	Protocol string `json:"protocol" yaml:"protocol"`

	// Address to bind to (empty = use from handshake)
	BindAddress string `json:"bind_address" yaml:"bind_address"`

	// Port to bind to (0 = auto-assign)
	BindPort int `json:"bind_port" yaml:"bind_port"`

	// Timeout configurations
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout" yaml:"idle_timeout"`

	// Connection limits
	MaxConnections int `json:"max_connections" yaml:"max_connections"`
}

// DefaultServeConfig provides reasonable defaults for serving plugins.
var DefaultServeConfig = ServeConfig{
	PluginName:      "unnamed-plugin",
	PluginVersion:   "1.0.0",
	PluginType:      "generic",
	HandshakeConfig: DefaultHandshakeConfig,
	NetworkConfig: NetworkServeConfig{
		Protocol:       "tcp",
		BindAddress:    "127.0.0.1",
		BindPort:       0, // Auto-assign
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxConnections: 100,
	},
}

// Validate checks if the ServeConfig is valid and complete.
func (sc *ServeConfig) Validate() error {
	if sc.PluginName == "" {
		return fmt.Errorf("plugin name is required")
	}

	if sc.PluginVersion == "" {
		return fmt.Errorf("plugin version is required")
	}

	if sc.PluginType == "" {
		return fmt.Errorf("plugin type is required")
	}

	// Validate network configuration
	if sc.NetworkConfig.Protocol == "" {
		return fmt.Errorf("network protocol is required")
	}

	if sc.NetworkConfig.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be greater than 0")
	}

	if sc.NetworkConfig.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be greater than 0")
	}

	if sc.NetworkConfig.MaxConnections < 0 {
		return fmt.Errorf("max connections must be >= 0")
	}

	// Validate handshake configuration
	if err := sc.HandshakeConfig.Validate(); err != nil {
		return fmt.Errorf("handshake config validation failed: %w", err)
	}

	return nil
}

// Validate checks if the NetworkServeConfig is valid.
func (nsc *NetworkServeConfig) Validate() error {
	if nsc.Protocol == "" {
		return fmt.Errorf("protocol is required")
	}

	if nsc.BindPort < 0 || nsc.BindPort > 65535 {
		return fmt.Errorf("bind port must be between 0 and 65535")
	}

	if nsc.ReadTimeout < 0 {
		return fmt.Errorf("read timeout cannot be negative")
	}

	if nsc.WriteTimeout < 0 {
		return fmt.Errorf("write timeout cannot be negative")
	}

	if nsc.IdleTimeout < 0 {
		return fmt.Errorf("idle timeout cannot be negative")
	}

	if nsc.MaxConnections < 0 {
		return fmt.Errorf("max connections cannot be negative")
	}

	return nil
}

// GenericPluginServer provides a base implementation of PluginServer.
type GenericPluginServer struct {
	// Configuration
	config ServeConfig
	logger Logger

	// Health monitoring
	healthChecker *HealthChecker

	// Network management
	listener    net.Listener
	connections map[string]net.Conn
	connMutex   sync.RWMutex

	// Handler registration
	handlers     map[string]RequestHandler
	handlerMutex sync.RWMutex

	// Lifecycle management
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	running  bool
	runMutex sync.Mutex

	// Statistics
	stats ServeStats
}

// RequestHandler handles specific types of requests.
type RequestHandler interface {
	// HandleRequest processes a request and returns a response.
	HandleRequest(ctx context.Context, request *PluginRequest) (*PluginResponse, error)

	// GetRequestType returns the type of requests this handler processes.
	GetRequestType() string
}

// PluginRequest represents a request from the host to the plugin.
type PluginRequest struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Method    string                 `json:"method"`
	Data      []byte                 `json:"data"`
	Metadata  map[string]string      `json:"metadata"`
	Options   map[string]interface{} `json:"options"`
	Timestamp time.Time              `json:"timestamp"`
}

// PluginResponse represents a response from the plugin to the host.
type PluginResponse struct {
	ID        string                 `json:"id"`
	Success   bool                   `json:"success"`
	Data      []byte                 `json:"data"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]string      `json:"metadata"`
	Options   map[string]interface{} `json:"options"`
	Timestamp time.Time              `json:"timestamp"`
}

// ServeStats contains statistics about the plugin server.
type ServeStats struct {
	StartTime           time.Time     `json:"start_time"`
	RequestsHandled     int64         `json:"requests_handled"`
	RequestsFailed      int64         `json:"requests_failed"`
	ConnectionsTotal    int64         `json:"connections_total"`
	ActiveConnections   int           `json:"active_connections"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	LastRequestTime     time.Time     `json:"last_request_time"`
}

// NewGenericPluginServer creates a new generic plugin server.
func NewGenericPluginServer(config ServeConfig) *GenericPluginServer {
	if config.Logger == nil {
		config.Logger = DefaultLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := &GenericPluginServer{
		config:      config,
		logger:      config.Logger,
		connections: make(map[string]net.Conn),
		handlers:    make(map[string]RequestHandler),
		ctx:         ctx,
		cancel:      cancel,
		stats: ServeStats{
			StartTime: time.Now(),
		},
	}

	// Initialize health checker if enabled
	if config.HealthConfig.Enabled {
		server.healthChecker = NewHealthChecker(server, config.HealthConfig)
	}

	return server
}

// RegisterHandler registers a handler for a specific request type.
func (gps *GenericPluginServer) RegisterHandler(handler RequestHandler) error {
	gps.handlerMutex.Lock()
	defer gps.handlerMutex.Unlock()

	requestType := handler.GetRequestType()
	if requestType == "" {
		return fmt.Errorf("handler must specify a non-empty request type")
	}

	if _, exists := gps.handlers[requestType]; exists {
		return fmt.Errorf("handler for request type '%s' already registered", requestType)
	}

	gps.handlers[requestType] = handler
	gps.logger.Debug("Registered request handler", "type", requestType)

	return nil
}

// UnregisterHandler removes a handler for a specific request type.
func (gps *GenericPluginServer) UnregisterHandler(requestType string) {
	gps.handlerMutex.Lock()
	defer gps.handlerMutex.Unlock()

	delete(gps.handlers, requestType)
	gps.logger.Debug("Unregistered request handler", "type", requestType)
}

// Serve starts serving requests from the host process.
func (gps *GenericPluginServer) Serve(ctx context.Context, config ServeConfig) error {
	gps.runMutex.Lock()
	defer gps.runMutex.Unlock()

	if gps.running {
		return fmt.Errorf("plugin server is already running")
	}

	// Update configuration if provided
	if config.PluginName != "" {
		gps.config = config
		gps.logger = config.Logger
	}

	gps.logger.Info("Starting plugin server",
		"name", gps.config.PluginName,
		"version", gps.config.PluginVersion,
		"type", gps.config.PluginType)

	// Validate handshake environment
	handshakeManager := NewHandshakeManager(gps.config.HandshakeConfig, gps.logger)
	handshakeInfo, err := handshakeManager.ValidatePluginEnvironment()
	if err != nil {
		return fmt.Errorf("handshake validation failed: %w", err)
	}

	gps.logger.Info("Handshake validation successful",
		"protocol_version", handshakeInfo.ProtocolVersion,
		"server_address", handshakeInfo.ServerAddress,
		"server_port", handshakeInfo.ServerPort)

	// Determine bind address from handshake or config
	bindAddress := gps.config.NetworkConfig.BindAddress
	if handshakeInfo.ServerAddress != "" {
		bindAddress = handshakeInfo.ServerAddress
	}

	// Create listener
	listenerAddr := fmt.Sprintf("%s:%d", bindAddress, gps.config.NetworkConfig.BindPort)
	listener, err := net.Listen("tcp", listenerAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	gps.listener = listener
	actualAddr, ok := gps.listener.Addr().(*net.TCPAddr)
	if !ok {
		if closeErr := gps.listener.Close(); closeErr != nil {
			gps.logger.Error("Failed to close listener", "error", closeErr)
		}
		return fmt.Errorf("listener address is not TCP")
	}

	gps.logger.Info("Plugin server listening",
		"address", actualAddr.IP.String(),
		"port", actualAddr.Port,
		"protocol", gps.config.NetworkConfig.Protocol)

	// Start accepting connections
	gps.wg.Add(1)
	go gps.acceptLoop(ctx)

	gps.running = true
	gps.stats.StartTime = time.Now()

	// Wait for context cancellation or error
	<-ctx.Done()
	return ctx.Err()
}

// Stop gracefully shuts down the plugin server.
func (gps *GenericPluginServer) Stop(ctx context.Context) error {
	gps.runMutex.Lock()
	defer gps.runMutex.Unlock()

	if !gps.running {
		return nil
	}

	gps.logger.Info("Stopping plugin server")

	// Stop health checker if running
	if gps.healthChecker != nil {
		gps.healthChecker.Stop()
	}

	// Cancel context to signal goroutines to stop
	gps.cancel()

	// Close listener
	if gps.listener != nil {
		if err := gps.listener.Close(); err != nil {
			gps.logger.Warn("Failed to close listener", "error", err)
		}
	}

	// Close all connections
	gps.connMutex.Lock()
	for id, conn := range gps.connections {
		if err := conn.Close(); err != nil {
			gps.logger.Warn("Failed to close connection", "id", id, "error", err)
		}
		gps.logger.Debug("Closed connection", "id", id)
	}
	gps.connMutex.Unlock()

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		gps.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		gps.logger.Info("Plugin server stopped gracefully")
	case <-ctx.Done():
		gps.logger.Warn("Plugin server stop timeout exceeded")
		return ctx.Err()
	}

	gps.running = false
	return nil
}

// Close stops the plugin server (required by HealthChecker interface).
func (gps *GenericPluginServer) Close() error {
	return gps.Stop(context.Background())
}

// acceptLoop handles incoming connections.
func (gps *GenericPluginServer) acceptLoop(ctx context.Context) {
	defer gps.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set accept timeout
		if tcpListener, ok := gps.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				gps.logger.Debug("Failed to set accept deadline", "error", err)
			}
		}

		conn, err := gps.listener.Accept()
		if err != nil {
			// Check if this is a timeout or if we're shutting down
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			select {
			case <-ctx.Done():
				return
			default:
				gps.logger.Error("Accept failed", "error", err)
				continue
			}
		}

		// Handle connection
		connID := fmt.Sprintf("%s->%s", conn.RemoteAddr(), conn.LocalAddr())
		gps.stats.ConnectionsTotal++

		gps.connMutex.Lock()
		gps.connections[connID] = conn
		gps.stats.ActiveConnections = len(gps.connections)
		gps.connMutex.Unlock()

		gps.logger.Debug("New connection accepted", "id", connID)

		// Handle connection in goroutine
		gps.wg.Add(1)
		go gps.handleConnection(ctx, connID, conn)
	}
}

// handleConnection processes requests from a connection.
func (gps *GenericPluginServer) handleConnection(ctx context.Context, connID string, conn net.Conn) {
	defer gps.wg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			gps.logger.Debug("Failed to close connection", "error", err, "conn_id", connID)
		}
	}()
	defer func() {
		gps.connMutex.Lock()
		delete(gps.connections, connID)
		gps.stats.ActiveConnections = len(gps.connections)
		gps.connMutex.Unlock()
		gps.logger.Debug("Connection closed", "id", connID)
	}()

	// Set connection timeouts
	if gps.config.NetworkConfig.ReadTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(gps.config.NetworkConfig.ReadTimeout)); err != nil {
			gps.logger.Debug("Failed to set read deadline", "error", err, "conn_id", connID)
		}
	}

	// Request/response protocol uses direct subprocess communication
	// This provides the connection foundation for JSON-RPC communication
	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				gps.logger.Debug("Connection read error", "error", err, "conn_id", connID)
			}
			return
		}

		gps.stats.RequestsHandled++
		gps.stats.LastRequestTime = time.Now()

		// Echo response for testing/demo purposes
		_, writeErr := conn.Write(buffer[:n])
		if writeErr != nil {
			gps.logger.Debug("Connection write error", "error", writeErr, "conn_id", connID)
			return
		}
	}
}

// Health returns the current health status of the plugin.
func (gps *GenericPluginServer) Health(ctx context.Context) HealthStatus {
	gps.runMutex.Lock()
	running := gps.running
	gps.runMutex.Unlock()

	if !running {
		return HealthStatus{
			Status:       StatusOffline,
			Message:      "Plugin server is not running",
			LastCheck:    time.Now(),
			ResponseTime: 0,
		}
	}

	start := time.Now()
	return HealthStatus{
		Status:       StatusHealthy,
		Message:      "Plugin server is healthy and running",
		LastCheck:    time.Now(),
		ResponseTime: time.Since(start),
		Metadata: map[string]string{
			"active_connections":  fmt.Sprintf("%d", gps.stats.ActiveConnections),
			"requests_handled":    fmt.Sprintf("%d", gps.stats.RequestsHandled),
			"requests_failed":     fmt.Sprintf("%d", gps.stats.RequestsFailed),
			"uptime":              time.Since(gps.stats.StartTime).String(),
			"registered_handlers": fmt.Sprintf("%d", len(gps.handlers)),
		},
	}
}

// Info returns information about the plugin.
func (gps *GenericPluginServer) Info() PluginInfo {
	gps.handlerMutex.RLock()
	handlerTypes := make([]string, 0, len(gps.handlers))
	for requestType := range gps.handlers {
		handlerTypes = append(handlerTypes, requestType)
	}
	gps.handlerMutex.RUnlock()

	return PluginInfo{
		Name:         gps.config.PluginName,
		Version:      gps.config.PluginVersion,
		Description:  "Generic plugin server",
		Author:       "go-plugins",
		Capabilities: handlerTypes,
		Metadata: map[string]string{
			"protocol":        gps.config.NetworkConfig.Protocol,
			"max_connections": fmt.Sprintf("%d", gps.config.NetworkConfig.MaxConnections),
		},
	}
}

// GetStats returns current serving statistics.
func (gps *GenericPluginServer) GetStats() ServeStats {
	return gps.stats
}

// ServePlugin is a convenience function to serve a plugin with default configuration.
func ServePlugin(ctx context.Context, server PluginServer) error {
	config := DefaultServeConfig
	return server.Serve(ctx, config)
}
