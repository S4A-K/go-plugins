// unix_transport.go: Unix Domain Socket transport implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// UnixSocketPlugin implements Plugin interface using Unix Domain Sockets for high-performance local communication.
//
// This implementation provides the fastest possible communication mechanism for
// plugins running on the same machine, using Unix domain sockets to eliminate
// network overhead. It's ideal for high-throughput scenarios where plugins
// and the main application are co-located.
//
// Features:
//   - Ultra-low latency local communication via Unix domain sockets
//   - Connection pooling for high concurrency scenarios
//   - JSON-based message protocol for consistency with other transports
//   - Proper connection lifecycle and error handling
//   - Request correlation and timeout management
//   - Health checking with rapid local validation
//
// Performance characteristics:
//   - Lowest possible latency (no network stack)
//   - Highest throughput for local communication
//   - Zero network security concerns (local socket)
//   - No serialization overhead beyond JSON
//
// Example usage:
//
//	config := PluginConfig{
//	    Name:      "local-processor",
//	    Transport: TransportUnix,
//	    Endpoint:  "/tmp/processor.sock",  // Unix socket path
//	    Connection: ConnectionConfig{
//	        MaxConnections: 20,  // Pool size for concurrent requests
//	    },
//	}
//
//	plugin, err := NewUnixSocketPlugin[ProcessRequest, ProcessResponse](config, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// High-speed local communication
//	response, err := plugin.Execute(ctx, execCtx, request)
//	if err != nil {
//	    log.Printf("Local processing failed: %v", err)
//	}
//
//	// Cleanup
//	defer plugin.Close()
type UnixSocketPlugin[Req, Resp any] struct {
	info   PluginInfo
	config PluginConfig
	logger *slog.Logger

	// Connection management
	connPool  *UnixConnectionPool
	connected atomic.Bool
	lastCheck atomic.Int64 // Unix timestamp in nanoseconds
}

// UnixConnectionPool manages a pool of Unix socket connections
type UnixConnectionPool struct {
	socketPath     string
	maxConnections int
	connections    chan net.Conn
	closed         atomic.Bool
}

// UnixSocketMessage represents a standardized message format for Unix socket communication.
//
// This structure defines the wire protocol for Unix domain socket communication,
// providing a consistent message format that supports different operation types
// and includes all necessary metadata for request handling and correlation.
//
// Message types:
//   - "execute": Normal plugin execution request
//   - "health": Health check request
//   - "info": Plugin information request
//   - "ping": Connection test/keepalive
//
// Example message for execution:
//
//	{
//	  "type": "execute",
//	  "request_id": "req-12345",
//	  "data": {"user_id": "user123", "action": "validate"},
//	  "headers": {"X-Trace-ID": "trace-abc"},
//	  "timeout_ms": 5000
//	}
//
// The JSON format ensures consistency with other transports while maintaining
// the performance benefits of Unix domain sockets.
type UnixSocketMessage struct {
	Type      string            `json:"type"`
	RequestID string            `json:"request_id"`
	Data      json.RawMessage   `json:"data"`
	Headers   map[string]string `json:"headers,omitempty"`
	Timeout   int64             `json:"timeout_ms,omitempty"`
}

// UnixSocketResponse represents a standardized response format for Unix socket communication.
//
// This structure defines the response protocol for Unix domain socket communication,
// providing consistent success/error handling and metadata propagation. It enables
// proper request correlation and comprehensive error reporting.
//
// Response handling:
//   - Success=true: Data field contains the successful response
//   - Success=false: Error field contains the error message
//   - RequestID matches the original request for correlation
//   - Headers can include metadata like processing time, trace info
//
// Example successful response:
//
//	{
//	  "type": "execute",
//	  "request_id": "req-12345",
//	  "success": true,
//	  "data": {"token": "abc123", "expires": 3600},
//	  "headers": {"X-Processing-Time-Ms": "23"}
//	}
//
// Example error response:
//
//	{
//	  "type": "execute",
//	  "request_id": "req-12345",
//	  "success": false,
//	  "error": "Invalid user credentials",
//	  "headers": {"X-Error-Code": "AUTH_FAILED"}
//	}
type UnixSocketResponse struct {
	Type      string            `json:"type"`
	RequestID string            `json:"request_id"`
	Success   bool              `json:"success"`
	Data      json.RawMessage   `json:"data,omitempty"`
	Error     string            `json:"error,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// NewUnixSocketPlugin creates a new Unix socket plugin instance
func NewUnixSocketPlugin[Req, Resp any](config PluginConfig, logger *slog.Logger) (*UnixSocketPlugin[Req, Resp], error) {
	if logger == nil {
		logger = slog.Default()
	}

	if err := validateUnixSocketConfig(config); err != nil {
		return nil, fmt.Errorf("invalid Unix socket config: %w", err)
	}

	plugin := &UnixSocketPlugin[Req, Resp]{
		info: PluginInfo{
			Name:        config.Name,
			Version:     "unknown", // Will be fetched from remote
			Description: fmt.Sprintf("Unix socket plugin connecting to %s", config.Endpoint),
		},
		config: config,
		logger: logger,
	}

	// Initialize connection pool
	plugin.connPool = NewUnixConnectionPool(config.Endpoint, config.Connection.MaxConnections)

	// Test initial connection
	if err := plugin.testConnection(); err != nil {
		return nil, fmt.Errorf("failed to establish Unix socket connection: %w", err)
	}

	// Fetch plugin info from remote
	if err := plugin.fetchRemoteInfo(); err != nil {
		logger.Warn("Failed to fetch remote plugin info", "error", err)
	}

	return plugin, nil
}

// NewUnixConnectionPool creates a new Unix socket connection pool
func NewUnixConnectionPool(socketPath string, maxConnections int) *UnixConnectionPool {
	if maxConnections <= 0 {
		maxConnections = 5 // Default pool size
	}

	return &UnixConnectionPool{
		socketPath:     socketPath,
		maxConnections: maxConnections,
		connections:    make(chan net.Conn, maxConnections),
	}
}

// validateUnixSocketConfig validates Unix socket specific configuration
func validateUnixSocketConfig(config PluginConfig) error {
	if config.Transport != TransportUnix {
		return fmt.Errorf("transport must be unix, got %s", config.Transport)
	}

	if config.Endpoint == "" {
		return fmt.Errorf("socket path (endpoint) is required for Unix socket transport")
	}

	// Check if socket exists
	if _, err := os.Stat(config.Endpoint); err != nil {
		return fmt.Errorf("socket path does not exist or is not accessible: %w", err)
	}

	return nil
}

// GetConnection gets a connection from the pool or creates a new one
func (p *UnixConnectionPool) GetConnection() (net.Conn, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("connection pool is closed")
	}

	select {
	case conn := <-p.connections:
		// Test if connection is still valid
		if err := p.testConnection(conn); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				// Log the error but continue with creating new connection
			}
			return p.createConnection()
		}
		return conn, nil
	default:
		// No connection available, create new one
		return p.createConnection()
	}
}

// ReturnConnection returns a connection to the pool
func (p *UnixConnectionPool) ReturnConnection(conn net.Conn) {
	if p.closed.Load() || conn == nil {
		if conn != nil {
			if closeErr := conn.Close(); closeErr != nil {
				// Log error but continue - connection is being discarded anyway
			}
		}
		return
	}

	select {
	case p.connections <- conn:
		// Successfully returned to pool
	default:
		// Pool is full, close the connection
		if closeErr := conn.Close(); closeErr != nil {
			// Log error but continue - connection is being discarded anyway
		}
	}
}

// createConnection creates a new Unix socket connection
func (p *UnixConnectionPool) createConnection() (net.Conn, error) {
	conn, err := net.DialTimeout("unix", p.socketPath, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Unix socket %s: %w", p.socketPath, err)
	}
	return conn, nil
}

// testConnection tests if a connection is still valid
func (p *UnixConnectionPool) testConnection(conn net.Conn) error {
	// Simple test: try to write and read
	if err := conn.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return err
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			// Log error but continue - deadline reset failure is not critical for this test
		}
	}()

	testMsg := UnixSocketMessage{
		Type:      "ping",
		RequestID: "health-check",
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(testMsg); err != nil {
		return err
	}

	var response UnixSocketResponse
	decoder := json.NewDecoder(conn)
	return decoder.Decode(&response)
}

// Close closes all connections in the pool
func (p *UnixConnectionPool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	close(p.connections)
	for conn := range p.connections {
		if closeErr := conn.Close(); closeErr != nil {
			// Log error but continue closing other connections
		}
	}

	return nil
}

// testConnection tests the Unix socket connection
func (u *UnixSocketPlugin[Req, Resp]) testConnection() error {
	conn, err := u.connPool.GetConnection()
	if err != nil {
		return err
	}
	defer u.connPool.ReturnConnection(conn)

	u.connected.Store(true)
	u.logger.Info("Unix socket connection established",
		"plugin", u.info.Name,
		"socket_path", u.config.Endpoint)

	return nil
}

// fetchRemoteInfo fetches plugin information from the remote server
func (u *UnixSocketPlugin[Req, Resp]) fetchRemoteInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := u.connPool.GetConnection()
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	defer u.connPool.ReturnConnection(conn)

	// Send info request
	msg := UnixSocketMessage{
		Type:      "info",
		RequestID: generateRequestID(),
		Timeout:   5000, // 5 seconds
	}

	response, err := u.sendMessage(ctx, conn, msg)
	if err != nil {
		return fmt.Errorf("failed to fetch plugin info: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("info request failed: %s", response.Error)
	}

	var remoteInfo PluginInfo
	if err := json.Unmarshal(response.Data, &remoteInfo); err != nil {
		return fmt.Errorf("failed to parse remote plugin info: %w", err)
	}

	// Update local info with remote data
	u.info.Version = remoteInfo.Version
	if remoteInfo.Description != "" {
		u.info.Description = remoteInfo.Description
	}
	if len(remoteInfo.Capabilities) > 0 {
		u.info.Capabilities = remoteInfo.Capabilities
	}

	return nil
}

// Info returns plugin information
func (u *UnixSocketPlugin[Req, Resp]) Info() PluginInfo {
	return u.info
}

// Execute processes a request using Unix socket
func (u *UnixSocketPlugin[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp

	if !u.connected.Load() {
		return zero, fmt.Errorf("unix socket connection not established")
	}

	// Get connection from pool
	conn, err := u.connPool.GetConnection()
	if err != nil {
		return zero, fmt.Errorf("failed to get connection: %w", err)
	}
	defer u.connPool.ReturnConnection(conn)

	// Serialize request
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return zero, fmt.Errorf("failed to serialize request: %w", err)
	}

	// Prepare message
	msg := UnixSocketMessage{
		Type:      "execute",
		RequestID: execCtx.RequestID,
		Data:      requestBytes,
		Headers:   execCtx.Headers,
		Timeout:   execCtx.Timeout.Milliseconds(),
	}

	// Send request and get response
	response, err := u.sendMessage(ctx, conn, msg)
	if err != nil {
		return zero, fmt.Errorf("failed to execute request: %w", err)
	}

	if !response.Success {
		return zero, fmt.Errorf("remote execution failed: %s", response.Error)
	}

	// Deserialize response
	var result Resp
	if err := json.Unmarshal(response.Data, &result); err != nil {
		return zero, fmt.Errorf("failed to deserialize response: %w", err)
	}

	return result, nil
}

// Health performs a health check via Unix socket
func (u *UnixSocketPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	startTime := time.Now()
	healthStatus := HealthStatus{
		LastCheck: startTime,
		Metadata:  make(map[string]string),
	}

	if !u.connected.Load() {
		healthStatus.Status = StatusOffline
		healthStatus.Message = "Unix socket connection not established"
		return healthStatus
	}

	// Get connection for health check
	conn, err := u.connPool.GetConnection()
	if err != nil {
		healthStatus.Status = StatusUnhealthy
		healthStatus.Message = fmt.Sprintf("Failed to get connection: %v", err)
		healthStatus.ResponseTime = time.Since(startTime)
		return healthStatus
	}
	defer u.connPool.ReturnConnection(conn)

	// Perform health check with timeout
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	msg := UnixSocketMessage{
		Type:      "health",
		RequestID: generateRequestID(),
		Timeout:   5000, // 5 seconds
	}

	response, err := u.sendMessage(healthCtx, conn, msg)
	healthStatus.ResponseTime = time.Since(startTime)

	if err != nil {
		healthStatus.Status = StatusUnhealthy
		healthStatus.Message = fmt.Sprintf("Health check failed: %v", err)
	} else if !response.Success {
		healthStatus.Status = StatusDegraded
		healthStatus.Message = fmt.Sprintf("Health check returned error: %s", response.Error)
	} else {
		healthStatus.Status = StatusHealthy
		healthStatus.Message = "OK"
	}

	healthStatus.Metadata["socket_path"] = u.config.Endpoint
	healthStatus.Metadata["transport"] = string(u.config.Transport)
	u.lastCheck.Store(startTime.UnixNano())

	return healthStatus
}

// Close closes the Unix socket connection pool
func (u *UnixSocketPlugin[Req, Resp]) Close() error {
	if !u.connected.CompareAndSwap(true, false) {
		return nil // Already closed
	}

	err := u.connPool.Close()
	u.logger.Info("Unix socket connection closed", "plugin", u.info.Name)
	return err
}

// sendMessage sends a message and waits for response with timeout
func (u *UnixSocketPlugin[Req, Resp]) sendMessage(ctx context.Context, conn net.Conn, msg UnixSocketMessage) (*UnixSocketResponse, error) {
	// Set up timeout based on context
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set deadline: %w", err)
		}
		defer func() {
			if err := conn.SetDeadline(time.Time{}); err != nil {
				// Log error but continue - deadline reset failure is not critical
			}
		}()
	}

	// Send message
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var response UnixSocketResponse
	if err := decoder.Decode(&response); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("connection closed by remote")
		}
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Verify request ID matches
	if response.RequestID != msg.RequestID {
		return nil, fmt.Errorf("response request ID mismatch: expected %s, got %s",
			msg.RequestID, response.RequestID)
	}

	return &response, nil
}

// UnixSocketPluginFactory creates Unix socket plugin instances
type UnixSocketPluginFactory[Req, Resp any] struct {
	logger *slog.Logger
}

// NewUnixSocketPluginFactory creates a new Unix socket plugin factory
func NewUnixSocketPluginFactory[Req, Resp any](logger *slog.Logger) *UnixSocketPluginFactory[Req, Resp] {
	return &UnixSocketPluginFactory[Req, Resp]{logger: logger}
}

// CreatePlugin creates a new Unix socket plugin instance
func (f *UnixSocketPluginFactory[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	return NewUnixSocketPlugin[Req, Resp](config, f.logger)
}

// SupportedTransports returns supported transport types
func (f *UnixSocketPluginFactory[Req, Resp]) SupportedTransports() []string {
	return []string{string(TransportUnix)}
}

// ValidateConfig validates Unix socket plugin configuration
func (f *UnixSocketPluginFactory[Req, Resp]) ValidateConfig(config PluginConfig) error {
	return validateUnixSocketConfig(config)
}
