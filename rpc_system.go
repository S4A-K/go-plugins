// rpc_system.go: JSON-RPC communication over TCP transport
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	netrpc "net/rpc"
	"sync"
	"time"
)

// RPCProtocol implements JSON-RPC communication over our TCP transport layer
type RPCProtocol struct {
	logger Logger
	bridge *CommunicationBridge

	// Server-side components
	server     *netrpc.Server
	dispatcher *RPCDispatcher
	listener   net.Listener

	// Client-side components
	client     *netrpc.Client
	connection net.Conn

	// Configuration
	timeout    time.Duration
	actualPort int // The actual port the RPC server is listening on

	// State management
	running bool
	mutex   sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// RPCDispatcher handles plugin method dispatching
type RPCDispatcher struct {
	handlers map[string]RequestHandler
	logger   Logger
	mutex    sync.RWMutex
}

// RPCControlService provides control interface for RPC server
type RPCControlService struct {
	protocol *RPCProtocol
	logger   Logger
}

// RPCPluginService provides plugin method dispatch for RPC
type RPCPluginService struct {
	dispatcher *RPCDispatcher
	logger     Logger
}

// RPCMethodCall represents a method call over RPC
type RPCMethodCall struct {
	PluginName string          `json:"plugin_name"`
	Method     string          `json:"method"`
	Args       json.RawMessage `json:"args"`
	ID         string          `json:"id"`
	Timeout    time.Duration   `json:"timeout"`
}

// RPCMethodResult represents the result of an RPC method call
type RPCMethodResult struct {
	ID      string          `json:"id"`
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error,omitempty"`
}

// NewRPCProtocol creates a new RPC protocol instance
func NewRPCProtocol(logger Logger, bridge *CommunicationBridge) *RPCProtocol {
	if logger == nil {
		logger = DefaultLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &RPCProtocol{
		logger:     logger,
		bridge:     bridge,
		dispatcher: NewRPCDispatcher(logger),
		timeout:    30 * time.Second,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// NewRPCDispatcher creates a new RPC dispatcher
func NewRPCDispatcher(logger Logger) *RPCDispatcher {
	return &RPCDispatcher{
		handlers: make(map[string]RequestHandler),
		logger:   logger,
	}
}

// StartServer initializes and starts the RPC server
func (rpc *RPCProtocol) StartServer(ctx context.Context) error {
	rpc.mutex.Lock()
	defer rpc.mutex.Unlock()

	if rpc.running {
		return errors.New("RPC server already running")
	}

	// Create and configure the listener
	listener, err := rpc.createListener()
	if err != nil {
		return err
	}

	// Create and configure the RPC server
	if err := rpc.setupRPCServer(listener); err != nil {
		return err
	}

	// Finalize server setup
	rpc.listener = listener
	rpc.running = true

	// Store the actual port we're using
	if addr, ok := listener.Addr().(*net.TCPAddr); ok {
		rpc.actualPort = addr.Port
	}

	rpc.logger.Info("RPC server started", "address", listener.Addr().String(), "actual_port", rpc.actualPort)

	// Start accepting connections
	go rpc.acceptConnections(ctx)

	return nil
}

// createListener creates a TCP listener, trying multiple ports if needed
func (rpc *RPCProtocol) createListener() (net.Listener, error) {
	// Use a different port for RPC (bridge port + 1) to avoid conflicts
	rpcPort := rpc.bridge.GetPort() + 1
	address := fmt.Sprintf(":%d", rpcPort)
	listener, err := net.Listen("tcp", address)
	if err == nil {
		return listener, nil
	}

	// If port+1 is busy, try a few more ports
	for i := 2; i <= 10; i++ {
		rpcPort = rpc.bridge.GetPort() + i
		address = fmt.Sprintf(":%d", rpcPort)
		listener, err = net.Listen("tcp", address)
		if err == nil {
			return listener, nil
		}
	}

	return nil, fmt.Errorf("failed to start TCP listener on ports %d-%d: %w",
		rpc.bridge.GetPort()+1, rpc.bridge.GetPort()+10, err)
}

// setupRPCServer creates and configures the RPC server with services
func (rpc *RPCProtocol) setupRPCServer(listener net.Listener) error {
	// Create RPC server
	rpc.server = netrpc.NewServer()

	// Register control service
	controlService := &RPCControlService{
		protocol: rpc,
		logger:   rpc.logger,
	}

	if err := rpc.server.RegisterName("Control", controlService); err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			rpc.logger.Warn("Failed to close listener after Control service registration failed", "error", closeErr)
		}
		return fmt.Errorf("failed to register Control service: %w", err)
	}

	// Register plugin service
	pluginService := &RPCPluginService{
		dispatcher: rpc.dispatcher,
		logger:     rpc.logger,
	}

	if err := rpc.server.RegisterName("Plugin", pluginService); err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			rpc.logger.Warn("Failed to close listener after Plugin service registration failed", "error", closeErr)
		}
		return fmt.Errorf("failed to register Plugin service: %w", err)
	}

	return nil
}

// acceptConnections handles incoming connections
func (rpc *RPCProtocol) acceptConnections(ctx context.Context) {
	defer rpc.cleanupListenerOnShutdown()

	for {
		if rpc.shouldStopAccepting(ctx) {
			return
		}

		conn, err := rpc.acceptSingleConnection()
		if err != nil {
			rpc.handleAcceptError(err)
			continue
		}

		go rpc.handleConnection(ctx, conn)
	}
}

// cleanupListenerOnShutdown closes the listener when shutting down
func (rpc *RPCProtocol) cleanupListenerOnShutdown() {
	rpc.mutex.RLock()
	defer rpc.mutex.RUnlock()

	if rpc.listener != nil {
		if err := rpc.listener.Close(); err != nil {
			rpc.logger.Debug("Failed to close listener in acceptConnections", "error", err)
		}
	}
}

// shouldStopAccepting checks if the connection acceptance loop should stop
func (rpc *RPCProtocol) shouldStopAccepting(ctx context.Context) bool {
	// Check external context cancellation
	select {
	case <-ctx.Done():
		rpc.logger.Info("RPC server shutting down")
		return true
	default:
	}

	// Check internal context cancellation with proper locking
	rpc.mutex.RLock()
	ctxDone := rpc.ctx.Done()
	rpc.mutex.RUnlock()

	select {
	case <-ctxDone:
		rpc.logger.Info("RPC server context cancelled")
		return true
	default:
	}

	return false
}

// acceptSingleConnection attempts to accept one connection
func (rpc *RPCProtocol) acceptSingleConnection() (net.Conn, error) {
	rpc.mutex.RLock()
	listener := rpc.listener
	rpc.mutex.RUnlock()

	if listener == nil {
		return nil, errors.New("listener is nil")
	}

	return listener.Accept()
}

// handleAcceptError handles errors from accepting connections
func (rpc *RPCProtocol) handleAcceptError(err error) {
	if !errors.Is(err, net.ErrClosed) {
		rpc.logger.Error("Failed to accept connection", "error", err)
	}
}

// handleConnection processes a single RPC connection
func (rpc *RPCProtocol) handleConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			rpc.logger.Debug("Failed to close RPC connection", "error", err, "remote", conn.RemoteAddr())
		}
	}()

	rpc.logger.Debug("New RPC connection", "remote", conn.RemoteAddr())

	// Create a new RPC server for this connection
	server := netrpc.NewServer()

	// Register our RPC services with custom names
	controlService := &RPCControlService{protocol: rpc, logger: rpc.logger}
	err := server.RegisterName("Control", controlService)
	if err != nil {
		rpc.logger.Error("Failed to register RPC control service", "error", err)
		return
	}

	pluginService := &RPCPluginService{dispatcher: rpc.dispatcher, logger: rpc.logger}
	err = server.RegisterName("Plugin", pluginService)
	if err != nil {
		rpc.logger.Error("Failed to register RPC plugin service", "error", err)
		return
	}

	// Create a done channel to handle context cancellation
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Serve the connection
		server.ServeConn(conn)
	}()

	// Wait for either completion or context cancellation
	select {
	case <-done:
		rpc.logger.Debug("RPC connection completed", "remote", conn.RemoteAddr())
	case <-ctx.Done():
		rpc.logger.Debug("RPC connection cancelled", "remote", conn.RemoteAddr())
		if err := conn.Close(); err != nil {
			rpc.logger.Debug("Failed to force close connection on cancellation", "error", err, "remote", conn.RemoteAddr())
		}
	}
}

// RegisterHandler registers a request handler for RPC dispatch
func (rpc *RPCProtocol) RegisterHandler(name string, handler RequestHandler) error {
	return rpc.dispatcher.RegisterHandler(name, handler)
}

// RegisterHandler adds a request handler to the dispatcher
func (d *RPCDispatcher) RegisterHandler(name string, handler RequestHandler) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, exists := d.handlers[name]; exists {
		return fmt.Errorf("handler %s already registered", name)
	}

	d.handlers[name] = handler
	d.logger.Info("RPC handler registered", "name", name)
	return nil
}

// GetHandler retrieves a registered handler
func (d *RPCDispatcher) GetHandler(name string) (RequestHandler, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	handler, exists := d.handlers[name]
	return handler, exists
}

// Ping checks if the RPC connection is alive
func (c *RPCControlService) Ping(args bool, reply *bool) error {
	c.logger.Debug("Received ping")
	*reply = true
	return nil
}

// RPCStatusResponse represents the status response from the server
type RPCStatusResponse struct {
	Running            bool `json:"running"`
	RegisteredHandlers int  `json:"registered_handlers"`
	UptimeSeconds      int  `json:"uptime_seconds"`
}

// Status returns the current server status
func (c *RPCControlService) Status(args struct{}, reply *RPCStatusResponse) error {
	c.logger.Debug("Received status request")

	c.protocol.mutex.RLock()
	running := c.protocol.running
	handlersCount := len(c.protocol.dispatcher.handlers)
	c.protocol.mutex.RUnlock()

	*reply = RPCStatusResponse{
		Running:            running,
		RegisteredHandlers: handlersCount,
		UptimeSeconds:      0, // Placeholder
	}

	return nil
}

// Stop gracefully shuts down the RPC server
func (c *RPCControlService) Stop(args struct{}, reply *bool) error {
	c.logger.Info("Received stop signal")

	go func() {
		// Shutdown in background to avoid blocking RPC call
		time.Sleep(100 * time.Millisecond)
		if err := c.protocol.Stop(); err != nil {
			c.logger.Warn("Failed to stop protocol in background", "error", err)
		}
	}()

	*reply = true
	return nil
}

// Call invokes a plugin method
func (p *RPCPluginService) Call(call *RPCMethodCall, result *RPCMethodResult) error {
	p.logger.Debug("RPC method call", "plugin", call.PluginName, "method", call.Method, "id", call.ID)

	// Get the handler
	handler, exists := p.dispatcher.GetHandler(call.PluginName)
	if !exists {
		result.ID = call.ID
		result.Success = false
		result.Error = fmt.Sprintf("unknown plugin: %s", call.PluginName)
		return nil
	}

	// Create plugin request
	req := &PluginRequest{
		ID:        call.ID,
		Method:    call.Method,
		Data:      []byte(call.Args),
		Metadata:  make(map[string]string),
		Timestamp: time.Now(),
	}

	// Handle the request
	ctx, cancel := context.WithTimeout(context.Background(), call.Timeout)
	if call.Timeout == 0 {
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	}
	defer cancel()

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		result.ID = call.ID
		result.Success = false
		result.Error = err.Error()
		return nil
	}

	// Convert response
	result.ID = call.ID
	result.Success = resp.Success
	result.Result = resp.Data
	if !resp.Success {
		result.Error = resp.Error
	}

	return nil
}

// ConnectClient establishes an RPC client connection
func (rpc *RPCProtocol) ConnectClient(address string) error {
	rpc.mutex.Lock()
	defer rpc.mutex.Unlock()

	if rpc.client != nil {
		return errors.New("RPC client already connected")
	}

	conn, err := net.DialTimeout("tcp", address, rpc.timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to RPC server: %w", err)
	}

	// Create RPC client
	rpc.client = netrpc.NewClient(conn)
	rpc.connection = conn

	rpc.logger.Info("RPC client connected", "address", address)
	return nil
}

// CallRemoteMethod invokes a remote plugin method
func (rpc *RPCProtocol) CallRemoteMethod(pluginName, method string, args interface{}) (interface{}, error) {
	if rpc.client == nil {
		return nil, errors.New("RPC client not connected")
	}

	// Serialize args
	argsData, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal args: %w", err)
	}

	// Prepare the call
	call := &RPCMethodCall{
		PluginName: pluginName,
		Method:     method,
		Args:       argsData,
		ID:         fmt.Sprintf("call_%d", time.Now().UnixNano()),
		Timeout:    rpc.timeout,
	}

	var result RPCMethodResult
	err = rpc.client.Call("Plugin.Call", call, &result)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("remote call failed: %s", result.Error)
	}

	return result.Result, nil
}

// Ping tests the RPC connection
func (rpc *RPCProtocol) Ping() error {
	if rpc.client == nil {
		return errors.New("RPC client not connected")
	}

	var reply bool
	return rpc.client.Call("Control.Ping", true, &reply)
}

// GetRemoteStatus gets the status from remote server
func (rpc *RPCProtocol) GetRemoteStatus() (*RPCStatusResponse, error) {
	if rpc.client == nil {
		return nil, errors.New("RPC client not connected")
	}

	var reply RPCStatusResponse
	err := rpc.client.Call("Control.Status", struct{}{}, &reply)
	return &reply, err
}

// Stop gracefully shuts down the RPC protocol
func (rpc *RPCProtocol) Stop() error {
	rpc.mutex.Lock()
	defer rpc.mutex.Unlock()

	var errs []error

	// Cancel context
	if rpc.cancel != nil {
		rpc.cancel()
	}

	// Close client resources
	if clientErr := rpc.stopClient(); clientErr != nil {
		errs = append(errs, clientErr)
	}

	// Close server resources
	if serverErr := rpc.stopServer(); serverErr != nil {
		errs = append(errs, serverErr)
	}

	rpc.running = false

	if len(errs) > 0 {
		return fmt.Errorf("errors during RPC shutdown: %v", errs)
	}

	rpc.logger.Info("RPC protocol stopped")
	return nil
}

// stopClient handles cleanup of client resources
func (rpc *RPCProtocol) stopClient() error {
	if rpc.client == nil {
		return nil
	}

	// Try to notify server we're disconnecting with timeout
	var reply bool
	done := make(chan error, 1)
	go func() {
		done <- rpc.client.Call("Control.Stop", struct{}{}, &reply)
	}()

	select {
	case err := <-done:
		if err != nil {
			rpc.logger.Debug("Failed to notify server of disconnect", "error", err)
		}
	case <-time.After(2 * time.Second):
		rpc.logger.Debug("Timeout while notifying server of disconnect")
	}

	if err := rpc.client.Close(); err != nil {
		return fmt.Errorf("failed to close RPC client: %w", err)
	}
	rpc.client = nil

	// Close client connection
	if rpc.connection != nil {
		if err := rpc.connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("failed to close client connection: %w", err)
		}
		rpc.connection = nil
	}

	return nil
}

// stopServer handles cleanup of server resources
func (rpc *RPCProtocol) stopServer() error {
	if rpc.listener == nil {
		return nil
	}

	if err := rpc.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to close server listener: %w", err)
	}
	rpc.listener = nil
	return nil
}

// IsRunning returns whether the RPC server is running
func (rpc *RPCProtocol) IsRunning() bool {
	rpc.mutex.RLock()
	defer rpc.mutex.RUnlock()

	return rpc.running
}

// IsConnected returns whether the RPC client is connected
func (rpc *RPCProtocol) IsConnected() bool {
	rpc.mutex.RLock()
	defer rpc.mutex.RUnlock()

	return rpc.client != nil
}

// GetRPCPort returns the actual port the RPC server is listening on
func (rpc *RPCProtocol) GetRPCPort() int {
	rpc.mutex.RLock()
	defer rpc.mutex.RUnlock()

	return rpc.actualPort
}

// GetStats returns RPC protocol statistics
func (rpc *RPCProtocol) GetStats() map[string]interface{} {
	rpc.mutex.RLock()
	defer rpc.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["running"] = rpc.running
	stats["connected"] = rpc.client != nil
	stats["registered_handlers"] = len(rpc.dispatcher.handlers)
	stats["rpc_port"] = rpc.actualPort

	if rpc.bridge != nil {
		stats["bridge_port"] = rpc.bridge.GetPort()
		stats["bridge_address"] = rpc.bridge.GetAddress()
	}

	return stats
}
