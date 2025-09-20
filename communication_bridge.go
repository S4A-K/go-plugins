// communication_bridge.go: Bidirectional communication system for plugin-host interaction
//
// This file implements a bidirectional communication system that allows plugins
// to initiate connections back to the host process. This enables complex scenarios
// like callbacks, streaming data, and reverse RPC calls while maintaining
// compatibility with standard plugin communication patterns using generic terminology.
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
	"sync/atomic"
	"time"
)

// CommunicationBridge manages bidirectional communication between host and plugin.
//
// This system allows plugins to establish connections back to the host for
// complex communication patterns like callbacks, streaming, and reverse calls.
// It provides multiplexed communication channels for plugin interaction.
type CommunicationBridge struct {
	// Configuration
	config BridgeConfig
	logger Logger

	// Network management
	listener net.Listener
	address  string
	port     int

	// Channel management
	channels     map[uint32]*CommunicationChannel
	channelMutex sync.RWMutex
	nextID       uint32

	// Connection tracking
	connections     map[string]*ConnectionProxy
	connectionMutex sync.RWMutex

	// Lifecycle
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	running  bool
	runMutex sync.Mutex
}

// BridgeConfig configures the communication bridge.
type BridgeConfig struct {
	// Network configuration
	ListenAddress string `json:"listen_address" yaml:"listen_address"`
	ListenPort    int    `json:"listen_port" yaml:"listen_port"`

	// Channel configuration
	MaxChannels     uint32        `json:"max_channels" yaml:"max_channels"`
	ChannelTimeout  time.Duration `json:"channel_timeout" yaml:"channel_timeout"`
	AcceptTimeout   time.Duration `json:"accept_timeout" yaml:"accept_timeout"`
	HandshakeBuffer int           `json:"handshake_buffer" yaml:"handshake_buffer"`

	// Security settings
	AllowedSubnets []string `json:"allowed_subnets" yaml:"allowed_subnets"`
	RequireAuth    bool     `json:"require_auth" yaml:"require_auth"`
}

// DefaultBridgeConfig provides reasonable defaults.
var DefaultBridgeConfig = BridgeConfig{
	ListenAddress:   "127.0.0.1",
	ListenPort:      0, // Auto-assign
	MaxChannels:     100,
	ChannelTimeout:  30 * time.Second,
	AcceptTimeout:   10 * time.Second,
	HandshakeBuffer: 1024,
	AllowedSubnets:  []string{"127.0.0.0/8", "::1/128"},
	RequireAuth:     false,
}

// CommunicationChannel represents a bidirectional communication channel.
type CommunicationChannel struct {
	ID       uint32
	bridge   *CommunicationBridge
	conn     net.Conn
	metadata map[string]string

	// Channel state
	created  time.Time
	lastUsed time.Time
	closed   bool
	closeMux sync.Mutex

	// Statistics
	bytesRead    int64
	bytesWritten int64
	messagesRead int64
	messagesSent int64
}

// ConnectionProxy manages reverse connections from plugin to host.
type ConnectionProxy struct {
	ID         string
	RemoteAddr string
	LocalAddr  string
	conn       net.Conn
	bridge     *CommunicationBridge

	// Proxy state
	active    bool
	activeMux sync.Mutex
}

// NewCommunicationBridge creates a new bidirectional communication bridge.
func NewCommunicationBridge(config BridgeConfig, logger Logger) *CommunicationBridge {
	if logger == nil {
		logger = DefaultLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &CommunicationBridge{
		config:      config,
		logger:      logger,
		channels:    make(map[uint32]*CommunicationChannel),
		connections: make(map[string]*ConnectionProxy),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start initializes and starts the communication bridge.
func (cb *CommunicationBridge) Start() error {
	cb.runMutex.Lock()
	defer cb.runMutex.Unlock()

	if cb.running {
		return NewCommunicationError("communication bridge already running", nil)
	}

	// Create listener
	address := fmt.Sprintf("%s:%d", cb.config.ListenAddress, cb.config.ListenPort)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return NewCommunicationError("failed to create listener", err)
	}

	cb.listener = listener

	// Safely get TCP address
	tcpAddr, ok := cb.listener.Addr().(*net.TCPAddr)
	if !ok {
		if closeErr := cb.listener.Close(); closeErr != nil {
			cb.logger.Error("Failed to close listener", "error", closeErr)
		}
		return NewCommunicationError("listener address is not TCP", nil)
	}
	cb.address = tcpAddr.IP.String()
	cb.port = tcpAddr.Port

	cb.logger.Info("Communication bridge started",
		"address", cb.address,
		"port", cb.port,
		"max_channels", cb.config.MaxChannels)

	// Start accept loop
	cb.wg.Add(1)
	go cb.acceptLoop()

	cb.running = true
	return nil
}

// Stop gracefully shuts down the communication bridge.
func (cb *CommunicationBridge) Stop() error {
	cb.runMutex.Lock()
	defer cb.runMutex.Unlock()

	if !cb.running {
		return nil
	}

	cb.logger.Info("Stopping communication bridge")

	// Cancel context to signal goroutines to stop
	cb.cancel()

	// Close listener
	if cb.listener != nil {
		if err := cb.listener.Close(); err != nil {
			cb.logger.Warn("Failed to close listener", "error", err)
		}
	}

	// Close all channels
	cb.channelMutex.Lock()
	for id, channel := range cb.channels {
		if err := channel.Close(); err != nil {
			cb.logger.Warn("Failed to close channel", "id", id, "error", err)
		}
		cb.logger.Debug("Closed communication channel", "id", id)
	}
	cb.channelMutex.Unlock()

	// Close all connections
	cb.connectionMutex.Lock()
	for id, conn := range cb.connections {
		if err := conn.Close(); err != nil {
			cb.logger.Warn("Failed to close connection proxy", "id", id, "error", err)
		}
		cb.logger.Debug("Closed connection proxy", "id", id)
	}
	cb.connectionMutex.Unlock()

	// Wait for goroutines to finish
	cb.wg.Wait()

	cb.running = false
	cb.logger.Info("Communication bridge stopped")
	return nil
}

// acceptLoop handles incoming connections.
func (cb *CommunicationBridge) acceptLoop() {
	defer cb.wg.Done()

	for {
		select {
		case <-cb.ctx.Done():
			return
		default:
		}

		// Set accept timeout to allow checking context periodically
		if tcpListener, ok := cb.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(cb.config.AcceptTimeout)); err != nil {
				cb.logger.Debug("Failed to set accept deadline", "error", err)
			}
		}

		conn, err := cb.listener.Accept()
		if err != nil {
			// Check if this is a timeout or if we're shutting down
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			select {
			case <-cb.ctx.Done():
				return
			default:
				cb.logger.Error("Accept failed", "error", err)
				continue
			}
		}

		// Handle connection in a separate goroutine
		cb.wg.Add(1)
		go cb.handleConnection(conn)
	}
}

// handleConnection processes a new incoming connection.
func (cb *CommunicationBridge) handleConnection(conn net.Conn) {
	defer cb.wg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			cb.logger.Debug("Failed to close connection", "error", err)
		}
	}()

	remoteAddr := conn.RemoteAddr().String()
	cb.logger.Debug("New connection received", "remote_addr", remoteAddr)

	// Validate connection source if security is enabled
	if cb.config.RequireAuth || len(cb.config.AllowedSubnets) > 0 {
		if !cb.isConnectionAllowed(conn) {
			cb.logger.Warn("Connection rejected", "remote_addr", remoteAddr)
			return
		}
	}

	// Generate unique channel ID
	channelID := atomic.AddUint32(&cb.nextID, 1)

	// Create communication channel
	channel := &CommunicationChannel{
		ID:       channelID,
		bridge:   cb,
		conn:     conn,
		metadata: make(map[string]string),
		created:  time.Now(),
		lastUsed: time.Now(),
	}

	// Register channel
	cb.channelMutex.Lock()
	if len(cb.channels) >= int(cb.config.MaxChannels) {
		cb.channelMutex.Unlock()
		cb.logger.Warn("Maximum channels exceeded", "max", cb.config.MaxChannels)
		return
	}
	cb.channels[channelID] = channel
	cb.channelMutex.Unlock()

	cb.logger.Info("Communication channel established",
		"channel_id", channelID,
		"remote_addr", remoteAddr)

	// Handle channel communication
	cb.handleChannelCommunication(channel)

	// Cleanup
	cb.channelMutex.Lock()
	delete(cb.channels, channelID)
	cb.channelMutex.Unlock()

	cb.logger.Info("Communication channel closed", "channel_id", channelID)
}

// handleChannelCommunication manages communication for a specific channel.
func (cb *CommunicationBridge) handleChannelCommunication(channel *CommunicationChannel) {
	// Set connection timeout
	if cb.config.ChannelTimeout > 0 {
		if err := channel.conn.SetDeadline(time.Now().Add(cb.config.ChannelTimeout)); err != nil {
			cb.logger.Debug("Failed to set channel deadline", "error", err, "channel_id", channel.ID)
		}
	}

	// Protocol handling uses direct subprocess communication
	// This provides the transport foundation for subprocess communication
	buffer := make([]byte, cb.config.HandshakeBuffer)
	for {
		select {
		case <-cb.ctx.Done():
			return
		default:
		}

		n, err := channel.conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				cb.logger.Debug("Channel read error", "error", err, "channel_id", channel.ID)
			}
			return
		}

		// Update statistics
		atomic.AddInt64(&channel.bytesRead, int64(n))
		atomic.AddInt64(&channel.messagesRead, 1)
		channel.lastUsed = time.Now()

		// Echo back for testing (will be replaced with actual protocol)
		_, writeErr := channel.conn.Write(buffer[:n])
		if writeErr != nil {
			cb.logger.Debug("Channel write error", "error", writeErr, "channel_id", channel.ID)
			return
		}

		atomic.AddInt64(&channel.bytesWritten, int64(n))
		atomic.AddInt64(&channel.messagesSent, 1)
	}
}

// isConnectionAllowed validates if a connection is from an allowed source.
func (cb *CommunicationBridge) isConnectionAllowed(conn net.Conn) bool {
	if len(cb.config.AllowedSubnets) == 0 {
		return true
	}

	remoteAddr := conn.RemoteAddr()
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		for _, subnet := range cb.config.AllowedSubnets {
			_, network, err := net.ParseCIDR(subnet)
			if err != nil {
				cb.logger.Warn("Invalid subnet in configuration", "subnet", subnet, "error", err)
				continue
			}
			if network.Contains(tcpAddr.IP) {
				return true
			}
		}
	}

	return false
}

// GetAddress returns the listening address of the bridge.
func (cb *CommunicationBridge) GetAddress() string {
	return cb.address
}

// GetPort returns the listening port of the bridge.
func (cb *CommunicationBridge) GetPort() int {
	return cb.port
}

// GetChannelCount returns the current number of active channels.
func (cb *CommunicationBridge) GetChannelCount() int {
	cb.channelMutex.RLock()
	defer cb.channelMutex.RUnlock()
	return len(cb.channels)
}

// GetChannels returns information about all active channels.
func (cb *CommunicationBridge) GetChannels() []ChannelInfo {
	cb.channelMutex.RLock()
	defer cb.channelMutex.RUnlock()

	channels := make([]ChannelInfo, 0, len(cb.channels))
	for _, channel := range cb.channels {
		channels = append(channels, ChannelInfo{
			ID:           channel.ID,
			RemoteAddr:   channel.conn.RemoteAddr().String(),
			Created:      channel.created,
			LastUsed:     channel.lastUsed,
			BytesRead:    atomic.LoadInt64(&channel.bytesRead),
			BytesWritten: atomic.LoadInt64(&channel.bytesWritten),
			MessagesRead: atomic.LoadInt64(&channel.messagesRead),
			MessagesSent: atomic.LoadInt64(&channel.messagesSent),
		})
	}

	return channels
}

// ChannelInfo provides information about a communication channel.
type ChannelInfo struct {
	ID           uint32    `json:"id"`
	RemoteAddr   string    `json:"remote_addr"`
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used"`
	BytesRead    int64     `json:"bytes_read"`
	BytesWritten int64     `json:"bytes_written"`
	MessagesRead int64     `json:"messages_read"`
	MessagesSent int64     `json:"messages_sent"`
}

// Close closes a communication channel.
func (cc *CommunicationChannel) Close() error {
	cc.closeMux.Lock()
	defer cc.closeMux.Unlock()

	if cc.closed {
		return nil
	}

	if cc.conn != nil {
		if err := cc.conn.Close(); err != nil {
			// Log error but don't return it since Close should be idempotent
			if cc.bridge != nil && cc.bridge.logger != nil {
				cc.bridge.logger.Debug("Failed to close channel connection", "error", err, "channel_id", cc.ID)
			}
		}
	}
	cc.closed = true
	return nil
}

// Close closes a connection proxy.
func (cp *ConnectionProxy) Close() error {
	cp.activeMux.Lock()
	defer cp.activeMux.Unlock()

	if !cp.active {
		return nil
	}

	if cp.conn != nil {
		if err := cp.conn.Close(); err != nil {
			// Log error but don't return it since Close should be idempotent
			if cp.bridge != nil && cp.bridge.logger != nil {
				cp.bridge.logger.Debug("Failed to close proxy connection", "error", err, "proxy_id", cp.ID)
			}
		}
	}
	cp.active = false
	return nil
}
