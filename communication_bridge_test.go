// communication_bridge_test.go: Tests for bidirectional communication system
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestDefaultBridgeConfig(t *testing.T) {
	config := DefaultBridgeConfig

	if config.ListenAddress != "127.0.0.1" {
		t.Errorf("Expected listen address 127.0.0.1, got %s", config.ListenAddress)
	}

	if config.ListenPort != 0 {
		t.Errorf("Expected listen port 0 (auto-assign), got %d", config.ListenPort)
	}

	if config.MaxChannels != 100 {
		t.Errorf("Expected max channels 100, got %d", config.MaxChannels)
	}

	if config.ChannelTimeout != 30*time.Second {
		t.Errorf("Expected channel timeout 30s, got %v", config.ChannelTimeout)
	}

	if len(config.AllowedSubnets) != 2 {
		t.Errorf("Expected 2 allowed subnets, got %d", len(config.AllowedSubnets))
	}

	expectedSubnets := []string{"127.0.0.0/8", "::1/128"}
	for i, expected := range expectedSubnets {
		if i >= len(config.AllowedSubnets) || config.AllowedSubnets[i] != expected {
			t.Errorf("Expected subnet %d to be %s, got %s", i, expected,
				config.AllowedSubnets[i])
		}
	}
}

func TestNewCommunicationBridge(t *testing.T) {
	config := DefaultBridgeConfig
	logger := NewTestLogger()

	bridge := NewCommunicationBridge(config, logger)

	if bridge == nil {
		t.Fatal("NewCommunicationBridge returned nil")
	}

	if bridge.config.MaxChannels != config.MaxChannels {
		t.Error("Config not set correctly")
	}

	if len(bridge.channels) != 0 {
		t.Errorf("Expected 0 channels initially, got %d", len(bridge.channels))
	}

	if len(bridge.connections) != 0 {
		t.Errorf("Expected 0 connections initially, got %d", len(bridge.connections))
	}
}

func TestCommunicationBridgeStartStop(t *testing.T) {
	config := DefaultBridgeConfig
	config.ListenPort = 0 // Auto-assign port
	logger := NewTestLogger()

	bridge := NewCommunicationBridge(config, logger)

	// Start the bridge
	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start communication bridge: %v", err)
	}

	// Verify it's running
	if bridge.GetAddress() == "" {
		t.Error("Bridge address should be set after start")
	}

	if bridge.GetPort() == 0 {
		t.Error("Bridge port should be assigned after start")
	}

	// Try to start again (should fail)
	err = bridge.Start()
	if err == nil {
		t.Error("Expected error when starting already running bridge")
	}

	// Stop the bridge
	err = bridge.Stop()
	if err != nil {
		t.Fatalf("Failed to stop communication bridge: %v", err)
	}

	// Stop again (should not error)
	err = bridge.Stop()
	if err != nil {
		t.Errorf("Stopping already stopped bridge should not error: %v", err)
	}
}

func TestCommunicationBridgeGetters(t *testing.T) {
	config := DefaultBridgeConfig
	logger := NewTestLogger()
	bridge := NewCommunicationBridge(config, logger)

	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Test getters
	address := bridge.GetAddress()
	if address == "" {
		t.Error("GetAddress should return non-empty address")
	}

	port := bridge.GetPort()
	if port <= 0 || port > 65535 {
		t.Errorf("GetPort should return valid port, got %d", port)
	}

	channelCount := bridge.GetChannelCount()
	if channelCount != 0 {
		t.Errorf("Expected 0 channels initially, got %d", channelCount)
	}

	channels := bridge.GetChannels()
	if len(channels) != 0 {
		t.Errorf("Expected 0 channels initially, got %d", len(channels))
	}
}

func TestCommunicationBridgeConnection(t *testing.T) {
	config := DefaultBridgeConfig
	config.AcceptTimeout = 100 * time.Millisecond // Shorter timeout for testing
	logger := NewTestLogger()
	bridge := NewCommunicationBridge(config, logger)

	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Give the bridge a moment to start accepting connections
	time.Sleep(50 * time.Millisecond)

	// Connect to the bridge
	address := bridge.GetAddress()
	port := bridge.GetPort()

	conn, err := net.Dial("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatalf("Failed to connect to bridge: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Warning: failed to close connection: %v", err)
		}
	}()

	// Send test data
	testData := "Hello, bridge!"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("Failed to write to connection: %v", err)
	}

	// Read response (echo)
	buffer := make([]byte, len(testData))
	_, err = conn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read from connection: %v", err)
	}

	response := string(buffer)
	if response != testData {
		t.Errorf("Expected echo response '%s', got '%s'", testData, response)
	}

	// Give time for channel registration
	time.Sleep(100 * time.Millisecond)

	// Verify channel was created
	channelCount := bridge.GetChannelCount()
	if channelCount != 1 {
		t.Errorf("Expected 1 channel after connection, got %d", channelCount)
	}

	channels := bridge.GetChannels()
	if len(channels) != 1 {
		t.Errorf("Expected 1 channel info, got %d", len(channels))
	}

	if len(channels) > 0 {
		channel := channels[0]
		if channel.ID == 0 {
			t.Error("Channel ID should not be 0")
		}
		if channel.RemoteAddr == "" {
			t.Error("Channel RemoteAddr should not be empty")
		}
		if channel.BytesRead != int64(len(testData)) {
			t.Errorf("Expected bytes read %d, got %d", len(testData), channel.BytesRead)
		}
		if channel.BytesWritten != int64(len(testData)) {
			t.Errorf("Expected bytes written %d, got %d", len(testData), channel.BytesWritten)
		}
	}
}

func TestCommunicationBridgeMultipleConnections(t *testing.T) {
	config := DefaultBridgeConfig
	config.MaxChannels = 3 // Limit for testing
	config.AcceptTimeout = 100 * time.Millisecond
	logger := NewTestLogger()
	bridge := NewCommunicationBridge(config, logger)

	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	// Give the bridge a moment to start
	time.Sleep(50 * time.Millisecond)

	address := bridge.GetAddress()
	port := bridge.GetPort()

	// Create multiple connections
	connections := make([]net.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)))
		if err != nil {
			t.Fatalf("Failed to connect %d: %v", i, err)
		}
		connections = append(connections, conn)

		// Send some data to establish the channel
		if _, err := conn.Write([]byte("test")); err != nil {
			t.Errorf("Failed to write to connection %d: %v", i, err)
		}
		buffer := make([]byte, 4)
		if _, err := conn.Read(buffer); err != nil {
			t.Errorf("Failed to read from connection %d: %v", i, err)
		}
	}

	// Clean up connections
	defer func() {
		for _, conn := range connections {
			if err := conn.Close(); err != nil {
				t.Logf("Warning: failed to close connection: %v", err)
			}
		}
	}()

	// Give time for all channels to register
	time.Sleep(200 * time.Millisecond)

	// Verify all channels were created
	channelCount := bridge.GetChannelCount()
	if channelCount != 3 {
		t.Errorf("Expected 3 channels, got %d", channelCount)
	}
}

func TestBridgeConfigMaxChannelsLimit(t *testing.T) {
	config := DefaultBridgeConfig
	config.MaxChannels = 1 // Very limited
	config.AcceptTimeout = 50 * time.Millisecond
	logger := NewTestLogger()
	bridge := NewCommunicationBridge(config, logger)

	err := bridge.Start()
	if err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			t.Logf("Warning: failed to stop bridge: %v", err)
		}
	}()

	time.Sleep(25 * time.Millisecond)

	address := bridge.GetAddress()
	port := bridge.GetPort()

	// Create first connection (should succeed)
	conn1, err := net.Dial("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatalf("Failed to create first connection: %v", err)
	}
	defer func() {
		if err := conn1.Close(); err != nil {
			t.Logf("Warning: failed to close connection1: %v", err)
		}
	}()

	// Establish the channel
	if _, err := conn1.Write([]byte("test")); err != nil {
		t.Errorf("Failed to write to connection1: %v", err)
	}
	buffer := make([]byte, 4)
	if _, err := conn1.Read(buffer); err != nil {
		t.Errorf("Failed to read from connection1: %v", err)
	}

	// Give time for channel registration
	time.Sleep(100 * time.Millisecond)

	// Create second connection (should be rejected due to limit)
	conn2, err := net.Dial("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatalf("Failed to create second connection: %v", err)
	}
	defer func() {
		if err := conn2.Close(); err != nil {
			t.Logf("Warning: failed to close connection2: %v", err)
		}
	}()

	// Try to send data - connection should be closed quickly
	if _, err := conn2.Write([]byte("test")); err != nil {
		t.Logf("Expected: connection2 write failed (connection rejected): %v", err)
	}

	// Give time for processing
	time.Sleep(100 * time.Millisecond)

	// Should still only have 1 channel
	channelCount := bridge.GetChannelCount()
	if channelCount > 1 {
		t.Errorf("Expected max 1 channel due to limit, got %d", channelCount)
	}
}

func TestChannelInfo(t *testing.T) {
	// Test ChannelInfo structure with fixed times for verification
	createdTime := time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC)
	lastUsedTime := time.Date(2023, 1, 1, 11, 0, 0, 0, time.UTC)

	info := ChannelInfo{
		ID:           123,
		RemoteAddr:   "127.0.0.1:45678",
		Created:      createdTime,
		LastUsed:     lastUsedTime,
		BytesRead:    100,
		BytesWritten: 200,
		MessagesRead: 5,
		MessagesSent: 5,
	}

	if info.ID != 123 {
		t.Errorf("Expected ID 123, got %d", info.ID)
	}

	if info.RemoteAddr != "127.0.0.1:45678" {
		t.Errorf("Expected RemoteAddr '127.0.0.1:45678', got %s", info.RemoteAddr)
	}

	if info.BytesRead != 100 {
		t.Errorf("Expected BytesRead 100, got %d", info.BytesRead)
	}

	if info.BytesWritten != 200 {
		t.Errorf("Expected BytesWritten 200, got %d", info.BytesWritten)
	}

	if info.MessagesRead != 5 {
		t.Errorf("Expected MessagesRead 5, got %d", info.MessagesRead)
	}

	if info.MessagesSent != 5 {
		t.Errorf("Expected MessagesSent 5, got %d", info.MessagesSent)
	}

	if !info.Created.Equal(createdTime) {
		t.Errorf("Expected Created %v, got %v", createdTime, info.Created)
	}

	if !info.LastUsed.Equal(lastUsedTime) {
		t.Errorf("Expected LastUsed %v, got %v", lastUsedTime, info.LastUsed)
	}
}

func TestConnectionAllowed(t *testing.T) {
	config := BridgeConfig{
		ListenAddress:  "127.0.0.1",
		ListenPort:     0,
		AllowedSubnets: []string{"127.0.0.0/8"},
		RequireAuth:    false,
	}

	logger := NewTestLogger()
	bridge := NewCommunicationBridge(config, logger)

	// Mock connection from localhost (should be allowed)
	localAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("Failed to resolve local address: %v", err)
	}
	remoteAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:54321")
	if err != nil {
		t.Fatalf("Failed to resolve remote address: %v", err)
	}

	// We can't easily test isConnectionAllowed without a real connection,
	// but we can test the configuration validation
	if len(bridge.config.AllowedSubnets) != 1 {
		t.Errorf("Expected 1 allowed subnet, got %d", len(bridge.config.AllowedSubnets))
	}

	if bridge.config.AllowedSubnets[0] != "127.0.0.0/8" {
		t.Errorf("Expected subnet '127.0.0.0/8', got %s", bridge.config.AllowedSubnets[0])
	}

	// Test invalid subnet parsing (this would happen in isConnectionAllowed)
	_, _, parseErr := net.ParseCIDR("invalid-subnet")
	if parseErr == nil {
		t.Error("Expected error for invalid subnet")
	}

	_ = localAddr // Use the variables to avoid compiler warnings
	_ = remoteAddr
}

func TestCommunicationChannelClose(t *testing.T) {
	config := DefaultBridgeConfig
	logger := NewTestLogger()
	bridge := NewCommunicationBridge(config, logger)

	// Create a mock channel
	channel := &CommunicationChannel{
		ID:       1,
		bridge:   bridge,
		conn:     nil, // Mock connection
		metadata: make(map[string]string),
		created:  time.Now(),
		lastUsed: time.Now(),
		closed:   false,
	}

	// Close the channel
	err := channel.Close()
	if err != nil {
		t.Errorf("Channel.Close() should not error with nil connection: %v", err)
	}

	if !channel.closed {
		t.Error("Channel should be marked as closed")
	}

	// Close again (should not error)
	err = channel.Close()
	if err != nil {
		t.Errorf("Closing already closed channel should not error: %v", err)
	}
}

func TestConnectionProxyClose(t *testing.T) {
	config := DefaultBridgeConfig
	logger := NewTestLogger()
	bridge := NewCommunicationBridge(config, logger)

	// Create a mock connection proxy
	proxy := &ConnectionProxy{
		ID:         "test-proxy",
		RemoteAddr: "127.0.0.1:12345",
		LocalAddr:  "127.0.0.1:54321",
		conn:       nil, // Mock connection
		bridge:     bridge,
		created:    time.Now(),
		active:     true,
	}

	// Close the proxy
	err := proxy.Close()
	if err != nil {
		t.Errorf("ConnectionProxy.Close() should not error with nil connection: %v", err)
	}

	if proxy.active {
		t.Error("Proxy should be marked as inactive")
	}

	// Close again (should not error)
	err = proxy.Close()
	if err != nil {
		t.Errorf("Closing already inactive proxy should not error: %v", err)
	}
}
