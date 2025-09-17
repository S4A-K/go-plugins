// handshake_test.go: Tests for standard handshake protocol
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestDefaultHandshakeConfig(t *testing.T) {
	config := DefaultHandshakeConfig

	if config.ProtocolVersion != 1 {
		t.Errorf("Expected protocol version 1, got %d", config.ProtocolVersion)
	}

	if config.MagicCookieKey != "AGILIRA_PLUGIN_MAGIC_COOKIE" {
		t.Errorf("Expected magic cookie key 'AGILIRA_PLUGIN_MAGIC_COOKIE', got %s", config.MagicCookieKey)
	}

	if config.MagicCookieValue != "agilira-go-plugins-v1" {
		t.Errorf("Expected magic cookie value 'agilira-go-plugins-v1', got %s", config.MagicCookieValue)
	}
}

func TestPluginTypeString(t *testing.T) {
	tests := []struct {
		pluginType PluginType
		expected   string
	}{
		{PluginTypeInvalid, "invalid"},
		{PluginTypeGRPC, "grpc"},
	}

	for _, test := range tests {
		if got := test.pluginType.String(); got != test.expected {
			t.Errorf("PluginType(%d).String() = %s, expected %s", test.pluginType, got, test.expected)
		}
	}
}

func TestHandshakeManagerPrepareEnvironment(t *testing.T) {
	config := DefaultHandshakeConfig
	logger := NewTestLogger()
	manager := NewHandshakeManager(config, logger)

	info := HandshakeInfo{
		ProtocolVersion: 1,
		PluginType:      PluginTypeGRPC,
		ServerAddress:   "127.0.0.1",
		ServerPort:      8080,
		PluginName:      "test-plugin",
		PluginVersion:   "1.0.0",
	}

	env := manager.PrepareEnvironment(info)

	// Check that environment variables are set correctly
	envMap := make(map[string]string)
	for _, envVar := range env {
		if len(envVar) > 0 && envVar[0] != '=' { // Skip invalid env vars
			parts := splitEnvVar(envVar)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}
	}

	// Verify magic cookie
	if envMap[config.MagicCookieKey] != config.MagicCookieValue {
		t.Errorf("Magic cookie not set correctly in environment")
	}

	// Verify protocol version
	if envMap["PLUGIN_PROTOCOL_VERSION"] != "1" {
		t.Errorf("Protocol version not set correctly in environment")
	}

	// Verify server info
	if envMap["PLUGIN_SERVER_ADDRESS"] != "127.0.0.1" {
		t.Errorf("Server address not set correctly in environment")
	}

	if envMap["PLUGIN_SERVER_PORT"] != "8080" {
		t.Errorf("Server port not set correctly in environment")
	}

	// Verify plugin type
	if envMap["PLUGIN_TYPE"] != "grpc" {
		t.Errorf("Plugin type not set correctly in environment")
	}

	// Verify optional fields
	if envMap["PLUGIN_NAME"] != "test-plugin" {
		t.Errorf("Plugin name not set correctly in environment")
	}

	if envMap["PLUGIN_VERSION"] != "1.0.0" {
		t.Errorf("Plugin version not set correctly in environment")
	}
}

func TestHandshakeManagerValidatePluginEnvironment(t *testing.T) {
	config := DefaultHandshakeConfig
	logger := NewTestLogger()
	manager := NewHandshakeManager(config, logger)

	// Set up test environment
	oldEnv := os.Environ()
	defer func() {
		// Restore original environment
		for _, envVar := range oldEnv {
			parts := splitEnvVar(envVar)
			if len(parts) == 2 {
				if err := os.Setenv(parts[0], parts[1]); err != nil {
					t.Logf("Warning: failed to restore env var %s: %v", parts[0], err)
				}
			}
		}
	}()

	// Clear and set test environment
	os.Clearenv()
	if err := os.Setenv(config.MagicCookieKey, config.MagicCookieValue); err != nil {
		t.Fatalf("Failed to set magic cookie: %v", err)
	}
	if err := os.Setenv("PLUGIN_PROTOCOL_VERSION", "1"); err != nil {
		t.Fatalf("Failed to set protocol version: %v", err)
	}
	if err := os.Setenv("PLUGIN_SERVER_ADDRESS", "127.0.0.1"); err != nil {
		t.Fatalf("Failed to set server address: %v", err)
	}
	if err := os.Setenv("PLUGIN_SERVER_PORT", "8080"); err != nil {
		t.Fatalf("Failed to set server port: %v", err)
	}
	if err := os.Setenv("PLUGIN_TYPE", "grpc"); err != nil {
		t.Fatalf("Failed to set plugin type: %v", err)
	}
	if err := os.Setenv("PLUGIN_NAME", "test-plugin"); err != nil {
		t.Fatalf("Failed to set plugin name: %v", err)
	}
	if err := os.Setenv("PLUGIN_VERSION", "1.0.0"); err != nil {
		t.Fatalf("Failed to set plugin version: %v", err)
	}

	info, err := manager.ValidatePluginEnvironment()
	if err != nil {
		t.Fatalf("ValidatePluginEnvironment failed: %v", err)
	}

	if info.ProtocolVersion != 1 {
		t.Errorf("Expected protocol version 1, got %d", info.ProtocolVersion)
	}

	if info.PluginType != PluginTypeGRPC {
		t.Errorf("Expected plugin type gRPC, got %s", info.PluginType.String())
	}

	if info.ServerAddress != "127.0.0.1" {
		t.Errorf("Expected server address 127.0.0.1, got %s", info.ServerAddress)
	}

	if info.ServerPort != 8080 {
		t.Errorf("Expected server port 8080, got %d", info.ServerPort)
	}

	if info.PluginName != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got %s", info.PluginName)
	}

	if info.PluginVersion != "1.0.0" {
		t.Errorf("Expected plugin version '1.0.0', got %s", info.PluginVersion)
	}
}

func TestHandshakeManagerValidatePluginEnvironment_InvalidMagicCookie(t *testing.T) {
	config := DefaultHandshakeConfig
	logger := NewTestLogger()
	manager := NewHandshakeManager(config, logger)

	// Set up test environment with invalid magic cookie
	oldEnv := os.Environ()
	defer func() {
		for _, envVar := range oldEnv {
			parts := splitEnvVar(envVar)
			if len(parts) == 2 {
				if err := os.Setenv(parts[0], parts[1]); err != nil {
					t.Logf("Warning: failed to restore env var %s: %v", parts[0], err)
				}
			}
		}
	}()

	os.Clearenv()
	if err := os.Setenv(config.MagicCookieKey, "invalid-value"); err != nil {
		t.Fatalf("Failed to set invalid magic cookie: %v", err)
	}

	_, err := manager.ValidatePluginEnvironment()
	if err == nil {
		t.Error("Expected error for invalid magic cookie, got nil")
	}
}

func TestGenerateSecureID(t *testing.T) {
	id1, err := GenerateSecureID()
	if err != nil {
		t.Fatalf("GenerateSecureID failed: %v", err)
	}

	if len(id1) != 32 { // 16 bytes = 32 hex characters
		t.Errorf("Expected ID length 32, got %d", len(id1))
	}

	id2, err := GenerateSecureID()
	if err != nil {
		t.Fatalf("GenerateSecureID failed: %v", err)
	}

	if id1 == id2 {
		t.Error("GenerateSecureID should generate unique IDs")
	}
}

func TestProtocolError(t *testing.T) {
	err := NewProtocolError("version mismatch", 1, 2)
	expected := "protocol error: version mismatch (expected: 1, actual: 2)"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}

	err2 := NewProtocolError("generic error", nil, nil)
	expected2 := "protocol error: generic error"
	if err2.Error() != expected2 {
		t.Errorf("Expected error message '%s', got '%s'", expected2, err2.Error())
	}
}

func TestIsHandshakeTimeoutError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Microsecond)
	defer cancel()

	time.Sleep(time.Millisecond) // Ensure timeout occurs

	if !IsHandshakeTimeoutError(ctx.Err()) {
		t.Error("Expected context deadline exceeded to be identified as handshake timeout")
	}

	if IsHandshakeTimeoutError(nil) {
		t.Error("Expected nil error to not be identified as handshake timeout")
	}
}

// splitEnvVar splits an environment variable string into key and value.
func splitEnvVar(envVar string) []string {
	for i, char := range envVar {
		if char == '=' {
			return []string{envVar[:i], envVar[i+1:]}
		}
	}
	return []string{envVar} // No '=' found
}
