// handshake.go: Standard plugin handshake protocol
//
// This file implements a secure handshake protocol for plugin communication
// to establish communication between host and subprocess plugin, including
// protocol version negotiation and capability discovery.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HandshakeConfig represents the configuration for plugin handshake.
//
// Defines the protocol version and magic cookie
// used to validate that both sides are speaking the same protocol.
type HandshakeConfig struct {
	// ProtocolVersion is the version of the plugin protocol being used.
	// This must match between host and plugin or handshake will fail.
	ProtocolVersion uint

	// MagicCookieKey and MagicCookieValue are used as a basic verification
	// that the plugin is intended to be launched. This is not a security
	// feature, just a UX feature to prevent obvious errors.
	MagicCookieKey   string
	MagicCookieValue string
}

// DefaultHandshakeConfig provides a reasonable default handshake configuration.
var DefaultHandshakeConfig = HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "AGILIRA_PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agilira-go-plugins-v1",
}

// Validate checks if the HandshakeConfig is valid and complete.
func (hc *HandshakeConfig) Validate() error {
	if hc.ProtocolVersion == 0 {
		return NewHandshakeError("protocol version must be greater than 0", nil)
	}

	if hc.MagicCookieKey == "" {
		return NewHandshakeError("magic cookie key is required", nil)
	}

	if hc.MagicCookieValue == "" {
		return NewHandshakeError("magic cookie value is required", nil)
	}

	// Validate magic cookie key format (should be valid environment variable name)
	if !isValidEnvVarName(hc.MagicCookieKey) {
		return NewHandshakeError("magic cookie key must be a valid environment variable name", nil)
	}

	return nil
}

// isValidEnvVarName checks if a string is a valid environment variable name.
// isValidEnvVarName validates environment variable name according to POSIX standards
func isValidEnvVarName(name string) bool {
	if name == "" {
		return false
	}

	// Environment variable names must start with letter or underscore
	// and contain only letters, digits, and underscores
	matched, err := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_]*$`, name)
	if err != nil {
		// This should not happen with our static regex pattern, but handle gracefully
		return false
	}
	return matched
}

// PluginType represents the type of plugin communication protocol.
type PluginType int

const (
	PluginTypeInvalid PluginType = iota
	PluginTypeGRPC               // gRPC protocol (preferred)
)

// String implements fmt.Stringer for PluginType.
func (pt PluginType) String() string {
	switch pt {
	case PluginTypeGRPC:
		return "grpc"
	default:
		return "invalid"
	}
}

// HandshakeInfo contains information exchanged during the handshake process.
type HandshakeInfo struct {
	ProtocolVersion uint       `json:"protocol_version"`
	PluginType      PluginType `json:"plugin_type"`
	ServerAddress   string     `json:"server_address"`
	ServerPort      int        `json:"server_port"`

	// Additional metadata
	PluginName    string            `json:"plugin_name,omitempty"`
	PluginVersion string            `json:"plugin_version,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// HandshakeManager manages the handshake process between host and plugin.
type HandshakeManager struct {
	config HandshakeConfig
	logger Logger
}

// NewHandshakeManager creates a new handshake manager.
func NewHandshakeManager(config HandshakeConfig, logger Logger) *HandshakeManager {
	if logger == nil {
		logger = DefaultLogger()
	}

	return &HandshakeManager{
		config: config,
		logger: logger,
	}
}

// PrepareEnvironment prepares the environment variables for plugin launch.
//
// This sets up the environment variables that the plugin subprocess will
// read to perform the handshake, following industry-standard conventions.
func (hm *HandshakeManager) PrepareEnvironment(info HandshakeInfo) []string {
	env := os.Environ()

	// Add magic cookie for basic validation
	env = append(env, fmt.Sprintf("%s=%s", hm.config.MagicCookieKey, hm.config.MagicCookieValue))

	// Add protocol version
	env = append(env, fmt.Sprintf("PLUGIN_PROTOCOL_VERSION=%d", hm.config.ProtocolVersion))

	// Add server information
	env = append(env, fmt.Sprintf("PLUGIN_SERVER_ADDRESS=%s", info.ServerAddress))
	env = append(env, fmt.Sprintf("PLUGIN_SERVER_PORT=%d", info.ServerPort))

	// Add plugin type
	env = append(env, fmt.Sprintf("PLUGIN_TYPE=%s", info.PluginType.String()))

	// Add optional metadata
	if info.PluginName != "" {
		env = append(env, fmt.Sprintf("PLUGIN_NAME=%s", info.PluginName))
	}
	if info.PluginVersion != "" {
		env = append(env, fmt.Sprintf("PLUGIN_VERSION=%s", info.PluginVersion))
	}

	hm.logger.Debug("Prepared plugin environment",
		"magic_cookie", hm.config.MagicCookieKey,
		"protocol_version", hm.config.ProtocolVersion,
		"server_address", info.ServerAddress,
		"server_port", info.ServerPort,
		"plugin_type", info.PluginType.String())

	return env
}

// ValidatePluginEnvironment validates that the current process has the
// expected environment variables for a plugin (called from plugin side).
func (hm *HandshakeManager) ValidatePluginEnvironment() (*HandshakeInfo, error) {
	if err := hm.validateMagicCookie(); err != nil {
		return nil, err
	}

	version, err := hm.validateProtocolVersion()
	if err != nil {
		return nil, err
	}

	address, port, err := hm.validateServerInfo()
	if err != nil {
		return nil, err
	}

	pluginType, err := hm.validatePluginType()
	if err != nil {
		return nil, err
	}

	info := &HandshakeInfo{
		ProtocolVersion: version,
		PluginType:      pluginType,
		ServerAddress:   address,
		ServerPort:      port,
		PluginName:      os.Getenv("PLUGIN_NAME"),
		PluginVersion:   os.Getenv("PLUGIN_VERSION"),
	}

	hm.logValidationSuccess(info)
	return info, nil
}

// validateMagicCookie validates the magic cookie from environment
func (hm *HandshakeManager) validateMagicCookie() error {
	cookieValue := os.Getenv(hm.config.MagicCookieKey)
	if cookieValue != hm.config.MagicCookieValue {
		return NewHandshakeError(fmt.Sprintf("invalid magic cookie: expected %s, got %s",
			hm.config.MagicCookieValue, cookieValue), nil)
	}
	return nil
}

// validateProtocolVersion validates and parses the protocol version
func (hm *HandshakeManager) validateProtocolVersion() (uint, error) {
	versionStr := os.Getenv("PLUGIN_PROTOCOL_VERSION")
	if versionStr == "" {
		return 0, NewHandshakeError("missing PLUGIN_PROTOCOL_VERSION environment variable", nil)
	}

	version, err := strconv.ParseUint(versionStr, 10, 32)
	if err != nil {
		return 0, NewHandshakeError("invalid protocol version", err)
	}

	if uint(version) != hm.config.ProtocolVersion {
		return 0, NewHandshakeError(fmt.Sprintf("protocol version mismatch: expected %d, got %d",
			hm.config.ProtocolVersion, version), nil)
	}

	return uint(version), nil
}

// validateServerInfo validates and parses server address and port
func (hm *HandshakeManager) validateServerInfo() (string, int, error) {
	address := os.Getenv("PLUGIN_SERVER_ADDRESS")
	if address == "" {
		return "", 0, NewHandshakeError("missing PLUGIN_SERVER_ADDRESS environment variable", nil)
	}

	portStr := os.Getenv("PLUGIN_SERVER_PORT")
	if portStr == "" {
		return "", 0, NewHandshakeError("missing PLUGIN_SERVER_PORT environment variable", nil)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, NewHandshakeError("invalid server port", err)
	}

	return address, port, nil
}

// validatePluginType validates and parses the plugin type
func (hm *HandshakeManager) validatePluginType() (PluginType, error) {
	pluginTypeStr := os.Getenv("PLUGIN_TYPE")
	switch strings.ToLower(pluginTypeStr) {
	case "grpc":
		return PluginTypeGRPC, nil
	default:
		return PluginType(0), NewHandshakeError(fmt.Sprintf("invalid or missing plugin type: %s", pluginTypeStr), nil)
	}
}

// logValidationSuccess logs successful validation
func (hm *HandshakeManager) logValidationSuccess(info *HandshakeInfo) {
	hm.logger.Info("Plugin environment validated successfully",
		"protocol_version", info.ProtocolVersion,
		"plugin_type", info.PluginType.String(),
		"server_address", info.ServerAddress,
		"server_port", info.ServerPort)
}

// GenerateSecureID generates a cryptographically secure random ID for sessions.
func GenerateSecureID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", NewHandshakeError("failed to generate secure ID", err)
	}
	return hex.EncodeToString(bytes), nil
}

// ProtocolError represents an error in protocol negotiation.
type ProtocolError struct {
	Expected interface{}
	Actual   interface{}
	Message  string
}

// Error implements the error interface.
func (pe *ProtocolError) Error() string {
	if pe.Expected != nil && pe.Actual != nil {
		return fmt.Sprintf("protocol error: %s (expected: %v, actual: %v)",
			pe.Message, pe.Expected, pe.Actual)
	}
	return fmt.Sprintf("protocol error: %s", pe.Message)
}

// NewProtocolError creates a new protocol error.
func NewProtocolError(message string, expected, actual interface{}) *ProtocolError {
	return &ProtocolError{
		Expected: expected,
		Actual:   actual,
		Message:  message,
	}
}

// HandshakeTimeout represents the maximum time allowed for handshake completion.
const HandshakeTimeout = 30 * time.Second

// IsHandshakeTimeoutError checks if an error is a handshake timeout.
func IsHandshakeTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// Check for handshake timeout messages
	errorMsg := err.Error()
	return strings.Contains(errorMsg, "handshake timeout") ||
		strings.Contains(errorMsg, "deadline exceeded") ||
		strings.Contains(errorMsg, "context deadline exceeded") ||
		err == context.DeadlineExceeded
}
