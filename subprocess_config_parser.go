// subprocess_config_parser.go: Configuration parsing and validation for subprocess plugins
//
// This component handles parsing, validation, and preparation of subprocess
// plugin configurations, separating configuration concerns from the main plugin logic.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
	"os"
	"strings"
)

// ConfigParser handles parsing and validation of subprocess plugin configurations.
//
// Responsibilities:
// - Parsing arguments from multiple sources
// - Parsing environment variables from multiple sources
// - Validating executable paths and security
// - Preparing environment for handshake
type ConfigParser struct {
	logger Logger
}

// ParsedConfig contains the parsed and validated configuration.
type ParsedConfig struct {
	ExecutablePath string
	Args           []string
	Env            []string
}

// NewConfigParser creates a new configuration parser.
func NewConfigParser(logger Logger) *ConfigParser {
	if logger == nil {
		logger = DefaultLogger()
	}

	return &ConfigParser{
		logger: logger,
	}
}

// ParseConfig parses and validates a plugin configuration.
func (cp *ConfigParser) ParseConfig(config PluginConfig) (*ParsedConfig, error) {
	parsed := &ParsedConfig{
		ExecutablePath: config.Endpoint,
		Args:           cp.parseArgs(config),
		Env:            cp.parseEnv(config),
	}

	if err := cp.validateConfig(parsed); err != nil {
		return nil, err
	}

	return parsed, nil
}

// parseArgs extracts command line arguments from plugin config.
//
// Arguments can be specified in several ways:
// 1. config.Args (direct field)
// 2. config.Options["args"] as []string
// 3. config.Annotations["args"] as comma-separated string
func (cp *ConfigParser) parseArgs(config PluginConfig) []string {
	// Use config.Args field first (direct approach)
	if len(config.Args) > 0 {
		return config.Args
	}

	// Try config.Options["args"]
	if args, ok := config.Options["args"].([]string); ok {
		return args
	}

	// Try config.Annotations["args"] as comma-separated string
	if argsStr, ok := config.Annotations["args"]; ok && argsStr != "" {
		var result []string
		for _, arg := range strings.Split(argsStr, ",") {
			if trimmed := strings.TrimSpace(arg); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}

	return []string{}
}

// parseEnv extracts environment variables from plugin config.
//
// Environment variables can be specified in several ways:
// 1. config.Env (direct field)
// 2. config.Options["env"] as []string in "KEY=VALUE" format
// 3. config.Options["environment"] as map[string]string
// 4. config.Annotations with "env_" prefix (e.g., "env_DEBUG=1")
func (cp *ConfigParser) parseEnv(config PluginConfig) []string {
	var result []string

	// Use config.Env field first (direct approach)
	if len(config.Env) > 0 {
		result = append(result, config.Env...)
	}

	// Try config.Options["env"] as []string
	if env, ok := config.Options["env"].([]string); ok {
		result = append(result, env...)
	}

	// Try config.Options["environment"] as map[string]string
	if envMap, ok := config.Options["environment"].(map[string]string); ok {
		for key, value := range envMap {
			result = append(result, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Try config.Annotations with "env_" prefix
	for key, value := range config.Annotations {
		if strings.HasPrefix(key, "env_") && value != "" {
			envKey := strings.TrimPrefix(key, "env_")
			if envKey != "" {
				result = append(result, fmt.Sprintf("%s=%s", envKey, value))
			}
		}
	}

	return result
}

// validateConfig performs security and correctness validation on the parsed config.
func (cp *ConfigParser) validateConfig(config *ParsedConfig) error {
	return cp.validateExecutablePath(config.ExecutablePath, config.Args)
}

// validateExecutablePath validates the executable path to prevent command injection.
func (cp *ConfigParser) validateExecutablePath(executablePath string, args []string) error {
	if executablePath == "" {
		return NewConfigPathError("", "executable path is empty")
	}

	// Check if the path contains potentially dangerous characters
	if strings.Contains(executablePath, "..") {
		return NewPathTraversalError("executable path contains path traversal characters")
	}

	// Ensure the file exists and is executable
	if _, err := os.Stat(executablePath); err != nil {
		return NewConfigFileError("", "executable not found", err)
	}

	// Validate arguments for basic injection prevention
	for _, arg := range args {
		if strings.Contains(arg, ";") || strings.Contains(arg, "&") || strings.Contains(arg, "|") {
			return NewConfigValidationError(fmt.Sprintf("argument contains potentially dangerous characters: %s", arg), nil)
		}
	}

	return nil
}

// PrepareHandshakeEnvironment prepares environment variables for handshake.
func (cp *ConfigParser) PrepareHandshakeEnvironment(config *ParsedConfig, handshakeInfo HandshakeInfo, handshakeManager *HandshakeManager) []string {
	// Start with handshake environment
	pluginEnv := handshakeManager.PrepareEnvironment(handshakeInfo)

	// Add custom environment variables
	if len(config.Env) > 0 {
		pluginEnv = append(pluginEnv, config.Env...)
	}

	return pluginEnv
}
