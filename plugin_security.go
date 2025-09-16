// plugin_security.go: Security whitelist system for plugin authorization
//
// This module provides comprehensive plugin security validation using cryptographic
// hashes and authorization whitelists. It integrates with Argus for hot-reload
// configuration monitoring and comprehensive audit trails.
//
// Features:
// - SHA-256 hash validation of plugin binaries/sources
// - JSON/ENV configuration with hot-reload via Argus
// - Comprehensive audit trail for security events
// - Configurable security policies (strict/permissive modes)
// - Integration with existing plugin factory system
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agilira/argus"
)

// SecurityPolicy defines the security enforcement mode
type SecurityPolicy int

const (
	// SecurityPolicyDisabled - No security validation (default for backward compatibility)
	SecurityPolicyDisabled SecurityPolicy = iota
	// SecurityPolicyPermissive - Log violations but allow loading
	SecurityPolicyPermissive
	// SecurityPolicyStrict - Block unauthorized plugin loading
	SecurityPolicyStrict
	// SecurityPolicyAuditOnly - Only audit, no validation or blocking
	SecurityPolicyAuditOnly
)

func (sp SecurityPolicy) String() string {
	switch sp {
	case SecurityPolicyDisabled:
		return "disabled"
	case SecurityPolicyPermissive:
		return "permissive"
	case SecurityPolicyAuditOnly:
		return "audit-only"
	case SecurityPolicyStrict:
		return "strict"
	default:
		return "unknown"
	}
}

// HashAlgorithm defines supported hash algorithms
type HashAlgorithm string

const (
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
	// Future: HashAlgorithmSHA512, HashAlgorithmBLAKE3
)

// PluginHashInfo contains hash and metadata for a plugin
type PluginHashInfo struct {
	// Plugin identification
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`

	// Hash information
	Algorithm HashAlgorithm `json:"algorithm"`
	Hash      string        `json:"hash"`
	FilePath  string        `json:"file_path,omitempty"`

	// Metadata
	Description string                 `json:"description,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// Validation configuration
	AllowedEndpoints []string `json:"allowed_endpoints,omitempty"`
	MaxFileSize      int64    `json:"max_file_size,omitempty"`

	// Timestamps
	AddedAt   time.Time `json:"added_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecurityConfig contains the plugin security configuration
type SecurityConfig struct {
	// Core security settings
	Enabled bool           `json:"enabled" env:"GOPLUGINS_SECURITY_ENABLED"`
	Policy  SecurityPolicy `json:"policy" env:"GOPLUGINS_SECURITY_POLICY"`

	// Whitelist configuration
	WhitelistFile   string        `json:"whitelist_file" env:"GOPLUGINS_WHITELIST_FILE"`
	AutoUpdate      bool          `json:"auto_update" env:"GOPLUGINS_SECURITY_AUTO_UPDATE"`
	HashAlgorithm   HashAlgorithm `json:"hash_algorithm" env:"GOPLUGINS_HASH_ALGORITHM"`
	ValidateOnStart bool          `json:"validate_on_start" env:"GOPLUGINS_VALIDATE_ON_START"`

	// Security constraints
	MaxFileSize    int64    `json:"max_file_size" env:"GOPLUGINS_MAX_FILE_SIZE"`
	AllowedTypes   []string `json:"allowed_types" env:"GOPLUGINS_ALLOWED_TYPES"`
	ForbiddenPaths []string `json:"forbidden_paths" env:"GOPLUGINS_FORBIDDEN_PATHS"`

	// Audit configuration
	AuditConfig SecurityAuditConfig `json:"audit"`

	// Hot-reload settings
	WatchConfig bool          `json:"watch_config" env:"GOPLUGINS_WATCH_CONFIG"`
	ReloadDelay time.Duration `json:"reload_delay" env:"GOPLUGINS_RELOAD_DELAY"`
}

// SecurityAuditConfig contains audit-specific security settings
type SecurityAuditConfig struct {
	Enabled          bool   `json:"enabled" env:"GOPLUGINS_AUDIT_ENABLED"`
	AuditFile        string `json:"audit_file" env:"GOPLUGINS_AUDIT_FILE"`
	LogUnauthorized  bool   `json:"log_unauthorized" env:"GOPLUGINS_LOG_UNAUTHORIZED"`
	LogAuthorized    bool   `json:"log_authorized" env:"GOPLUGINS_LOG_AUTHORIZED"`
	LogConfigChanges bool   `json:"log_config_changes" env:"GOPLUGINS_LOG_CONFIG_CHANGES"`
	IncludeMetadata  bool   `json:"include_metadata" env:"GOPLUGINS_INCLUDE_METADATA"`
}

// PluginWhitelist contains the authorized plugins and their hashes
type PluginWhitelist struct {
	// Configuration metadata
	Version     string    `json:"version"`
	UpdatedAt   time.Time `json:"updated_at"`
	Description string    `json:"description,omitempty"`

	// Security configuration
	DefaultPolicy SecurityPolicy `json:"default_policy"`
	HashAlgorithm HashAlgorithm  `json:"hash_algorithm"`

	// Authorized plugins
	Plugins map[string]PluginHashInfo `json:"plugins"`

	// Global constraints
	GlobalConstraints struct {
		MaxFileSize    int64    `json:"max_file_size,omitempty"`
		AllowedTypes   []string `json:"allowed_types,omitempty"`
		ForbiddenPaths []string `json:"forbidden_paths,omitempty"`
	} `json:"global_constraints,omitempty"`
}

// SecurityValidator handles plugin security validation
type SecurityValidator struct {
	config    SecurityConfig
	whitelist *PluginWhitelist
	logger    Logger

	// Argus integration for hot-reload and audit
	argusIntegration *SecurityArgusIntegration
	auditLogger      *argus.AuditLogger

	// State management
	mutex   sync.RWMutex
	enabled bool
	stats   SecurityStats
}

// SecurityStats tracks security validation statistics
type SecurityStats struct {
	ValidationAttempts int64     `json:"validation_attempts"`
	AuthorizedLoads    int64     `json:"authorized_loads"`
	RejectedLoads      int64     `json:"rejected_loads"`
	ConfigReloads      int64     `json:"config_reloads"`
	HashMismatches     int64     `json:"hash_mismatches"`
	LastValidation     time.Time `json:"last_validation"`
	LastConfigReload   time.Time `json:"last_config_reload"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	Type      string                 `json:"type"`
	Plugin    string                 `json:"plugin"`
	Reason    string                 `json:"reason"`
	Expected  string                 `json:"expected,omitempty"`
	Actual    string                 `json:"actual,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// ValidationResult contains the result of plugin security validation
type ValidationResult struct {
	Authorized bool                `json:"authorized"`
	Policy     SecurityPolicy      `json:"policy"`
	Plugin     PluginHashInfo      `json:"plugin,omitempty"`
	Violations []SecurityViolation `json:"violations,omitempty"`
	Timestamp  time.Time           `json:"timestamp"`
}

// NewSecurityValidator creates a new security validator with the given configuration
func NewSecurityValidator(config SecurityConfig, logger Logger) (*SecurityValidator, error) {
	if logger == nil {
		logger = DefaultLogger()
	}

	// Apply defaults
	if config.HashAlgorithm == "" {
		config.HashAlgorithm = HashAlgorithmSHA256
	}
	if config.ReloadDelay == 0 {
		config.ReloadDelay = 1 * time.Second
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 100 * 1024 * 1024 // 100MB default
	}

	validator := &SecurityValidator{
		config:  config,
		logger:  logger,
		enabled: config.Enabled,
		stats:   SecurityStats{},
	}

	// Initialize Argus integration
	validator.argusIntegration = NewSecurityArgusIntegration(validator, logger)

	// Load initial whitelist if enabled
	if config.Enabled && config.WhitelistFile != "" {
		if err := validator.loadWhitelist(); err != nil {
			return nil, fmt.Errorf("failed to load initial whitelist: %w", err)
		}
	}

	// Setup audit logging
	if config.AuditConfig.Enabled && config.AuditConfig.AuditFile != "" {
		if err := validator.setupAuditLogging(); err != nil {
			logger.Warn("Failed to setup security audit logging", "error", err)
		}
	}

	return validator, nil
}

// setupAuditLogging configures Argus audit logging for security events
func (sv *SecurityValidator) setupAuditLogging() error {
	auditConfig := argus.AuditConfig{
		Enabled:       true,
		OutputFile:    sv.config.AuditConfig.AuditFile,
		MinLevel:      argus.AuditInfo,
		BufferSize:    1000,
		FlushInterval: 5 * time.Second,
		IncludeStack:  false,
	}

	auditor, err := argus.NewAuditLogger(auditConfig)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	sv.auditLogger = auditor
	sv.logger.Info("Security audit logging enabled", "file", sv.config.AuditConfig.AuditFile)
	return nil
}

// Enable activates the security validator
func (sv *SecurityValidator) Enable() error {
	sv.mutex.Lock()
	defer sv.mutex.Unlock()

	if sv.enabled {
		return fmt.Errorf("security validator already enabled")
	}

	// Load whitelist
	if sv.config.WhitelistFile != "" {
		if err := sv.loadWhitelist(); err != nil {
			return fmt.Errorf("failed to load whitelist: %w", err)
		}
	}

	// Setup hot-reload monitoring with Argus if configured
	if sv.config.WatchConfig && sv.config.WhitelistFile != "" {
		auditFile := sv.config.AuditConfig.AuditFile
		if err := sv.argusIntegration.EnableWatchingWithArgus(sv.config.WhitelistFile, auditFile); err != nil {
			sv.logger.Warn("Failed to start Argus config monitoring", "error", err)
		} else {
			sv.logger.Info("Argus-based config monitoring enabled",
				"whitelist", sv.config.WhitelistFile,
				"audit", auditFile)
		}
	}

	sv.enabled = true
	sv.logger.Info("Plugin security validator enabled", "policy", sv.config.Policy.String())

	// Audit the enablement
	sv.auditSecurityEvent("security_validator_enabled", map[string]interface{}{
		"policy":         sv.config.Policy.String(),
		"whitelist_file": sv.config.WhitelistFile,
		"watch_config":   sv.config.WatchConfig,
	})

	return nil
}

// Disable deactivates the security validator
func (sv *SecurityValidator) Disable() error {
	sv.mutex.Lock()
	defer sv.mutex.Unlock()

	if !sv.enabled {
		return fmt.Errorf("security validator already disabled")
	}

	// Stop Argus config monitoring
	if sv.argusIntegration != nil && sv.argusIntegration.IsRunning() {
		if err := sv.argusIntegration.DisableWatching(); err != nil {
			sv.logger.Warn("Failed to stop Argus monitoring", "error", err)
		}
	}

	sv.enabled = false
	sv.logger.Info("Plugin security validator disabled")

	// Audit the disablement
	sv.auditSecurityEvent("security_validator_disabled", map[string]interface{}{
		"final_stats": sv.stats,
	})

	return nil
}

// ValidatePlugin validates a plugin against the security whitelist
func (sv *SecurityValidator) ValidatePlugin(pluginConfig PluginConfig, pluginPath string) (*ValidationResult, error) {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()

	result := &ValidationResult{
		Policy:    sv.config.Policy,
		Timestamp: time.Now(),
	}

	// Update stats
	sv.stats.ValidationAttempts++
	sv.stats.LastValidation = result.Timestamp

	// If disabled, always authorize
	if !sv.enabled || sv.config.Policy == SecurityPolicyDisabled {
		result.Authorized = true
		return result, nil
	}

	// If audit-only mode, always authorize but log
	if sv.config.Policy == SecurityPolicyAuditOnly {
		result.Authorized = true
		sv.auditPluginValidation(pluginConfig, result, nil)
		return result, nil
	}

	// Perform actual validation
	violations, err := sv.performValidation(pluginConfig, pluginPath)
	if err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	result.Violations = violations
	result.Authorized = len(violations) == 0

	// Handle violations based on policy
	if len(violations) > 0 {
		sv.stats.RejectedLoads++

		// In permissive mode, log but allow
		if sv.config.Policy == SecurityPolicyPermissive {
			result.Authorized = true
			sv.logger.Warn("Plugin security violations detected (permissive mode)",
				"plugin", pluginConfig.Name,
				"violations", len(violations))
		} else {
			// Strict mode: reject
			sv.logger.Error("Plugin security validation failed",
				"plugin", pluginConfig.Name,
				"violations", len(violations))
		}
	} else {
		sv.stats.AuthorizedLoads++
	}

	// Audit the validation
	sv.auditPluginValidation(pluginConfig, result, violations)

	return result, nil
}

// performValidation performs the actual security validation checks
func (sv *SecurityValidator) performValidation(pluginConfig PluginConfig, pluginPath string) ([]SecurityViolation, error) {
	var violations []SecurityViolation
	timestamp := time.Now()

	// Check if whitelist is loaded
	if sv.whitelist == nil {
		violations = append(violations, SecurityViolation{
			Type:      "whitelist_not_loaded",
			Plugin:    pluginConfig.Name,
			Reason:    "Security whitelist not loaded",
			Timestamp: timestamp,
		})
		return violations, nil
	}

	// Check if plugin is in whitelist
	whitelistEntry, exists := sv.whitelist.Plugins[pluginConfig.Name]
	if !exists {
		violations = append(violations, SecurityViolation{
			Type:      "plugin_not_whitelisted",
			Plugin:    pluginConfig.Name,
			Reason:    "Plugin not found in security whitelist",
			Timestamp: timestamp,
		})
		return violations, nil
	}

	// Validate hash if file path provided
	if pluginPath != "" {
		if err := sv.validatePluginHash(pluginPath, whitelistEntry, &violations, timestamp); err != nil {
			return violations, fmt.Errorf("hash validation error: %w", err)
		}
	}

	// Validate plugin type
	if whitelistEntry.Type != "" && whitelistEntry.Type != pluginConfig.Type {
		violations = append(violations, SecurityViolation{
			Type:      "type_mismatch",
			Plugin:    pluginConfig.Name,
			Reason:    "Plugin type does not match whitelist",
			Expected:  whitelistEntry.Type,
			Actual:    pluginConfig.Type,
			Timestamp: timestamp,
		})
	}

	// Validate file size constraints
	if pluginPath != "" && (whitelistEntry.MaxFileSize > 0 || sv.config.MaxFileSize > 0) {
		if err := sv.validateFileSize(pluginPath, whitelistEntry, &violations, timestamp); err != nil {
			return violations, fmt.Errorf("file size validation error: %w", err)
		}
	}

	// Validate allowed endpoints
	if len(whitelistEntry.AllowedEndpoints) > 0 {
		if err := sv.validateEndpoints(pluginConfig, whitelistEntry, &violations, timestamp); err != nil {
			return violations, fmt.Errorf("endpoint validation error: %w", err)
		}
	}

	return violations, nil
}

// validatePluginHash validates the plugin file hash against the whitelist
func (sv *SecurityValidator) validatePluginHash(pluginPath string, entry PluginHashInfo, violations *[]SecurityViolation, timestamp time.Time) error {
	// Calculate actual hash
	actualHash, err := sv.calculateFileHash(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Compare with expected hash
	if actualHash != entry.Hash {
		sv.stats.HashMismatches++
		*violations = append(*violations, SecurityViolation{
			Type:      "hash_mismatch",
			Plugin:    entry.Name,
			Reason:    "Plugin file hash does not match whitelist",
			Expected:  entry.Hash,
			Actual:    actualHash,
			Timestamp: timestamp,
			Context: map[string]interface{}{
				"file_path": pluginPath,
				"algorithm": string(entry.Algorithm),
			},
		})
	}

	return nil
}

// validateFileSize validates the plugin file size
func (sv *SecurityValidator) validateFileSize(pluginPath string, entry PluginHashInfo, violations *[]SecurityViolation, timestamp time.Time) error {
	stat, err := os.Stat(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	fileSize := stat.Size()
	maxSize := entry.MaxFileSize
	if maxSize == 0 {
		maxSize = sv.config.MaxFileSize
	}

	if maxSize > 0 && fileSize > maxSize {
		*violations = append(*violations, SecurityViolation{
			Type:      "file_size_exceeded",
			Plugin:    entry.Name,
			Reason:    fmt.Sprintf("Plugin file size (%d bytes) exceeds maximum allowed (%d bytes)", fileSize, maxSize),
			Expected:  fmt.Sprintf("%d", maxSize),
			Actual:    fmt.Sprintf("%d", fileSize),
			Timestamp: timestamp,
			Context: map[string]interface{}{
				"file_path": pluginPath,
				"file_size": fileSize,
				"max_size":  maxSize,
			},
		})
	}

	return nil
}

// validateEndpoints validates plugin endpoints against whitelist
func (sv *SecurityValidator) validateEndpoints(pluginConfig PluginConfig, entry PluginHashInfo, violations *[]SecurityViolation, timestamp time.Time) error {
	if pluginConfig.Endpoint == "" || len(entry.AllowedEndpoints) == 0 {
		return nil
	}

	// Check if endpoint is in allowed list
	allowed := false
	for _, allowedEndpoint := range entry.AllowedEndpoints {
		if pluginConfig.Endpoint == allowedEndpoint {
			allowed = true
			break
		}
	}

	if !allowed {
		*violations = append(*violations, SecurityViolation{
			Type:      "endpoint_not_allowed",
			Plugin:    entry.Name,
			Reason:    "Plugin endpoint not in allowed endpoints list",
			Expected:  fmt.Sprintf("one of: %v", entry.AllowedEndpoints),
			Actual:    pluginConfig.Endpoint,
			Timestamp: timestamp,
			Context: map[string]interface{}{
				"endpoint":          pluginConfig.Endpoint,
				"allowed_endpoints": entry.AllowedEndpoints,
			},
		})
	}

	return nil
}

// calculateFileHash calculates the hash of a file using the configured algorithm
func (sv *SecurityValidator) calculateFileHash(filePath string) (string, error) {
	// Validate file path to prevent directory traversal attacks
	cleanPath := filepath.Clean(filePath)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid file path: %s", filePath)
	}

	file, err := os.Open(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }() // Ignore close error

	switch sv.config.HashAlgorithm {
	case HashAlgorithmSHA256:
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", fmt.Errorf("failed to hash file: %w", err)
		}
		return hex.EncodeToString(hasher.Sum(nil)), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", sv.config.HashAlgorithm)
	}
}

// loadWhitelist loads the plugin whitelist from the configured file
func (sv *SecurityValidator) loadWhitelist() error {
	if sv.config.WhitelistFile == "" {
		return fmt.Errorf("whitelist file path not configured")
	}

	data, err := os.ReadFile(sv.config.WhitelistFile)
	if err != nil {
		return fmt.Errorf("failed to read whitelist file: %w", err)
	}

	var whitelist PluginWhitelist
	if err := json.Unmarshal(data, &whitelist); err != nil {
		return fmt.Errorf("failed to parse whitelist JSON: %w", err)
	}

	// Validate whitelist structure
	if err := sv.validateWhitelistStructure(&whitelist); err != nil {
		return fmt.Errorf("invalid whitelist structure: %w", err)
	}

	sv.whitelist = &whitelist
	sv.stats.ConfigReloads++
	sv.stats.LastConfigReload = time.Now()

	sv.logger.Info("Plugin whitelist loaded",
		"file", sv.config.WhitelistFile,
		"plugins", len(whitelist.Plugins),
		"version", whitelist.Version)

	return nil
}

// validateWhitelistStructure validates the loaded whitelist
func (sv *SecurityValidator) validateWhitelistStructure(whitelist *PluginWhitelist) error {
	if whitelist.Plugins == nil {
		return fmt.Errorf("whitelist must contain plugins map")
	}

	if whitelist.HashAlgorithm == "" {
		whitelist.HashAlgorithm = HashAlgorithmSHA256
	}

	// Validate individual plugin entries
	for name, plugin := range whitelist.Plugins {
		if plugin.Name != name {
			return fmt.Errorf("plugin name mismatch: key %s != plugin.name %s", name, plugin.Name)
		}
		if plugin.Hash == "" {
			return fmt.Errorf("plugin %s missing hash", name)
		}
		if plugin.Algorithm == "" {
			plugin.Algorithm = whitelist.HashAlgorithm
		}
	}

	return nil
}

// auditSecurityEvent logs a security event to the audit trail
func (sv *SecurityValidator) auditSecurityEvent(event string, context map[string]interface{}) {
	if sv.auditLogger == nil || !sv.config.AuditConfig.Enabled {
		return
	}

	// LogSecurityEvent expects (event, description, context)
	sv.auditLogger.LogSecurityEvent(event, "Plugin security validation event", context)
}

// auditPluginValidation logs plugin validation results
func (sv *SecurityValidator) auditPluginValidation(pluginConfig PluginConfig, result *ValidationResult, violations []SecurityViolation) {
	if !sv.config.AuditConfig.Enabled {
		return
	}

	// Log authorized loads if configured
	if result.Authorized && !sv.config.AuditConfig.LogAuthorized {
		return
	}

	// Log unauthorized loads if configured
	if !result.Authorized && !sv.config.AuditConfig.LogUnauthorized {
		return
	}

	context := map[string]interface{}{
		"plugin_name": pluginConfig.Name,
		"plugin_type": pluginConfig.Type,
		"authorized":  result.Authorized,
		"policy":      result.Policy.String(),
		"violations":  len(violations),
	}

	if sv.config.AuditConfig.IncludeMetadata {
		context["plugin_config"] = pluginConfig
		context["validation_result"] = result
	}

	eventType := "plugin_authorized"
	if !result.Authorized {
		eventType = "plugin_rejected"
	}

	sv.auditSecurityEvent(eventType, context)
}

// GetStats returns current security validation statistics
func (sv *SecurityValidator) GetStats() SecurityStats {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()
	return sv.stats
}

// IsEnabled returns whether the security validator is currently enabled
func (sv *SecurityValidator) IsEnabled() bool {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()
	return sv.enabled
}

// GetConfig returns a copy of the current configuration
func (sv *SecurityValidator) GetConfig() SecurityConfig {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()
	return sv.config
}

// GetWhitelistInfo returns information about the current whitelist
func (sv *SecurityValidator) GetWhitelistInfo() map[string]interface{} {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()

	if sv.whitelist == nil {
		return map[string]interface{}{
			"loaded": false,
		}
	}

	return map[string]interface{}{
		"loaded":         true,
		"version":        sv.whitelist.Version,
		"plugin_count":   len(sv.whitelist.Plugins),
		"updated_at":     sv.whitelist.UpdatedAt,
		"hash_algorithm": sv.whitelist.HashAlgorithm,
	}
}

// ReloadWhitelist manually reloads the whitelist from file
func (sv *SecurityValidator) ReloadWhitelist() error {
	sv.mutex.Lock()
	defer sv.mutex.Unlock()

	if !sv.enabled {
		return fmt.Errorf("security validator not enabled")
	}

	if err := sv.loadWhitelist(); err != nil {
		return fmt.Errorf("failed to reload whitelist: %w", err)
	}

	sv.auditSecurityEvent("whitelist_reloaded", map[string]interface{}{
		"file":    sv.config.WhitelistFile,
		"plugins": len(sv.whitelist.Plugins),
	})

	return nil
}

// UpdateConfig updates the security configuration (requires restart for some changes)
func (sv *SecurityValidator) UpdateConfig(newConfig SecurityConfig) error {
	sv.mutex.Lock()
	defer sv.mutex.Unlock()

	oldConfig := sv.config
	sv.config = newConfig

	// Restart monitoring if whitelist file changed
	// Restart monitoring if whitelist file changed
	if oldConfig.WhitelistFile != newConfig.WhitelistFile {
		if sv.argusIntegration.IsRunning() {
			_ = sv.argusIntegration.DisableWatching() // Ignore error during config update
		}
		if newConfig.WatchConfig && newConfig.WhitelistFile != "" {
			if err := sv.argusIntegration.EnableWatchingWithArgus(newConfig.WhitelistFile, newConfig.AuditConfig.AuditFile); err != nil {
				sv.logger.Warn("Failed to restart Argus config monitoring", "error", err)
			}
		}
	}

	sv.auditSecurityEvent("config_updated", map[string]interface{}{
		"old_policy": oldConfig.Policy.String(),
		"new_policy": newConfig.Policy.String(),
		"old_file":   oldConfig.WhitelistFile,
		"new_file":   newConfig.WhitelistFile,
	})

	return nil
}

// DefaultSecurityConfig returns a secure default configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Enabled:         false, // Disabled by default for backward compatibility
		Policy:          SecurityPolicyDisabled,
		HashAlgorithm:   HashAlgorithmSHA256,
		ValidateOnStart: true,
		AutoUpdate:      false,
		MaxFileSize:     100 * 1024 * 1024, // 100MB
		WatchConfig:     true,
		ReloadDelay:     1 * time.Second,
		AuditConfig: SecurityAuditConfig{
			Enabled:          false,
			LogUnauthorized:  true,
			LogAuthorized:    false,
			LogConfigChanges: true,
			IncludeMetadata:  false,
		},
	}
}

// CreateSampleWhitelist creates a sample whitelist file for testing/documentation
func CreateSampleWhitelist(filePath string) error {
	sample := PluginWhitelist{
		Version:       "1.0.0",
		UpdatedAt:     time.Now(),
		Description:   "Sample plugin security whitelist",
		DefaultPolicy: SecurityPolicyStrict,
		HashAlgorithm: HashAlgorithmSHA256,
		Plugins: map[string]PluginHashInfo{
			"auth-service": {
				Name:        "auth-service",
				Type:        "http",
				Version:     "1.2.0",
				Algorithm:   HashAlgorithmSHA256,
				Hash:        "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab",
				Description: "Authentication service plugin",
				AllowedEndpoints: []string{
					"https://auth.example.com",
					"https://auth-staging.example.com",
				},
				MaxFileSize: 50 * 1024 * 1024, // 50MB
				AddedAt:     time.Now(),
				UpdatedAt:   time.Now(),
			},
			"logging-plugin": {
				Name:        "logging-plugin",
				Type:        "grpc",
				Version:     "2.1.0",
				Algorithm:   HashAlgorithmSHA256,
				Hash:        "b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
				Description: "Centralized logging plugin",
				AllowedEndpoints: []string{
					"grpc://logs.example.com:9090",
				},
				MaxFileSize: 25 * 1024 * 1024, // 25MB
				AddedAt:     time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
		GlobalConstraints: struct {
			MaxFileSize    int64    `json:"max_file_size,omitempty"`
			AllowedTypes   []string `json:"allowed_types,omitempty"`
			ForbiddenPaths []string `json:"forbidden_paths,omitempty"`
		}{
			MaxFileSize:  100 * 1024 * 1024, // 100MB
			AllowedTypes: []string{"http", "grpc", "https"},
			ForbiddenPaths: []string{
				"/tmp",
				"/var/tmp",
				"~/.ssh",
			},
		},
	}

	data, err := json.MarshalIndent(sample, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sample whitelist: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write sample whitelist: %w", err)
	}

	return nil
}

// LoadSecurityConfigFromEnv loads security configuration from environment variables
// Essential for cloud environments and container deployments
func LoadSecurityConfigFromEnv() (*SecurityConfig, error) {
	config := &SecurityConfig{
		Policy:        SecurityPolicyDisabled,
		HashAlgorithm: HashAlgorithmSHA256,
	}

	// Core security settings
	if enabled := os.Getenv("GOPLUGINS_SECURITY_ENABLED"); enabled != "" {
		config.Enabled = parseBool(enabled)
	}

	if policy := os.Getenv("GOPLUGINS_SECURITY_POLICY"); policy != "" {
		switch strings.ToLower(strings.TrimSpace(policy)) {
		case "strict":
			config.Policy = SecurityPolicyStrict
		case "permissive":
			config.Policy = SecurityPolicyPermissive
		case "audit-only":
			config.Policy = SecurityPolicyAuditOnly
		}
	}

	if whitelistFile := os.Getenv("GOPLUGINS_WHITELIST_FILE"); whitelistFile != "" {
		config.WhitelistFile = whitelistFile
	}

	return config, nil
}

// parseBool parses boolean values from environment variables
// Supports: true/false, 1/0, yes/no, on/off, enabled/disabled
func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}
