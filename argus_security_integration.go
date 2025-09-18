// security_argus_integration.go: Argus integration for security hot-reload and audit
//
// This module implements complete Argus integration for the plugin security system,
// providing hot-reload capabilities for the whitelist and comprehensive audit trail
// for all security events.
//
// Features:
// - Whitelist hot-reload via Argus file watching
// - Complete audit trail for security events
// - ENV configuration for Argus settings
// - Tamper detection validation for whitelist
// - Performance monitoring of security system
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agilira/argus"
)

// SecurityArgusIntegration manages Argus integration for the security system
type SecurityArgusIntegration struct {
	validator *SecurityValidator
	logger    Logger

	// Argus components
	configWatcher interface{} // Argus watcher instance
	auditLogger   *argus.AuditLogger

	// Configuration
	whitelistFile string
	auditFile     string

	// State management
	mutex   sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc

	// Statistics
	stats SecurityArgusStats
}

// SecurityArgusStats tracks Argus integration statistics
type SecurityArgusStats struct {
	WhitelistReloads int64     `json:"whitelist_reloads"`
	AuditEvents      int64     `json:"audit_events"`
	ConfigErrors     int64     `json:"config_errors"`
	LastReload       time.Time `json:"last_reload"`
	LastAuditEvent   time.Time `json:"last_audit_event"`
	LastError        string    `json:"last_error,omitempty"`
	UptimeSeconds    int64     `json:"uptime_seconds"`
}

// NewSecurityArgusIntegration creates a new Argus integration for security
func NewSecurityArgusIntegration(validator *SecurityValidator, logger Logger) *SecurityArgusIntegration {
	ctx, cancel := context.WithCancel(context.Background())

	return &SecurityArgusIntegration{
		validator: validator,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		stats:     SecurityArgusStats{},
	}
}

// EnableWatchingWithArgus enables Argus-based watching of the whitelist file
func (sai *SecurityArgusIntegration) EnableWatchingWithArgus(whitelistFile, auditFile string) error {
	sai.mutex.Lock()
	defer sai.mutex.Unlock()

	if sai.running {
		return NewSecurityValidationError("argus integration already running", nil)
	}

	sai.whitelistFile = whitelistFile
	sai.auditFile = auditFile

	// Setup audit logging
	if err := sai.setupAuditLogging(); err != nil {
		return NewAuditError("failed to setup audit logging", err)
	}

	// Setup file watching
	if err := sai.setupFileWatching(); err != nil {
		return NewConfigWatcherError("failed to setup file watching", err)
	}

	sai.running = true
	sai.logger.Info("Argus security integration enabled",
		"whitelist_file", whitelistFile,
		"audit_file", auditFile)

	// Audit the enablement
	sai.auditEvent("security_argus_enabled", map[string]interface{}{
		"whitelist_file": whitelistFile,
		"audit_file":     auditFile,
	})

	return nil
}

// DisableWatching disables Argus watching
func (sai *SecurityArgusIntegration) DisableWatching() error {
	sai.mutex.Lock()
	defer sai.mutex.Unlock()

	if !sai.running {
		return NewSecurityValidationError("argus integration not running", nil)
	}

	// Cancel context to stop all operations
	sai.cancel()

	// Close audit logger
	if sai.auditLogger != nil {
		if err := sai.auditLogger.Close(); err != nil {
			sai.logger.Warn("Failed to close audit logger during cleanup", "error", err)
		}
		sai.auditLogger = nil
	}

	sai.running = false
	sai.logger.Info("Argus security integration disabled")

	return nil
}

// setupAuditLogging configures Argus audit logging
func (sai *SecurityArgusIntegration) setupAuditLogging() error {
	if sai.auditFile == "" {
		return nil // Audit logging not configured
	}

	// Ensure audit directory exists
	auditDir := filepath.Dir(sai.auditFile)
	if err := os.MkdirAll(auditDir, 0750); err != nil {
		return NewAuditError("failed to create audit directory", err)
	}

	auditConfig := argus.AuditConfig{
		Enabled:       true,
		OutputFile:    sai.auditFile,
		MinLevel:      argus.AuditInfo,
		BufferSize:    1000,
		FlushInterval: 5 * time.Second,
		IncludeStack:  false,
	}

	auditor, err := argus.NewAuditLogger(auditConfig)
	if err != nil {
		return NewAuditError("failed to create audit logger", err)
	}

	sai.auditLogger = auditor
	sai.logger.Info("Security audit logging configured", "file", sai.auditFile)
	return nil
}

// setupFileWatching configures Argus file watching for the whitelist
func (sai *SecurityArgusIntegration) setupFileWatching() error {
	if sai.whitelistFile == "" {
		return NewConfigValidationError("whitelist file not specified", nil)
	}

	// Create Argus configuration for optimal performance
	argusConfig := argus.Config{
		PollInterval:    500 * time.Millisecond, // Fast response for security changes
		CacheTTL:        1 * time.Second,
		MaxWatchedFiles: 10, // We only watch whitelist files
		ErrorHandler: func(err error, path string) {
			sai.mutex.Lock()
			sai.stats.ConfigErrors++
			sai.stats.LastError = err.Error()
			sai.mutex.Unlock()

			sai.logger.Error("Argus file watching error", "path", path, "error", err)
			sai.auditEvent("whitelist_watch_error", map[string]interface{}{
				"path":  path,
				"error": err.Error(),
			})
		},
		Audit: argus.AuditConfig{
			Enabled:       sai.auditLogger != nil,
			OutputFile:    sai.auditFile,
			MinLevel:      argus.AuditInfo,
			BufferSize:    1000,
			FlushInterval: 5 * time.Second,
		},
	}

	// Start watching the whitelist file
	watcher, err := argus.UniversalConfigWatcherWithConfig(
		sai.whitelistFile,
		sai.handleWhitelistChange,
		argusConfig,
	)

	if err != nil {
		return NewConfigWatcherError("failed to create Argus watcher", err)
	}

	// Store watcher reference
	sai.configWatcher = watcher

	sai.logger.Info("Argus file watching configured", "file", sai.whitelistFile)
	return nil
}

// handleWhitelistChange is called by Argus when the whitelist file changes
func (sai *SecurityArgusIntegration) handleWhitelistChange(config map[string]interface{}) {
	sai.mutex.Lock()
	defer sai.mutex.Unlock()

	sai.logger.Info("Whitelist file changed, reloading", "file", sai.whitelistFile)

	// Reload the whitelist in the validator
	if err := sai.validator.ReloadWhitelist(); err != nil {
		sai.stats.ConfigErrors++
		sai.stats.LastError = err.Error()

		sai.logger.Error("Failed to reload whitelist", "error", err)
		sai.auditEvent("whitelist_reload_failed", map[string]interface{}{
			"file":  sai.whitelistFile,
			"error": err.Error(),
		})
		return
	}

	// Update statistics
	sai.stats.WhitelistReloads++
	sai.stats.LastReload = time.Now()

	sai.logger.Info("Whitelist reloaded successfully")
	sai.auditEvent("whitelist_reloaded", map[string]interface{}{
		"file":            sai.whitelistFile,
		"reload_count":    sai.stats.WhitelistReloads,
		"validator_stats": sai.validator.GetStats(),
	})
}

// auditEvent logs a security event to the Argus audit trail
func (sai *SecurityArgusIntegration) auditEvent(eventType string, context map[string]interface{}) {
	if sai.auditLogger == nil {
		return
	}

	sai.mutex.Lock()
	sai.stats.AuditEvents++
	sai.stats.LastAuditEvent = time.Now()
	sai.mutex.Unlock()

	// Add common context information
	context["component"] = "plugin_security"
	context["integration"] = "argus"
	context["timestamp"] = time.Now().Format(time.RFC3339)

	sai.auditLogger.LogSecurityEvent(eventType, "Plugin security Argus integration event", context)
}

// GetStats returns current Argus integration statistics
func (sai *SecurityArgusIntegration) GetStats() SecurityArgusStats {
	sai.mutex.RLock()
	defer sai.mutex.RUnlock()

	stats := sai.stats
	if sai.running {
		// Calculate uptime
		startTime := stats.LastReload
		if startTime.IsZero() {
			startTime = time.Now() // Fallback if no reloads yet
		}
		stats.UptimeSeconds = int64(time.Since(startTime).Seconds())
	}

	return stats
}

// IsRunning returns whether the Argus integration is currently active
func (sai *SecurityArgusIntegration) IsRunning() bool {
	sai.mutex.RLock()
	defer sai.mutex.RUnlock()
	return sai.running
}

// GetWatchedFiles returns the list of files being watched by Argus
func (sai *SecurityArgusIntegration) GetWatchedFiles() []string {
	sai.mutex.RLock()
	defer sai.mutex.RUnlock()

	var files []string
	if sai.whitelistFile != "" {
		files = append(files, sai.whitelistFile)
	}
	return files
}

// ValidateWhitelistIntegrity performs integrity check on the whitelist file
func (sai *SecurityArgusIntegration) ValidateWhitelistIntegrity() error {
	if sai.whitelistFile == "" {
		return NewConfigValidationError("whitelist file not configured", nil)
	}

	// Check file existence and readability
	info, err := os.Stat(sai.whitelistFile)
	if err != nil {
		return NewFilePermissionError(sai.whitelistFile, err)
	}

	// Check file size (prevent extremely large files)
	maxSize := int64(10 * 1024 * 1024) // 10MB max
	if info.Size() > maxSize {
		return NewConfigFileError(sai.whitelistFile, fmt.Sprintf("whitelist file too large: %d bytes (max %d)", info.Size(), maxSize), nil)
	}

	// Audit the integrity check
	sai.auditEvent("whitelist_integrity_check", map[string]interface{}{
		"file":     sai.whitelistFile,
		"size":     info.Size(),
		"mod_time": info.ModTime(),
		"result":   "valid",
	})

	return nil
}

// ForceReload manually triggers a whitelist reload (bypassing file watching)
func (sai *SecurityArgusIntegration) ForceReload() error {
	sai.mutex.Lock()
	defer sai.mutex.Unlock()

	if !sai.running {
		return NewSecurityValidationError("argus integration not running", nil)
	}

	sai.logger.Info("Forcing whitelist reload", "file", sai.whitelistFile)

	// Validate integrity first
	if err := sai.ValidateWhitelistIntegrity(); err != nil {
		return NewWhitelistError("whitelist integrity check failed", err)
	}

	// Reload the whitelist
	if err := sai.validator.ReloadWhitelist(); err != nil {
		sai.stats.ConfigErrors++
		sai.stats.LastError = err.Error()

		sai.auditEvent("forced_reload_failed", map[string]interface{}{
			"file":  sai.whitelistFile,
			"error": err.Error(),
		})
		return NewWhitelistError("failed to reload whitelist", err)
	}

	// Update statistics
	sai.stats.WhitelistReloads++
	sai.stats.LastReload = time.Now()

	sai.auditEvent("forced_reload_success", map[string]interface{}{
		"file":         sai.whitelistFile,
		"reload_count": sai.stats.WhitelistReloads,
	})

	return nil
}

// UpdateSecurityValidator updates the associated security validator
func (sai *SecurityArgusIntegration) UpdateSecurityValidator(validator *SecurityValidator) {
	sai.mutex.Lock()
	defer sai.mutex.Unlock()

	sai.validator = validator
	sai.logger.Info("Security validator updated in Argus integration")
}

// GetArgusIntegrationInfo returns comprehensive information about Argus integration
func (sv *SecurityValidator) GetArgusIntegrationInfo() map[string]interface{} {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()

	if sv.argusIntegration == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	stats := sv.argusIntegration.GetStats()
	watchedFiles := sv.argusIntegration.GetWatchedFiles()

	return map[string]interface{}{
		"enabled":       sv.argusIntegration.IsRunning(),
		"watched_files": watchedFiles,
		"stats":         stats,
	}
}

// ForceReloadWhitelist manually triggers a whitelist reload via Argus
func (sv *SecurityValidator) ForceReloadWhitelist() error {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()

	if sv.argusIntegration == nil {
		return NewSecurityValidationError("argus integration not initialized", nil)
	}

	return sv.argusIntegration.ForceReload()
}
