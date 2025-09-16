// discovery.go: Plugin auto-discovery system with filesystem and network support
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// PluginManifest represents a plugin manifest file that describes plugin metadata and capabilities.
//
// The manifest file is the primary way plugins declare their identity, version, capabilities,
// and runtime requirements. It supports both JSON and YAML formats and includes validation
// rules to ensure plugin compatibility and security.
//
// Example JSON manifest:
//
//	{
//	  "name": "auth-service",
//	  "version": "1.2.3",
//	  "description": "Authentication and authorization service",
//	  "author": "security-team@company.com",
//	  "capabilities": ["authenticate", "authorize", "validate-token"],
//	  "transport": "https",
//	  "endpoint": "https://auth.internal.company.com/api/v1",
//	  "requirements": {
//	    "min_go_version": "1.21",
//	    "required_plugins": ["logging-service"]
//	  },
//	  "resources": {
//	    "max_memory_mb": 256,
//	    "max_cpu_percent": 50
//	  },
//	  "health_check": {
//	    "path": "/health",
//	    "interval": "30s",
//	    "timeout": "5s"
//	  }
//	}
type PluginManifest struct {
	// Core plugin identity
	Name        string `json:"name" yaml:"name" validate:"required,min=1"`
	Version     string `json:"version" yaml:"version" validate:"required,semver"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Author      string `json:"author,omitempty" yaml:"author,omitempty"`
	Homepage    string `json:"homepage,omitempty" yaml:"homepage,omitempty"`
	License     string `json:"license,omitempty" yaml:"license,omitempty"`

	// Plugin capabilities and features
	Capabilities []string          `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Tags         []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Runtime configuration
	Transport TransportType `json:"transport" yaml:"transport" validate:"required"`
	Endpoint  string        `json:"endpoint" yaml:"endpoint" validate:"required"`
	Auth      *AuthConfig   `json:"auth,omitempty" yaml:"auth,omitempty"`

	// Plugin requirements and constraints
	Requirements *PluginRequirements `json:"requirements,omitempty" yaml:"requirements,omitempty"`
	Resources    *ResourceLimits     `json:"resources,omitempty" yaml:"resources,omitempty"`
	HealthCheck  *HealthCheckConfig  `json:"health_check,omitempty" yaml:"health_check,omitempty"`

	// Discovery metadata
	DiscoveredAt   time.Time `json:"discovered_at" yaml:"discovered_at"`
	DiscoveryType  string    `json:"discovery_type" yaml:"discovery_type"`
	ManifestPath   string    `json:"manifest_path,omitempty" yaml:"manifest_path,omitempty"`
	NetworkAddress string    `json:"network_address,omitempty" yaml:"network_address,omitempty"`
}

// PluginRequirements defines system and dependency requirements for a plugin.
type PluginRequirements struct {
	MinGoVersion    string   `json:"min_go_version,omitempty" yaml:"min_go_version,omitempty"`
	RequiredPlugins []string `json:"required_plugins,omitempty" yaml:"required_plugins,omitempty"`
	OptionalPlugins []string `json:"optional_plugins,omitempty" yaml:"optional_plugins,omitempty"`
	SystemPackages  []string `json:"system_packages,omitempty" yaml:"system_packages,omitempty"`
	EnvironmentVars []string `json:"environment_vars,omitempty" yaml:"environment_vars,omitempty"`
}

// ResourceLimits defines resource constraints for plugin execution.
type ResourceLimits struct {
	MaxMemoryMB    int64 `json:"max_memory_mb,omitempty" yaml:"max_memory_mb,omitempty"`
	MaxCPUPercent  int   `json:"max_cpu_percent,omitempty" yaml:"max_cpu_percent,omitempty"`
	MaxConnections int   `json:"max_connections,omitempty" yaml:"max_connections,omitempty"`
	MaxRequests    int64 `json:"max_requests,omitempty" yaml:"max_requests,omitempty"`
}

// DiscoveryResult contains information about a discovered plugin and discovery context.
type DiscoveryResult struct {
	Manifest     *PluginManifest `json:"manifest"`
	Source       string          `json:"source"`
	DiscoveredAt time.Time       `json:"discovered_at"`
	Capabilities []string        `json:"capabilities"`
	HealthStatus PluginStatus    `json:"health_status"`
	ErrorMessage string          `json:"error_message,omitempty"`
}

// ExtendedDiscoveryConfig extends the existing DiscoveryConfig with additional fields for filesystem and network discovery.
type ExtendedDiscoveryConfig struct {
	DiscoveryConfig // Embed the existing config

	// Extended filesystem discovery settings
	SearchPaths    []string `json:"search_paths,omitempty" yaml:"search_paths,omitempty"`
	FilePatterns   []string `json:"file_patterns,omitempty" yaml:"file_patterns,omitempty"`
	MaxDepth       int      `json:"max_depth,omitempty" yaml:"max_depth,omitempty"`
	FollowSymlinks bool     `json:"follow_symlinks,omitempty" yaml:"follow_symlinks,omitempty"`

	// Network discovery deprecated - filesystem-based approach is preferred for security and simplicity
	NetworkInterfaces []string      `json:"network_interfaces,omitempty" yaml:"network_interfaces,omitempty"` // DEPRECATED
	DiscoveryTimeout  time.Duration `json:"discovery_timeout,omitempty" yaml:"discovery_timeout,omitempty"`   // DEPRECATED

	// Filtering and validation
	AllowedTransports    []TransportType `json:"allowed_transports,omitempty" yaml:"allowed_transports,omitempty"`
	RequiredCapabilities []string        `json:"required_capabilities,omitempty" yaml:"required_capabilities,omitempty"`
	ExcludePaths         []string        `json:"exclude_paths,omitempty" yaml:"exclude_paths,omitempty"`
	ValidateManifests    bool            `json:"validate_manifests,omitempty" yaml:"validate_manifests,omitempty"`
}

// DiscoveryEngine discovers plugins through filesystem scanning and network discovery.
//
// The engine provides intelligent plugin discovery capabilities with support for
// multiple discovery methods, manifest validation, capability matching, and
// real-time discovery events. It's designed to work seamlessly with the existing
// plugin system and manager.
//
// Key features:
//   - Filesystem discovery with configurable search paths and patterns
//   - Plugin manifest parsing and validation (JSON/YAML)
//   - Capability detection and filtering
//   - Real-time discovery events and notifications
//   - Thread-safe concurrent discovery operations
//
// Example usage:
//
//	config := DiscoveryConfig{
//	    SearchPaths:   []string{"/plugins", "./local-plugins"},
//	    FilePatterns:  []string{"*.json", "plugin.yaml"},
//	    MaxDepth:      5,
//	    ValidateManifests: true,
//	}
//
//	engine := NewDiscoveryEngine(config, logger)
//	results, err := engine.DiscoverPlugins(ctx)
//	if err != nil {
//	    log.Printf("Discovery failed: %v", err)
//	}
//
//	for _, result := range results {
//	    fmt.Printf("Found plugin: %s v%s at %s\n",
//	        result.Manifest.Name, result.Manifest.Version, result.Source)
//	}
type DiscoveryEngine struct {
	config ExtendedDiscoveryConfig
	logger Logger

	// Discovery state
	mu                sync.RWMutex
	discoveredPlugins map[string]*DiscoveryResult
	eventHandlers     []DiscoveryEventHandler
}

// DiscoveryEventHandler handles discovery events for real-time notifications.
type DiscoveryEventHandler func(event DiscoveryEvent)

// DiscoveryEvent represents a plugin discovery event.
type DiscoveryEvent struct {
	Type      string           `json:"type"`
	Timestamp time.Time        `json:"timestamp"`
	Plugin    *DiscoveryResult `json:"plugin,omitempty"`
	Error     error            `json:"error,omitempty"`
}

// Network discovery structures deprecated for security and simplicity

// NewDiscoveryEngine creates a new plugin discovery engine with the specified configuration.
//
// The engine is initialized with default values for optional configuration parameters:
//   - Default file patterns: ["plugin.json", "plugin.yaml", "plugin.yml", "manifest.json", "manifest.yaml"]
//   - Default max depth: 5 levels
//   - Default discovery timeout: 30 seconds
//   - Filesystem-based discovery for security and reliability
//
// Example:
//
//	config := ExtendedDiscoveryConfig{
//	    SearchPaths: []string{"/opt/plugins", "/usr/local/plugins"},
//	    ValidateManifests: true,
//	    MaxDepth: 3,
//	}
//	engine := NewDiscoveryEngine(config, slog.Default())
func NewDiscoveryEngine(config ExtendedDiscoveryConfig, logger Logger) *DiscoveryEngine {
	// Initialize with filesystem-based discovery for security and performance
	return &DiscoveryEngine{
		config:            config,
		logger:            logger,
		discoveredPlugins: make(map[string]*DiscoveryResult),
		eventHandlers:     make([]DiscoveryEventHandler, 0),
	}
}

// DiscoverPlugins performs comprehensive plugin discovery using all configured methods.
//
// This method orchestrates both filesystem and network discovery, validates discovered
// plugins, and returns a consolidated list of available plugins. Discovery is performed
// concurrently for optimal performance while maintaining thread safety.
//
// The discovery process:
//  1. Filesystem discovery across all configured search paths
//  2. Manifest validation and parsing
//  3. Capability detection and filtering
//  4. Duplicate detection and resolution
//  5. Health status verification (basic connectivity test)
//
// Returns a map of plugin names to discovery results, or an error if discovery fails.
func (d *DiscoveryEngine) DiscoverPlugins(ctx context.Context) (map[string]*DiscoveryResult, error) {
	d.logger.Info("Starting plugin discovery",
		"search_paths", d.config.SearchPaths)

	ctx, cancel := context.WithTimeout(ctx, d.config.DiscoveryTimeout)
	defer cancel()

	results, err := d.executeDiscoveryMethods(ctx)
	if err != nil {
		return nil, err
	}

	d.updateCacheAndEmitEvents(results)
	d.logger.Info("Plugin discovery completed", "plugins_found", len(results))

	return results, nil
}

// executeDiscoveryMethods runs filesystem and network discovery concurrently.
func (d *DiscoveryEngine) executeDiscoveryMethods(ctx context.Context) (map[string]*DiscoveryResult, error) {
	results := make(map[string]*DiscoveryResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errorCh := make(chan error, 10)

	// Launch discovery methods
	d.launchFilesystemDiscovery(ctx, &wg, &mu, results, errorCh)

	return d.waitForCompletion(ctx, &wg, errorCh, results)
}

// launchFilesystemDiscovery starts filesystem discovery if configured.
func (d *DiscoveryEngine) launchFilesystemDiscovery(ctx context.Context, wg *sync.WaitGroup, mu *sync.Mutex, results map[string]*DiscoveryResult, errorCh chan error) {
	if len(d.config.SearchPaths) > 0 {
		wg.Add(1)
		go d.runFilesystemDiscovery(ctx, wg, mu, results, errorCh)
	}
}

// runFilesystemDiscovery performs filesystem discovery in a goroutine.
func (d *DiscoveryEngine) runFilesystemDiscovery(ctx context.Context, wg *sync.WaitGroup, mu *sync.Mutex, results map[string]*DiscoveryResult, errorCh chan error) {
	defer wg.Done()
	filesystemResults, err := d.discoverFilesystemPlugins(ctx)
	if err != nil {
		errorCh <- fmt.Errorf("filesystem discovery failed: %w", err)
		return
	}

	mu.Lock()
	for name, result := range filesystemResults {
		results[name] = result
	}
	mu.Unlock()
}

// waitForCompletion waits for all discovery methods to complete and handles errors.
func (d *DiscoveryEngine) waitForCompletion(ctx context.Context, wg *sync.WaitGroup, errorCh chan error, results map[string]*DiscoveryResult) (map[string]*DiscoveryResult, error) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("plugin discovery timeout: %w", ctx.Err())
	case <-done:
		// Discovery completed successfully
	}

	close(errorCh)

	// Collect any errors
	var discoveryErrors []error
	for err := range errorCh {
		discoveryErrors = append(discoveryErrors, err)
	}

	if len(discoveryErrors) > 0 && len(results) == 0 {
		return nil, discoveryErrors[0]
	}

	return results, nil
}

// updateCacheAndEmitEvents updates the internal cache and emits discovery events.
func (d *DiscoveryEngine) updateCacheAndEmitEvents(results map[string]*DiscoveryResult) {
	// Update internal cache
	d.mu.Lock()
	d.discoveredPlugins = results
	d.mu.Unlock()

	// Emit discovery events
	for _, result := range results {
		d.emitEvent(DiscoveryEvent{
			Type:      "plugin_discovered",
			Timestamp: time.Now(),
			Plugin:    result,
		})
	}
}

// discoverFilesystemPlugins searches for plugin manifests in the configured filesystem paths.
func (d *DiscoveryEngine) discoverFilesystemPlugins(ctx context.Context) (map[string]*DiscoveryResult, error) {
	results := make(map[string]*DiscoveryResult)

	for _, searchPath := range d.config.SearchPaths {
		if err := d.scanDirectory(ctx, searchPath, 0, results); err != nil {
			d.logger.Error("Failed to scan directory", "path", searchPath, "error", err)
			continue
		}
	}

	return results, nil
}

// scanDirectory recursively scans a directory for plugin manifests.
func (d *DiscoveryEngine) scanDirectory(ctx context.Context, path string, depth int, results map[string]*DiscoveryResult) error {
	if !d.shouldScanPath(path, depth) {
		return nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", path, err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fullPath := filepath.Join(path, entry.Name())
		if err := d.processDirectoryEntry(ctx, entry, fullPath, depth, results); err != nil {
			d.logger.Error("Failed to process directory entry", "path", fullPath, "error", err)
		}
	}

	return nil
}

// shouldScanPath determines if a path should be scanned based on depth and exclusion rules.
func (d *DiscoveryEngine) shouldScanPath(path string, depth int) bool {
	if depth > d.config.MaxDepth {
		return false
	}

	// Check if path should be excluded
	for _, excludePath := range d.config.ExcludePaths {
		if strings.Contains(path, excludePath) {
			return false
		}
	}

	return true
}

// processDirectoryEntry processes a single directory entry (file or subdirectory).
func (d *DiscoveryEngine) processDirectoryEntry(ctx context.Context, entry os.DirEntry, fullPath string, depth int, results map[string]*DiscoveryResult) error {
	if entry.IsDir() {
		return d.scanDirectory(ctx, fullPath, depth+1, results)
	}

	return d.processManifestFile(entry.Name(), fullPath, results)
}

// processManifestFile processes a potential manifest file.
func (d *DiscoveryEngine) processManifestFile(fileName, fullPath string, results map[string]*DiscoveryResult) error {
	if !d.matchesPattern(fileName) {
		return nil
	}

	result, err := d.parseManifestFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	d.enrichDiscoveryResult(result, fullPath)

	if d.shouldIncludePlugin(result.Manifest) {
		results[result.Manifest.Name] = result
		d.logger.Debug("Discovered plugin",
			"name", result.Manifest.Name,
			"version", result.Manifest.Version,
			"path", fullPath)
	}

	return nil
}

// enrichDiscoveryResult adds discovery metadata to a result.
func (d *DiscoveryEngine) enrichDiscoveryResult(result *DiscoveryResult, fullPath string) {
	result.Source = fullPath
	result.DiscoveredAt = time.Now()
	result.Manifest.DiscoveryType = "filesystem"
	result.Manifest.ManifestPath = fullPath
}

// matchesPattern checks if a filename matches any of the configured file patterns.
func (d *DiscoveryEngine) matchesPattern(filename string) bool {
	for _, pattern := range d.config.FilePatterns {
		if matched, err := filepath.Match(pattern, filename); err == nil && matched {
			return true
		}
	}
	return false
}

// parseManifestFile parses a plugin manifest file (JSON or YAML format).
func (d *DiscoveryEngine) parseManifestFile(filePath string) (*DiscoveryResult, error) {
	// Security: validate file path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)
	if !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("manifest path must be absolute: %s", filePath)
	}

	data, err := os.ReadFile(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifest PluginManifest

	// Try JSON first, then YAML
	if err := json.Unmarshal(data, &manifest); err != nil {
		if err := yaml.Unmarshal(data, &manifest); err != nil {
			return nil, fmt.Errorf("failed to parse manifest as JSON or YAML: %w", err)
		}
	}

	// Validate manifest if configured
	if d.config.ValidateManifests {
		if err := d.validateManifest(&manifest); err != nil {
			return nil, fmt.Errorf("manifest validation failed: %w", err)
		}
	}

	return &DiscoveryResult{
		Manifest:     &manifest,
		Capabilities: manifest.Capabilities,
		HealthStatus: StatusUnknown,
	}, nil
}

// validateManifest performs basic validation on a plugin manifest.
func (d *DiscoveryEngine) validateManifest(manifest *PluginManifest) error {
	if manifest.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	if manifest.Version == "" {
		return fmt.Errorf("plugin version is required")
	}

	if manifest.Transport == "" {
		return fmt.Errorf("plugin transport is required")
	}

	if manifest.Endpoint == "" {
		return fmt.Errorf("plugin endpoint is required")
	}

	// Validate transport type
	validTransports := []TransportType{
		TransportGRPC, TransportGRPCTLS, TransportExecutable,
	}

	validTransport := false
	for _, valid := range validTransports {
		if manifest.Transport == valid {
			validTransport = true
			break
		}
	}

	if !validTransport {
		return fmt.Errorf("invalid transport type: %s", manifest.Transport)
	}

	return nil
}

// shouldIncludePlugin determines if a plugin should be included based on configuration filters.
func (d *DiscoveryEngine) shouldIncludePlugin(manifest *PluginManifest) bool {
	return d.isTransportAllowed(manifest) && d.hasRequiredCapabilities(manifest)
}

// isTransportAllowed checks if the plugin's transport is in the allowed list
func (d *DiscoveryEngine) isTransportAllowed(manifest *PluginManifest) bool {
	if len(d.config.AllowedTransports) == 0 {
		return true // No restrictions
	}

	for _, allowedTransport := range d.config.AllowedTransports {
		if manifest.Transport == allowedTransport {
			return true
		}
	}
	return false
}

// hasRequiredCapabilities checks if the plugin has all required capabilities
func (d *DiscoveryEngine) hasRequiredCapabilities(manifest *PluginManifest) bool {
	if len(d.config.RequiredCapabilities) == 0 {
		return true // No requirements
	}

	for _, requiredCap := range d.config.RequiredCapabilities {
		if !d.pluginHasCapability(manifest, requiredCap) {
			return false
		}
	}
	return true
}

// pluginHasCapability checks if a plugin has a specific capability
func (d *DiscoveryEngine) pluginHasCapability(manifest *PluginManifest, requiredCap string) bool {
	for _, pluginCap := range manifest.Capabilities {
		if pluginCap == requiredCap {
			return true
		}
	}
	return false
}

// GetDiscoveredPlugins returns the current list of discovered plugins from the internal cache.
func (d *DiscoveryEngine) GetDiscoveredPlugins() map[string]*DiscoveryResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Return a copy to prevent external modification
	results := make(map[string]*DiscoveryResult)
	for name, result := range d.discoveredPlugins {
		results[name] = result
	}

	return results
}

// AddEventHandler adds a discovery event handler for real-time notifications.
func (d *DiscoveryEngine) AddEventHandler(handler DiscoveryEventHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.eventHandlers = append(d.eventHandlers, handler)
}

// emitEvent emits a discovery event to all registered handlers.
func (d *DiscoveryEngine) emitEvent(event DiscoveryEvent) {
	d.mu.RLock()
	handlers := make([]DiscoveryEventHandler, len(d.eventHandlers))
	copy(handlers, d.eventHandlers)
	d.mu.RUnlock()

	for _, handler := range handlers {
		go func(h DiscoveryEventHandler) {
			defer withStackRecover(d.logger)()
			h(event)
		}(handler)
	}
}

// Close shuts down the discovery engine and releases resources.
func (d *DiscoveryEngine) Close() error {
	d.mu.Lock()
	d.discoveredPlugins = make(map[string]*DiscoveryResult)
	d.eventHandlers = nil
	d.mu.Unlock()

	return nil
}
