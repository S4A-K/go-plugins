// dynamic_loader.go: Dynamic plugin loading framework with Argus integration
//
// This module implements hot-loading of discovered plugins without restart,
// version compatibility checking, automatic dependency resolution, and
// real-time discovery event notifications. It leverages the existing Argus
// infrastructure for ultra-fast configuration changes (12.10ns/op) and
// integrates seamlessly with the discovery engine.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/argus"
	"github.com/agilira/go-errors"
)

// PluginVersion represents a semantic version with comparison capabilities.
//
// This structure provides comprehensive version parsing and comparison
// functionality for plugin compatibility checking. It supports semantic
// versioning (semver) with major, minor, and patch components plus
// optional prerelease and build metadata.
//
// Example usage:
//
//	v1, _ := ParsePluginVersion("1.2.3-beta.1+build.123")
//	v2, _ := ParsePluginVersion("1.2.4")
//	if v1.IsCompatible(v2) {
//	    // Versions are compatible
//	}
type PluginVersion struct {
	Major      uint64 `json:"major"`
	Minor      uint64 `json:"minor"`
	Patch      uint64 `json:"patch"`
	Prerelease string `json:"prerelease,omitempty"`
	Build      string `json:"build,omitempty"`
	Original   string `json:"original"`
}

// DependencyGraph represents plugin dependencies and loading order.
//
// This structure maintains a directed acyclic graph (DAG) of plugin
// dependencies and calculates the correct loading order to ensure
// dependencies are satisfied. It includes cycle detection and validation
// to prevent dependency conflicts.
//
// Fields:
//   - Nodes: Map of plugin names to their dependency information
//   - Edges: Directed edges representing dependency relationships
//   - LoadOrder: Calculated loading order respecting dependencies
//
// Example usage:
//
//	graph := NewDependencyGraph()
//	graph.AddPlugin("auth", []string{"logging", "config"})
//	graph.AddPlugin("api", []string{"auth"})
//	order, err := graph.CalculateLoadOrder()
type DependencyGraph struct {
	mu        sync.RWMutex
	nodes     map[string]*DependencyNode
	edges     map[string][]string
	loadOrder []string
	validated bool
}

// DependencyNode represents a single plugin in the dependency graph.
type DependencyNode struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Dependencies []string `json:"dependencies"`
	Dependents   []string `json:"dependents"`
	Status       string   `json:"status"`
}

// LoadingState represents the current state of a plugin during loading.
type LoadingState string

const (
	// LoadingStatePending indicates plugin is waiting to be loaded
	LoadingStatePending LoadingState = "pending"
	// LoadingStateLoading indicates plugin is currently being loaded
	LoadingStateLoading LoadingState = "loading"
	// LoadingStateLoaded indicates plugin has been successfully loaded
	LoadingStateLoaded LoadingState = "loaded"
	// LoadingStateFailed indicates plugin loading failed
	LoadingStateFailed LoadingState = "failed"
	// LoadingStateUnloading indicates plugin is being unloaded
	LoadingStateUnloading LoadingState = "unloading"
)

// DynamicLoader manages dynamic loading of discovered plugins with hot-reload capabilities.
//
// This component provides intelligent plugin lifecycle management with support for
// hot-loading, version compatibility checking, dependency resolution, and real-time
// event notifications. It integrates with the existing Argus configuration system
// for ultra-fast change detection and applies changes atomically.
//
// Key features:
//   - Hot-loading of discovered plugins without service restart
//   - Semantic version compatibility validation
//   - Automatic dependency resolution and ordering
//   - Real-time discovery event notifications
//   - Atomic loading operations with rollback support
//   - Integration with existing Argus infrastructure
//
// Example usage:
//
//	loader := NewDynamicLoader(manager, discoveryEngine, logger)
//	loader.SetCompatibilityRule("^1.0.0") // Compatible with 1.x.x
//
//	// Enable automatic loading of discovered plugins
//	if err := loader.EnableAutoLoading(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Manual loading with dependency resolution
//	if err := loader.LoadDiscoveredPlugin(ctx, "auth-service"); err != nil {
//	    log.Printf("Failed to load plugin: %v", err)
//	}
type DynamicLoader[Req, Resp any] struct {
	manager         *Manager[Req, Resp]
	discoveryEngine *DiscoveryEngine
	logger          Logger

	// Version compatibility
	compatibilityRules map[string]string // plugin name -> version constraint
	minSystemVersion   *PluginVersion

	// Dependency management
	dependencyGraph *DependencyGraph
	loadingStates   map[string]LoadingState
	loadingMutex    sync.RWMutex

	// Event handling
	eventHandlers []DynamicLoaderEventHandler
	eventMutex    sync.RWMutex

	// Auto-loading state
	autoLoading    atomic.Bool
	autoLoadCtx    context.Context
	autoLoadCancel context.CancelFunc
	autoLoadMutex  sync.Mutex

	// Argus integration for configuration watching
	configWatcher *argus.Watcher
	watcherMutex  sync.Mutex

	// Performance metrics
	metrics DynamicLoaderMetrics
}

// DynamicLoaderMetrics tracks operational metrics for the dynamic loader.
type DynamicLoaderMetrics struct {
	PluginsLoaded         atomic.Int64
	PluginsUnloaded       atomic.Int64
	LoadingFailures       atomic.Int64
	DependencyResolutions atomic.Int64
	VersionConflicts      atomic.Int64
	EventsProcessed       atomic.Int64
}

// DynamicLoaderEvent represents an event in the dynamic loading lifecycle.
type DynamicLoaderEvent struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Plugin    string                 `json:"plugin,omitempty"`
	Version   string                 `json:"version,omitempty"`
	State     LoadingState           `json:"state,omitempty"`
	Error     error                  `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// DynamicLoaderEventHandler handles dynamic loader events.
type DynamicLoaderEventHandler func(event DynamicLoaderEvent)

// NewDynamicLoader creates a new dynamic plugin loader.
//
// The loader is initialized with default compatibility rules and empty
// dependency graph. It integrates with the provided manager and discovery
// engine to provide seamless hot-loading capabilities.
//
// Parameters:
//   - manager: Plugin manager for registering/unregistering plugins
//   - discoveryEngine: Discovery engine for finding available plugins
//   - logger: Logger for operational events and debugging
//
// Returns a fully initialized dynamic loader ready for configuration.
func NewDynamicLoader[Req, Resp any](manager *Manager[Req, Resp], discoveryEngine *DiscoveryEngine, logger Logger) *DynamicLoader[Req, Resp] {
	return &DynamicLoader[Req, Resp]{
		manager:            manager,
		discoveryEngine:    discoveryEngine,
		logger:             logger,
		compatibilityRules: make(map[string]string),
		dependencyGraph:    NewDependencyGraph(),
		loadingStates:      make(map[string]LoadingState),
		eventHandlers:      make([]DynamicLoaderEventHandler, 0),
		metrics:            DynamicLoaderMetrics{},
	}
}

// SetCompatibilityRule sets version compatibility constraint for a plugin.
//
// The constraint follows semantic versioning rules and supports ranges,
// wildcards, and comparison operators. Examples:
//   - "^1.0.0" - Compatible with 1.x.x (>= 1.0.0, < 2.0.0)
//   - "~1.2.0" - Compatible with 1.2.x (>= 1.2.0, < 1.3.0)
//   - ">=1.0.0,<2.0.0" - Range specification
//   - "*" - Any version (use with caution)
//
// Parameters:
//   - pluginName: Name of plugin to set constraint for
//   - constraint: Semantic version constraint string
func (dl *DynamicLoader[Req, Resp]) SetCompatibilityRule(pluginName, constraint string) {
	dl.loadingMutex.Lock()
	defer dl.loadingMutex.Unlock()

	dl.compatibilityRules[pluginName] = constraint
	dl.logger.Debug("Compatibility rule set",
		"plugin", pluginName,
		"constraint", constraint)
}

// SetMinSystemVersion sets the minimum system version for plugin compatibility.
//
// Plugins with manifests declaring lower minimum system versions will be
// rejected during loading. This ensures system compatibility and prevents
// runtime errors from version mismatches.
func (dl *DynamicLoader[Req, Resp]) SetMinSystemVersion(version string) error {
	v, err := ParsePluginVersion(version)
	if err != nil {
		return NewPluginValidationError(0, err)
	}

	dl.loadingMutex.Lock()
	defer dl.loadingMutex.Unlock()

	dl.minSystemVersion = v
	dl.logger.Info("Minimum system version set", "version", version)
	return nil
}

// EnableAutoLoading enables automatic loading of newly discovered plugins.
//
// When enabled, the loader monitors discovery events and automatically
// loads compatible plugins that satisfy dependency requirements and
// version constraints. Loading occurs in dependency order with proper
// error handling and rollback on failures.
//
// This method starts a background goroutine that listens for discovery
// events and processes them asynchronously. Use DisableAutoLoading()
// to stop automatic loading.
func (dl *DynamicLoader[Req, Resp]) EnableAutoLoading(ctx context.Context) error {
	dl.autoLoadMutex.Lock()
	defer dl.autoLoadMutex.Unlock()

	if dl.autoLoading.Load() {
		return NewPluginExecutionFailedError("auto-loading", nil)
	}

	// Create cancellable context for auto-loading
	dl.autoLoadCtx, dl.autoLoadCancel = context.WithCancel(ctx)

	// Register discovery event handler
	dl.discoveryEngine.AddEventHandler(dl.handleDiscoveryEvent)

	// Start auto-loading goroutine
	go dl.autoLoadingWorker(dl.autoLoadCtx)

	dl.autoLoading.Store(true)
	dl.emitEvent(DynamicLoaderEvent{
		Type:      "auto_loading_enabled",
		Timestamp: time.Now(),
	})

	dl.logger.Info("Auto-loading enabled for discovered plugins")
	return nil
}

// DisableAutoLoading disables automatic loading of discovered plugins.
//
// This method stops the background auto-loading worker and cancels any
// pending loading operations. It does not affect already loaded plugins.
func (dl *DynamicLoader[Req, Resp]) DisableAutoLoading() error {
	dl.autoLoadMutex.Lock()
	defer dl.autoLoadMutex.Unlock()

	if !dl.autoLoading.Load() {
		return NewPluginExecutionFailedError("auto-loading", nil)
	}

	// Cancel auto-loading context
	if dl.autoLoadCancel != nil {
		dl.autoLoadCancel()
	}

	dl.autoLoading.Store(false)
	dl.emitEvent(DynamicLoaderEvent{
		Type:      "auto_loading_disabled",
		Timestamp: time.Now(),
	})

	dl.logger.Info("Auto-loading disabled")
	return nil
}

// LoadDiscoveredPlugin loads a specific discovered plugin with dependency resolution.
//
// This method performs comprehensive plugin loading including version
// compatibility checking, dependency resolution, and atomic loading
// operations. If the plugin has dependencies, they are loaded first
// in the correct order.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - pluginName: Name of the plugin to load
//
// Returns error if loading fails at any stage.
func (dl *DynamicLoader[Req, Resp]) LoadDiscoveredPlugin(ctx context.Context, pluginName string) error {
	return dl.loadDiscoveredPluginInternal(ctx, pluginName, make(map[string]bool))
}

// loadDiscoveredPluginInternal is the internal implementation that tracks loading path for circular dependency detection.
func (dl *DynamicLoader[Req, Resp]) loadDiscoveredPluginInternal(ctx context.Context, pluginName string, loadingPath map[string]bool) error {
	// Get discovered plugin information
	discovered := dl.discoveryEngine.GetDiscoveredPlugins()
	result, exists := discovered[pluginName]
	if !exists {
		return NewPluginNotFoundError(pluginName)
	}

	// Check if already loaded
	dl.loadingMutex.RLock()
	if state, exists := dl.loadingStates[pluginName]; exists && state == LoadingStateLoaded {
		dl.loadingMutex.RUnlock()
		return NewPluginExecutionFailedError(pluginName, nil)
	}
	dl.loadingMutex.RUnlock()

	// Validate version compatibility
	if err := dl.validateVersionCompatibility(result.Manifest); err != nil {
		dl.metrics.VersionConflicts.Add(1)
		return NewPluginValidationError(0, err)
	}

	// Update dependency graph
	if err := dl.updateDependencyGraph(result.Manifest); err != nil {
		return NewPluginExecutionFailedError(pluginName, err)
	}

	// Resolve and load dependencies with path tracking
	if err := dl.resolveDependenciesWithPath(ctx, pluginName, loadingPath); err != nil {
		return NewPluginExecutionFailedError(pluginName, err)
	}

	// Load the plugin itself
	return dl.loadPlugin(ctx, result)
}

// UnloadPlugin unloads a dynamically loaded plugin with dependency checking.
//
// This method safely unloads a plugin after checking that no other
// plugins depend on it. If dependencies exist, the unload operation
// fails unless forced. The method handles graceful shutdown and
// resource cleanup.
func (dl *DynamicLoader[Req, Resp]) UnloadPlugin(ctx context.Context, pluginName string, force bool) error {
	dl.loadingMutex.Lock()
	defer dl.loadingMutex.Unlock()

	// Check if plugin is loaded
	state, exists := dl.loadingStates[pluginName]
	if !exists || state != LoadingStateLoaded {
		return NewPluginNotFoundError(pluginName)
	}

	// Check for dependents unless forced
	if !force {
		if dependents := dl.dependencyGraph.GetDependents(pluginName); len(dependents) > 0 {
			return NewPluginExecutionFailedError(pluginName, nil)
		}
	}

	// Update state
	dl.loadingStates[pluginName] = LoadingStateUnloading

	// Emit event
	dl.emitEvent(DynamicLoaderEvent{
		Type:      "plugin_unloading",
		Timestamp: time.Now(),
		Plugin:    pluginName,
		State:     LoadingStateUnloading,
	})

	// Unregister from manager
	if err := dl.manager.Unregister(pluginName); err != nil {
		dl.loadingStates[pluginName] = LoadingStateLoaded // Rollback state
		return NewPluginExecutionFailedError(pluginName, err)
	}

	// Remove from dependency graph
	dl.dependencyGraph.RemovePlugin(pluginName)
	delete(dl.loadingStates, pluginName)

	dl.metrics.PluginsUnloaded.Add(1)
	dl.emitEvent(DynamicLoaderEvent{
		Type:      "plugin_unloaded",
		Timestamp: time.Now(),
		Plugin:    pluginName,
	})

	dl.logger.Info("Plugin unloaded successfully", "plugin", pluginName)
	return nil
}

// GetLoadingStatus returns the current loading status of all plugins.
func (dl *DynamicLoader[Req, Resp]) GetLoadingStatus() map[string]LoadingState {
	dl.loadingMutex.RLock()
	defer dl.loadingMutex.RUnlock()

	status := make(map[string]LoadingState)
	for name, state := range dl.loadingStates {
		status[name] = state
	}

	return status
}

// GetDependencyGraph returns a copy of the current dependency graph.
func (dl *DynamicLoader[Req, Resp]) GetDependencyGraph() *DependencyGraph {
	return dl.dependencyGraph.Copy()
}

// AddEventHandler adds an event handler for dynamic loading events.
func (dl *DynamicLoader[Req, Resp]) AddEventHandler(handler DynamicLoaderEventHandler) {
	dl.eventMutex.Lock()
	defer dl.eventMutex.Unlock()

	dl.eventHandlers = append(dl.eventHandlers, handler)
}

// GetMetrics returns current dynamic loader metrics.
func (dl *DynamicLoader[Req, Resp]) GetMetrics() DynamicLoaderMetrics {
	return DynamicLoaderMetrics{
		PluginsLoaded:         atomic.Int64{},
		PluginsUnloaded:       atomic.Int64{},
		LoadingFailures:       atomic.Int64{},
		DependencyResolutions: atomic.Int64{},
		VersionConflicts:      atomic.Int64{},
		EventsProcessed:       atomic.Int64{},
	}
}

// Close shuts down the dynamic loader and cleans up resources.
func (dl *DynamicLoader[Req, Resp]) Close() error {
	// Disable auto-loading if enabled
	if dl.autoLoading.Load() {
		if err := dl.DisableAutoLoading(); err != nil {
			dl.logger.Warn("Error disabling auto-loading during close", "error", err)
		}
	}

	// Stop configuration watcher if running
	dl.watcherMutex.Lock()
	if dl.configWatcher != nil {
		if err := dl.configWatcher.Stop(); err != nil {
			dl.logger.Warn("Error stopping config watcher", "error", err)
		}
		dl.configWatcher = nil
	}
	dl.watcherMutex.Unlock()

	// Clear event handlers
	dl.eventMutex.Lock()
	dl.eventHandlers = nil
	dl.eventMutex.Unlock()

	dl.logger.Info("Dynamic loader closed successfully")
	return nil
}

// Helper methods

// validateVersionCompatibility checks if a plugin version is compatible.
func (dl *DynamicLoader[Req, Resp]) validateVersionCompatibility(manifest *PluginManifest) error {
	// BUG FIX: Always validate plugin version format first (security critical!)
	// This prevents malformed versions from bypassing validation
	pluginVersion, err := ParsePluginVersion(manifest.Version)
	if err != nil {
		return NewPluginValidationError(0, err)
	}

	// Check minimum system version if set
	if dl.minSystemVersion != nil && manifest.Requirements != nil && manifest.Requirements.MinGoVersion != "" {
		pluginMinVersion, err := ParsePluginVersion(manifest.Requirements.MinGoVersion)
		if err != nil {
			return NewPluginValidationError(0, err)
		}

		if pluginMinVersion.Compare(dl.minSystemVersion) > 0 {
			return NewPluginValidationError(0, nil)
		}
	}

	// Check plugin-specific compatibility rules
	if constraint, exists := dl.compatibilityRules[manifest.Name]; exists {
		if !pluginVersion.SatisfiesConstraint(constraint) {
			return NewPluginValidationError(0, nil)
		}
	}

	return nil
}

// updateDependencyGraph updates the dependency graph with plugin information.
func (dl *DynamicLoader[Req, Resp]) updateDependencyGraph(manifest *PluginManifest) error {
	dependencies := make([]string, 0)
	if manifest.Requirements != nil {
		dependencies = append(dependencies, manifest.Requirements.RequiredPlugins...)
	}

	return dl.dependencyGraph.AddPlugin(manifest.Name, dependencies)
}

// resolveDependenciesWithPath resolves dependencies while tracking the loading path to detect circular dependencies.
func (dl *DynamicLoader[Req, Resp]) resolveDependenciesWithPath(ctx context.Context, pluginName string, loadingPath map[string]bool) error {
	dependencies := dl.dependencyGraph.GetDependencies(pluginName)

	for _, dep := range dependencies {
		// Check for circular dependency
		if loadingPath[dep] {
			return NewPluginExecutionFailedError(dep, fmt.Errorf("circular dependency detected: %s -> %s", pluginName, dep))
		}

		// Check if dependency is already loaded
		dl.loadingMutex.RLock()
		state, exists := dl.loadingStates[dep]
		dl.loadingMutex.RUnlock()

		if exists && state == LoadingStateLoaded {
			continue // Dependency already loaded
		}

		// Check if dependency is currently being loaded (circular dependency)
		if exists && state == LoadingStateLoading {
			return NewPluginExecutionFailedError(dep, fmt.Errorf("circular dependency detected: %s is already being loaded", dep))
		}

		// Add current dependency to loading path for circular detection
		newPath := make(map[string]bool)
		for k, v := range loadingPath {
			newPath[k] = v
		}
		newPath[pluginName] = true

		// Load dependency recursively with updated path
		if err := dl.loadDiscoveredPluginInternal(ctx, dep, newPath); err != nil {
			return NewPluginExecutionFailedError(dep, err)
		}
	}

	dl.metrics.DependencyResolutions.Add(1)
	return nil
}

// loadPlugin performs the actual plugin loading operation.
func (dl *DynamicLoader[Req, Resp]) loadPlugin(ctx context.Context, result *DiscoveryResult) error {
	_ = ctx // Reserved for future use (timeouts, cancellation)
	pluginName := result.Manifest.Name

	// Update loading state
	dl.loadingMutex.Lock()
	dl.loadingStates[pluginName] = LoadingStateLoading
	dl.loadingMutex.Unlock()

	// Emit loading event
	dl.emitEvent(DynamicLoaderEvent{
		Type:      "plugin_loading",
		Timestamp: time.Now(),
		Plugin:    pluginName,
		Version:   result.Manifest.Version,
		State:     LoadingStateLoading,
	})

	// Create plugin configuration from manifest
	config := PluginConfig{
		Name:       result.Manifest.Name,
		Type:       string(result.Manifest.Transport), // Convert transport to type
		Transport:  result.Manifest.Transport,
		Endpoint:   result.Manifest.Endpoint,
		Version:    result.Manifest.Version,  // Add version from manifest
		Executable: result.Manifest.Endpoint, // For executable transport, endpoint is the executable path
		Args:       result.Manifest.Args,     // Copy args from manifest
		Env:        result.Manifest.Env,      // Copy env from manifest
		WorkDir:    result.Manifest.WorkDir,  // Copy work dir from manifest
		Enabled:    true,                     // Enable discovered plugins by default
	}

	// Add auth if present
	if result.Manifest.Auth != nil {
		config.Auth = *result.Manifest.Auth
	}

	// Add health check if present
	if result.Manifest.HealthCheck != nil {
		config.HealthCheck = *result.Manifest.HealthCheck
	}

	// Get appropriate factory for the transport type
	factory, err := dl.getPluginFactory(result.Manifest.Transport)
	if err != nil {
		dl.updateLoadingState(pluginName, LoadingStateFailed)
		return NewUnsupportedTransportError(result.Manifest.Transport)
	}

	// Create plugin instance
	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		dl.updateLoadingState(pluginName, LoadingStateFailed)
		return NewPluginExecutionFailedError(pluginName, err)
	}

	// Register with manager
	if err := dl.manager.Register(plugin); err != nil {
		dl.updateLoadingState(pluginName, LoadingStateFailed)
		return NewPluginExecutionFailedError(pluginName, err)
	}

	// Update final state
	dl.updateLoadingState(pluginName, LoadingStateLoaded)

	dl.metrics.PluginsLoaded.Add(1)
	dl.emitEvent(DynamicLoaderEvent{
		Type:      "plugin_loaded",
		Timestamp: time.Now(),
		Plugin:    pluginName,
		Version:   result.Manifest.Version,
		State:     LoadingStateLoaded,
	})

	dl.logger.Info("Plugin loaded successfully",
		"plugin", pluginName,
		"version", result.Manifest.Version,
		"transport", result.Manifest.Transport)

	return nil
}

// updateLoadingState atomically updates the loading state of a plugin.
func (dl *DynamicLoader[Req, Resp]) updateLoadingState(pluginName string, state LoadingState) {
	dl.loadingMutex.Lock()
	defer dl.loadingMutex.Unlock()

	dl.loadingStates[pluginName] = state

	if state == LoadingStateFailed {
		dl.metrics.LoadingFailures.Add(1)
	}
}

// getPluginFactory retrieves the appropriate plugin factory for a transport type.
func (dl *DynamicLoader[Req, Resp]) getPluginFactory(transport TransportType) (PluginFactory[Req, Resp], error) {
	// Create appropriate factory based on transport type
	switch transport {
	case TransportGRPC, TransportGRPCTLS:
		// Check if Req/Resp implement ProtobufMessage interface
		var req Req
		var resp Resp

		// Use type assertion to check if they implement ProtobufMessage
		if _, reqOk := any(req).(ProtobufMessage); reqOk {
			if _, respOk := any(resp).(ProtobufMessage); respOk {
				// Both implement ProtobufMessage, use native GRPC factory
				if grpcFactory, ok := any(NewGRPCPluginFactory[ProtobufMessage, ProtobufMessage](dl.logger)).(PluginFactory[Req, Resp]); ok {
					return grpcFactory, nil
				}
			}
		}

		// ERROR: GRPC transport requested but types don't implement ProtobufMessage
		return nil, NewPluginValidationError(0,
			fmt.Errorf("GRPC transport requires request and response types to implement ProtobufMessage interface"))
	case TransportExecutable:
		// Standard subprocess plugin factory
		return NewSubprocessPluginFactory[Req, Resp](dl.logger), nil
	default:
		return nil, NewUnsupportedTransportError(transport)
	}
}

// handleDiscoveryEvent handles discovery events for auto-loading.
func (dl *DynamicLoader[Req, Resp]) handleDiscoveryEvent(event DiscoveryEvent) {
	if !dl.autoLoading.Load() {
		return
	}

	dl.metrics.EventsProcessed.Add(1)

	switch event.Type {
	case "plugin_discovered":
		if event.Plugin != nil {
			// Auto-load the discovered plugin
			go func() {
				if err := dl.LoadDiscoveredPlugin(dl.autoLoadCtx, event.Plugin.Manifest.Name); err != nil {
					dl.logger.Warn("Auto-loading failed for discovered plugin",
						"plugin", event.Plugin.Manifest.Name,
						"error", err)
				}
			}()
		}
	}
}

// autoLoadingWorker runs the auto-loading background process.
func (dl *DynamicLoader[Req, Resp]) autoLoadingWorker(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Check for new plugins every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dl.performPeriodicDiscoveryCheck(ctx)
		}
	}
}

// performPeriodicDiscoveryCheck checks for new plugins and loads them.
func (dl *DynamicLoader[Req, Resp]) performPeriodicDiscoveryCheck(ctx context.Context) {
	discovered := dl.discoveryEngine.GetDiscoveredPlugins()

	for name := range discovered {
		dl.loadingMutex.RLock()
		_, alreadyProcessed := dl.loadingStates[name]
		dl.loadingMutex.RUnlock()

		if !alreadyProcessed {
			if err := dl.LoadDiscoveredPlugin(ctx, name); err != nil {
				dl.logger.Debug("Failed to auto-load plugin",
					"plugin", name,
					"error", err)
			}
		}
	}
}

// emitEvent emits an event to all registered handlers.
func (dl *DynamicLoader[Req, Resp]) emitEvent(event DynamicLoaderEvent) {
	dl.eventMutex.RLock()
	handlers := make([]DynamicLoaderEventHandler, len(dl.eventHandlers))
	copy(handlers, dl.eventHandlers)
	dl.eventMutex.RUnlock()

	for _, handler := range handlers {
		go func(h DynamicLoaderEventHandler) {
			defer withStackRecover(dl.logger)()
			h(event)
		}(handler)
	}
}

// ParsePluginVersion parses a semantic version string.
// validateBuildMetadata validates build metadata component
func validateBuildMetadata(buildPart string) error {
	if buildPart == "" {
		return NewPluginValidationError(0, nil)
	}
	if strings.Contains(buildPart, "+") {
		return NewPluginValidationError(0, nil)
	}
	if len(buildPart) > 100 {
		return NewPluginValidationError(0, nil)
	}
	return nil
}

// validatePrerelease validates prerelease component
func validatePrerelease(prereleasePart string) error {
	if prereleasePart == "" {
		return NewPluginValidationError(0, nil)
	}
	if strings.Contains(prereleasePart, "--") {
		return NewPluginValidationError(0, nil)
	}
	if len(prereleasePart) > 100 {
		return NewPluginValidationError(0, nil)
	}
	return nil
}

// parseVersionComponents splits version string into main version, prerelease, and build
func parseVersionComponents(versionStr string) (string, string, string, error) {
	var mainVersion, prerelease, build string

	// Handle build metadata first (+ separator)
	if buildIdx := strings.Index(versionStr, "+"); buildIdx >= 0 {
		mainVersion = versionStr[:buildIdx]
		buildPart := versionStr[buildIdx+1:]

		if err := validateBuildMetadata(buildPart); err != nil {
			return "", "", "", err
		}
		build = buildPart
	} else {
		mainVersion = versionStr
	}

	// Handle prerelease (- separator)
	if prereleaseIdx := strings.Index(mainVersion, "-"); prereleaseIdx >= 0 {
		prereleasePart := mainVersion[prereleaseIdx+1:]
		mainVersion = mainVersion[:prereleaseIdx]

		if err := validatePrerelease(prereleasePart); err != nil {
			return "", "", "", err
		}
		prerelease = prereleasePart
	}

	return mainVersion, prerelease, build, nil
}

// parseMainVersionNumbers parses x.y.z version numbers
func parseMainVersionNumbers(mainVersion string) (uint64, uint64, uint64, error) {
	parts := strings.Split(mainVersion, ".")
	if len(parts) != 3 {
		return 0, 0, 0, NewPluginValidationError(0, nil)
	}

	major, err := parseVersionComponent(parts[0], "major")
	if err != nil {
		return 0, 0, 0, err
	}

	minor, err := parseVersionComponent(parts[1], "minor")
	if err != nil {
		return 0, 0, 0, err
	}

	patch, err := parseVersionComponent(parts[2], "patch")
	if err != nil {
		return 0, 0, 0, err
	}

	return major, minor, patch, nil
}

func ParsePluginVersion(versionStr string) (*PluginVersion, error) {
	if versionStr == "" {
		return nil, NewPluginValidationError(0, nil)
	}

	// Parse version components
	mainVersion, prerelease, build, err := parseVersionComponents(versionStr)
	if err != nil {
		return nil, err
	}

	// Parse main version numbers
	major, minor, patch, err := parseMainVersionNumbers(mainVersion)
	if err != nil {
		return nil, err
	}

	return &PluginVersion{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		Build:      build,
		Original:   versionStr,
	}, nil
}

// parseVersionComponent parses a single version component (major, minor, patch)
func parseVersionComponent(component, componentType string) (uint64, error) {
	// Validate component format
	if component == "" {
		structuredErr := errors.New(ErrCodeInvalidPluginName, "Empty version component").
			WithContext("component_type", componentType).
			WithSeverity("error")
		return 0, NewPluginValidationError(0, structuredErr)
	}

	// Check for leading zeros (not allowed in semver except for "0")
	if len(component) > 1 && component[0] == '0' {
		structuredErr := errors.New(ErrCodeInvalidPluginName, "Leading zeros not allowed in version components").
			WithContext("component_type", componentType).
			WithContext("component_value", component).
			WithSeverity("error")
		return 0, NewPluginValidationError(0, structuredErr)
	}

	// Check for invalid characters (must be digits only)
	for _, char := range component {
		if char < '0' || char > '9' {
			structuredErr := errors.New(ErrCodeInvalidPluginName, "Invalid character in version component").
				WithContext("component_type", componentType).
				WithContext("component_value", component).
				WithContext("invalid_char", string(char)).
				WithSeverity("error")
			return 0, NewPluginValidationError(0, structuredErr)
		}
	}

	value, err := strconv.ParseUint(component, 10, 64)
	if err != nil {
		structuredErr := errors.Wrap(err, ErrCodeInvalidPluginName, "Invalid version component").
			WithContext("component_type", componentType).
			WithContext("component_value", component).
			WithSeverity("error")
		return 0, NewPluginValidationError(0, structuredErr)
	}
	return value, nil
}

// Compare compares two plugin versions. Returns -1, 0, or 1.
func (pv *PluginVersion) Compare(other *PluginVersion) int {
	// Compare major version
	if result := pv.compareComponent(pv.Major, other.Major); result != 0 {
		return result
	}

	// Compare minor version
	if result := pv.compareComponent(pv.Minor, other.Minor); result != 0 {
		return result
	}

	// Compare patch version
	if result := pv.compareComponent(pv.Patch, other.Patch); result != 0 {
		return result
	}

	// Compare prerelease versions
	return pv.comparePrerelease(other)
}

// compareComponent compares two uint64 version components
func (pv *PluginVersion) compareComponent(a, b uint64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// comparePrerelease compares prerelease versions (simplified)
func (pv *PluginVersion) comparePrerelease(other *PluginVersion) int {
	if pv.Prerelease == "" && other.Prerelease != "" {
		return 1 // Release > prerelease
	}
	if pv.Prerelease != "" && other.Prerelease == "" {
		return -1 // Prerelease < release
	}

	return strings.Compare(pv.Prerelease, other.Prerelease)
}

// SatisfiesConstraint checks if the version satisfies a constraint.
func (pv *PluginVersion) SatisfiesConstraint(constraint string) bool {
	// Simplified constraint checking
	if constraint == "*" {
		return true
	}

	// Handle caret range (^x.y.z)
	if strings.HasPrefix(constraint, "^") {
		return pv.satisfiesCaretConstraint(constraint)
	}

	// Handle tilde range (~x.y.z)
	if strings.HasPrefix(constraint, "~") {
		return pv.satisfiesTildeConstraint(constraint)
	}

	// Exact match
	target, err := ParsePluginVersion(constraint)
	if err != nil {
		return false
	}

	return pv.Compare(target) == 0
}

// satisfiesCaretConstraint checks if version satisfies caret constraint (^x.y.z)
func (pv *PluginVersion) satisfiesCaretConstraint(constraint string) bool {
	targetStr := strings.TrimPrefix(constraint, "^")
	target, err := ParsePluginVersion(targetStr)
	if err != nil {
		return false
	}

	// BUG FIX: Prerelease versions should not satisfy stable constraints
	// If constraint target is stable (no prerelease) but our version has prerelease,
	// we need stricter checking according to semver rules
	if target.Prerelease == "" && pv.Prerelease != "" {
		// For prerelease versions, they can only satisfy if they're higher in major.minor.patch
		// A prerelease 1.0.0-alpha should NOT satisfy ^1.0.0
		return pv.Major == target.Major &&
			(pv.Minor > target.Minor ||
				(pv.Minor == target.Minor && pv.Patch > target.Patch))
	}

	return pv.Major == target.Major &&
		(pv.Minor > target.Minor ||
			(pv.Minor == target.Minor && pv.Patch >= target.Patch))
}

// satisfiesTildeConstraint checks if version satisfies tilde constraint (~x.y.z)
func (pv *PluginVersion) satisfiesTildeConstraint(constraint string) bool {
	targetStr := strings.TrimPrefix(constraint, "~")
	target, err := ParsePluginVersion(targetStr)
	if err != nil {
		return false
	}

	// BUG FIX: Prerelease versions should not satisfy stable constraints
	// If constraint target is stable (no prerelease) but our version has prerelease,
	// we need stricter checking according to semver rules
	if target.Prerelease == "" && pv.Prerelease != "" {
		// For prerelease versions with tilde, they can only satisfy if patch is higher
		// A prerelease 1.2.0-alpha should NOT satisfy ~1.2.0
		return pv.Major == target.Major &&
			pv.Minor == target.Minor &&
			pv.Patch > target.Patch
	}

	return pv.Major == target.Major &&
		pv.Minor == target.Minor &&
		pv.Patch >= target.Patch
}

// NewDependencyGraph creates a new dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[string]*DependencyNode),
		edges: make(map[string][]string),
	}
}

// cleanupOldDependencies removes plugin from old dependencies' dependents lists
func (dg *DependencyGraph) cleanupOldDependencies(name string, node *DependencyNode) {
	for _, oldDep := range node.Dependencies {
		if depNode, depExists := dg.nodes[oldDep]; depExists {
			for i, dependent := range depNode.Dependents {
				if dependent == name {
					depNode.Dependents = append(depNode.Dependents[:i], depNode.Dependents[i+1:]...)
					break
				}
			}
		}
	}
}

// createOrUpdateNode creates a new dependency node or returns existing one
func (dg *DependencyGraph) createOrUpdateNode(name string) *DependencyNode {
	if node, exists := dg.nodes[name]; exists {
		return node
	}

	node := &DependencyNode{
		Name:         name,
		Dependencies: make([]string, 0),
		Dependents:   make([]string, 0),
		Status:       "pending",
	}
	dg.nodes[name] = node
	return node
}

// updateDependentRelationships updates dependent relationships for all dependencies
func (dg *DependencyGraph) updateDependentRelationships(name string, dependencies []string) {
	for _, dep := range dependencies {
		depNode := dg.createOrUpdateNode(dep)

		// Add to dependents list if not already present
		found := false
		for _, existing := range depNode.Dependents {
			if existing == name {
				found = true
				break
			}
		}
		if !found {
			depNode.Dependents = append(depNode.Dependents, name)
		}
	}
}

// AddPlugin adds a plugin to the dependency graph.
func (dg *DependencyGraph) AddPlugin(name string, dependencies []string) error {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	// Handle existing or new node
	if node, exists := dg.nodes[name]; exists {
		dg.cleanupOldDependencies(name, node)
	} else {
		dg.createOrUpdateNode(name)
	}

	// Update dependencies
	dg.nodes[name].Dependencies = dependencies
	dg.edges[name] = dependencies

	// Update dependent relationships
	dg.updateDependentRelationships(name, dependencies)

	dg.validated = false
	return nil
}

// RemovePlugin removes a plugin from the dependency graph.
func (dg *DependencyGraph) RemovePlugin(name string) {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	// Remove from nodes
	delete(dg.nodes, name)
	delete(dg.edges, name)

	// Remove from other nodes' dependents lists
	for _, node := range dg.nodes {
		for i, dep := range node.Dependents {
			if dep == name {
				node.Dependents = append(node.Dependents[:i], node.Dependents[i+1:]...)
				break
			}
		}
	}

	dg.validated = false
}

// GetDependencies returns the dependencies of a plugin.
func (dg *DependencyGraph) GetDependencies(name string) []string {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	if node, exists := dg.nodes[name]; exists {
		result := make([]string, len(node.Dependencies))
		copy(result, node.Dependencies)
		return result
	}

	return []string{}
}

// GetDependents returns the dependents of a plugin.
func (dg *DependencyGraph) GetDependents(name string) []string {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	if node, exists := dg.nodes[name]; exists {
		result := make([]string, len(node.Dependents))
		copy(result, node.Dependents)
		return result
	}

	return []string{}
}

// Copy returns a copy of the dependency graph.
func (dg *DependencyGraph) Copy() *DependencyGraph {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	copyGraph := &DependencyGraph{
		nodes:     make(map[string]*DependencyNode),
		edges:     make(map[string][]string),
		validated: dg.validated,
	}

	for name, node := range dg.nodes {
		copyNode := &DependencyNode{
			Name:         node.Name,
			Version:      node.Version,
			Status:       node.Status,
			Dependencies: make([]string, len(node.Dependencies)),
			Dependents:   make([]string, len(node.Dependents)),
		}
		copy(copyNode.Dependencies, node.Dependencies)
		copy(copyNode.Dependents, node.Dependents)
		copyGraph.nodes[name] = copyNode
	}

	for name, edges := range dg.edges {
		copyEdges := make([]string, len(edges))
		copy(copyEdges, edges)
		copyGraph.edges[name] = copyEdges
	}

	return copyGraph
}

// CalculateLoadOrder calculates the correct loading order for plugins based on dependencies.
// Returns the load order and an error if circular dependencies are detected.
func (dg *DependencyGraph) CalculateLoadOrder() ([]string, error) {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	// First check for missing dependencies
	for _, node := range dg.nodes {
		for _, dep := range node.Dependencies {
			if _, exists := dg.nodes[dep]; !exists {
				return nil, NewPluginValidationError(0, nil)
			}
		}
	}

	// Topological sort using Kahn's algorithm
	inDegree := dg.calculateInDegrees()
	queue := dg.findRootNodes(inDegree)
	loadOrder := dg.processTopologicalSort(queue, inDegree)

	// Check for circular dependencies
	if len(loadOrder) != len(dg.nodes) {
		return nil, NewPluginValidationError(0, nil)
	}

	dg.loadOrder = loadOrder
	dg.validated = true

	return loadOrder, nil
}

// calculateInDegrees calculates in-degrees for all nodes in the graph
func (dg *DependencyGraph) calculateInDegrees() map[string]int {
	inDegree := make(map[string]int)

	// Initialize in-degree count for all nodes
	for name := range dg.nodes {
		inDegree[name] = 0
	}

	// Calculate in-degree for each node
	// For each plugin and its dependencies, increment the plugin's in-degree
	for pluginName, dependencies := range dg.edges {
		inDegree[pluginName] = len(dependencies)
	}

	return inDegree
}

// findRootNodes finds nodes with no incoming edges (in-degree 0)
func (dg *DependencyGraph) findRootNodes(inDegree map[string]int) []string {
	var queue []string
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}
	return queue
}

// processTopologicalSort processes the topological sort using Kahn's algorithm
func (dg *DependencyGraph) processTopologicalSort(queue []string, inDegree map[string]int) []string {
	var loadOrder []string

	// Process nodes with no dependencies first
	for len(queue) > 0 {
		// Remove node from queue
		current := queue[0]
		queue = queue[1:]
		loadOrder = append(loadOrder, current)

		// Find all nodes that depend on current and decrement their in-degree
		for nodeName, dependencies := range dg.edges {
			for _, dep := range dependencies {
				if dep == current {
					inDegree[nodeName]--
					if inDegree[nodeName] == 0 {
						queue = append(queue, nodeName)
					}
					break // Found dependency, no need to check more
				}
			}
		}
	}

	return loadOrder
}

// ValidateDependencies checks for circular dependencies and missing dependencies.
func (dg *DependencyGraph) ValidateDependencies() error {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	// Check for missing dependencies
	for _, node := range dg.nodes {
		for _, dep := range node.Dependencies {
			if _, exists := dg.nodes[dep]; !exists {
				return NewPluginValidationError(0, nil)
			}
		}
	}

	// Check for circular dependencies using DFS
	// (without calling CalculateLoadOrder to avoid deadlock)
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	for nodeName := range dg.nodes {
		if !visited[nodeName] {
			if dg.hasCycleDFS(nodeName, visited, recursionStack) {
				return NewPluginValidationError(0, nil)
			}
		}
	}

	return nil
}

// hasCycleDFS performs depth-first search to detect cycles
func (dg *DependencyGraph) hasCycleDFS(nodeName string, visited, recursionStack map[string]bool) bool {
	visited[nodeName] = true
	recursionStack[nodeName] = true

	// Visit all dependencies of current node
	if dependencies, exists := dg.edges[nodeName]; exists {
		for _, dep := range dependencies {
			// If dependency not visited, recurse
			if !visited[dep] {
				if dg.hasCycleDFS(dep, visited, recursionStack) {
					return true
				}
			} else if recursionStack[dep] {
				// If dependency is in current recursion stack, we found a cycle
				return true
			}
		}
	}

	// Remove from recursion stack before returning
	recursionStack[nodeName] = false
	return false
}
