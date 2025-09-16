# Dynamic Loading Framework

The Dynamic Loading Framework in go-plugins provides intelligent plugin lifecycle management with hot-loading capabilities, version compatibility checking, automatic dependency resolution, and real-time discovery event notifications.

## Table of Contents

- [Overview](#overview)
- [Core Components](#core-components)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Plugin Manifests](#plugin-manifests)
- [Version Management](#version-management)
- [Dependency Resolution](#dependency-resolution)
- [Discovery Engine](#discovery-engine)
- [API Reference](#api-reference)
- [Best Practices](#best-practices)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Overview

The Dynamic Loading Framework enables applications to:

- **Discover plugins automatically** from configured sources (filesystem, network, service registry)
- **Load plugins dynamically** without service restart or downtime
- **Manage dependencies** automatically with topological sorting and circular dependency detection
- **Enforce version compatibility** using semantic versioning constraints
- **Monitor loading status** with comprehensive metrics and event notifications
- **Handle failures gracefully** with automatic rollback and error recovery

### Key Benefits

- **Zero-downtime plugin updates**: Load new plugin versions without service interruption
- **Reduced operational complexity**: Automatic discovery eliminates manual configuration
- **Enhanced reliability**: Built-in dependency resolution prevents loading order issues
- **Improved observability**: Real-time metrics and events for all loading operations
- **Enterprise-ready**: Production-tested with comprehensive error handling

## Core Components

### DynamicLoader

The `DynamicLoader` is the central component that orchestrates plugin loading operations.

```go
type DynamicLoader[Req, Resp any] struct {
    // Core dependencies
    manager         *Manager[Req, Resp]
    discoveryEngine *DiscoveryEngine
    logger          Logger

    // Version compatibility
    compatibilityRules map[string]string
    minSystemVersion   *PluginVersion

    // Dependency management
    dependencyGraph *DependencyGraph
    loadingStates   map[string]LoadingState

    // Auto-loading state
    autoLoading atomic.Bool
    
    // Performance metrics
    metrics DynamicLoaderMetrics
}
```

### DiscoveryEngine

The `DiscoveryEngine` handles plugin discovery from multiple sources.

```go
type DiscoveryEngine struct {
    config ExtendedDiscoveryConfig
    logger Logger
    
    // Discovery state
    discoveredPlugins map[string]*DiscoveryResult
    eventHandlers     []DiscoveryEventHandler
}
```

### DependencyGraph

The `DependencyGraph` manages plugin dependencies and loading order.

```go
type DependencyGraph struct {
    nodes     map[string]*DependencyNode
    edges     map[string][]string
    loadOrder []string
}
```

## Getting Started

### Basic Setup

```go
package main

import (
    "context"
    "log/slog"
    "os"
    
    "github.com/agilira/go-plugins"
)

func main() {
    // Create manager with dynamic loading enabled
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    manager := goplugins.NewManager[MyRequest, MyResponse](logger)
    
    // The manager automatically initializes dynamic loading components
    // - DynamicLoader
    // - DiscoveryEngine  
    // - DependencyGraph
    
    ctx := context.Background()
    
    // Enable automatic loading
    if err := manager.EnableDynamicLoading(ctx); err != nil {
        log.Fatalf("Failed to enable dynamic loading: %v", err)
    }
    
    // Set compatibility rules
    manager.SetPluginCompatibilityRule("auth-plugin", "^1.0.0")
    
    // Manual plugin loading
    if err := manager.LoadDiscoveredPlugin(ctx, "specific-plugin"); err != nil {
        log.Printf("Failed to load plugin: %v", err)
    }
}
```

### Integration with Existing Code

The dynamic loading framework integrates seamlessly with existing go-plugins applications:

```go
// Existing manager setup
manager := goplugins.NewManager[Request, Response](logger)

// Register factories (existing code unchanged)
manager.RegisterFactory("http", httpFactory)
manager.RegisterFactory("grpc", grpcFactory)

// Load static configuration (existing code unchanged)
if err := manager.LoadFromConfig(staticConfig); err != nil {
    log.Fatal(err)
}

// Add dynamic loading (new capability)
if err := manager.EnableDynamicLoading(ctx); err != nil {
    log.Fatal(err)
}

// Both static and dynamic plugins now work together
response, err := manager.Execute(ctx, "any-plugin", request)
```

## Configuration

### Discovery Configuration

```go
type ExtendedDiscoveryConfig struct {
    DiscoveryConfig // Base configuration
    
    // Filesystem discovery
    SearchPaths       []string      `json:"search_paths"`
    FilePatterns      []string      `json:"file_patterns"`
    MaxDepth          int           `json:"max_depth"`
    FollowSymlinks    bool          `json:"follow_symlinks"`
    
    // Network discovery
    EnableMDNS        bool          `json:"enable_mdns"`
    MDNSService       string        `json:"mdns_service"`
    NetworkInterfaces []string      `json:"network_interfaces"`
    DiscoveryTimeout  time.Duration `json:"discovery_timeout"`
    
    // Filtering and validation
    AllowedTransports    []TransportType `json:"allowed_transports"`
    RequiredCapabilities []string        `json:"required_capabilities"`
    ExcludePaths         []string        `json:"exclude_paths"`
    ValidateManifests    bool            `json:"validate_manifests"`
}
```

### Example Configuration

```yaml
# config.yaml
discovery:
  enabled: true
  directories:
    - "/opt/plugins"
    - "./plugins"
    - "/usr/local/lib/plugins"
  patterns:
    - "*.json"
    - "plugin.yaml"
    - "manifest.yml"
  watch_mode: true

extended_discovery:
  search_paths:
    - "/opt/plugins"
    - "/usr/local/plugins"
  file_patterns:
    - "plugin.json"
    - "manifest.yaml"
    - "*.plugin"
  max_depth: 5
  follow_symlinks: false
  
  # Network discovery
  enable_mdns: true
  mdns_service: "_goplugins._tcp"
  network_interfaces: ["eth0", "wlan0"]
  discovery_timeout: "10s"
  
  # Filtering
  allowed_transports: ["https", "grpc", "grpc+tls"]
  required_capabilities: ["authentication"]
  exclude_paths: ["/tmp", "*.test"]
  validate_manifests: true
```

## Plugin Manifests

Plugin manifests define plugin metadata, requirements, and configuration.

### Complete Manifest Example

```json
{
  "name": "auth-service",
  "version": "1.2.3-beta.1+build.456",
  "description": "Enterprise authentication service",
  
  "transport": "https",
  "endpoint": "https://auth.company.com/api/v1",
  
  "capabilities": [
    "authentication",
    "user-management", 
    "session-management"
  ],
  
  "requirements": {
    "min_go_version": "1.21",
    "min_system_version": "1.0.0",
    "required_plugins": [
      "logging-service",
      "config-service"
    ],
    "optional_plugins": [
      "metrics-collector"
    ]
  },
  
  "auth": {
    "type": "bearer",
    "token": "${AUTH_TOKEN}",
    "headers": {
      "X-API-Version": "v1"
    }
  },
  
  "health_check": {
    "enabled": true,
    "endpoint": "/health",
    "interval": "30s", 
    "timeout": "5s",
    "failure_limit": 3
  },
  
  "load_balancing": {
    "algorithm": "round_robin",
    "weight": 100
  },
  
  "circuit_breaker": {
    "enabled": true,
    "failure_threshold": 5,
    "recovery_timeout": "30s"
  },
  
  "metadata": {
    "maintainer": "security-team@company.com",
    "repository": "https://github.com/company/auth-service",
    "documentation": "https://docs.company.com/auth-service",
    "tags": ["auth", "security", "enterprise"],
    "license": "MIT"
  }
}
```

### Minimal Manifest Example

```json
{
  "name": "simple-plugin",
  "version": "1.0.0", 
  "transport": "http",
  "endpoint": "http://localhost:8080"
}
```

## Version Management

### Semantic Versioning Support

The framework uses semantic versioning (semver) for version compatibility checking:

```go
// Version parsing
version, err := goplugins.ParsePluginVersion("1.2.3-beta.1+build.123")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Major: %d, Minor: %d, Patch: %d\n", 
    version.Major, version.Minor, version.Patch)
fmt.Printf("Prerelease: %s, Build: %s\n", 
    version.Prerelease, version.Build)
```

### Version Constraints

```go
// Caret constraints (compatible within major version)
manager.SetPluginCompatibilityRule("auth-plugin", "^1.0.0")
// Accepts: 1.0.0, 1.1.0, 1.9.9
// Rejects: 2.0.0, 0.9.9

// Tilde constraints (compatible within minor version) 
manager.SetPluginCompatibilityRule("log-plugin", "~1.2.0")
// Accepts: 1.2.0, 1.2.5, 1.2.99
// Rejects: 1.3.0, 1.1.9

// Exact version matching
manager.SetPluginCompatibilityRule("critical-plugin", "2.1.4")
// Accepts: 2.1.4 only

// Wildcard (any version - use with caution)
manager.SetPluginCompatibilityRule("dev-plugin", "*")
// Accepts: any version
```

### System Version Requirements

```go
// Set minimum system version
loader.SetMinSystemVersion("2.0.0")

// Plugins with higher min_system_version requirements will be rejected
// Example: Plugin requires "2.1.0" but system is "2.0.0" → rejection
```

## Dependency Resolution

### Dependency Graph Operations

```go
// Create and populate dependency graph
graph := goplugins.NewDependencyGraph()

// Add plugins with dependencies
err := graph.AddPlugin("auth", []string{"logging", "config"})
err = graph.AddPlugin("api", []string{"auth"})
err = graph.AddPlugin("logging", []string{})
err = graph.AddPlugin("config", []string{})

// Calculate loading order
order, err := graph.CalculateLoadOrder()
if err != nil {
    log.Fatalf("Circular dependency detected: %v", err)
}

fmt.Printf("Load order: %v\n", order)
// Output: [logging config auth api]
```

### Circular Dependency Detection

```go
// This will create a circular dependency: A → B → C → A
graph.AddPlugin("plugin-a", []string{"plugin-c"})
graph.AddPlugin("plugin-b", []string{"plugin-a"})
graph.AddPlugin("plugin-c", []string{"plugin-b"})

_, err := graph.CalculateLoadOrder()
if err != nil {
    log.Printf("Detected circular dependency: %v", err)
    // Handle circular dependency error
}
```

### Dependency Management in Practice

```go
// The dynamic loader automatically handles dependencies
err := manager.LoadDiscoveredPlugin(ctx, "api-gateway")

// This single call will:
// 1. Check dependencies of api-gateway
// 2. Load required dependencies first (auth, logging, config)
// 3. Load api-gateway last
// 4. Handle any loading failures with proper rollback
```

## Discovery Engine

### Filesystem Discovery

The discovery engine automatically scans configured directories for plugin manifests:

```go
// Configure filesystem discovery
config := goplugins.ExtendedDiscoveryConfig{
    SearchPaths: []string{
        "/opt/plugins",           // System plugins
        "/usr/local/plugins",     // Local plugins  
        "./plugins",              // Application plugins
        os.ExpandEnv("$HOME/.plugins"), // User plugins
    },
    FilePatterns: []string{
        "plugin.json",
        "manifest.yaml", 
        "*.plugin",
    },
    MaxDepth: 3,                 // Subdirectory scan depth
    FollowSymlinks: false,       // Security: don't follow symlinks
    ExcludePaths: []string{
        "*.tmp",
        "backup/*",
        ".git/*",
    },
}
```

### Network Discovery (Future)

```go
// Network-based plugin discovery (implementation planned)
config := goplugins.ExtendedDiscoveryConfig{
    EnableMDNS: true,
    MDNSService: "_goplugins._tcp",
    NetworkInterfaces: []string{"eth0", "wlan0"},
    DiscoveryTimeout: 10 * time.Second,
}
```

### Discovery Events

```go
// Register for discovery events
manager.discoveryEngine.AddEventHandler(func(event goplugins.DiscoveryEvent) {
    switch event.Type {
    case "plugin_discovered":
        log.Printf("New plugin found: %s v%s", 
            event.Plugin.Manifest.Name,
            event.Plugin.Manifest.Version)
            
    case "plugin_updated":
        log.Printf("Plugin updated: %s", event.Plugin.Manifest.Name)
        
    case "plugin_removed":
        log.Printf("Plugin removed: %s", event.Plugin.Manifest.Name)
    }
})
```

## API Reference

### Manager Methods

```go
// Enable/disable dynamic loading
func (m *Manager[Req, Resp]) EnableDynamicLoading(ctx context.Context) error
func (m *Manager[Req, Resp]) DisableDynamicLoading() error

// Manual plugin loading
func (m *Manager[Req, Resp]) LoadDiscoveredPlugin(ctx context.Context, pluginName string) error
func (m *Manager[Req, Resp]) UnloadDynamicPlugin(ctx context.Context, pluginName string, force bool) error

// Configuration and rules
func (m *Manager[Req, Resp]) SetPluginCompatibilityRule(pluginName, constraint string)
func (m *Manager[Req, Resp]) ConfigureDiscovery(config ExtendedDiscoveryConfig) error

// Status and monitoring
func (m *Manager[Req, Resp]) GetDiscoveredPlugins() map[string]*DiscoveryResult
func (m *Manager[Req, Resp]) GetDynamicLoadingStatus() map[string]LoadingState
func (m *Manager[Req, Resp]) GetDependencyGraph() *DependencyGraph
func (m *Manager[Req, Resp]) GetDynamicLoadingMetrics() DynamicLoaderMetrics
```

### DynamicLoader Methods

```go
// Core operations
func (dl *DynamicLoader[Req, Resp]) EnableAutoLoading(ctx context.Context) error
func (dl *DynamicLoader[Req, Resp]) DisableAutoLoading() error
func (dl *DynamicLoader[Req, Resp]) LoadDiscoveredPlugin(ctx context.Context, pluginName string) error
func (dl *DynamicLoader[Req, Resp]) UnloadPlugin(ctx context.Context, pluginName string, force bool) error

// Configuration
func (dl *DynamicLoader[Req, Resp]) SetCompatibilityRule(pluginName, constraint string)
func (dl *DynamicLoader[Req, Resp]) SetMinSystemVersion(version string) error

// Monitoring
func (dl *DynamicLoader[Req, Resp]) GetLoadingStatus() map[string]LoadingState
func (dl *DynamicLoader[Req, Resp]) GetDependencyGraph() *DependencyGraph
func (dl *DynamicLoader[Req, Resp]) AddEventHandler(handler DynamicLoaderEventHandler)
func (dl *DynamicLoader[Req, Resp]) GetMetrics() DynamicLoaderMetrics

// Lifecycle
func (dl *DynamicLoader[Req, Resp]) Close() error
```

### Loading States

```go
type LoadingState string

const (
    LoadingStatePending    LoadingState = "pending"    // Waiting to be loaded
    LoadingStateLoading    LoadingState = "loading"    // Currently being loaded
    LoadingStateLoaded     LoadingState = "loaded"     // Successfully loaded
    LoadingStateFailed     LoadingState = "failed"     // Loading failed
    LoadingStateUnloading  LoadingState = "unloading"  // Being unloaded
)
```

### Metrics

```go
type DynamicLoaderMetrics struct {
    PluginsLoaded         atomic.Int64  // Total plugins loaded
    PluginsUnloaded       atomic.Int64  // Total plugins unloaded
    LoadingFailures       atomic.Int64  // Total loading failures
    DependencyResolutions atomic.Int64  // Dependency resolutions performed
    VersionConflicts      atomic.Int64  // Version compatibility failures
    EventsProcessed       atomic.Int64  // Discovery events processed
}
```

## Best Practices

### Plugin Organization

```
/opt/plugins/
├── production/
│   ├── auth-service/
│   │   ├── plugin.json
│   │   └── README.md
│   └── logging-service/
│       ├── plugin.json
│       └── config/
├── staging/
│   └── new-feature-plugin/
│       └── plugin.json
└── development/
    └── experimental-plugin/
        └── plugin.json
```

### Manifest Management

1. **Use semantic versioning** for all plugin versions
2. **Specify precise dependencies** to avoid compatibility issues
3. **Include comprehensive metadata** for maintainability
4. **Validate manifests** before deployment
5. **Use environment variables** for sensitive configuration

### Version Strategy

```go
// Production: Use caret constraints for automatic compatible updates
manager.SetPluginCompatibilityRule("auth-service", "^2.1.0")

// Staging: Use tilde constraints for patch-level updates only  
manager.SetPluginCompatibilityRule("auth-service", "~2.1.0")

// Critical systems: Use exact versions
manager.SetPluginCompatibilityRule("payment-processor", "3.2.1")
```

### Error Handling

```go
// Always handle loading errors gracefully
if err := manager.LoadDiscoveredPlugin(ctx, "plugin-name"); err != nil {
    var versionErr *VersionCompatibilityError
    var depErr *DependencyError
    
    switch {
    case errors.As(err, &versionErr):
        log.Printf("Version incompatibility: %v", versionErr)
        // Maybe try loading a different version
        
    case errors.As(err, &depErr):
        log.Printf("Dependency issue: %v", depErr)
        // Maybe load dependencies first
        
    default:
        log.Printf("Generic loading error: %v", err)
        // Fallback strategy
    }
}
```

### Performance Optimization

```go
// Batch operations when possible
var plugins []string = []string{"auth", "logging", "metrics"}

for _, plugin := range plugins {
    if err := manager.LoadDiscoveredPlugin(ctx, plugin); err != nil {
        log.Printf("Failed to load %s: %v", plugin, err)
        // Continue with other plugins
    }
}

// Monitor metrics regularly
go func() {
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        metrics := manager.GetDynamicLoadingMetrics()
        log.Printf("Dynamic loading stats - Loaded: %d, Failures: %d", 
            metrics.PluginsLoaded.Load(), 
            metrics.LoadingFailures.Load())
    }
}()
```

## Examples

### Complete Application Example

```go
package main

import (
    "context"
    "log/slog"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "github.com/agilira/go-plugins"
)

type AuthRequest struct {
    Token string `json:"token"`
    User  string `json:"user"`
}

type AuthResponse struct {
    Valid   bool   `json:"valid"`
    Message string `json:"message"`
}

func main() {
    // Setup logging
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))
    
    // Create manager with dynamic loading
    manager := goplugins.NewManager[AuthRequest, AuthResponse](logger)
    
    // Configure discovery
    discoveryConfig := goplugins.ExtendedDiscoveryConfig{
        DiscoveryConfig: goplugins.DiscoveryConfig{
            Enabled:     true,
            Directories: []string{"./plugins", "/opt/plugins"},
            Patterns:    []string{"*.json", "*.yaml"},
            WatchMode:   true,
        },
        SearchPaths:          []string{"./plugins"},
        FilePatterns:         []string{"plugin.json"},
        MaxDepth:             2,
        ValidateManifests:    true,
        AllowedTransports:    []goplugins.TransportType{goplugins.TransportHTTPS},
        RequiredCapabilities: []string{"authentication"},
    }
    
    // Set compatibility rules
    manager.SetPluginCompatibilityRule("auth-service", "^1.0.0")
    manager.SetPluginCompatibilityRule("fallback-auth", "*")
    
    // Enable dynamic loading
    ctx := context.Background()
    if err := manager.EnableDynamicLoading(ctx); err != nil {
        logger.Error("Failed to enable dynamic loading", "error", err)
        os.Exit(1)
    }
    
    // Load critical plugins manually
    criticalPlugins := []string{"auth-service", "logging-service"}
    for _, plugin := range criticalPlugins {
        if err := manager.LoadDiscoveredPlugin(ctx, plugin); err != nil {
            logger.Warn("Failed to load critical plugin", 
                "plugin", plugin, "error", err)
        }
    }
    
    // Start metrics monitoring
    go monitorMetrics(manager, logger)
    
    // Setup graceful shutdown
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    
    logger.Info("Application started with dynamic loading enabled")
    
    // Simulate some requests
    go simulateRequests(manager, logger)
    
    // Wait for shutdown signal
    <-c
    
    logger.Info("Shutting down gracefully...")
    
    // Disable dynamic loading
    if err := manager.DisableDynamicLoading(); err != nil {
        logger.Error("Error disabling dynamic loading", "error", err)
    }
    
    // Shutdown manager
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := manager.Shutdown(shutdownCtx); err != nil {
        logger.Error("Error during shutdown", "error", err)
    }
    
    logger.Info("Shutdown complete")
}

func monitorMetrics(manager *goplugins.Manager[AuthRequest, AuthResponse], logger *slog.Logger) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        // Dynamic loading metrics
        metrics := manager.GetDynamicLoadingMetrics()
        logger.Info("Dynamic loading metrics",
            "plugins_loaded", metrics.PluginsLoaded.Load(),
            "plugins_unloaded", metrics.PluginsUnloaded.Load(),
            "loading_failures", metrics.LoadingFailures.Load(),
            "version_conflicts", metrics.VersionConflicts.Load())
        
        // Loading status
        status := manager.GetDynamicLoadingStatus()
        for plugin, state := range status {
            logger.Debug("Plugin status", "plugin", plugin, "state", state)
        }
        
        // Discovered plugins
        discovered := manager.GetDiscoveredPlugins()
        logger.Info("Discovery status", "discovered_count", len(discovered))
    }
}

func simulateRequests(manager *goplugins.Manager[AuthRequest, AuthResponse], logger *slog.Logger) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        request := AuthRequest{
            Token: "sample-token-123",
            User:  "testuser",
        }
        
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        
        response, err := manager.Execute(ctx, "auth-service", request)
        if err != nil {
            logger.Error("Request failed", "error", err)
        } else {
            logger.Info("Request successful", 
                "valid", response.Valid, 
                "message", response.Message)
        }
        
        cancel()
    }
}
```

### Plugin Development Example

Create a simple authentication plugin:

**plugin.json**:
```json
{
  "name": "simple-auth",
  "version": "1.0.0",
  "description": "Simple authentication service",
  "transport": "http",
  "endpoint": "http://localhost:8080",
  "capabilities": ["authentication"],
  "health_check": {
    "enabled": true,
    "endpoint": "/health",
    "interval": "30s"
  }
}
```

**Plugin service** (separate application):
```go
package main

import (
    "encoding/json"
    "log"
    "net/http"
)

type AuthRequest struct {
    Token string `json:"token"`
    User  string `json:"user"`
}

type AuthResponse struct {
    Valid   bool   `json:"valid"`
    Message string `json:"message"`
}

func main() {
    http.HandleFunc("/", handleAuth)
    http.HandleFunc("/health", handleHealth)
    
    log.Println("Simple auth plugin starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
    var req AuthRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // Simple token validation
    valid := req.Token != "" && len(req.Token) > 10
    
    response := AuthResponse{
        Valid:   valid,
        Message: map[bool]string{true: "Token valid", false: "Token invalid"}[valid],
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}
```

## Troubleshooting

### Common Issues

**1. Plugin Not Discovered**
```
Error: Plugin not found in discovery results
```
- Check if plugin directory is in SearchPaths
- Verify manifest file matches FilePatterns
- Ensure ValidateManifests passes
- Check ExcludePaths doesn't exclude the plugin

**2. Version Compatibility Errors**
```
Error: Version 2.0.0 does not satisfy constraint ^1.0.0
```
- Review compatibility rules with `GetCompatibilityRules()`
- Update plugin to compatible version
- Adjust constraint if appropriate

**3. Dependency Resolution Failures**
```
Error: Failed to load dependency auth-service
```
- Check if all dependencies are discovered
- Verify dependency manifests are valid
- Look for circular dependencies

**4. Loading Timeouts**
```
Error: Context deadline exceeded during loading
```
- Increase context timeout
- Check plugin health endpoint
- Verify network connectivity

### Debug Logging

Enable debug logging to troubleshoot issues:

```go
// Enable debug logging
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

// Add event handlers for detailed information
manager.dynamicLoader.AddEventHandler(func(event goplugins.DynamicLoaderEvent) {
    log.Printf("Dynamic loader event: %s - Plugin: %s - Error: %v", 
        event.Type, event.Plugin, event.Error)
})
```

### Performance Issues

Monitor and optimize performance:

```go
// Check metrics for performance bottlenecks
metrics := manager.GetDynamicLoadingMetrics()
if metrics.LoadingFailures.Load() > metrics.PluginsLoaded.Load()/10 {
    log.Println("High failure rate detected - check plugin health")
}

// Monitor dependency resolution time
start := time.Now()
err := manager.LoadDiscoveredPlugin(ctx, "complex-plugin")
duration := time.Since(start)
if duration > 5*time.Second {
    log.Printf("Slow loading detected: %v", duration)
}
```

### Validation Tools

```go
// Validate manifests before deployment
func validateManifest(manifestPath string) error {
    discovery := goplugins.NewDiscoveryEngine(config, logger)
    result, err := discovery.parseManifestFile(manifestPath)
    if err != nil {
        return fmt.Errorf("manifest parsing failed: %w", err)
    }
    
    if err := discovery.validateManifest(result.Manifest); err != nil {
        return fmt.Errorf("manifest validation failed: %w", err)
    }
    
    return nil
}

// Test dependency graphs
func testDependencyGraph(plugins map[string][]string) error {
    graph := goplugins.NewDependencyGraph()
    
    for name, deps := range plugins {
        if err := graph.AddPlugin(name, deps); err != nil {
            return err
        }
    }
    
    _, err := graph.CalculateLoadOrder()
    return err // Will return error if circular dependencies exist
}
```

---

For more examples and advanced usage, see the [examples directory](../examples/) and [API documentation](API.md).