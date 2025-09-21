---
title: Dynamic Loading & Discovery
description: Intelligent plugin lifecycle management with hot-loading and auto-discovery
weight: 50
---

# Dynamic Loading & Discovery Guide

The Dynamic Loading Framework in go-plugins provides intelligent plugin lifecycle management with hot-loading capabilities, version compatibility checking, automatic dependency resolution, and real-time discovery event notifications.

## Table of Contents

- [Overview](#overview)
- [Core Components](#core-components)
- [Getting Started](#getting-started)
- [Plugin Discovery](#plugin-discovery)
- [Version Management](#version-management)
- [Dependency Resolution](#dependency-resolution)
- [Hot-Loading](#hot-loading)
- [Best Practices](#best-practices)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Overview

The dynamic loading system consists of several integrated components:

- **Discovery Engine**: Automatically finds plugins in directories or via network
- **Version Manager**: Handles semantic versioning and compatibility checking
- **Dependency Resolver**: Manages plugin dependencies and load ordering
- **Hot-Loader**: Enables runtime plugin loading/unloading without restart
- **Manifest Parser**: Validates and processes plugin manifest files

### Key Features

- **Automatic Discovery**: Filesystem and network-based plugin detection
- **Version Compatibility**: Semantic versioning with constraint checking
- **Dependency Resolution**: Automatic dependency ordering and validation
- **Hot-Loading**: Runtime plugin management without service interruption
- **Manifest Validation**: Comprehensive plugin metadata validation
- **Real-time Events**: Immediate notifications of plugin changes

## Core Components

### Discovery Engine

The Discovery Engine automatically finds plugins through multiple mechanisms:

```go
// Create discovery engine
config := goplugins.ExtendedDiscoveryConfig{
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Enabled:     true,
        Directories: []string{"./plugins", "/opt/plugins"},
        Patterns:    []string{"*.so", "*-plugin"},
        WatchMode:   true,
    },
    SearchPaths:         []string{"./plugins", "/usr/local/plugins"},
    FilePatterns:        []string{"*.so", "*.dll", "*.dylib"},
    MaxDepth:            3,
    FollowSymlinks:      false,
    ValidateManifests:   true,
    RequiredCapabilities: []string{"v1.0"},
}

discoveryEngine := goplugins.NewDiscoveryEngine(config, logger)
```

### Dynamic Loader

The Dynamic Loader manages the complete plugin lifecycle:

```go
// Create dynamic loader
loader := goplugins.NewDynamicLoader(manager, discoveryEngine, logger)

// Enable auto-loading (hot-loading)
err := loader.EnableAutoLoading(context.Background())
if err != nil {
    log.Fatal("Failed to enable auto-loading:", err)
}
```

## Getting Started

### Simple Auto-Discovery

Use the Simple API for basic auto-discovery:

```go
manager, err := goplugins.Auto[Req, Resp]().
    FromDirectory("./plugins").
    WithPattern("*-plugin").
    WithDefaults().
    Build()
```

### Advanced Discovery Configuration

```go
// Create manager with advanced discovery
manager := goplugins.NewManager[Req, Resp](logger)

// Configure discovery
discoveryConfig := goplugins.ExtendedDiscoveryConfig{
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Enabled:     true,
        Directories: []string{"./plugins", "/opt/plugins"},
        Patterns:    []string{"*-plugin", "*.so"},
        WatchMode:   true,
    },
    SearchPaths:           []string{"./plugins", "/usr/local/plugins"},
    FilePatterns:          []string{"*.so", "*.dll", "*.dylib"},
    MaxDepth:              3,
    FollowSymlinks:        false,
    ValidateManifests:     true,
    RequiredCapabilities:  []string{"auth", "logging"},
    ExcludePaths:          []string{"./plugins/test", "./plugins/deprecated"},
}

// Create and start discovery
discoveryEngine := goplugins.NewDiscoveryEngine(discoveryConfig, logger)
dynamicLoader := goplugins.NewDynamicLoader(manager, discoveryEngine, logger)

// Start discovery
err := dynamicLoader.StartDiscovery()
if err != nil {
    log.Fatal("Failed to start discovery:", err)
}
```

## Plugin Discovery

### Plugin Manifests

Plugins are discovered through manifest files (JSON or YAML):

#### plugin-manifest.json
```json
{
  "name": "auth-service",
  "version": "1.2.3",
  "description": "Authentication and authorization service",
  "author": "security-team@company.com",
  "capabilities": ["authenticate", "authorize", "validate-token"],
  "transport": "grpc",
  "endpoint": "auth.internal.company.com:9090",
  "requirements": {
    "min_go_version": "1.21",
    "required_plugins": ["logging-service"],
    "optional_plugins": ["metrics-service"]
  },
  "resources": {
    "max_memory_mb": 512,
    "max_cpu_cores": 2
  },
  "metadata": {
    "team": "security",
    "environment": "production",
    "last_updated": "2025-01-15T10:30:00Z"
  }
}
```

#### plugin-manifest.yaml
```yaml
name: payment-service
version: 2.1.0
description: Payment processing service
author: payments-team@company.com
capabilities:
  - process_payment
  - refund_payment
  - validate_card
transport: subprocess
endpoint: ./payment-plugin
requirements:
  min_go_version: "1.21"
  required_plugins:
    - auth-service
    - logging-service
  optional_plugins:
    - fraud-detection
resources:
  max_memory_mb: 1024
  max_cpu_cores: 4
metadata:
  team: payments
  environment: production
  compliance: pci-dss
```

### Discovery Events

Listen for real-time discovery events:

```go
// Subscribe to discovery events
eventChan := dynamicLoader.GetEventChannel()

go func() {
    for event := range eventChan {
        switch event.Type {
        case "plugin_discovered":
            log.Printf("New plugin discovered: %s v%s", 
                event.Manifest.Name, event.Manifest.Version)
            
        case "plugin_updated":
            log.Printf("Plugin updated: %s v%s -> v%s", 
                event.Manifest.Name, event.OldVersion, event.Manifest.Version)
            
        case "plugin_removed":
            log.Printf("Plugin removed: %s", event.Manifest.Name)
            
        case "manifest_invalid":
            log.Printf("Invalid manifest: %s - %s", 
                event.Source, event.Error)
        }
    }
}()
```

## Version Management

### Semantic Versioning

The system uses semantic versioning (semver) for version management:

```go
// Version compatibility checking
version1 := goplugins.ParseVersion("1.2.3")
version2 := goplugins.ParseVersion("1.3.0")

compatible, err := goplugins.IsCompatible(version1, "^1.2.0")
if err != nil {
    log.Printf("Version compatibility error: %v", err)
}

if compatible {
    log.Printf("Version %s is compatible with constraint ^1.2.0", version1)
}
```

### Version Constraints

Support for various version constraint formats:

```go
// Version constraint examples
constraints := []string{
    "^1.2.0",     // Compatible with 1.2.0, allows 1.x.x but not 2.x.x
    "~1.2.3",     // Compatible with 1.2.3, allows 1.2.x but not 1.3.x
    ">=1.0.0",    // Greater than or equal to 1.0.0
    "<2.0.0",     // Less than 2.0.0
    "1.2.3",      // Exact version match
    "*",          // Any version
}

for _, constraint := range constraints {
    compatible, err := goplugins.SatisfiesConstraint("1.2.5", constraint)
    if err != nil {
        log.Printf("Constraint error: %v", err)
        continue
    }
    
    log.Printf("Version 1.2.5 satisfies %s: %v", constraint, compatible)
}
```

### Version Policies

Configure version compatibility policies:

```go
versionPolicy := goplugins.VersionPolicy{
    AllowPrerelease:    false,
    AllowDowngrade:     false,
    RequireExactMatch:  false,
    BreakingChangeMode: goplugins.BreakingChangeReject,
}

err := dynamicLoader.SetVersionPolicy(versionPolicy)
```

## Dependency Resolution

### Dependency Graph

The system automatically resolves plugin dependencies:

```go
// Plugin dependencies are resolved automatically based on manifests
// Example: auth-service depends on logging-service

// The system will:
// 1. Load logging-service first
// 2. Then load auth-service
// 3. Handle circular dependency detection
// 4. Report unresolved dependencies

// Get dependency information
dependencies := dynamicLoader.GetDependencyGraph()
for pluginName, deps := range dependencies {
    log.Printf("Plugin %s depends on: %v", pluginName, deps.Required)
    if len(deps.Optional) > 0 {
        log.Printf("  Optional dependencies: %v", deps.Optional)
    }
}
```

### Dependency Resolution Strategies

```go
// Configure dependency resolution
resolutionConfig := goplugins.DependencyResolutionConfig{
    Strategy:           goplugins.ResolutionStrategyStrict,
    AllowOptionalFail:  true,
    MaxResolutionDepth: 10,
    CircularDependencyMode: goplugins.CircularDependencyReject,
}

err := dynamicLoader.SetDependencyResolution(resolutionConfig)
```

### Load Order Calculation

```go
// Get calculated load order
loadOrder, err := dynamicLoader.CalculateLoadOrder()
if err != nil {
    log.Printf("Failed to calculate load order: %v", err)
} else {
    log.Printf("Plugin load order: %v", loadOrder)
}

// Load plugins in dependency order
for _, pluginName := range loadOrder {
    err := dynamicLoader.LoadPlugin(pluginName)
    if err != nil {
        log.Printf("Failed to load plugin %s: %v", pluginName, err)
    }
}
```

## Hot-Loading

### Enable Hot-Loading

```go
// Enable hot-loading with configuration
hotLoadConfig := goplugins.HotLoadConfig{
    Enabled:           true,
    GracefulTimeout:   30 * time.Second,
    BackupOldVersions: true,
    RollbackOnFailure: true,
    PreloadValidation: true,
}

err := dynamicLoader.EnableHotLoading(hotLoadConfig)
```

### Hot-Load Operations

```go
// Load a new plugin at runtime
err := dynamicLoader.LoadDiscoveredPlugin("new-service")
if err != nil {
    log.Printf("Failed to hot-load plugin: %v", err)
}

// Update an existing plugin
err = dynamicLoader.UpdatePlugin("auth-service", "1.3.0")
if err != nil {
    log.Printf("Failed to update plugin: %v", err)
}

// Unload a plugin gracefully
err = dynamicLoader.UnloadPlugin("old-service", 30*time.Second)
if err != nil {
    log.Printf("Failed to unload plugin: %v", err)
}
```

### Hot-Load Events

```go
// Monitor hot-load events
hotLoadEvents := dynamicLoader.GetHotLoadEventChannel()

go func() {
    for event := range hotLoadEvents {
        switch event.Type {
        case "plugin_loading":
            log.Printf("Loading plugin: %s v%s", event.PluginName, event.Version)
            
        case "plugin_loaded":
            log.Printf("Plugin loaded successfully: %s", event.PluginName)
            
        case "plugin_load_failed":
            log.Printf("Plugin load failed: %s - %s", event.PluginName, event.Error)
            
        case "plugin_unloading":
            log.Printf("Unloading plugin: %s", event.PluginName)
            
        case "plugin_unloaded":
            log.Printf("Plugin unloaded: %s", event.PluginName)
            
        case "plugin_updated":
            log.Printf("Plugin updated: %s v%s -> v%s", 
                event.PluginName, event.OldVersion, event.NewVersion)
        }
    }
}()
```

## Best Practices

### 1. Use Proper Manifest Validation

```go
// Enable comprehensive manifest validation
discoveryConfig := goplugins.ExtendedDiscoveryConfig{
    ValidateManifests: true,
    RequiredFields:    []string{"name", "version", "transport"},
    RequiredCapabilities: []string{"v1.0"},
}
```

### 2. Handle Discovery Errors Gracefully

```go
// Set up error handling for discovery
discoveryEngine.SetErrorHandler(func(err error, source string) {
    log.Printf("Discovery error from %s: %v", source, err)
    
    // Send to monitoring system
    metrics.IncrementCounter("plugin_discovery_errors", map[string]string{
        "source": source,
        "error_type": classifyError(err),
    })
})
```

### 3. Monitor Plugin Lifecycle

```go
// Set up lifecycle monitoring
lifecycleMonitor := goplugins.NewLifecycleMonitor()
lifecycleMonitor.OnPluginLoaded(func(pluginName string) {
    log.Printf("Plugin %s loaded successfully", pluginName)
    metrics.IncrementCounter("plugins_loaded", map[string]string{
        "plugin": pluginName,
    })
})

lifecycleMonitor.OnPluginFailed(func(pluginName string, err error) {
    log.Printf("Plugin %s failed to load: %v", pluginName, err)
    // Send alert to monitoring system
})

dynamicLoader.SetLifecycleMonitor(lifecycleMonitor)
```

### 4. Use Resource Limits

```go
// Configure resource limits in manifests
resourceLimits := goplugins.ResourceLimits{
    MaxMemoryMB:    512,
    MaxCPUCores:    2,
    MaxGoroutines:  1000,
    MaxFileHandles: 100,
}

// Validate resource usage
err := dynamicLoader.SetResourceLimits(resourceLimits)
```

### 5. Implement Rollback Strategies

```go
// Configure rollback behavior
rollbackConfig := goplugins.RollbackConfig{
    Enabled:           true,
    BackupVersions:    3,
    RollbackOnFailure: true,
    HealthCheckDelay:  10 * time.Second,
}

err := dynamicLoader.SetRollbackConfig(rollbackConfig)
```

## Examples

### Complete Dynamic Loading Setup

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/agilira/go-plugins"
)

func main() {
    // Create logger
    logger := goplugins.SimpleDefaultLogger()
    
    // Create manager
    manager := goplugins.NewManager[MyRequest, MyResponse](logger)
    
    // Configure discovery
    discoveryConfig := goplugins.ExtendedDiscoveryConfig{
        DiscoveryConfig: goplugins.DiscoveryConfig{
            Enabled:     true,
            Directories: []string{"./plugins"},
            Patterns:    []string{"*-plugin"},
            WatchMode:   true,
        },
        ValidateManifests: true,
        MaxDepth:         2,
    }
    
    // Create discovery engine
    discoveryEngine := goplugins.NewDiscoveryEngine(discoveryConfig, logger)
    
    // Create dynamic loader
    dynamicLoader := goplugins.NewDynamicLoader(manager, discoveryEngine, logger)
    
    // Enable auto-loading
    err := dynamicLoader.EnableAutoLoading(context.Background())
    if err != nil {
        log.Fatal("Failed to enable auto-loading:", err)
    }
    
    // Perform initial discovery
    ctx := context.Background()
    discovered, err := discoveryEngine.DiscoverPlugins(ctx)
    if err != nil {
        log.Fatal("Failed to discover plugins:", err)
    }
    
    log.Printf("Discovered %d plugins", len(discovered))
    
    // Monitor events
    go monitorEvents(dynamicLoader)
    
    // Keep running
    select {}
}

func monitorEvents(loader *goplugins.DynamicLoader) {
    events := loader.GetEventChannel()
    
    for event := range events {
        switch event.Type {
        case "plugin_discovered":
            log.Printf("Discovered: %s v%s", event.Manifest.Name, event.Manifest.Version)
            
        case "plugin_loaded":
            log.Printf("Loaded: %s", event.Manifest.Name)
            
        case "plugin_failed":
            log.Printf("Failed: %s - %s", event.Manifest.Name, event.Error)
        }
    }
}
```

## Troubleshooting

### Common Issues

**Plugin Not Discovered:**
```go
// Check discovery configuration
config := discoveryEngine.GetConfig()
log.Printf("Search directories: %v", config.Directories)
log.Printf("File patterns: %v", config.Patterns)
log.Printf("Max depth: %d", config.MaxDepth)

// Check file permissions
for _, dir := range config.Directories {
    if !isDirectoryReadable(dir) {
        log.Printf("Directory not readable: %s", dir)
    }
}
```

**Version Conflicts:**
```go
// Check version compatibility
conflicts := dynamicLoader.GetVersionConflicts()
for pluginName, conflict := range conflicts {
    log.Printf("Version conflict for %s:", pluginName)
    log.Printf("  Required: %s", conflict.Required)
    log.Printf("  Available: %s", conflict.Available)
    log.Printf("  Constraint: %s", conflict.Constraint)
}
```

**Dependency Issues:**
```go
// Check dependency resolution
unresolved := dynamicLoader.GetUnresolvedDependencies()
for pluginName, deps := range unresolved {
    log.Printf("Unresolved dependencies for %s: %v", pluginName, deps)
}

// Check circular dependencies
circular := dynamicLoader.GetCircularDependencies()
if len(circular) > 0 {
    log.Printf("Circular dependencies detected: %v", circular)
}
```

**Hot-Load Failures:**
```go
// Check hot-load status
status := dynamicLoader.GetHotLoadStatus()
for pluginName, pluginStatus := range status {
    if pluginStatus.State == "failed" {
        log.Printf("Hot-load failed for %s: %s", pluginName, pluginStatus.Error)
        log.Printf("  Rollback available: %v", pluginStatus.CanRollback)
    }
}
```

## Next Steps

- Learn about [Plugin Development](/guides/plugin-development/) for creating discoverable plugins
- Explore [Production Deployment](/guides/production/) for production discovery setup
- Check out the [Dynamic Loading API Reference](/api/dynamic-loading/) for detailed configuration options

{{% alert title="Performance Note" %}}
Enable discovery features gradually in production. Start with basic filesystem discovery, then add network discovery and hot-loading as needed.
{{% /alert %}}
