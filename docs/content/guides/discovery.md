---
title: Plugin Discovery System
description: Automatic plugin detection through filesystem scanning and manifest validation
weight: 35
---

# Plugin Discovery System

The Discovery Engine provides intelligent plugin detection through filesystem scanning, manifest validation, capability matching, and real-time event notifications.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Plugin Manifests](#plugin-manifests)
- [Discovery Methods](#discovery-methods)
- [Event Handling](#event-handling)
- [Best Practices](#best-practices)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Overview

The Discovery Engine provides intelligent plugin detection through multiple mechanisms:

- **Filesystem Discovery**: Scans directories for plugin manifests and executables
- **Manifest Validation**: Comprehensive JSON/YAML parsing and validation
- **Capability Matching**: Filters plugins based on required capabilities
- **Real-time Events**: Immediate notifications of plugin discoveries
- **Security Validation**: Ensures discovered plugins meet security requirements

### Key Features

- **Automatic Detection**: Scans configured directories for plugins
- **Multiple Formats**: Supports JSON and YAML manifest files
- **Pattern Matching**: Flexible file pattern matching for plugin discovery
- **Capability Filtering**: Discovers only plugins with required capabilities
- **Security Integration**: Works with the plugin security system
- **Event System**: Real-time notifications of discovery events

## Quick Start

### Simple Auto-Discovery

Use the Simple API for basic auto-discovery:

```go
// Auto-discover plugins from a directory
manager, err := goplugins.Auto[Req, Resp]().
    FromDirectory("./plugins").
    WithPattern("*-plugin").
    WithDefaults().
    Build()
if err != nil {
    log.Fatal("Failed to build manager with auto-discovery:", err)
}
```

### Manual Discovery

```go
// Create discovery engine manually
config := goplugins.ExtendedDiscoveryConfig{
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Enabled:     true,
        Directories: []string{"./plugins", "/opt/plugins"},
        Patterns:    []string{"*.json", "*.yaml"},
        WatchMode:   false,
    },
    SearchPaths:       []string{"./plugins"},
    FilePatterns:      []string{"plugin.json", "manifest.yaml"},
    MaxDepth:          3,
    ValidateManifests: true,
}

// Create discovery engine
logger := goplugins.SimpleDefaultLogger()
discoveryEngine := goplugins.NewDiscoveryEngine(config, logger)

// Perform discovery
ctx := context.Background()
discovered, err := discoveryEngine.DiscoverPlugins(ctx)
if err != nil {
    log.Fatal("Discovery failed:", err)
}

fmt.Printf("Discovered %d plugins\n", len(discovered))
for name, result := range discovered {
    fmt.Printf("Plugin: %s v%s at %s\n", 
        result.Manifest.Name, 
        result.Manifest.Version, 
        result.Source)
}
```

## Configuration

### ExtendedDiscoveryConfig

The main configuration structure for the discovery system:

```go
config := goplugins.ExtendedDiscoveryConfig{
    // Basic discovery settings
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Enabled:     true,
        Directories: []string{"./plugins", "/opt/plugins"},
        Patterns:    []string{"*.json", "*.yaml", "*-plugin"},
        WatchMode:   true,  // Enable real-time watching
    },
    
    // Extended filesystem settings
    SearchPaths:       []string{"./plugins", "/usr/local/plugins"},
    FilePatterns:      []string{"plugin.json", "manifest.yaml"},
    MaxDepth:          3,
    FollowSymlinks:    false,
    ValidateManifests: true,
    
    // Filtering settings
    AllowedTransports:    []goplugins.TransportType{
        goplugins.TransportExecutable,
        goplugins.TransportGRPC,
    },
    RequiredCapabilities: []string{"v1.0"},
    ExcludePaths:         []string{"./plugins/test", "./plugins/deprecated"},
    
    // Timeouts and limits
    DiscoveryTimeout: 30 * time.Second,
}
```

### Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Enable/disable discovery |
| `Directories` | `[]string` | `[]` | Directories to scan for plugins |
| `Patterns` | `[]string` | `["*.so", "*.dll", "*.dylib"]` | File patterns to match |
| `WatchMode` | `bool` | `false` | Enable real-time file watching |
| `SearchPaths` | `[]string` | `[]` | Additional search paths |
| `FilePatterns` | `[]string` | `["*.json", "*.yaml"]` | Manifest file patterns |
| `MaxDepth` | `int` | `3` | Maximum directory depth |
| `FollowSymlinks` | `bool` | `false` | Follow symbolic links |
| `ValidateManifests` | `bool` | `true` | Validate discovered manifests |
| `AllowedTransports` | `[]TransportType` | `[]` | Allowed transport types |
| `RequiredCapabilities` | `[]string` | `[]` | Required plugin capabilities |
| `ExcludePaths` | `[]string` | `[]` | Paths to exclude from discovery |

## Plugin Manifests

Plugins are discovered through manifest files that describe their capabilities and configuration.

### JSON Manifest Format

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

### YAML Manifest Format

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

### Manifest Validation

The discovery engine validates manifests automatically:

```go
// Required fields validation
requiredFields := []string{"name", "version", "transport"}

// Security validation
// - Plugin name security (no path traversal, control characters)
// - Endpoint validation for different transport types
// - Capability format validation

// Resource validation
// - Memory and CPU limits within reasonable bounds
// - Version format validation (semantic versioning)
```

## Discovery Methods

### Filesystem Discovery

The primary discovery method scans directories for plugin manifests:

```go
// Create discovery engine
discoveryEngine := goplugins.NewDiscoveryEngine(config, logger)

// Perform one-time discovery
ctx := context.Background()
discovered, err := discoveryEngine.DiscoverPlugins(ctx)
if err != nil {
    log.Printf("Discovery failed: %v", err)
} else {
    log.Printf("Discovered %d plugins", len(discovered))
}

// Access discovered plugins
discoveredPlugins := discoveryEngine.GetDiscoveredPlugins()
for name, result := range discoveredPlugins {
    manifest := result.Manifest
    fmt.Printf("Plugin: %s v%s\n", manifest.Name, manifest.Version)
    fmt.Printf("  Transport: %s\n", manifest.Transport)
    fmt.Printf("  Endpoint: %s\n", manifest.Endpoint)
    fmt.Printf("  Capabilities: %v\n", manifest.Capabilities)
    fmt.Printf("  Source: %s\n", result.Source)
}
```

### Watch Mode

Enable real-time monitoring of plugin directories:

```go
config := goplugins.ExtendedDiscoveryConfig{
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Enabled:   true,
        WatchMode: true,  // Enable real-time watching
        Directories: []string{"./plugins"},
        Patterns:    []string{"*.json", "*.yaml"},
    },
    ValidateManifests: true,
}

discoveryEngine := goplugins.NewDiscoveryEngine(config, logger)

// Set up event handler for real-time notifications
discoveryEngine.AddEventHandler(func(event goplugins.DiscoveryEvent) {
    switch event.Type {
    case "plugin_discovered":
        log.Printf("New plugin discovered: %s", event.Plugin)
    case "plugin_updated":
        log.Printf("Plugin updated: %s", event.Plugin)
    case "plugin_removed":
        log.Printf("Plugin removed: %s", event.Plugin)
    case "manifest_invalid":
        log.Printf("Invalid manifest: %s - %s", event.Source, event.Error)
    }
})
```

## Event Handling

### Discovery Events

The discovery engine emits events for real-time monitoring:

```go
// Event types
const (
    EventPluginDiscovered = "plugin_discovered"
    EventPluginUpdated    = "plugin_updated"
    EventPluginRemoved    = "plugin_removed"
    EventManifestInvalid  = "manifest_invalid"
    EventDiscoveryError   = "discovery_error"
)

// Event structure
type DiscoveryEvent struct {
    Type        string                 `json:"type"`
    Timestamp   time.Time              `json:"timestamp"`
    Plugin      string                 `json:"plugin,omitempty"`
    Source      string                 `json:"source,omitempty"`
    Manifest    *PluginManifest        `json:"manifest,omitempty"`
    Error       string                 `json:"error,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

### Custom Event Handlers

```go
// Implement custom event handler
func handleDiscoveryEvents(event goplugins.DiscoveryEvent) {
    // Log to structured logger
    logger.Info("Discovery event",
        "type", event.Type,
        "plugin", event.Plugin,
        "source", event.Source)
    
    // Send to monitoring system
    metrics.IncrementCounter("plugin_discovery_events", map[string]string{
        "type":   event.Type,
        "plugin": event.Plugin,
    })
    
    // Handle specific event types
    switch event.Type {
    case "plugin_discovered":
        // Notify plugin management system
        notifyPluginManagement(event.Manifest)
        
    case "manifest_invalid":
        // Alert security team
        alertSecurityTeam(event.Source, event.Error)
        
    case "discovery_error":
        // Escalate to operations team
        escalateToOps(event.Error)
    }
}

// Register event handler
discoveryEngine.AddEventHandler(handleDiscoveryEvents)
```

## Integration with Dynamic Loading

### Combined Discovery and Loading

```go
// Create manager
manager := goplugins.NewManager[Req, Resp](logger)

// Configure discovery
discoveryConfig := goplugins.ExtendedDiscoveryConfig{
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Enabled:     true,
        Directories: []string{"./plugins"},
        Patterns:    []string{"*.json"},
        WatchMode:   true,
    },
    ValidateManifests: true,
    MaxDepth:         2,
}

// Create discovery engine
discoveryEngine := goplugins.NewDiscoveryEngine(discoveryConfig, logger)

// Create dynamic loader
dynamicLoader := goplugins.NewDynamicLoader(manager, discoveryEngine, logger)

// Enable auto-loading of discovered plugins
err := dynamicLoader.EnableAutoLoading(context.Background())
if err != nil {
    log.Fatal("Failed to enable auto-loading:", err)
}

// Perform initial discovery
ctx := context.Background()
discovered, err := discoveryEngine.DiscoverPlugins(ctx)
if err != nil {
    log.Fatal("Initial discovery failed:", err)
}

// Load discovered plugins
for name := range discovered {
    err := dynamicLoader.LoadDiscoveredPlugin(ctx, name)
    if err != nil {
        log.Printf("Failed to load discovered plugin %s: %v", name, err)
    }
}
```

## Best Practices

### 1. Use Specific Patterns

```go
// Good: Specific patterns
config := goplugins.ExtendedDiscoveryConfig{
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Patterns: []string{"plugin.json", "*-plugin.yaml"},
    },
    FilePatterns: []string{"plugin.json", "manifest.yaml"},
}

// Avoid: Too broad patterns that might match unintended files
// Patterns: []string{"*"} // Too broad
```

### 2. Validate Security

```go
// Enable comprehensive validation
config := goplugins.ExtendedDiscoveryConfig{
    ValidateManifests: true,
    RequiredCapabilities: []string{"v1.0"},
    AllowedTransports: []goplugins.TransportType{
        goplugins.TransportExecutable,  // Most secure
        goplugins.TransportGRPC,       // For performance
    },
    ExcludePaths: []string{
        "./plugins/test",        // Exclude test plugins
        "./plugins/deprecated",  // Exclude deprecated plugins
    },
}
```

### 3. Handle Discovery Errors

```go
// Set up comprehensive error handling
discoveryEngine.AddEventHandler(func(event goplugins.DiscoveryEvent) {
    switch event.Type {
    case "manifest_invalid":
        log.Printf("Invalid manifest found: %s", event.Source)
        log.Printf("Error: %s", event.Error)
        
        // Optionally move invalid files to quarantine
        quarantineInvalidManifest(event.Source)
        
    case "discovery_error":
        log.Printf("Discovery error: %s", event.Error)
        
        // Alert operations team
        sendAlert("discovery_error", event.Error)
    }
})
```

### 4. Monitor Discovery Performance

```go
// Monitor discovery performance
startTime := time.Now()
discovered, err := discoveryEngine.DiscoverPlugins(ctx)
discoveryDuration := time.Since(startTime)

log.Printf("Discovery completed in %v", discoveryDuration)
log.Printf("Discovered %d plugins", len(discovered))

// Alert if discovery takes too long
if discoveryDuration > 30*time.Second {
    log.Printf("WARNING: Discovery took longer than expected: %v", discoveryDuration)
}
```

### 5. Use Capability Filtering

```go
// Filter plugins by required capabilities
config := goplugins.ExtendedDiscoveryConfig{
    RequiredCapabilities: []string{
        "authenticate",     // Must support authentication
        "v1.0",            // Must support v1.0 API
        "production-ready", // Must be production-ready
    },
}

// Only plugins with ALL required capabilities will be discovered
```

## Examples

### Complete Discovery Setup

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
    
    // Configure discovery
    config := goplugins.ExtendedDiscoveryConfig{
        DiscoveryConfig: goplugins.DiscoveryConfig{
            Enabled:     true,
            Directories: []string{"./plugins", "/opt/plugins"},
            Patterns:    []string{"plugin.json", "*.yaml"},
            WatchMode:   true,
        },
        
        // Extended configuration
        SearchPaths:       []string{"./plugins"},
        FilePatterns:      []string{"plugin.json", "manifest.yaml"},
        MaxDepth:          3,
        FollowSymlinks:    false,
        ValidateManifests: true,
        
        // Security and filtering
        AllowedTransports: []goplugins.TransportType{
            goplugins.TransportExecutable,
            goplugins.TransportGRPC,
        },
        RequiredCapabilities: []string{"v1.0"},
        ExcludePaths:         []string{"./plugins/test"},
        
        // Timeouts
        DiscoveryTimeout: 30 * time.Second,
    }
    
    // Create discovery engine
    discoveryEngine := goplugins.NewDiscoveryEngine(config, logger)
    defer discoveryEngine.Close()
    
    // Set up event monitoring
    discoveryEngine.AddEventHandler(handleDiscoveryEvent)
    
    // Perform initial discovery
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()
    
    discovered, err := discoveryEngine.DiscoverPlugins(ctx)
    if err != nil {
        log.Fatal("Discovery failed:", err)
    }
    
    // Process discovered plugins
    processDiscoveredPlugins(discovered)
    
    // Keep running if watch mode is enabled
    if config.WatchMode {
        log.Println("Watch mode enabled, monitoring for changes...")
        select {} // Keep running
    }
}

func handleDiscoveryEvent(event goplugins.DiscoveryEvent) {
    log.Printf("[%s] %s: %s", 
        event.Timestamp.Format(time.RFC3339),
        event.Type, 
        event.Plugin)
    
    if event.Error != "" {
        log.Printf("  Error: %s", event.Error)
    }
    
    if event.Manifest != nil {
        log.Printf("  Version: %s", event.Manifest.Version)
        log.Printf("  Transport: %s", event.Manifest.Transport)
        log.Printf("  Capabilities: %v", event.Manifest.Capabilities)
    }
}

func processDiscoveredPlugins(discovered map[string]*goplugins.DiscoveryResult) {
    for name, result := range discovered {
        manifest := result.Manifest
        
        log.Printf("Processing plugin: %s", name)
        log.Printf("  Version: %s", manifest.Version)
        log.Printf("  Description: %s", manifest.Description)
        log.Printf("  Author: %s", manifest.Author)
        log.Printf("  Transport: %s", manifest.Transport)
        log.Printf("  Endpoint: %s", manifest.Endpoint)
        log.Printf("  Capabilities: %v", manifest.Capabilities)
        log.Printf("  Source: %s", result.Source)
        log.Printf("  Discovered at: %v", result.DiscoveredAt)
        
        // Validate requirements
        if manifest.Requirements != nil {
            log.Printf("  Min Go version: %s", manifest.Requirements.MinGoVersion)
            log.Printf("  Required plugins: %v", manifest.Requirements.RequiredPlugins)
            log.Printf("  Optional plugins: %v", manifest.Requirements.OptionalPlugins)
        }
        
        // Check resource limits
        if manifest.Resources != nil {
            log.Printf("  Max memory: %d MB", manifest.Resources.MaxMemoryMB)
            log.Printf("  Max CPU cores: %d", manifest.Resources.MaxCPUCores)
        }
        
        log.Println("---")
    }
}
```

### Directory Structure Example

```
./plugins/
├── auth-service/
│   ├── auth-service           # Executable
│   └── plugin.json           # Manifest
├── payment-service/
│   ├── payment-plugin        # Executable
│   └── manifest.yaml         # Manifest
├── logging-service/
│   ├── logging-service       # Executable
│   └── plugin.json           # Manifest
└── shared/
    └── common-manifest.yaml  # Shared configuration
```

## Troubleshooting

### Common Issues

**No Plugins Discovered:**
```go
// Check configuration
config := discoveryEngine.GetConfig()
log.Printf("Enabled: %v", config.Enabled)
log.Printf("Directories: %v", config.Directories)
log.Printf("Patterns: %v", config.Patterns)

// Check directory permissions
for _, dir := range config.Directories {
    if _, err := os.Stat(dir); os.IsNotExist(err) {
        log.Printf("Directory does not exist: %s", dir)
    } else if err != nil {
        log.Printf("Cannot access directory %s: %v", dir, err)
    }
}
```

**Invalid Manifests:**
```go
// Enable detailed validation logging
config := goplugins.ExtendedDiscoveryConfig{
    ValidateManifests: true,
    // ... other config
}

// Monitor validation errors
discoveryEngine.AddEventHandler(func(event goplugins.DiscoveryEvent) {
    if event.Type == "manifest_invalid" {
        log.Printf("Invalid manifest: %s", event.Source)
        log.Printf("Validation error: %s", event.Error)
        
        // Optionally, try to fix common issues
        if strings.Contains(event.Error, "missing required field") {
            log.Printf("Hint: Check that manifest includes name, version, and transport fields")
        }
    }
})
```

**Discovery Timeout:**
```go
// Increase timeout for large plugin directories
config := goplugins.ExtendedDiscoveryConfig{
    DiscoveryTimeout: 60 * time.Second,  // Increase from default 30s
    MaxDepth:        2,                  // Reduce depth to improve performance
}
```

**Permission Errors:**
```go
// Check file permissions
func checkPermissions(path string) error {
    info, err := os.Stat(path)
    if err != nil {
        return fmt.Errorf("cannot access %s: %w", path, err)
    }
    
    mode := info.Mode()
    if !mode.IsRegular() && !mode.IsDir() {
        return fmt.Errorf("%s is not a regular file or directory", path)
    }
    
    // Check read permissions
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("cannot read %s: %w", path, err)
    }
    file.Close()
    
    return nil
}
```

## Integration with Manager

### Configure Discovery on Manager

```go
// Configure discovery on an existing manager
manager := goplugins.NewManager[Req, Resp](logger)

discoveryConfig := goplugins.ExtendedDiscoveryConfig{
    DiscoveryConfig: goplugins.DiscoveryConfig{
        Enabled:     true,
        Directories: []string{"./plugins"},
        Patterns:    []string{"*.json"},
    },
    ValidateManifests: true,
}

err := manager.ConfigureDiscovery(discoveryConfig)
if err != nil {
    log.Fatal("Failed to configure discovery:", err)
}
```

### Auto-Loading Discovered Plugins

```go
// Combine discovery with dynamic loading
discoveryEngine := goplugins.NewDiscoveryEngine(config, logger)
dynamicLoader := goplugins.NewDynamicLoader(manager, discoveryEngine, logger)

// Enable auto-loading
err := dynamicLoader.EnableAutoLoading(context.Background())
if err != nil {
    log.Fatal("Failed to enable auto-loading:", err)
}

// Discovered plugins will be automatically loaded
```

## Next Steps

- Learn about [Dynamic Loading](/guides/dynamic-loading/) for automatic plugin loading
- Explore [Security System](/guides/security/) for securing discovered plugins
- Check out [Plugin Development](/guides/plugin-development/) for creating discoverable plugins

{{% alert title="Security Note" %}}
Always validate discovered plugins through the security system before loading them. Use the plugin whitelist to ensure only authorized plugins are loaded in production.
{{% /alert %}}

{{% alert title="Performance Tip" %}}
For large plugin directories, consider reducing MaxDepth and using specific file patterns to improve discovery performance.
{{% /alert %}}
