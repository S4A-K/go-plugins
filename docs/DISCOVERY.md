# Plugin Discovery System

> **Complete filesystem and network-based plugin auto-discovery system**

## Overview

The Discovery Engine provides intelligent plugin detection through multiple mechanisms:
- **Filesystem Discovery**: Scans directories for plugin manifests
- **Network Discovery**: Detects plugins via mDNS and service registry
- **Manifest Validation**: Comprehensive JSON/YAML parsing and validation
- **Capability Matching**: Filters plugins based on required capabilities
- **Real-time Events**: Immediate notifications of plugin discoveries

## Quick Start

```go
package main

import (
    "context"
    "time"
    goplugins "github.com/agilira/go-plugins"
)

func main() {
    // Configure discovery engine
    config := goplugins.ExtendedDiscoveryConfig{
        // Filesystem discovery
        SearchPaths:       []string{"/plugins", "./local-plugins"},
        FilePatterns:      []string{"*.json", "plugin.yaml"},
        MaxDepth:          3,
        ValidateManifests: true,
        
        // Network discovery
        EnableMDNS:        true,
        MDNSService:       "_goplugins._tcp",
        NetworkInterfaces: []string{"127.0.0.1", "localhost"},
        DiscoveryTimeout:  10 * time.Second,
        
        // Filtering
        AllowedTransports: []goplugins.TransportType{
            goplugins.TransportHTTP,
            goplugins.TransportGRPC,
        },
        RequiredCapabilities: []string{"authenticate"},
    }
    
    // Create discovery engine
    engine := goplugins.NewDiscoveryEngine(config, logger)
    defer engine.Close()
    
    // Add event handler
    engine.AddEventHandler(func(event goplugins.DiscoveryEvent) {
        if event.Plugin != nil {
            log.Printf("Discovered: %s v%s", 
                event.Plugin.Manifest.Name,
                event.Plugin.Manifest.Version)
        }
    })
    
    // Discover plugins
    ctx := context.WithTimeout(context.Background(), 30*time.Second)
    results, err := engine.DiscoverPlugins(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    // Process discovered plugins
    for name, result := range results {
        log.Printf("Plugin: %s at %s", name, result.Source)
    }
}
```

## Configuration

### ExtendedDiscoveryConfig

```go
type ExtendedDiscoveryConfig struct {
    // Filesystem discovery settings
    SearchPaths    []string `json:"search_paths,omitempty"`
    FilePatterns   []string `json:"file_patterns,omitempty"`
    MaxDepth       int      `json:"max_depth,omitempty"`
    FollowSymlinks bool     `json:"follow_symlinks,omitempty"`

    // Network discovery settings
    EnableMDNS        bool          `json:"enable_mdns,omitempty"`
    MDNSService       string        `json:"mdns_service,omitempty"`
    NetworkInterfaces []string      `json:"network_interfaces,omitempty"`
    DiscoveryTimeout  time.Duration `json:"discovery_timeout,omitempty"`

    // Filtering and validation
    AllowedTransports    []TransportType `json:"allowed_transports,omitempty"`
    RequiredCapabilities []string        `json:"required_capabilities,omitempty"`
    ExcludePaths         []string        `json:"exclude_paths,omitempty"`
    ValidateManifests    bool            `json:"validate_manifests,omitempty"`
}
```

### Default Values

| Setting | Default Value | Description |
|---------|---------------|-------------|
| `SearchPaths` | `["./plugins"]` | Directories to scan for plugins |
| `FilePatterns` | `["plugin.json", "plugin.yaml", "manifest.json"]` | Manifest filename patterns |
| `MaxDepth` | `5` | Maximum directory depth to scan |
| `MDNSService` | `"_goplugins._tcp"` | mDNS service type |
| `DiscoveryTimeout` | `30s` | Timeout for network operations |
| `ValidateManifests` | `true` | Enable manifest validation |

## Plugin Manifests

### JSON Format

```json
{
  "name": "auth-service",
  "version": "1.2.3",
  "description": "Authentication and authorization service",
  "author": "security-team@company.com",
  "capabilities": ["authenticate", "authorize", "validate-token"],
  "transport": "https",
  "endpoint": "https://auth.internal.company.com/api/v1",
  "requirements": {
    "min_go_version": "1.21",
    "required_plugins": ["logging-service"]
  },
  "resources": {
    "max_memory_mb": 256,
    "max_cpu_percent": 50
  },
  "health_check": {
    "path": "/health",
    "interval": "30s",
    "timeout": "5s"
  }
}
```

### YAML Format

```yaml
name: payment-service
version: 2.1.0
description: Payment processing service
author: payments@company.com
capabilities:
  - process-payment
  - refund
  - validate-card
transport: grpc
endpoint: payment.example.com:8080
requirements:
  min_go_version: "1.21"
  required_plugins:
    - auth-service
resources:
  max_memory_mb: 512
  max_cpu_percent: 75
health_check:
  path: /health
  interval: 30s
  timeout: 10s
```

## Filesystem Discovery

### Search Behavior

1. **Path Scanning**: Recursively scans configured search paths
2. **Pattern Matching**: Uses glob patterns to identify manifest files
3. **Depth Control**: Limits scan depth to prevent infinite recursion
4. **Symlink Handling**: Optionally follows symbolic links
5. **Path Exclusion**: Skips directories matching exclude patterns

### Example Directory Structure

```
plugins/
├── auth/
│   └── plugin.json          # Discovered
├── payment/
│   └── manifest.yaml        # Discovered
├── logging/
│   ├── plugin.json          # Discovered
│   └── logs/                # Skipped (no manifest)
└── .git/                    # Excluded by default
```

## Network Discovery

### mDNS Detection

The discovery engine scans common plugin service ports and attempts to:

1. **TCP Connection**: Tests connectivity to detect active services
2. **HTTP Probe**: Attempts to fetch manifest from standard endpoints:
   - `/plugin.json`
   - `/manifest.json`
   - `/plugin-manifest`
   - `/.well-known/plugin`
3. **Manifest Validation**: Validates retrieved manifests
4. **Service Registration**: Registers discovered network plugins

### Common Scan Ports

```
8080, 8081, 8082, 9090, 9091, 9092, 3000, 3001, 5000, 5001
```

### Network Service Structure

```go
type NetworkDiscoveryService struct {
    Name        string            `json:"name"`
    Host        string            `json:"host"`
    Port        int               `json:"port"`
    Protocol    string            `json:"protocol"`
    TXTRecords  map[string]string `json:"txt_records"`
    Endpoint    string            `json:"endpoint"`
    DiscoveredAt time.Time        `json:"discovered_at"`
}
```

## Event System

### Event Types

- **`plugin_discovered`**: New plugin found
- **`plugin_updated`**: Existing plugin changed
- **`plugin_removed`**: Plugin no longer available
- **`discovery_started`**: Discovery process began
- **`discovery_completed`**: Discovery process finished
- **`discovery_failed`**: Discovery process failed

### Event Handler

```go
engine.AddEventHandler(func(event goplugins.DiscoveryEvent) {
    switch event.Type {
    case "plugin_discovered":
        log.Printf("New plugin: %s", event.Plugin.Manifest.Name)
    case "plugin_updated":
        log.Printf("Updated plugin: %s", event.Plugin.Manifest.Name)
    case "discovery_failed":
        log.Printf("Discovery failed: %v", event.Error)
    }
})
```

## Filtering and Validation

### Transport Filtering

```go
config := ExtendedDiscoveryConfig{
    AllowedTransports: []TransportType{
        TransportHTTP,
        TransportGRPC,
        // TransportUnix excluded
    },
}
```

### Capability Matching

```go
config := ExtendedDiscoveryConfig{
    RequiredCapabilities: []string{
        "authenticate", 
        "authorize",
    },
}

// Only plugins with ALL required capabilities will be discovered
```

### Path Exclusion

```go
config := ExtendedDiscoveryConfig{
    ExcludePaths: []string{
        "*/test/*",
        "*/.*",        // Hidden directories
        "*/node_modules/*",
    },
}
```

## Discovery Results

### DiscoveryResult Structure

```go
type DiscoveryResult struct {
    Manifest     *PluginManifest `json:"manifest"`
    Source       string          `json:"source"`
    DiscoveredAt time.Time       `json:"discovered_at"`
    Capabilities []string        `json:"capabilities"`
    HealthStatus PluginStatus    `json:"health_status"`
    ErrorMessage string          `json:"error_message,omitempty"`
}
```

### Source Examples

- **Filesystem**: `/path/to/plugins/auth/plugin.json`
- **Network**: `network://192.168.1.100:8080`
- **Service Registry**: `consul://service/auth-service`

## Advanced Usage

### Concurrent Discovery

```go
// Discovery operations are thread-safe
var wg sync.WaitGroup
for i := 0; i < 5; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        results, _ := engine.DiscoverPlugins(ctx)
        // Process results...
    }()
}
wg.Wait()
```

### Custom Validation

```go
config := ExtendedDiscoveryConfig{
    ValidateManifests: true,
}

// Implements comprehensive validation:
// - Required fields (name, version, transport, endpoint)
// - Transport type validation
// - Capability format validation
// - Resource constraint validation
```

### Performance Optimization

```go
config := ExtendedDiscoveryConfig{
    MaxDepth:         2,        // Limit scan depth
    DiscoveryTimeout: 5*time.Second, // Faster network timeout
    ValidateManifests: false,   // Skip validation for speed
}
```

## Error Handling

### Common Errors

| Error Type | Description | Recovery |
|------------|-------------|----------|
| `PATH_NOT_FOUND` | Search path doesn't exist | Check path configuration |
| `MANIFEST_INVALID` | Malformed JSON/YAML | Fix manifest syntax |
| `NETWORK_TIMEOUT` | Network discovery timeout | Increase timeout or check connectivity |
| `VALIDATION_FAILED` | Manifest validation error | Review manifest content |

### Error Context

```go
results, err := engine.DiscoverPlugins(ctx)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Println("Discovery timed out")
    }
    // Handle other errors...
}
```

## Integration Examples

### With Plugin Manager

```go
// Discover plugins
results, err := engine.DiscoverPlugins(ctx)
if err != nil {
    return err
}

// Register discovered plugins with manager
manager := goplugins.NewManager(config, logger)
for name, result := range results {
    pluginConfig := convertManifestToConfig(result.Manifest)
    if err := manager.RegisterPlugin(pluginConfig); err != nil {
        log.Printf("Failed to register %s: %v", name, err)
    }
}
```

### With Hot Reload

```go
// Set up periodic discovery
ticker := time.NewTicker(30 * time.Second)
go func() {
    for range ticker.C {
        results, _ := engine.DiscoverPlugins(ctx)
        updatePluginRegistry(results)
    }
}()
```

## Best Practices

### Security Considerations

1. **Path Validation**: Always validate search paths to prevent directory traversal
2. **Network Security**: Limit network interfaces to trusted networks
3. **Manifest Validation**: Enable validation for production deployments
4. **Resource Limits**: Configure appropriate timeouts and depth limits

### Performance Guidelines

1. **Limit Search Depth**: Set reasonable `MaxDepth` to avoid deep scans
2. **Pattern Optimization**: Use specific file patterns to reduce I/O
3. **Network Timeout**: Configure appropriate network timeouts
4. **Caching**: Consider caching discovery results for frequently accessed data

### Monitoring and Observability

```go
// Add metrics collection
engine.AddEventHandler(func(event goplugins.DiscoveryEvent) {
    metrics.IncrementCounter("plugin_discovery_events", 
        map[string]string{"type": event.Type})
    
    if event.Plugin != nil {
        metrics.RecordGauge("plugins_discovered_total", 
            float64(len(engine.GetDiscoveredPlugins())))
    }
})
```

## Troubleshooting

### Common Issues

**Q: No plugins discovered despite valid manifests**
A: Check search paths, file patterns, and ensure manifests pass validation

**Q: Network discovery not finding services**
A: Verify network connectivity, check port accessibility, ensure services expose manifest endpoints

**Q: Discovery taking too long**
A: Reduce MaxDepth, optimize file patterns, or decrease network timeout

**Q: Memory usage growing over time**
A: Call `engine.Close()` to clean up resources when done

### Debug Logging

Enable debug logging to troubleshoot discovery issues:

```go
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
engine := goplugins.NewDiscoveryEngine(config, goplugins.NewLogger(logger))
```

## API Reference

### Core Methods

- `NewDiscoveryEngine(config, logger) *DiscoveryEngine`
- `(*DiscoveryEngine).DiscoverPlugins(ctx) (map[string]*DiscoveryResult, error)`
- `(*DiscoveryEngine).GetDiscoveredPlugins() map[string]*DiscoveryResult`
- `(*DiscoveryEngine).AddEventHandler(handler DiscoveryEventHandler)`
- `(*DiscoveryEngine).Close() error`

### Internal Methods

- `(*DiscoveryEngine).discoverFilesystemPlugins(ctx) (map[string]*DiscoveryResult, error)`
- `(*DiscoveryEngine).discoverNetworkPlugins(ctx) (map[string]*DiscoveryResult, error)`
- `(*DiscoveryEngine).validateManifest(manifest *PluginManifest) error`
- `(*DiscoveryEngine).shouldIncludePlugin(manifest *PluginManifest) bool`

---

**Version**: v1.0.0  
**Last Updated**: September 15, 2025  
**See Also**: [Configuration Guide](CONFIGURATION.md), [Development Roadmap](DEVELOPMENT_ROADMAP.md)