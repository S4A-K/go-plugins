---
title: Plugin Development
description: Learn how to develop plugins for the go-plugins system
weight: 70
---

# Plugin Development Guide

This guide covers how to develop plugins that work with the go-plugins system, including both the plugin implementation and the plugin serving infrastructure.

## Table of Contents

- [Overview](#overview)
- [Plugin Interface](#plugin-interface)
- [Plugin Serving](#plugin-serving)
- [Transport Protocols](#transport-protocols)
- [Health Checks](#health-checks)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Overview

A plugin in the go-plugins system consists of two main components:

1. **Plugin Implementation**: Implements the `Plugin[Req, Resp]` interface
2. **Plugin Server**: Serves the plugin and handles communication with the host

### Plugin Architecture

```
Host Application                    Plugin Process
┌─────────────────┐                ┌─────────────────┐
│   Manager       │                │  Plugin Server  │
│   ├─ Execute()  │◄──────────────►│  ├─ Serve()     │
│   ├─ Health()   │                │  └─ Plugin Impl │
│   └─ Register() │                │     ├─ Execute()│
└─────────────────┘                │     ├─ Health() │
                                   │     ├─ Info()   │
                                   │     └─ Close()  │
                                   └─────────────────┘
```

## Plugin Interface

Every plugin must implement the `Plugin[Req, Resp]` interface:

```go
type Plugin[Req, Resp any] interface {
    Info() PluginInfo
    Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error)
    Health(ctx context.Context) HealthStatus
    Close() error
}
```

### Basic Plugin Implementation

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/agilira/go-plugins"
)

// Define your request/response types
type CalculatorRequest struct {
    Operation string  `json:"operation"` // add, subtract, multiply, divide
    A         float64 `json:"a"`
    B         float64 `json:"b"`
}

type CalculatorResponse struct {
    Result float64 `json:"result"`
    Error  string  `json:"error,omitempty"`
}

// Implement the plugin
type CalculatorPlugin struct {
    name    string
    version string
    started time.Time
}

func (p *CalculatorPlugin) Info() goplugins.PluginInfo {
    return goplugins.PluginInfo{
        Name:        p.name,
        Version:     p.version,
        Description: "Simple calculator plugin",
        Author:      "your-team@company.com",
        Capabilities: []string{
            "arithmetic",
            "basic-operations",
            "v1.0",
        },
        Metadata: map[string]string{
            "operations": "add,subtract,multiply,divide",
            "precision":  "float64",
        },
    }
}

func (p *CalculatorPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request CalculatorRequest) (CalculatorResponse, error) {
    // Validate input
    if request.Operation == "" {
        return CalculatorResponse{
            Error: "Operation is required",
        }, fmt.Errorf("operation cannot be empty")
    }
    
    // Perform calculation
    var result float64
    var err error
    
    switch request.Operation {
    case "add":
        result = request.A + request.B
    case "subtract":
        result = request.A - request.B
    case "multiply":
        result = request.A * request.B
    case "divide":
        if request.B == 0 {
            return CalculatorResponse{
                Error: "Division by zero",
            }, fmt.Errorf("cannot divide by zero")
        }
        result = request.A / request.B
    default:
        return CalculatorResponse{
            Error: fmt.Sprintf("Unknown operation: %s", request.Operation),
        }, fmt.Errorf("unsupported operation: %s", request.Operation)
    }
    
    return CalculatorResponse{
        Result: result,
    }, nil
}

func (p *CalculatorPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    uptime := time.Since(p.started)
    
    return goplugins.HealthStatus{
        Status:       goplugins.StatusHealthy,
        Message:      "Calculator plugin is operational",
        LastCheck:    time.Now(),
        ResponseTime: time.Millisecond, // Health check is very fast
        Metadata: map[string]string{
            "uptime":     uptime.String(),
            "operations": "4", // Number of supported operations
        },
    }
}

func (p *CalculatorPlugin) Close() error {
    fmt.Println("Calculator plugin shutting down...")
    return nil
}
```

## Plugin Serving

To make your plugin available to the host application, you need to serve it:

### Simple Plugin Serving

```go
func main() {
    // Create plugin instance
    plugin := &CalculatorPlugin{
        name:    "calculator",
        version: "1.0.0",
        started: time.Now(),
    }
    
    // Create plugin server
    server := goplugins.NewGenericPluginServer(goplugins.ServeConfig{
        PluginName:    "calculator",
        PluginVersion: "1.0.0",
        PluginType:    "calculator",
    })
    
    // Register plugin with server
    server.RegisterPlugin(plugin)
    
    // Serve plugin
    ctx := context.Background()
    err := server.Serve(ctx, goplugins.DefaultServeConfig)
    if err != nil {
        log.Fatal("Failed to serve plugin:", err)
    }
}
```

### Advanced Plugin Serving

```go
func main() {
    // Create plugin with custom configuration
    plugin := &CalculatorPlugin{
        name:    "advanced-calculator",
        version: "2.0.0",
        started: time.Now(),
    }
    
    // Custom serve configuration
    config := goplugins.ServeConfig{
        PluginName:    "advanced-calculator",
        PluginVersion: "2.0.0",
        PluginType:    "calculator",
        
        // Custom network configuration
        NetworkConfig: goplugins.NetworkServeConfig{
            Protocol:       "tcp",
            BindAddress:    "127.0.0.1",
            BindPort:       8080, // Specific port
            ReadTimeout:    30 * time.Second,
            WriteTimeout:   30 * time.Second,
            IdleTimeout:    60 * time.Second,
            MaxConnections: 50,
        },
        
        // Custom handshake configuration
        HandshakeConfig: goplugins.HandshakeConfig{
            ProtocolVersion: 1,
            MagicCookieKey:  "CALCULATOR_PLUGIN",
            MagicCookieValue: "calculator-v2",
        },
        
        // Custom logger
        Logger: goplugins.SimpleDefaultLogger(),
    }
    
    // Create and serve plugin
    server := goplugins.NewGenericPluginServer(config)
    server.RegisterPlugin(plugin)
    
    ctx := context.Background()
    err := server.Serve(ctx, config)
    if err != nil {
        log.Fatal("Failed to serve plugin:", err)
    }
}
```

## Transport Protocols

### Subprocess Transport (Recommended)

For subprocess plugins, the communication happens through TCP:

```go
// Plugin serves on a TCP port
config := goplugins.ServeConfig{
    NetworkConfig: goplugins.NetworkServeConfig{
        Protocol:    "tcp",
        BindAddress: "127.0.0.1",
        BindPort:    0, // Auto-assign port
    },
}
```

### gRPC Transport

For gRPC plugins, implement the protobuf interface:

```go
// Ensure your types implement ProtobufMessage
type ProtobufRequest struct {
    // protobuf fields
}

func (pr *ProtobufRequest) ProtoMessage() {}
func (pr *ProtobufRequest) Reset() { *pr = ProtobufRequest{} }
func (pr *ProtobufRequest) String() string { return "ProtobufRequest" }

// Create gRPC plugin
plugin := &MyGRPCPlugin{}
server := goplugins.NewGRPCNativePlugin[ProtobufRequest, ProtobufResponse](config, logger)
```

## Health Checks

Implement comprehensive health checks in your plugin:

```go
func (p *MyPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    start := time.Now()
    
    // Check dependencies
    if !p.isDatabaseHealthy(ctx) {
        return goplugins.HealthStatus{
            Status:       goplugins.StatusUnhealthy,
            Message:      "Database connection failed",
            LastCheck:    time.Now(),
            ResponseTime: time.Since(start),
            Metadata: map[string]string{
                "database_status": "disconnected",
                "last_error":      p.lastDBError.Error(),
            },
        }
    }
    
    // Check external services
    if !p.isExternalServiceHealthy(ctx) {
        return goplugins.HealthStatus{
            Status:       goplugins.StatusDegraded,
            Message:      "External service unavailable, using cache",
            LastCheck:    time.Now(),
            ResponseTime: time.Since(start),
            Metadata: map[string]string{
                "external_service": "unavailable",
                "fallback_mode":    "cache_only",
                "cache_size":       fmt.Sprintf("%d", p.cache.Size()),
            },
        }
    }
    
    // All systems healthy
    return goplugins.HealthStatus{
        Status:       goplugins.StatusHealthy,
        Message:      "All systems operational",
        LastCheck:    time.Now(),
        ResponseTime: time.Since(start),
        Metadata: map[string]string{
            "database":         "connected",
            "external_service": "available",
            "uptime":          time.Since(p.started).String(),
            "requests_served": fmt.Sprintf("%d", p.requestCount.Load()),
        },
    }
}
```

## Error Handling

### Structured Error Responses

```go
func (p *MyPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request MyRequest) (MyResponse, error) {
    // Validate request
    if err := p.validateRequest(request); err != nil {
        return MyResponse{
            Error: fmt.Sprintf("Invalid request: %v", err),
        }, fmt.Errorf("request validation failed: %w", err)
    }
    
    // Process request with timeout
    ctx, cancel := context.WithTimeout(ctx, execCtx.Timeout)
    defer cancel()
    
    result, err := p.processRequest(ctx, request)
    if err != nil {
        // Return structured error response
        return MyResponse{
            Error: fmt.Sprintf("Processing failed: %v", err),
        }, fmt.Errorf("request processing failed: %w", err)
    }
    
    return MyResponse{
        Data:   result,
        Status: "success",
    }, nil
}
```

### Error Recovery

```go
func (p *MyPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request MyRequest) (MyResponse, error) {
    // Implement retry logic for transient failures
    for attempt := 0; attempt < execCtx.MaxRetries; attempt++ {
        result, err := p.tryExecute(ctx, request)
        if err == nil {
            return result, nil
        }
        
        // Check if error is retryable
        if !p.isRetryableError(err) {
            return MyResponse{Error: err.Error()}, err
        }
        
        // Wait before retry with exponential backoff
        if attempt < execCtx.MaxRetries-1 {
            backoff := time.Duration(attempt+1) * 100 * time.Millisecond
            select {
            case <-ctx.Done():
                return MyResponse{Error: "Context cancelled"}, ctx.Err()
            case <-time.After(backoff):
                // Continue to next attempt
            }
        }
    }
    
    return MyResponse{Error: "Max retries exceeded"}, fmt.Errorf("failed after %d attempts", execCtx.MaxRetries)
}
```

## Testing

### Unit Testing Your Plugin

```go
package main

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/agilira/go-plugins"
)

func TestCalculatorPlugin(t *testing.T) {
    plugin := &CalculatorPlugin{
        name:    "test-calculator",
        version: "1.0.0",
        started: time.Now(),
    }
    
    ctx := context.Background()
    execCtx := goplugins.ExecutionContext{
        RequestID:  "test-req-1",
        Timeout:    30 * time.Second,
        MaxRetries: 3,
    }
    
    t.Run("Addition", func(t *testing.T) {
        request := CalculatorRequest{
            Operation: "add",
            A:         5.0,
            B:         3.0,
        }
        
        response, err := plugin.Execute(ctx, execCtx, request)
        assert.NoError(t, err)
        assert.Equal(t, 8.0, response.Result)
        assert.Empty(t, response.Error)
    })
    
    t.Run("Division by Zero", func(t *testing.T) {
        request := CalculatorRequest{
            Operation: "divide",
            A:         5.0,
            B:         0.0,
        }
        
        response, err := plugin.Execute(ctx, execCtx, request)
        assert.Error(t, err)
        assert.Equal(t, "Division by zero", response.Error)
    })
    
    t.Run("Health Check", func(t *testing.T) {
        health := plugin.Health(ctx)
        assert.Equal(t, goplugins.StatusHealthy, health.Status)
        assert.NotEmpty(t, health.Message)
    })
    
    t.Run("Plugin Info", func(t *testing.T) {
        info := plugin.Info()
        assert.Equal(t, "test-calculator", info.Name)
        assert.Equal(t, "1.0.0", info.Version)
        assert.Contains(t, info.Capabilities, "arithmetic")
    })
}
```

### Integration Testing

```go
func TestPluginIntegration(t *testing.T) {
    // Start plugin server in background
    plugin := &CalculatorPlugin{
        name:    "integration-calculator",
        version: "1.0.0",
        started: time.Now(),
    }
    
    server := goplugins.NewGenericPluginServer(goplugins.DefaultServeConfig)
    server.RegisterPlugin(plugin)
    
    // Start server in background
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    go func() {
        err := server.Serve(ctx, goplugins.DefaultServeConfig)
        if err != nil && ctx.Err() == nil {
            t.Errorf("Plugin server failed: %v", err)
        }
    }()
    
    // Wait for server to start
    time.Sleep(100 * time.Millisecond)
    
    // Create manager and test integration
    manager := goplugins.NewManager[CalculatorRequest, CalculatorResponse](nil)
    
    // Register subprocess factory
    factory := goplugins.NewSubprocessPluginFactory[CalculatorRequest, CalculatorResponse](nil)
    err := manager.RegisterFactory("subprocess", factory)
    assert.NoError(t, err)
    
    // Test plugin execution through manager
    request := CalculatorRequest{
        Operation: "add",
        A:         10.0,
        B:         5.0,
    }
    
    response, err := manager.Execute(ctx, "integration-calculator", request)
    assert.NoError(t, err)
    assert.Equal(t, 15.0, response.Result)
}
```

## Plugin Manifest

Create a manifest file for your plugin to enable auto-discovery:

### plugin.json
```json
{
  "name": "calculator",
  "version": "1.0.0",
  "description": "Simple calculator plugin for arithmetic operations",
  "author": "your-team@company.com",
  "capabilities": [
    "arithmetic",
    "basic-operations",
    "v1.0"
  ],
  "transport": "subprocess",
  "endpoint": "./calculator-plugin",
  "requirements": {
    "min_go_version": "1.21",
    "required_plugins": [],
    "optional_plugins": ["logging-service"]
  },
  "resources": {
    "max_memory_mb": 256,
    "max_cpu_cores": 1
  },
  "metadata": {
    "team": "platform",
    "category": "utility",
    "operations": "add,subtract,multiply,divide",
    "precision": "float64"
  }
}
```

## Best Practices

### 1. Implement Proper Error Handling

```go
func (p *MyPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request MyRequest) (MyResponse, error) {
    // Always validate input
    if err := p.validateRequest(request); err != nil {
        return MyResponse{Error: err.Error()}, err
    }
    
    // Respect context cancellation
    select {
    case <-ctx.Done():
        return MyResponse{Error: "Request cancelled"}, ctx.Err()
    default:
    }
    
    // Implement timeout handling
    ctx, cancel := context.WithTimeout(ctx, execCtx.Timeout)
    defer cancel()
    
    // Process request
    result, err := p.processWithTimeout(ctx, request)
    if err != nil {
        return MyResponse{Error: err.Error()}, err
    }
    
    return MyResponse{Data: result}, nil
}
```

### 2. Implement Comprehensive Health Checks

```go
func (p *MyPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    start := time.Now()
    
    // Check all dependencies
    checks := []struct {
        name string
        check func(context.Context) error
    }{
        {"database", p.checkDatabase},
        {"external_api", p.checkExternalAPI},
        {"disk_space", p.checkDiskSpace},
        {"memory_usage", p.checkMemoryUsage},
    }
    
    var failures []string
    for _, check := range checks {
        if err := check.check(ctx); err != nil {
            failures = append(failures, fmt.Sprintf("%s: %v", check.name, err))
        }
    }
    
    // Determine overall status
    status := goplugins.StatusHealthy
    message := "All systems operational"
    
    if len(failures) > 0 {
        if len(failures) >= len(checks)/2 {
            status = goplugins.StatusUnhealthy
            message = "Multiple system failures"
        } else {
            status = goplugins.StatusDegraded
            message = "Some systems degraded"
        }
    }
    
    return goplugins.HealthStatus{
        Status:       status,
        Message:      message,
        LastCheck:    time.Now(),
        ResponseTime: time.Since(start),
        Metadata: map[string]string{
            "failures": fmt.Sprintf("%d/%d", len(failures), len(checks)),
            "details":  strings.Join(failures, "; "),
        },
    }
}
```

### 3. Handle Graceful Shutdown

```go
func (p *MyPlugin) Close() error {
    p.logger.Info("Starting graceful shutdown")
    
    // Stop accepting new requests
    p.shutdown.Store(true)
    
    // Wait for active requests to complete
    timeout := time.After(30 * time.Second)
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    for {
        select {
        case <-timeout:
            p.logger.Warn("Shutdown timeout reached, forcing close")
            return p.forceClose()
            
        case <-ticker.C:
            if p.activeRequests.Load() == 0 {
                p.logger.Info("All requests completed, shutting down")
                return p.cleanupResources()
            }
        }
    }
}

func (p *MyPlugin) cleanupResources() error {
    var errors []error
    
    // Close database connections
    if err := p.db.Close(); err != nil {
        errors = append(errors, fmt.Errorf("database close error: %w", err))
    }
    
    // Close external connections
    if err := p.httpClient.CloseIdleConnections(); err != nil {
        errors = append(errors, fmt.Errorf("HTTP client close error: %w", err))
    }
    
    // Clean up temporary files
    if err := p.cleanupTempFiles(); err != nil {
        errors = append(errors, fmt.Errorf("temp file cleanup error: %w", err))
    }
    
    if len(errors) > 0 {
        return fmt.Errorf("cleanup completed with errors: %v", errors)
    }
    
    return nil
}
```

### 4. Use Structured Logging

```go
type MyPlugin struct {
    logger goplugins.Logger
    // ... other fields
}

func (p *MyPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request MyRequest) (MyResponse, error) {
    // Add request context to logger
    requestLogger := p.logger.With(
        "request_id", execCtx.RequestID,
        "operation", request.Operation,
        "user_id", request.UserID,
    )
    
    requestLogger.Info("Processing request")
    
    start := time.Now()
    defer func() {
        duration := time.Since(start)
        requestLogger.Info("Request completed",
            "duration", duration,
            "duration_ms", duration.Milliseconds())
    }()
    
    // Process request
    result, err := p.processRequest(ctx, request)
    if err != nil {
        requestLogger.Error("Request failed", "error", err)
        return MyResponse{Error: err.Error()}, err
    }
    
    requestLogger.Info("Request successful")
    return result, nil
}
```

### 5. Implement Plugin Metadata

```go
func (p *MyPlugin) Info() goplugins.PluginInfo {
    return goplugins.PluginInfo{
        Name:        p.name,
        Version:     p.version,
        Description: "Detailed description of what this plugin does",
        Author:      "team@company.com",
        
        // Capabilities help with discovery and compatibility
        Capabilities: []string{
            "v1.0",           // API version
            "async",          // Supports async operations
            "batch",          // Supports batch processing
            "caching",        // Has caching capabilities
            "production",     // Production-ready
        },
        
        // Metadata provides additional context
        Metadata: map[string]string{
            "team":             "platform-team",
            "repository":       "https://github.com/company/plugin-repo",
            "documentation":    "https://docs.company.com/plugins/myplugin",
            "support_contact":  "platform-team@company.com",
            "build_date":       p.buildDate,
            "commit_hash":      p.commitHash,
            "supported_formats": "json,yaml",
            "max_request_size": "10MB",
        },
    }
}
```

## Complete Plugin Example

Here's a complete, production-ready plugin example:

```go
package main

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "sync/atomic"
    "time"
    
    "github.com/agilira/go-plugins"
    _ "github.com/lib/pq" // PostgreSQL driver
)

// UserAuthPlugin handles user authentication
type UserAuthPlugin struct {
    name         string
    version      string
    started      time.Time
    db           *sql.DB
    logger       goplugins.Logger
    requestCount atomic.Int64
    shutdown     atomic.Bool
}

type AuthRequest struct {
    UserID   string `json:"user_id"`
    Password string `json:"password"`
    Token    string `json:"token,omitempty"`
}

type AuthResponse struct {
    Valid    bool              `json:"valid"`
    UserID   string            `json:"user_id,omitempty"`
    Token    string            `json:"token,omitempty"`
    Metadata map[string]string `json:"metadata,omitempty"`
    Error    string            `json:"error,omitempty"`
}

func NewUserAuthPlugin(dbURL string, logger goplugins.Logger) (*UserAuthPlugin, error) {
    db, err := sql.Open("postgres", dbURL)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %w", err)
    }
    
    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("database ping failed: %w", err)
    }
    
    return &UserAuthPlugin{
        name:    "user-auth",
        version: "1.0.0",
        started: time.Now(),
        db:      db,
        logger:  logger,
    }, nil
}

func (p *UserAuthPlugin) Info() goplugins.PluginInfo {
    return goplugins.PluginInfo{
        Name:        p.name,
        Version:     p.version,
        Description: "User authentication and authorization plugin",
        Author:      "security-team@company.com",
        Capabilities: []string{
            "authenticate",
            "authorize",
            "token-validation",
            "v1.0",
            "production",
        },
        Metadata: map[string]string{
            "database":       "postgresql",
            "auth_methods":   "password,token",
            "token_lifetime": "24h",
            "team":          "security",
        },
    }
}

func (p *UserAuthPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request AuthRequest) (AuthResponse, error) {
    if p.shutdown.Load() {
        return AuthResponse{Error: "Plugin is shutting down"}, fmt.Errorf("plugin shutdown in progress")
    }
    
    p.requestCount.Add(1)
    
    requestLogger := p.logger.With(
        "request_id", execCtx.RequestID,
        "user_id", request.UserID,
    )
    
    requestLogger.Info("Processing authentication request")
    
    // Validate request
    if request.UserID == "" {
        return AuthResponse{Error: "User ID required"}, fmt.Errorf("user ID cannot be empty")
    }
    
    // Authenticate user
    if request.Password != "" {
        return p.authenticateWithPassword(ctx, request, requestLogger)
    } else if request.Token != "" {
        return p.authenticateWithToken(ctx, request, requestLogger)
    }
    
    return AuthResponse{Error: "Password or token required"}, fmt.Errorf("no authentication method provided")
}

func (p *UserAuthPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    start := time.Now()
    
    // Check database connectivity
    if err := p.db.PingContext(ctx); err != nil {
        return goplugins.HealthStatus{
            Status:       goplugins.StatusUnhealthy,
            Message:      "Database connection failed",
            LastCheck:    time.Now(),
            ResponseTime: time.Since(start),
            Metadata: map[string]string{
                "database_error": err.Error(),
                "uptime":        time.Since(p.started).String(),
            },
        }
    }
    
    return goplugins.HealthStatus{
        Status:       goplugins.StatusHealthy,
        Message:      "Authentication service operational",
        LastCheck:    time.Now(),
        ResponseTime: time.Since(start),
        Metadata: map[string]string{
            "uptime":          time.Since(p.started).String(),
            "requests_served": fmt.Sprintf("%d", p.requestCount.Load()),
            "database":        "connected",
        },
    }
}

func (p *UserAuthPlugin) Close() error {
    p.logger.Info("Starting graceful shutdown")
    p.shutdown.Store(true)
    
    // Close database connection
    if err := p.db.Close(); err != nil {
        p.logger.Error("Failed to close database", "error", err)
        return err
    }
    
    p.logger.Info("Shutdown completed")
    return nil
}

func main() {
    // Initialize logger
    logger := goplugins.SimpleDefaultLogger()
    
    // Create plugin
    plugin, err := NewUserAuthPlugin("postgres://user:pass@localhost/auth", logger)
    if err != nil {
        log.Fatal("Failed to create plugin:", err)
    }
    
    // Create and configure server
    config := goplugins.ServeConfig{
        PluginName:    "user-auth",
        PluginVersion: "1.0.0",
        PluginType:    "auth",
        Logger:        logger,
    }
    
    server := goplugins.NewGenericPluginServer(config)
    server.RegisterPlugin(plugin)
    
    // Serve plugin
    ctx := context.Background()
    err = server.Serve(ctx, config)
    if err != nil {
        log.Fatal("Failed to serve plugin:", err)
    }
}
```

## Building and Deployment

### Building Your Plugin

```bash
# Build for the target platform
go build -o my-plugin ./plugin/

# Build with optimizations for production
go build -ldflags="-s -w" -o my-plugin ./plugin/

# Cross-compile for different platforms
GOOS=linux GOARCH=amd64 go build -o my-plugin-linux ./plugin/
GOOS=windows GOARCH=amd64 go build -o my-plugin.exe ./plugin/
GOOS=darwin GOARCH=amd64 go build -o my-plugin-darwin ./plugin/
```

### Plugin Deployment

```bash
# Create plugin directory structure
mkdir -p /opt/plugins/my-plugin/
cp my-plugin /opt/plugins/my-plugin/
cp plugin.json /opt/plugins/my-plugin/

# Set proper permissions
chmod +x /opt/plugins/my-plugin/my-plugin
chmod 644 /opt/plugins/my-plugin/plugin.json

# Generate security hash for whitelist
plugin-hash --file /opt/plugins/my-plugin/my-plugin --algorithm sha256
```

## Next Steps

- Learn about [Plugin Discovery](/guides/discovery/) for making your plugins discoverable
- Explore [Security System](/guides/security/) for securing your plugins
- Check out [Production Deployment](/guides/production/) for deployment best practices

{{% alert title="Development Tip" %}}
Use the `Development()` builder in the host application when testing your plugins locally. It provides verbose logging and longer timeouts suitable for debugging.
{{% /alert %}}

{{% alert title="Security Note" %}}
Always validate input in your plugin's Execute method. Never trust data from the host application, and implement proper error handling for all failure scenarios.
{{% /alert %}}
