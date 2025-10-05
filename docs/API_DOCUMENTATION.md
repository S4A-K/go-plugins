# go-plugins - Complete API Documentation

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE.md)

## Overview

**go-plugins** provides a production-ready, type-safe plugin architecture for Go applications. It supports gRPC and subprocess transport protocols with built-in circuit breaking, health monitoring, authentication, and graceful degradation.

### Key Features

- **Type-safe plugin interfaces** using Go generics
- **Multiple transport protocols** (gRPC, subprocess execution)
- **Circuit breaker pattern** for resilience
- **Health monitoring** and automatic recovery
- **Advanced security system** with plugin whitelisting and hash validation
- **Comprehensive observability** with metrics and distributed tracing
- **Hot-reloading** of plugin configurations with active request monitoring
- **Production-grade graceful draining** (no more time.Sleep!)
- **Pluggable logging system** supporting any framework
- **Graceful shutdown** with proper cleanup

## Table of Contents

1. [Quick Start](#quick-start)
2. [Simple API](#simple-api)
3. [Advanced Configuration](#advanced-configuration)
4. [Security System](#security-system)
5. [Observability & Metrics](#observability--metrics)
6. [Plugin Development](#plugin-development)
7. [Transport Protocols](#transport-protocols)
8. [Production Deployment](#production-deployment)
9. [API Reference](#api-reference)

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/agilira/go-plugins"
)

// Define your plugin request/response types
type AuthRequest struct {
    UserID string `json:"user_id"`
    Token  string `json:"token"`
}

type AuthResponse struct {
    Valid   bool   `json:"valid"`
    UserID  string `json:"user_id,omitempty"`
    Error   string `json:"error,omitempty"`
}

func main() {
    // Create a simple manager with development defaults
    manager, err := goplugins.Development[AuthRequest, AuthResponse]().
        WithPlugin("auth", goplugins.Subprocess("./auth-plugin")).
        WithPlugin("backup-auth", goplugins.GRPC("localhost:9090")).
        Build()
    if err != nil {
        log.Fatal("Failed to build manager:", err)
    }
    defer manager.Shutdown(context.Background())

    // Execute plugin operations
    ctx := context.Background()
    response, err := manager.Execute(ctx, "auth", AuthRequest{
        UserID: "user123",
        Token:  "jwt-token-here",
    })
    if err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    log.Printf("Authentication result: %+v", response)
}
```

## Simple API

The Simple API provides a fluent, builder-pattern interface for common use cases:

### Builder Functions

```go
// Development environment with verbose logging and longer timeouts
manager := goplugins.Development[Req, Resp]()

// Production environment with metrics and shorter timeouts
manager := goplugins.Production[Req, Resp]()

// Auto-discovery from directories
manager := goplugins.Auto[Req, Resp]().
    FromDirectory("./plugins").
    WithPattern("*-plugin").
    Build()
```

### Configuration Methods

```go
manager := goplugins.Simple[Req, Resp]().
    WithPlugin("service", goplugins.Subprocess("./service")).
    WithLogger(myLogger).
    WithTimeout(30 * time.Second).
    WithSecurity("./plugins.whitelist").  // Enable security
    WithMetrics().                        // Enable metrics
    Build()
```

## Advanced Configuration

### Full Configuration Example

```go
config := goplugins.GetDefaultManagerConfig()

// Add plugins with detailed configuration
config.Plugins = []goplugins.PluginConfig{
    {
        Name:      "auth-service",
        Type:      "subprocess",
        Transport: goplugins.TransportExecutable,
        Executable: "./plugins/auth-service",
        Args:      []string{"--config", "/etc/auth.conf"},
        Env:       []string{"LOG_LEVEL=info", "MAX_MEMORY=1GB"},
        Enabled:   true,
        Priority:  1,
        
        // Authentication
        Auth: goplugins.AuthConfig{
            Method: goplugins.AuthAPIKey,
            APIKey: "secure-api-key",
        },
        
        // Resilience patterns
        Retry: goplugins.RetryConfig{
            MaxRetries:      3,
            InitialInterval: 100 * time.Millisecond,
            MaxInterval:     5 * time.Second,
            Multiplier:      2.0,
            RandomJitter:    true,
        },
        
        CircuitBreaker: goplugins.CircuitBreakerConfig{
            Enabled:             true,
            FailureThreshold:    5,
            RecoveryTimeout:     30 * time.Second,
            MinRequestThreshold: 3,
            SuccessThreshold:    2,
        },
        
        HealthCheck: goplugins.HealthCheckConfig{
            Enabled:      true,
            Interval:     30 * time.Second,
            Timeout:      5 * time.Second,
            FailureLimit: 3,
        },
        
        // Performance tuning
        Connection: goplugins.ConnectionConfig{
            MaxConnections:     10,
            MaxIdleConnections: 5,
            IdleTimeout:        30 * time.Second,
            ConnectionTimeout:  10 * time.Second,
            RequestTimeout:     30 * time.Second,
            KeepAlive:          true,
        },
        
        RateLimit: goplugins.RateLimitConfig{
            Enabled:           true,
            RequestsPerSecond: 10.0,
            BurstSize:         20,
            TimeWindow:        time.Second,
        },
    },
}

// Load configuration
manager := goplugins.NewManager[AuthRequest, AuthResponse](logger)
err := manager.LoadFromConfig(config)
```

## Security System

go-plugins includes a comprehensive security system with plugin whitelisting and hash validation:

### Security Configuration

```go
securityConfig := goplugins.SecurityConfig{
    Enabled:       true,
    Policy:        goplugins.SecurityPolicyStrict,
    WhitelistFile: "./config/plugins.whitelist",
    WatchConfig:   true,  // Hot-reload security config
    HashAlgorithm: goplugins.HashAlgorithmSHA256,
    
    // Audit configuration
    AuditConfig: goplugins.SecurityAuditConfig{
        Enabled:         true,
        AuditFile:       "", // Empty = unified SQLite backend (recommended)
        LogUnauthorized: true,
        LogAuthorized:   false,
        LogConfigChanges: true,
        IncludeMetadata:  true,
    },
}

err := manager.EnablePluginSecurity(securityConfig)
```

### Plugin Whitelist Format

Create a `plugins.whitelist` file:

```yaml
# Plugin Whitelist Configuration
version: "1.0"
plugins:
  - name: "auth-service"
    path: "./plugins/auth-service"
    hash: "sha256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
    algorithm: "sha256"
    enabled: true
    metadata:
      version: "1.2.3"
      author: "security-team@company.com"
      
  - name: "payment-service" 
    path: "./plugins/payment-service"
    hash: "sha256:fedcba0987654321098765432109876543210fedcba0987654321098765432"
    algorithm: "sha256"
    enabled: true
```

### Security Policies

- **Strict**: Only whitelisted plugins with valid hashes can be loaded
- **Permissive**: Warnings for non-whitelisted plugins, but allows execution
- **Audit**: Logs all plugin operations for compliance and monitoring

### Security Features

- **Hash Validation**: SHA256 hash verification of plugin binaries
- **Path Traversal Protection**: Prevents malicious path manipulation
- **Audit Logging**: Comprehensive security event logging
- **Hot-reload**: Security configuration updates without restart
- **Plugin Isolation**: Process-level isolation for subprocess plugins

## Observability & Metrics

### Built-in Metrics

go-plugins provides comprehensive observability out of the box:

```go
// Enable metrics during manager creation
manager := goplugins.Production[Req, Resp]().
    WithMetrics().
    Build()

// Access metrics programmatically
metrics := manager.GetMetrics()
fmt.Printf("Total requests: %d\n", metrics.RequestsTotal.Load())
fmt.Printf("Success rate: %.2f%%\n", 
    float64(metrics.RequestsSuccess.Load()) / 
    float64(metrics.RequestsTotal.Load()) * 100)
```

### Available Metrics

#### Manager-Level Metrics
- `plugin_requests_total`: Total number of plugin requests
- `plugin_requests_success`: Number of successful requests  
- `plugin_requests_failure`: Number of failed requests
- `plugin_request_duration`: Request latency histogram
- `plugin_circuit_breaker_trips`: Circuit breaker activation count
- `plugin_health_check_failures`: Health check failure count

#### Plugin-Level Metrics
- `plugin_status`: Current plugin status (healthy/degraded/unhealthy/offline)
- `plugin_response_time`: Plugin response time
- `plugin_error_rate`: Plugin error rate
- `plugin_active_requests`: Number of active requests per plugin

### Distributed Tracing

```go
// Configure tracing
tracingConfig := goplugins.TracingConfig{
    Enabled:     true,
    ServiceName: "my-service",
    Endpoint:    "http://jaeger:14268/api/traces",
    SampleRate:  0.1, // 10% sampling
}

manager.EnableTracing(tracingConfig)

// Tracing is automatically propagated through plugin calls
ctx = manager.InjectTracing(ctx, "operation-name")
response, err := manager.Execute(ctx, "plugin-name", request)
```

### Custom Metrics Exporters

```go
// Prometheus exporter
prometheusExporter := goplugins.NewPrometheusExporter(goplugins.PrometheusConfig{
    Namespace: "myapp",
    Subsystem: "plugins",
    Port:      9090,
})

// OpenTelemetry exporter  
otlpExporter := goplugins.NewOTLPExporter(goplugins.OTLPConfig{
    Endpoint: "http://otel-collector:4317",
    Headers:  map[string]string{"api-key": "secret"},
})

manager.RegisterMetricsExporter(prometheusExporter)
manager.RegisterMetricsExporter(otlpExporter)
```

## Plugin Development

### Implementing a Plugin

```go
package main

import (
    "context"
    "encoding/json"
    
    "github.com/agilira/go-plugins"
)

type AuthPlugin struct {
    name string
    db   *Database
}

func (p *AuthPlugin) Info() goplugins.PluginInfo {
    return goplugins.PluginInfo{
        Name:        p.name,
        Version:     "1.0.0", 
        Description: "Authentication service plugin",
        Author:      "security-team@company.com",
        Capabilities: []string{"authenticate", "authorize"},
        Metadata: map[string]string{
            "database": "postgresql",
            "cache":    "redis",
        },
    }
}

func (p *AuthPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request AuthRequest) (AuthResponse, error) {
    // Implement your plugin logic here
    valid, err := p.db.ValidateUser(ctx, request.UserID, request.Token)
    if err != nil {
        return AuthResponse{Error: err.Error()}, err
    }
    
    return AuthResponse{Valid: valid, UserID: request.UserID}, nil
}

func (p *AuthPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    // Check database connectivity
    if err := p.db.Ping(ctx); err != nil {
        return goplugins.HealthStatus{
            Status:    goplugins.StatusUnhealthy,
            Message:   "Database connection failed",
            LastCheck: time.Now(),
        }
    }
    
    return goplugins.HealthStatus{
        Status:    goplugins.StatusHealthy,
        Message:   "All systems operational",
        LastCheck: time.Now(),
    }
}

func (p *AuthPlugin) Close() error {
    return p.db.Close()
}

func main() {
    plugin := &AuthPlugin{
        name: "auth-service",
        db:   NewDatabase(),
    }
    
    // Serve the plugin
    goplugins.Serve(goplugins.ServeConfig{
        PluginName: "auth-service",
        Plugin:     plugin,
        Transport:  goplugins.TransportExecutable,
    })
}
```

## Transport Protocols

### Subprocess Transport (Recommended)

Best for security and isolation:

```go
transport := goplugins.Subprocess("./auth-plugin")

// With custom configuration
config := goplugins.PluginConfig{
    Name:       "auth-service",
    Transport:  goplugins.TransportExecutable,
    Executable: "./plugins/auth-service",
    Args:       []string{"--config", "/etc/auth.conf"},
    Env:        []string{"LOG_LEVEL=info"},
    WorkDir:    "/var/lib/plugins",
}
```

### gRPC Transport

For high-performance scenarios:

```go
transport := goplugins.GRPC("localhost:9090")

// With TLS
config := goplugins.PluginConfig{
    Name:      "payment-service",
    Transport: goplugins.TransportGRPCTLS,
    Endpoint:  "payment.internal:9090",
    Auth: goplugins.AuthConfig{
        Method:   goplugins.AuthMTLS,
        CertFile: "/etc/certs/client.crt",
        KeyFile:  "/etc/certs/client.key",
        CAFile:   "/etc/certs/ca.crt",
    },
}
```

## Production Deployment

### Zero-Downtime Updates

```go
// Graceful plugin replacement
err := manager.GracefulUnregister("old-plugin", 30*time.Second)
if err != nil {
    log.Printf("Failed to drain old plugin: %v", err)
}

newPlugin := createNewPlugin()
err = manager.Register(newPlugin)
if err != nil {
    log.Printf("Failed to register new plugin: %v", err)
}
```

### Health Monitoring

```go
// Check overall system health
healthStatus := manager.Health()
for pluginName, status := range healthStatus {
    if status.Status != goplugins.StatusHealthy {
        log.Printf("Plugin %s unhealthy: %s", pluginName, status.Message)
    }
}

// Get detailed plugin information
plugin, err := manager.GetPlugin("auth-service")
if err == nil {
    info := plugin.Info()
    log.Printf("Plugin %s v%s by %s", info.Name, info.Version, info.Author)
}
```

### Graceful Shutdown

```go
// Graceful shutdown with timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

err := manager.Shutdown(ctx)
if err != nil {
    log.Printf("Shutdown completed with warnings: %v", err)
}
```

## API Reference

### Core Interfaces

#### Plugin Interface
```go
type Plugin[Req, Resp any] interface {
    Info() PluginInfo
    Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error)
    Health(ctx context.Context) HealthStatus
    Close() error
}
```

#### PluginManager Interface
```go
type PluginManager[Req, Resp any] interface {
    Register(plugin Plugin[Req, Resp]) error
    Unregister(name string) error
    Execute(ctx context.Context, pluginName string, request Req) (Resp, error)
    ExecuteWithOptions(ctx context.Context, pluginName string, execCtx ExecutionContext, request Req) (Resp, error)
    GetPlugin(name string) (Plugin[Req, Resp], error)
    ListPlugins() map[string]HealthStatus
    LoadFromConfig(config ManagerConfig) error
    ReloadConfig(config ManagerConfig) error
    Health() map[string]HealthStatus
    Shutdown(ctx context.Context) error
}
```

### Configuration Types

#### ManagerConfig
Complete configuration for the plugin manager with global settings and plugin definitions.

#### PluginConfig  
Comprehensive configuration for individual plugins including transport, authentication, resilience patterns, and performance settings.

#### SecurityConfig
Security system configuration with whitelist management, audit logging, and policy enforcement.

### Transport Types

#### TransportType Constants
- `TransportGRPC`: gRPC protocol support
- `TransportGRPCTLS`: gRPC with TLS
- `TransportExecutable`: Subprocess execution (recommended)

### Authentication Methods

#### AuthMethod Constants
- `AuthNone`: No authentication required
- `AuthAPIKey`: API key-based authentication  
- `AuthBearer`: Bearer token authentication
- `AuthBasic`: Basic authentication with username/password
- `AuthMTLS`: Mutual TLS authentication using client certificates
- `AuthCustom`: Custom authentication method

### Error Types

The library provides structured error types with specific error codes for different failure scenarios:

- **Configuration errors** (1000-1099): Invalid plugin names, transports, endpoints
- **Authentication errors** (1100-1199): Missing credentials, invalid auth methods
- **Plugin execution errors** (1200-1299): Plugin not found, execution failures, timeouts
- **Transport errors** (1300-1399): gRPC and subprocess transport failures
- **Circuit breaker errors** (1400-1499): Circuit breaker open, timeouts
- **Security errors** (1800-1899): Security validation failures, whitelist violations

## Best Practices

### Security
1. Always use plugin whitelisting in production
2. Enable audit logging for compliance
3. Use subprocess transport for maximum isolation
4. Implement proper authentication between components
5. Regularly rotate API keys and certificates

### Performance  
1. Configure appropriate connection pools
2. Set reasonable timeouts and retry policies
3. Use circuit breakers to prevent cascade failures
4. Monitor metrics and adjust thresholds
5. Enable distributed tracing for debugging

### Reliability
1. Implement comprehensive health checks
2. Use graceful shutdown procedures
3. Plan for zero-downtime deployments
4. Test failure scenarios regularly
5. Have rollback procedures ready

### Monitoring
1. Export metrics to your monitoring system
2. Set up alerting on key metrics
3. Monitor plugin health continuously
4. Track request latency and error rates
5. Use distributed tracing for complex scenarios

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Mozilla Public License 2.0 - see [LICENSE.md](LICENSE.md) for details.
