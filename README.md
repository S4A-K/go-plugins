# go-plugins: Type-safe plugin system for Go
### an AGILira library

go-plugins is a production-ready, type-safe plugin architecture for Go applications with subprocess execution, circuit breaking, health monitoring, and ultra-fast hot-reload powered by [Argus](https://github.com/agilira/argus).

[![CI/CD Pipeline](https://github.com/agilira/go-plugins/actions/workflows/ci.yml/badge.svg)](https://github.com/agilira/go-plugins/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/security-gosec-brightgreen.svg)](https://github.com/agilira/go-plugins/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/agilira/go-plugins?v=2)](https://goreportcard.com/report/github.com/agilira/go-plugins)
[![Coverage](https://codecov.io/gh/agilira/go-plugins/branch/main/graph/badge.svg)](https://codecov.io/gh/agilira/go-plugins)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/agilira/go-plugins.svg)](https://pkg.go.dev/github.com/agilira/go-plugins)

**[Features](#features) • [Quick Start](#quick-start) • [Core Components](#core-components) • [Examples](#examples) • [Documentation](#documentation)**

## Features

- **Simplified API**: Ultra-simple fluent interface for common use cases (3 lines vs 15+ lines)
- **Smart Presets**: Development/Production presets with optimal defaults and automatic logging
- **Auto-Discovery**: Convention-over-configuration plugin discovery with filtering
- **Type Safety**: Generics-based architecture with compile-time type safety for requests/responses
- **Subprocess Execution**: Primary transport via isolated process execution for security and reliability  
- **Circuit Breaker**: Automatic failure detection and recovery with configurable thresholds
- **Health Monitoring**: Continuous health checks with automatic status tracking and recovery
- **Security System**: Hash-based plugin whitelist with SHA-256 validation and audit trails
- **Hot Reload**: Ultra-fast configuration reloading powered by [Argus](https://github.com/agilira/argus)
- **Observability**: Built-in metrics collection and structured logging
- **Pluggable Logging**: Interface-based logging supporting any framework (zap, logrus, zerolog, custom)
- **Graceful Operations**: Active request monitoring for zero-downtime deployments
- **Flexible Configuration**: JSON/YAML files + environment variables with `${VAR}` expansion
- **Single-File Setup**: Complete system configuration in one file with hot-reload support

## Compatibility and Support

go-plugins supports the latest two minor versions of Go (currently Go 1.24+ and Go 1.25+) and follows Long-Term Support guidelines to ensure consistent performance across production deployments.

## Quick Start

### Installation

```bash
go get github.com/agilira/go-plugins
```

## Simplified API (New!)

go-plugins now offers a simplified API for common use cases, Choose the approach that fits your needs:

### Ultra-Simple Setup

```go
// Before: 15+ lines of boilerplate
// After: 3 lines to get started!

manager, err := goplugins.Simple[AuthRequest, AuthResponse]().
    WithPlugin("auth-service", goplugins.Subprocess("./auth-plugin")).
    Build()
```

### Environment Presets

**Development Mode** (with automatic logging):
```go
manager, err := goplugins.Development[AuthRequest, AuthResponse]().
    WithPlugin("auth-service", goplugins.Subprocess("./auth-plugin")).
    Build()
// Output: [go-plugins] [INFO] Development preset initialized
```

**Production Mode** (optimized defaults):
```go
manager, err := goplugins.Production[AuthRequest, AuthResponse]().
    WithPlugin("api-gateway", goplugins.GRPC("gateway:443")).
    WithSecurity("./whitelist.json").
    WithMetrics().
    Build()
```

### Auto-Discovery

**Convention over Configuration**:
```go
// Automatically discover all plugins in directory
manager, err := goplugins.Auto[Request, Response]().
    FromDirectory("./plugins").
    WithDefaults().
    Build()

// Advanced auto-discovery with filters
manager, err := goplugins.Auto[Request, Response]().
    FromDirectories([]string{"./plugins", "./extensions"}).
    WithPattern("*-plugin").
    WithMaxDepth(3).
    WithFilter(func(manifest *goplugins.PluginManifest) bool {
        return manifest.Name != "disabled-plugin"
    }).
    WithDefaults().
    Build()
```

### Fluent Interface

**Chain multiple configurations**:
```go
manager, err := goplugins.Simple[Request, Response]().
    WithLogger(customLogger).
    WithTimeout(30 * time.Second).
    WithPlugin("auth", goplugins.Subprocess("./auth")).
    WithPlugin("cache", goplugins.HTTP("http://cache:8080")).
    WithPlugin("db", goplugins.GRPC("db-service:443")).
    WithSecurity("./security.json").
    WithMetrics().
    Build()
```

### API Comparison

| Task | Traditional API | Simplified API |
|------|-----------------|----------------|
| Basic setup | 15+ lines | 3 lines |
| Add logging | Custom Logger impl | `Development()` preset |
| Multiple plugins | Manual factory registration | Fluent chaining |
| Auto-discovery | Manual DiscoveryEngine setup | `Auto().FromDirectory()` |
| Production config | Complex ManagerConfig | `Production().WithSecurity()` |

> **Tip**: The simplified API is perfect for 80% of use cases. For advanced scenarios, the full traditional API remains available.

### Basic Example

```go
package main

import (
    "context"
    "log"
    "time"
    
    goplugins "github.com/agilira/go-plugins"
)

// Define your request/response types
type AuthRequest struct {
    UserID string `json:"user_id"`
    Token  string `json:"token"`
}

type AuthResponse struct {
    Valid   bool   `json:"valid"`
    Message string `json:"message,omitempty"`
}

func main() {
    // Create manager with pluggable logging
    // - Implement Logger interface for your framework (zap, logrus, etc.)
    // - Use nil for silent operation
    // - Zero external logging dependencies
    manager := goplugins.NewManager[AuthRequest, AuthResponse](nil)

    // Register subprocess factory (primary transport)
    factory := goplugins.NewSubprocessPluginFactory[AuthRequest, AuthResponse](nil)
    manager.RegisterFactory("subprocess", factory)

    // Load plugins from configuration
    config := goplugins.ManagerConfig{
        Plugins: []goplugins.PluginConfig{
            {
                Name:      "auth-service",
                Type:      "subprocess", 
                Transport: goplugins.TransportExecutable,
                Endpoint:  "./auth-plugin",
                Enabled:   true,
            },
        },
    }
    
    if err := manager.LoadFromConfig(config); err != nil {
        log.Fatal(err)
    }

    // Execute requests
    ctx := context.Background()
    response, err := manager.Execute(ctx, "auth-service", AuthRequest{
        UserID: "user123",
        Token:  "access-token",
    })
    
    if err != nil {
        log.Printf("Request failed: %v", err)
        return
    }
    
    log.Printf("Auth result: %+v", response)
    
    // Graceful shutdown
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    manager.Shutdown(shutdownCtx)
}
```

## Core Components

### Manager
Central controller for plugin lifecycle, routing, and orchestration. Provides circuit breaker integration, health monitoring, and graceful shutdown capabilities.

### Plugin Interface
Generic `Plugin[Req, Resp]` interface with Execute, Health, Info, and Close methods. Type-safe design ensures compile-time validation of request/response types.

### Plugin Factory
`PluginFactory[Req, Resp]` creates plugin instances from configuration. Built-in factories for subprocess and gRPC transports with extensible factory registration.

### Transport Layer
- **Subprocess** (primary): Isolated process execution for maximum security and reliability
- **gRPC Native**: High-performance protobuf serialization with TLS/mTLS support and type safety

## Key Features Overview

### Security System
Hash-based plugin whitelist with SHA-256 validation, audit trails, and hot-reload support. See **[Security Guide](./docs/PLUGIN_SECURITY.md)**.

### Auto-Discovery
Intelligent plugin detection via filesystem scanning with manifest validation. See **[Discovery Guide](./docs/DISCOVERY.md)**.

### Configuration Options

**Single-File Configuration**: Define everything in one file with environment variable support:

```json
{
  "plugins": [{
    "name": "auth-service",
    "type": "subprocess",
    "transport": "exec", 
    "endpoint": "${AUTH_SERVICE_PATH}",
    "auth": {
      "method": "bearer",
      "token": "${AUTH_TOKEN}"
    }
  }]
}
```

**Programmatic Configuration**: Direct API configuration without files:

```go
config := goplugins.ManagerConfig{
    Plugins: []goplugins.PluginConfig{
        {
            Name:      "service",
            Type:      "subprocess",
            Transport: goplugins.TransportExecutable,
            Endpoint:  "./service-plugin",
            Enabled:   true,
        },
    },
}
manager.LoadFromConfig(config)
```

### High-Performance gRPC Transport
Native protobuf support with advanced security and type safety:

```go
import "google.golang.org/protobuf/types/known/timestamppb"

// gRPC with protobuf messages (type-safe)
type AuthProtoRequest struct {
    UserID    string                 `protobuf:"bytes,1,opt,name=user_id,proto3"`
    Token     string                 `protobuf:"bytes,2,opt,name=token,proto3"`
    Timestamp *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=timestamp,proto3"`
}

type AuthProtoResponse struct {
    Valid     bool   `protobuf:"varint,1,opt,name=valid,proto3"`
    Message   string `protobuf:"bytes,2,opt,name=message,proto3"`
}

// Configure gRPC with TLS/mTLS authentication
config := goplugins.PluginConfig{
    Name:      "auth-grpc",
    Type:      "grpc",
    Transport: goplugins.TransportGRPCTLS,
    Endpoint:  "auth-service:443",
    Auth: goplugins.AuthConfig{
        Method:   goplugins.AuthMTLS,
        CertFile: "/path/to/client.crt",
        KeyFile:  "/path/to/client.key", 
        CAFile:   "/path/to/ca.crt",
    },
}

// Register gRPC factory for protobuf messages
factory := goplugins.NewGRPCPluginFactory[AuthProtoRequest, AuthProtoResponse](logger)
manager.RegisterFactory("grpc", factory)
```

### Pluggable Logging System
Zero-dependency logging interface supporting any framework. Implement the `Logger` interface to connect your preferred logging solution:

```go
// Use any logger that implements the interface
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any) 
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
    With(args ...any) Logger
}

// Examples with different frameworks
zapLogger := &ZapAdapter{zap.NewDevelopment()}
logrusLogger := &LogrusAdapter{logrus.New()}
manager := goplugins.NewManager[Req, Resp](zapLogger)

// Or use nil for silent operation
manager := goplugins.NewManager[Req, Resp](nil)
```

### Observability
Comprehensive metrics collection and structured logging integration. See **[Observability Guide](./docs/OBSERVABILITY.md)**.

### Dynamic Loading
Hot-loading capabilities with version compatibility checking and dependency resolution. See **[Dynamic Loading Guide](./docs/DYNAMIC_LOADING.md)**.

## Examples

Available examples demonstrating key plugin capabilities:

### [Security Demo](examples/security_demo/)
Hash-based plugin whitelist system with SHA-256 validation, hot-reload, and audit trails.

### [Crash Isolation Demo](examples/crash-isolation-demo/)
Subprocess plugin crash handling and automatic recovery mechanisms.

**Quick Start:**
```bash
cd examples/<example-name>/
go run .
```

## Documentation

Comprehensive documentation is available in the [docs](./docs/) folder:

- **[Configuration Guide](./docs/CONFIGURATION.md)** - Multi-format config support, hot-reload, and validation
- **[Security Guide](./docs/PLUGIN_SECURITY.md)** - Plugin whitelist, authentication, and audit systems
- **[Discovery Guide](./docs/DISCOVERY.md)** - Auto-discovery, manifest validation, and capability matching
- **[Dynamic Loading Guide](./docs/DYNAMIC_LOADING.md)** - Hot-loading, version management, and dependency resolution
- **[Observability Guide](./docs/OBSERVABILITY.md)** - Metrics, tracing, and structured logging integration

---

**Documentation**: [docs/](./docs/) | **Examples**: [examples/](./examples/) | **[🚀 New Simplified API](#-simplified-api-new)**

## What's New

### v2.1.0 - Simplified API Revolution

We've dramatically simplified go-plugins while maintaining 100% backward compatibility:

- **3-line setup** instead of 15+ lines of boilerplate
- **Smart presets** for Development/Production with optimal defaults
- **Auto-discovery** with convention-over-configuration
- **Built-in logger** for out-of-the-box development experience
- **Fluent interface** for readable, chainable configuration

```go
// New: Ultra-simple setup
manager, err := goplugins.Simple[Request, Response]().
    WithPlugin("service", goplugins.Subprocess("./service")).
    Build()

// Old API still works unchanged!
manager := goplugins.NewManager[Request, Response](logger)
// ... existing code continues to work
```

## License

go-plugins is licensed under the [Mozilla Public License 2.0](./LICENSE.md).

---

go-plugins • an AGILira library
