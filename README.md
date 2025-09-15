# go-plugins: GO Plugin System over HTTP, gRPC & Unix Sockets 
### an AGILira library

[![CI/CD Pipeline](https://github.com/agilira/go-plugins/actions/workflows/ci.yml/badge.svg)](https://github.com/agilira/go-plugins/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/security-gosec-brightgreen.svg)](https://github.com/agilira/go-plugins/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/agilira/go-plugins?v=2)](https://goreportcard.com/report/github.com/agilira/go-plugins)
[![Coverage](https://codecov.io/gh/agilira/orpheus/branch/main/graph/badge.svg)](https://codecov.io/gh/agilira/go-plugins)

go-plugins provides a production-ready, type-safe plugin architecture for Go applications. It supports multiple transport protocols (HTTP, gRPC, Unix sockets) with built-in circuit breaking, health monitoring, authentication, graceful degradation & hot reload powered by [Argus](https://github.com/agilira/argus) (12.10ns/op).

**[Features](#features) • [Quick Start](#quick-start) • [Usage](#usage) • [Usage Examples](#usage-examples) • [Observability](#observability) • [Examples](#examples) • [Documentation](#documentation) • [API Reference](#api-reference)**

## Features

- **Multiple Transport Protocols**: HTTP/HTTPS, gRPC (with optional TLS), Unix domain sockets, and executable plugins
- **Type Safety**: Generics-based architecture ensuring compile-time type safety for requests and responses
- **Circuit Breaker Pattern**: Automatic failure detection and recovery with configurable thresholds
- **Health Monitoring**: Continuous health checking with automatic plugin status management
- **Load Balancing**: Multiple algorithms including round-robin, least connections, and weighted random
- **Authentication**: Support for API keys, Bearer tokens, Basic auth, mTLS, and custom methods
- **Hot Reload**: Ultra-fast configuration reloading powered by [Argus](https://github.com/agilira/argus) with graceful connection draining
- **Rate Limiting**: Token bucket rate limiting to prevent overwhelming plugins
- **Observability**: Comprehensive metrics collection and structured logging
- **Connection Pooling**: Efficient resource management with configurable connection limits

## Compatibility and Support

go-plugins supports Go 1.23+ but **Go 1.25+ is recommended** for production environments due to enhanced security in dependency chains. The library follows Long-Term Support guidelines to ensure consistent performance across production deployments.

## Quick Start

### Installation

```bash
go get github.com/agilira/go-plugins
```

### Basic Usage

```go
package main

import (
    "context"
    "log"
    "log/slog"

    "github.com/agilira/go-plugins"
)

// Define request/response types
type AuthRequest struct {
    UserID string `json:"user_id"`
    Token  string `json:"token"`
}

type AuthResponse struct {
    Valid   bool   `json:"valid"`
    Message string `json:"message,omitempty"`
}

func main() {
    // Create manager
    logger := slog.Default()
    manager := goplugins.NewManager[AuthRequest, AuthResponse](logger)

    // Register plugin factory
    httpFactory := goplugins.NewHTTPPluginFactory[AuthRequest, AuthResponse]()
    manager.RegisterFactory("http", httpFactory)

    // Configure plugins
    config := goplugins.ManagerConfig{
        Plugins: []goplugins.PluginConfig{
            {
                Name:      "auth-service",
                Type:      "http",
                Transport: goplugins.TransportHTTPS,
                Endpoint:  "https://auth.example.com/api/v1/validate",
                Enabled:   true,
                Auth: goplugins.AuthConfig{
                    Method: goplugins.AuthBearer,
                    Token:  "your-jwt-token",
                },
            },
        },
    }

    // Load configuration
    if err := manager.LoadFromConfig(config); err != nil {
        log.Fatal(err)
    }

    // Execute plugin request
    ctx := context.Background()
    request := AuthRequest{
        UserID: "user123",
        Token:  "access-token",
    }

    response, err := manager.Execute(ctx, "auth-service", request)
    if err != nil {
        log.Printf("Request failed: %v", err)
        return
    }

    log.Printf("Authentication result: %+v", response)
}
```

### Usage

#### HTTP/HTTPS Plugin Configuration
```go
config := goplugins.PluginConfig{
    Name:      "api-service",
    Transport: goplugins.TransportHTTPS,
    Endpoint:  "https://api.example.com/v1/process",
    Auth: goplugins.AuthConfig{
        Method: goplugins.AuthAPIKey,
        APIKey: "your-api-key",
    },
    Connection: goplugins.ConnectionConfig{
        MaxConnections:    10,
        RequestTimeout:    30 * time.Second,
        ConnectionTimeout: 10 * time.Second,
    },
}
```

#### gRPC Plugin Configuration
```go
config := goplugins.PluginConfig{
    Name:      "grpc-service",
    Transport: goplugins.TransportGRPCTLS,
    Endpoint:  "grpc.example.com:443",
    Auth: goplugins.AuthConfig{
        Method:   goplugins.AuthMTLS,
        CertFile: "/etc/ssl/client.crt",
        KeyFile:  "/etc/ssl/client.key",
        CAFile:   "/etc/ssl/ca.crt",
    },
}
```

#### Unix Domain Socket Plugin Configuration
```go
config := goplugins.PluginConfig{
    Name:      "local-processor",
    Transport: goplugins.TransportUnix,
    Endpoint:  "/tmp/processor.sock",
    Connection: goplugins.ConnectionConfig{
        MaxConnections: 20,
    },
}
```

### Observability

#### Metrics Collection
```go
// Enable enhanced observability
observableManager := goplugins.NewObservableManager(manager, 
    goplugins.EnhancedObservabilityConfig(), logger)

// Get comprehensive metrics
metrics := observableManager.GetObservabilityMetrics()
log.Printf("Total requests: %d", metrics.TotalRequests)
log.Printf("Success rate: %.2f%%", metrics.OverallSuccessRate)

// Per-plugin metrics
for pluginName, pluginMetrics := range metrics.PluginMetrics {
    log.Printf("Plugin %s: %d requests, %.2f%% success rate",
        pluginName, pluginMetrics.TotalRequests, pluginMetrics.SuccessRate)
}
```

#### Circuit Breaker and Health Monitoring
```go
// Get plugin health status
healthStatus := manager.Health()
for pluginName, status := range healthStatus {
    log.Printf("Plugin %s: %s (%v)", 
        pluginName, status.Status, status.ResponseTime)
}

// Centralized health monitoring
monitor := goplugins.NewHealthMonitor()
monitor.AddChecker("auth-service", authHealthChecker)
monitor.AddChecker("payment-service", paymentHealthChecker)

overallHealth := monitor.GetOverallHealth()
if overallHealth.Status != goplugins.StatusHealthy {
    log.Printf("System degraded: %s", overallHealth.Message)
}
```

#### Advanced Metrics Integration

**Production-Ready Observability with Pluggable Exporters:**

```go
// Create metrics registry with multiple exporters
registry := goplugins.NewMetricsRegistry(goplugins.RegistryConfig{
    ExportInterval: 15 * time.Second,
    BatchSize:      1000,
})

// Register multiple observability backends
registry.RegisterExporter(goplugins.NewPrometheusExporter())
registry.RegisterExporter(goplugins.NewOpenTelemetryExporter())

// Type-safe metrics with automatic export
counter := registry.Counter("api_requests_total", 
    "Total API requests", "method", "status")
gauge := registry.Gauge("active_connections", 
    "Active connections", "plugin")
histogram := registry.Histogram("response_time_seconds", 
    "Response times", []float64{0.1, 0.5, 1.0, 2.0, 5.0}, "endpoint")

// Metrics are automatically exported to all registered backends
counter.Inc("GET", "200")
gauge.Set(42, "auth-service")
histogram.Observe(0.250, "/api/users")
```

**Custom Exporter Implementation:**

```go
type CustomExporter struct{}

func (e *CustomExporter) Export(ctx context.Context, metrics []goplugins.ExportableMetric) error {
    for _, metric := range metrics {
        // Send to your custom backend (CloudWatch, DataDog, etc.)
        if err := sendToCustomBackend(metric); err != nil {
            return err
        }
    }
    return nil
}

func (e *CustomExporter) Name() string { return "custom-backend" }
func (e *CustomExporter) Supports(t goplugins.MetricType) bool { return true }
func (e *CustomExporter) Close(ctx context.Context) error { return nil }
```

### Core Components

- **Manager**: Central plugin management with lifecycle control and load balancing
- **Circuit Breaker**: Automatic failure detection and recovery with configurable thresholds
- **Health Checker**: Continuous plugin health monitoring with status tracking
- **Load Balancer**: Multiple strategies for distributing requests across plugin instances
- **Hot Reloader**: Intelligent configuration updates with graceful connection draining
- **Observability System**: Comprehensive metrics collection and structured logging

## Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run benchmarks
go test -bench=. -benchmem ./...
```

## Usage Examples

### Load Balancing
```go
// Create load balancer with round-robin strategy
balancer := goplugins.NewLoadBalancer[MyRequest, MyResponse](
    goplugins.LoadBalanceStrategyRoundRobin,
    logger,
)

// Add plugins with different weights
balancer.AddPlugin("service-1", plugin1, 100, 1) // weight=100, priority=1
balancer.AddPlugin("service-2", plugin2, 50, 1)  // weight=50, priority=1

// Execute with load balancing
request := goplugins.LoadBalanceRequest{
    RequestID: "req-123",
    Data:      myRequest,
}
response, err := balancer.Execute(ctx, request)
```

### Hot Reload with Graceful Draining
```go
// Create reloader with advanced options
reloader := goplugins.NewPluginReloader(manager, goplugins.ReloadOptions{
    Strategy:             goplugins.ReloadStrategyGraceful,
    DrainTimeout:         30 * time.Second,
    GracefulTimeout:      60 * time.Second,
    MaxConcurrentReloads: 3,
    HealthCheckTimeout:   10 * time.Second,
    RollbackOnFailure:    true,
}, logger)

// Perform intelligent reload
ctx := context.Background()
err := reloader.ReloadWithIntelligentDiff(ctx, newConfig)
if err != nil {
    log.Printf("Reload failed: %v", err)
}
```

### Complete Production Configuration
```go
config := goplugins.ManagerConfig{
    LogLevel:    "info",
    MetricsPort: 9090,
    
    // Default settings applied to all plugins
    DefaultRetry: goplugins.RetryConfig{
        MaxRetries:      3,
        InitialInterval: 100 * time.Millisecond,
        MaxInterval:     5 * time.Second,
        Multiplier:      2.0,
        RandomJitter:    true,
    },
    
    DefaultCircuitBreaker: goplugins.CircuitBreakerConfig{
        Enabled:             true,
        FailureThreshold:    5,
        RecoveryTimeout:     30 * time.Second,
        MinRequestThreshold: 3,
        SuccessThreshold:    2,
    },
    
    DefaultHealthCheck: goplugins.HealthCheckConfig{
        Enabled:      true,
        Interval:     30 * time.Second,
        Timeout:      5 * time.Second,
        FailureLimit: 3,
    },
    
    Plugins: []goplugins.PluginConfig{
        {
            Name:      "payment-service",
            Type:      "http",
            Transport: goplugins.TransportHTTPS,
            Endpoint:  "https://payments.example.com/api/v1",
            Priority:  1,
            Enabled:   true,
            
            Auth: goplugins.AuthConfig{
                Method: goplugins.AuthBearer,
                Token:  os.Getenv("PAYMENT_SERVICE_TOKEN"),
            },
            
            RateLimit: goplugins.RateLimitConfig{
                Enabled:           true,
                RequestsPerSecond: 50.0,
                BurstSize:         100,
            },
            
            Labels: map[string]string{
                "environment": "production",
                "team":        "payments",
            },
        },
    },
}
```

## Examples

Four complete examples demonstrating different transport types:

### [HTTP Plugin](examples/http-plugin/)
Text processing service with REST API. Supports uppercase, lowercase, reverse, word count operations.

### [gRPC Plugin](examples/grpc-plugin/) 
Calculator service using Protocol Buffers. Demonstrates add, multiply, divide operations with type safety.

### [Hot Reload Plugin](examples/hot-reload-plugin/)
Dynamic configuration management with Argus file watching. Runtime plugin updates without service restart.

For complete hot reload documentation and advanced configuration options, see the [Argus repository](https://github.com/agilira/argus).

### [Unix Socket Plugin](examples/unix-socket-plugin/)
File manager using Unix domain sockets. High-performance local communication for file operations.

**Quick Start:**
```bash
cd examples/<example-name>/
go run .
```

## API Reference

### Core Interfaces
- `Plugin[Req, Resp]`: Main plugin interface with Execute, Health, Info, and Close methods
- `PluginManager[Req, Resp]`: Manager interface for plugin lifecycle and execution
- `PluginFactory[Req, Resp]`: Factory interface for creating plugin instances from configuration

### Transport Implementations
- `HTTPPlugin[Req, Resp]`: HTTP/HTTPS transport with authentication and connection pooling
- `GRPCPlugin[Req, Resp]`: gRPC transport with TLS support and service discovery
- `UnixSocketPlugin[Req, Resp]`: Unix domain socket transport for high-performance local communication

### Configuration Types
- `PluginConfig`: Complete plugin configuration with transport, auth, and operational settings
- `ManagerConfig`: Manager-level configuration with defaults and plugin definitions
- `AuthConfig`: Authentication configuration supporting multiple methods
- `RetryConfig`: Retry and backoff configuration for failed requests
- `CircuitBreakerConfig`: Circuit breaker settings for failure detection and recovery
- `HealthCheckConfig`: Health monitoring configuration with intervals and thresholds

## License

go-plugins is licensed under the [Mozilla Public License 2.0](./LICENSE.md).

---

go-plugins • an AGILira library
