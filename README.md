# go-plugins: GO Plugin System over HTTP & gRPC 
### an AGILira library

[![CI/CD Pipeline](https://github.com/agilira/go-plugins/actions/workflows/ci.yml/badge.svg)](https://github.com/agilira/go-plugins/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/security-gosec-brightgreen.svg)](https://github.com/agilira/go-plugins/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/agilira/go-plugins?v=2)](https://goreportcard.com/report/github.com/agilira/go-plugins)
[![Coverage](https://codecov.io/gh/agilira/orpheus/branch/main/graph/badge.svg)](https://codecov.io/gh/agilira/go-plugins)

go-plugins provides a production-ready, type-safe plugin architecture for Go applications. It supports HTTP and gRPC transport protocols with built-in circuit breaking, health monitoring, authentication, and hot reload powered by [Argus](https://github.com/agilira/argus) (12.10ns/op).

> **Note**: Unix sockets are deprecated and will be removed in v1.2.0. The library uses RPC/gRPC over TCP for secure and reliable communication.

**Roadmap**: Enhanced subprocess execution, bidirectional RPC, and advanced process management features. See [SIMPLIFIED_APPROACH.md](SIMPLIFIED_APPROACH.md) for details.

**[Features](#features) • [Quick Start](#quick-start) • [Usage](#usage) • [Usage Examples](#usage-examples) • [Observability](#observability) • [Examples](#examples) • [Documentation](#documentation) • [API Reference](#api-reference)**

## Features

### Core Plugin System
- **Type Safety**: Generics-based architecture ensuring compile-time type safety for requests and responses  
- **Multiple Transport Protocols**: HTTP/HTTPS, gRPC (with optional TLS) for secure communication
- **Multi-Format Configuration**: Native support for JSON, YAML with automatic format detection
- **Auto-Discovery**: Filesystem-based plugin detection with security focus
- **Security & Authentication**: API keys, Bearer tokens, Basic auth, mTLS, plugin verification
- **Plugin Whitelist System**: Hash-based plugin authorization with hot reload and audit trails
- **Circuit Breaker Pattern**: Automatic failure detection and recovery with configurable thresholds
- **Health Monitoring**: Continuous health checking with automatic plugin status management
- **Load Balancing**: Multiple algorithms including round-robin, least connections, and weighted random
- **Observability**: Built-in logging and metrics collection with industry standards
- **Hot Reload**: Ultra-fast configuration reloading powered by [Argus](https://github.com/agilira/argus)

### Coming Soon: Advanced Features (v1.1+)
- **Subprocess Plugins**: Launch plugins as separate processes for better isolation
- **Bidirectional RPC**: Plugins can call back into the host application
- **Process Management**: Automatic crash recovery and process reattachment  
- **I/O Multiplexing**: Multiple concurrent streams per plugin via MuxBroker
- **TTY Support**: Full debugging capabilities with TTY preservation

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

### Pluggable Logging System

**Flexible Logger Integration - Use Any Logging Framework:**

```go
// Backward compatibility - existing slog code continues to work
manager := goplugins.NewManager[Req, Resp](slog.Default())

// Interface-based logging (recommended for new code)
customLogger := &MyCustomLogger{} // Implements goplugins.Logger
manager := goplugins.NewManager[Req, Resp](customLogger)

// Built-in logger implementations
noOpLogger := goplugins.NewNoOpLogger()        // Silent
testLogger := goplugins.NewTestLogger()        // Captures messages for testing
defaultLogger := goplugins.DefaultLogger()     // JSON to stdout

// Automatic adapter detection - zero configuration required
var logger any = slog.Default()  // or zap.Logger, logrus.Logger, etc.
manager := goplugins.NewManager[Req, Resp](logger)
```

**Custom Logger Implementation:**

```go
type MyLogger struct{}

func (l *MyLogger) Debug(msg string, args ...any) { /* your implementation */ }
func (l *MyLogger) Info(msg string, args ...any)  { /* your implementation */ }  
func (l *MyLogger) Warn(msg string, args ...any)  { /* your implementation */ }
func (l *MyLogger) Error(msg string, args ...any) { /* your implementation */ }
func (l *MyLogger) With(args ...any) goplugins.Logger { return l }
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
    Transport: goplugins.TransportGRPCTLS, // DEPRECATED: Use native protobuf instead
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

#### Dynamic Loading & Auto-Discovery

go-plugins provides powerful dynamic loading capabilities that enable hot-loading of discovered plugins without service restart, automatic dependency resolution, and version compatibility checking.

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/agilira/go-plugins"
)

func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    manager := goplugins.NewManager[AuthRequest, AuthResponse](logger)

    // Configure discovery engine to scan for plugins
    discoveryConfig := goplugins.ExtendedDiscoveryConfig{
        DiscoveryConfig: goplugins.DiscoveryConfig{
            Enabled:     true,
            Directories: []string{"/opt/plugins", "./plugins"},
            Patterns:    []string{"*.json", "plugin.yaml"},
            WatchMode:   true, // Watch for new plugins
        },
        SearchPaths:          []string{"/opt/plugins", "/usr/local/plugins"},
        FilePatterns:         []string{"plugin.json", "manifest.yaml"},
        MaxDepth:             3,
        ValidateManifests:    true,
        AllowedTransports:    []goplugins.TransportType{goplugins.TransportHTTPS, goplugins.TransportGRPC},
        RequiredCapabilities: []string{"authentication", "logging"},
    }

    // Configure discovery (runtime config updates coming soon)
    if err := manager.ConfigureDiscovery(discoveryConfig); err != nil {
        log.Printf("Discovery configuration update not yet supported: %v", err)
    }

    // Set version compatibility rules
    manager.SetPluginCompatibilityRule("auth-service", "^1.0.0")    // 1.x.x compatible
    manager.SetPluginCompatibilityRule("logging-service", "~2.1.0") // 2.1.x compatible

    // Enable automatic loading of discovered plugins
    ctx := context.Background()
    if err := manager.EnableDynamicLoading(ctx); err != nil {
        log.Fatalf("Failed to enable dynamic loading: %v", err)
    }

    // The manager will now automatically discover and load compatible plugins
    // You can also manually load specific discovered plugins
    if err := manager.LoadDiscoveredPlugin(ctx, "auth-service"); err != nil {
        log.Printf("Failed to load auth-service: %v", err)
    }

    // Monitor loading status
    status := manager.GetDynamicLoadingStatus()
    for pluginName, state := range status {
        log.Printf("Plugin %s: %s", pluginName, state)
    }

    // View discovered plugins (not yet loaded)
    discovered := manager.GetDiscoveredPlugins()
    for name, result := range discovered {
        log.Printf("Discovered: %s v%s (%s)", 
            name, result.Manifest.Version, result.Manifest.Transport)
    }

    // Get dependency graph information
    graph := manager.GetDependencyGraph()
    if order, err := graph.CalculateLoadOrder(); err == nil {
        log.Printf("Load order: %v", order)
    }

    // Monitor dynamic loading metrics
    metrics := manager.GetDynamicLoadingMetrics()
    log.Printf("Plugins loaded: %d", metrics.PluginsLoaded.Load())
    log.Printf("Loading failures: %d", metrics.LoadingFailures.Load())

    // Graceful shutdown
    defer func() {
        if err := manager.DisableDynamicLoading(); err != nil {
            log.Printf("Error disabling dynamic loading: %v", err)
        }
        
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        if err := manager.Shutdown(shutdownCtx); err != nil {
            log.Printf("Error during shutdown: %v", err)
        }
    }()
}
```

**Key Dynamic Loading Features:**

- **Automatic Discovery**: Scans configured directories for plugin manifests
- **Hot Loading**: Load new plugins without service restart
- **Version Compatibility**: Semantic versioning constraints (`^1.0.0`, `~2.1.0`)
- **Dependency Resolution**: Automatic loading order based on plugin dependencies
- **Selective Loading**: Manual control over which discovered plugins to load
- **Real-time Monitoring**: Status tracking and metrics for all loading operations
- **Graceful Handling**: Proper error handling and rollback on loading failures

**Plugin Manifest Example** (`plugin.json`):
```json
{
    "name": "auth-service",
    "version": "1.2.3",
    "transport": "https",
    "endpoint": "https://auth.company.com/api/v1",
    "capabilities": ["authentication", "user-management"],
    "requirements": {
        "min_go_version": "1.21",
        "required_plugins": ["logging-service"],
        "min_system_version": "1.0.0"
    },
    "auth": {
        "type": "bearer",
        "token": "${AUTH_TOKEN}"
    },
    "health_check": {
        "enabled": true,
        "endpoint": "/health",
        "interval": "30s",
        "timeout": "5s"
    },
    "metadata": {
        "description": "Enterprise authentication service",
        "maintainer": "security-team@company.com",
        "tags": ["auth", "security", "enterprise"]
    }
}
```

### Observability

The go-plugins library includes a comprehensive observability system with metrics collection, distributed tracing, structured logging, and health monitoring. The system is fully integrated across all components and provides production-ready monitoring capabilities.

#### Quick Start with Observability

```go
// Enable default observability for Manager
manager := goplugins.NewManager[MyRequest, MyResponse](logger)
manager.EnableObservability()

// Or enable enhanced observability with advanced metrics
manager.EnableEnhancedObservability()

// Or enable observability with distributed tracing
tracingProvider := myTracingProvider // Your tracing implementation
manager.EnableObservabilityWithTracing(tracingProvider)
```

#### Using ObservableManager for Full Observability

```go
// Create standard manager
baseManager := goplugins.NewManager[AuthRequest, AuthResponse](logger)

// Wrap with observability
observableManager := goplugins.NewObservableManager(baseManager, 
    goplugins.EnhancedObservabilityConfig())

// Execute with full observability (metrics, tracing, logging)
response, err := observableManager.ExecuteWithObservability(ctx, "auth-plugin", execCtx, request)

// Get comprehensive metrics
metrics := observableManager.GetObservabilityMetrics()
log.Printf("Global stats - Total: %d, Errors: %d, Active: %d", 
    metrics.Global.TotalRequests, metrics.Global.TotalErrors, metrics.Global.ActiveRequests)

// Per-plugin detailed metrics
for pluginName, pluginMetrics := range metrics.Plugins {
    log.Printf("Plugin %s: %d requests, %.2f%% success rate, avg latency: %v",
        pluginName, pluginMetrics.TotalRequests, 
        pluginMetrics.SuccessRate, pluginMetrics.AvgLatency)
}
```

#### Integrated Health Monitoring

```go
// Health monitoring is automatically integrated with observability
healthStatus := manager.Health()
for pluginName, status := range healthStatus {
    log.Printf("Plugin %s: %s (response time: %v)", 
        pluginName, status.Status.String(), status.ResponseTime)
}

// Health metrics are automatically recorded in observability system
observabilityMetrics := manager.GetObservabilityMetrics()
healthMetrics := observabilityMetrics["health_status"]
```

#### Circuit Breaker Integration

```go
// Circuit breaker state changes are automatically tracked
// Get current circuit breaker states with metrics
observabilityStatus := manager.GetObservabilityStatus()
if observabilityStatus["metrics_enabled"].(bool) {
    metrics := manager.GetObservabilityMetrics()
    cbStates := metrics["circuit_breaker_states"].(map[string]string)
    
    for plugin, state := range cbStates {
        log.Printf("Plugin %s circuit breaker: %s", plugin, state)
    }
}
```

#### Advanced Observability Integration

**Comprehensive Plugin System Observability:**

```go
// 1. Manager-level observability (automatic integration)
manager := goplugins.NewManager[MyReq, MyResp](logger)
manager.EnableEnhancedObservability()

// All plugin operations are now automatically tracked:
// - Request counts, latencies, error rates
// - Circuit breaker state changes
// - Health check results
// - Active request tracking

// 2. Plugin Registry observability (automatic integration)
registry := goplugins.NewPluginRegistry(config)
registry.EnableEnhancedObservability()

// Registry operations are now automatically tracked:
// - Plugin client lifecycle (create/remove)
// - Factory registrations
// - Active client counts by type/status

// 3. Request Tracker observability (integrated automatically)
// Active request tracking with metrics is enabled by default
// when observability is enabled at the manager level

// 4. Get comprehensive system metrics
allMetrics := manager.GetObservabilityMetrics()
```

**Custom Metrics Collection:**

```go
// Use enhanced metrics collector for custom metrics
config := goplugins.EnhancedObservabilityConfig()
if enhancedCollector, ok := config.MetricsCollector.(goplugins.EnhancedMetricsCollector); ok {
    // Create custom metrics
    requestCounter := enhancedCollector.CounterWithLabels(
        "my_plugin_requests_total", 
        "Custom plugin requests", 
        "plugin", "operation", "status")
    
    latencyHistogram := enhancedCollector.HistogramWithLabels(
        "my_plugin_latency_seconds",
        "Custom plugin latency",
        []float64{0.001, 0.01, 0.1, 1, 10},
        "plugin", "operation")
    
    // Use in your code
    requestCounter.Inc("my-plugin", "process", "success")
    latencyHistogram.Observe(0.125, "my-plugin", "process")
    
    // Get Prometheus-formatted metrics
    promMetrics := enhancedCollector.GetPrometheusMetrics()
    for _, metric := range promMetrics {
        fmt.Printf("Metric: %s = %f (labels: %v)\n", 
            metric.Name, metric.Value, metric.Labels)
    }
}
```

**Integration with External Observability Systems:**

```go
// Example: Custom metrics collector for your monitoring system
type MyMetricsCollector struct {
    // Your monitoring system client
    client MyMonitoringClient
}

func (m *MyMetricsCollector) IncrementCounter(name string, labels map[string]string, value int64) {
    m.client.Counter(name).WithLabels(labels).Add(value)
}

func (m *MyMetricsCollector) SetGauge(name string, labels map[string]string, value float64) {
    m.client.Gauge(name).WithLabels(labels).Set(value)
}

func (m *MyMetricsCollector) RecordHistogram(name string, labels map[string]string, value float64) {
    m.client.Histogram(name).WithLabels(labels).Observe(value)
}

// ... implement other methods

// Use your custom collector
config := goplugins.ObservabilityConfig{
    MetricsEnabled:   true,
    MetricsCollector: &MyMetricsCollector{client: myClient},
    MetricsPrefix:    "myapp_plugins",
    // ... other config
}

manager.ConfigureObservability(config)
```

**Common Plugin Metrics Utilities:**

```go
// Use pre-defined common metrics for consistent monitoring
enhancedCollector := goplugins.NewEnhancedMetricsCollector()
commonMetrics := goplugins.CreateCommonPluginMetrics(enhancedCollector)

// Standard plugin metrics are automatically available:
// - plugin_requests_total (counter with plugin_name, status labels)
// - plugin_request_duration_seconds (histogram with plugin_name label)  
// - plugin_active_requests (gauge with plugin_name label)
// - plugin_errors_total (counter with plugin_name, error_type labels)
// - plugin_circuit_breaker_state (gauge with plugin_name label)

// Use in your plugin implementations
func (p *MyPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, req MyRequest) (MyResponse, error) {
    start := time.Now()
    commonMetrics.IncrementActiveRequests("my-plugin")
    defer commonMetrics.DecrementActiveRequests("my-plugin")
    
    // ... your plugin logic
    
    // Record result
    duration := time.Since(start)
    commonMetrics.RecordRequest("my-plugin", duration, err)
    
    return response, err
}
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

#### Active Request Monitoring

**Production-Grade Request Tracking for Zero-Downtime Operations:**

The library includes sophisticated active request monitoring that enables true zero-downtime deployments by tracking individual requests and waiting for completion before performing graceful operations.

```go
// Get real-time active request counts
activeRequests := manager.GetAllActiveRequests()
for plugin, count := range activeRequests {
    log.Printf("Plugin %s: %d active requests", plugin, count)
}

// Check specific plugin
count := manager.GetActiveRequestCount("payment-service")
log.Printf("Payment service has %d active requests", count)
```

**Intelligent Draining with Active Monitoring:**
```go
// Configure intelligent draining behavior
drainOptions := goplugins.DrainOptions{
    DrainTimeout:            30 * time.Second,  // Max wait for request completion
    ForceCancelAfterTimeout: true,              // Force cancel remaining requests
    ProgressCallback: func(pluginName string, activeCount int64) {
        log.Printf("Draining %s: %d requests remaining", pluginName, activeCount)
    },
}

// Perform graceful drain with active monitoring (no more time.Sleep!)
err := manager.DrainPlugin("payment-service", drainOptions)
if err != nil {
    if drainErr, ok := err.(*goplugins.DrainTimeoutError); ok {
        log.Printf("Drain timeout: %d requests canceled after %v", 
            drainErr.CanceledRequests, drainErr.DrainDuration)
    }
}
```

**Advanced Graceful Operations:**
```go
// Graceful plugin removal with intelligent request tracking
err := manager.GracefulUnregister("old-plugin", 45*time.Second)

// Real-time monitoring during operations
ticker := time.NewTicker(1 * time.Second)
defer ticker.Stop()

for range ticker.C {
    active := manager.GetActiveRequestCount("migrating-service")
    if active == 0 {
        log.Println("All requests completed - safe to proceed")
        break
    }
    log.Printf("Waiting for %d requests to complete...", active)
}
```

### Hot Reload & Graceful Draining

The library provides sophisticated hot reload capabilities with **active request monitoring** for true zero-downtime deployments:

#### Configuration-Based Reload Strategy with Active Monitoring
```go
// Automatic reload on config changes (powered by Argus + Active Request Tracking)
configLoader := goplugins.NewConfigLoader("config.json", goplugins.ConfigLoaderOptions{
    ReloadOnChange:   true,
    ReloadStrategy:   goplugins.ReloadStrategyGraceful,
    DrainTimeout:     30 * time.Second,    // Uses active request monitoring (not time.Sleep!)
    GracefulTimeout:  60 * time.Second,    // Maximum graceful shutdown time
    RollbackOnFailure: true,               // Auto-rollback on failed reloads
}, logger)

manager, err := configLoader.LoadManager()
```

#### Intelligent Diff-Based Reloads
```go
// Only reload what actually changed
reloader := goplugins.NewPluginReloader(manager, goplugins.ReloadOptions{
    Strategy:             goplugins.ReloadStrategyGraceful,
    MaxConcurrentReloads: 3,               // Limit concurrent plugin reloads
    HealthCheckTimeout:   10 * time.Second,// Verify health before considering reload successful
    ValidationTimeout:    5 * time.Second, // Config validation timeout
}, logger)

// Perform diff-based reload (only changes are applied)
err := reloader.ReloadWithIntelligentDiff(ctx, newConfig)
```

#### Manual Graceful Operations
```go
// Graceful plugin updates without service interruption
err := manager.UpdatePlugin(ctx, "payment-service", newConfig, 
    goplugins.UpdateOptions{
        GracefulDrain:   true,
        DrainTimeout:    30 * time.Second,
        ValidateHealth:  true,
    })

// Graceful plugin removal
err := manager.RemovePlugin(ctx, "old-service", 
    goplugins.RemoveOptions{
        GracefulDrain:  true,
        DrainTimeout:   45 * time.Second,
    })
```

#### Advanced Reload Configuration
```go
type ReloadOptions struct {
    Strategy               ReloadStrategy    // Immediate, Graceful, or BlueGreen
    DrainTimeout          time.Duration     // Max time to wait for request completion
    GracefulTimeout       time.Duration     // Total graceful shutdown timeout
    MaxConcurrentReloads  int              // Limit concurrent plugin operations
    HealthCheckTimeout    time.Duration     // Health verification timeout
    ValidationTimeout     time.Duration     // Config validation timeout
    RollbackOnFailure     bool             // Auto-rollback on failure
    DryRun               bool             // Validate without applying changes
    NotificationHandlers []ReloadHandler   // Custom notification handlers
}
```

#### Technical Implementation Details

**Active Request Monitoring Architecture:**

The graceful draining system is built on a sophisticated request tracking architecture that eliminates the need for fixed timeouts:

- **Atomic Counters**: Per-plugin request counters using `atomic.Int64` for lock-free performance
- **Context Tracking**: Active request contexts stored for selective cancellation
- **Real-time Monitoring**: 10ms polling interval for precise drain completion detection
- **Intelligent Timeouts**: Configurable drain timeouts with fallback to force cancellation
- **Zero Breaking Changes**: Backward compatible with existing configurations

**Performance Characteristics:**
- **Request Start/End**: ~50ns per operation (atomic operations)
- **Active Count Check**: ~10ns per operation (atomic load)
- **Drain Detection**: 10ms precision with minimal CPU overhead
- **Memory Overhead**: ~24 bytes per active request context

**Production Deployment Benefits:**
- ✅ **No more `time.Sleep()`** - Active monitoring replaces fixed delays
- ✅ **Precise completion detection** - Wait only as long as needed
- ✅ **Request-level visibility** - Real-time active request counts
- ✅ **Graceful fallbacks** - Force cancellation after configurable timeout
- ✅ **Progress callbacks** - Monitor drain progress in real-time

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

Complete examples demonstrating different capabilities:

### [Plugin Discovery Demo](examples/discovery-demo/)
**NEW:** Intelligent plugin auto-discovery system. Demonstrates filesystem and network-based plugin detection, manifest validation, capability filtering, and real-time discovery events.

### [HTTP Plugin](examples/http-plugin/)
Text processing service with REST API. Supports uppercase, lowercase, reverse, word count operations.

### [gRPC Plugin](examples/grpc-plugin/) 
Calculator service using Protocol Buffers. Demonstrates add, multiply, divide operations with type safety.

### [Hot Reload Plugin](examples/hot-reload-plugin/)
Dynamic configuration management with Argus file watching. Runtime plugin updates without service restart.

For complete hot reload documentation and advanced configuration options, see the [Argus repository](https://github.com/agilira/argus).

### [Plugin Security Demo](examples/security-demo/)
**NEW:** Comprehensive security system with hash-based plugin whitelist. Demonstrates authorized plugin validation, hot reload configuration changes, and audit trail monitoring with Argus integration.

### [Unix Socket Plugin](examples/unix-socket-plugin/)
File manager using Unix domain sockets. High-performance local communication for file operations.

### [Graceful Draining Demo](examples/graceful-draining-demo/)
**NEW:** Demonstrates the enhanced active request monitoring and intelligent graceful draining system. Shows real-time request tracking, precision drain detection, and zero-downtime operations that replace fixed `time.Sleep()` delays.

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
- `GRPCNativePlugin[Req, Resp]`: gRPC transport with native protobuf support (industry-standard)
- `UnixSocketPlugin[Req, Resp]`: Unix domain socket transport for high-performance local communication

### Multi-Format Configuration Support

go-plugins supports multiple configuration formats with automatic format detection:

- **JSON** (`.json`) - Native support via Argus
- **YAML** (`.yaml`, `.yml`) - Full support with complex structures  

- **Auto-detection** - Format determined by file extension

#### Hybrid Parsing Strategy
The library uses a sophisticated hybrid approach:
- **Argus** handles format detection and file watching for all formats
- **Specialized parsers** (gopkg.in/yaml.v3) for complex structured data
- **Seamless compatibility** - all configuration structures work identically across formats

#### Example Configuration Files

**JSON Configuration:**
```json
{
  "version": "1.0.0",
  "log_level": "INFO",
  "plugins": [{
    "name": "calculator-plugin",
    "enabled": true,
    "type": "grpc",
    "auth": {
      "method": "api_key",
      "api_key": "your-api-key"
    }
  }]
}
```

**YAML Configuration:**
```yaml
version: "1.0.0"
log_level: INFO
plugins:
  - name: calculator-plugin
    enabled: true
    type: grpc
    auth:
      method: api_key
      api_key: your-api-key
```



All formats support the same features: hot reload, validation, nested configurations, and complex data structures.

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
