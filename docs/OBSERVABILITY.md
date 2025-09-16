# Observability Guide

This guide covers the comprehensive observability features integrated into the go-plugins library, including metrics collection, distributed tracing, health monitoring, and structured logging.

## Overview

The go-plugins library provides a fully integrated observability system that automatically tracks:

- **Request Metrics**: Count, latency, success/error rates per plugin
- **Health Monitoring**: Continuous health checks with metrics integration
- **Circuit Breaker State**: Automatic tracking of circuit breaker state changes
- **Active Request Tracking**: Real-time monitoring of concurrent requests
- **Plugin Lifecycle**: Registration, deregistration, and operational events
- **Distributed Tracing**: Optional integration with tracing systems
- **Structured Logging**: Contextual logging with request correlation

## Quick Start

### Basic Observability

```go
// Enable observability with default configuration
manager := goplugins.NewManager[MyReq, MyResp](logger)
err := manager.EnableObservability()
if err != nil {
    log.Fatal("Failed to enable observability:", err)
}

// All operations are now automatically tracked
response, err := manager.Execute(ctx, "my-plugin", request)

// View metrics
metrics := manager.GetObservabilityMetrics()
fmt.Printf("Total requests: %d\n", metrics["manager"].(map[string]interface{})["requests_total"])
```

### Enhanced Observability

```go
// Enable enhanced observability with advanced metrics
manager := goplugins.NewManager[MyReq, MyResp](logger)
err := manager.EnableEnhancedObservability()
if err != nil {
    log.Fatal("Failed to enable enhanced observability:", err)
}

// Enhanced observability provides:
// - Prometheus-compatible metrics
// - Type-safe metric creation
// - Better performance with native label support
// - Pre-defined common plugin metrics
```

### Full Observability with Tracing

```go
// Enable observability with distributed tracing
tracingProvider := NewMyTracingProvider() // Your tracing implementation
manager := goplugins.NewManager[MyReq, MyResp](logger)
err := manager.EnableObservabilityWithTracing(tracingProvider)
if err != nil {
    log.Fatal("Failed to enable observability with tracing:", err)
}
```

## ObservableManager

For the most comprehensive observability, use `ObservableManager`:

```go
// Create base manager
baseManager := goplugins.NewManager[AuthRequest, AuthResponse](logger)

// Configure observability
config := goplugins.EnhancedObservabilityConfig()
config.TracingEnabled = true
config.TracingProvider = myTracingProvider
config.TracingSampleRate = 0.1 // 10% sampling

// Create observable manager
observableManager := goplugins.NewObservableManager(baseManager, config)

// Execute with full observability
response, err := observableManager.ExecuteWithObservability(ctx, "auth-plugin", execCtx, request)

// Get detailed metrics
report := observableManager.GetObservabilityMetrics()
fmt.Printf("System uptime: %v\n", report.UpTime)
fmt.Printf("Global success rate: %.2f%%\n", 
    float64(report.Global.TotalRequests - report.Global.TotalErrors) / float64(report.Global.TotalRequests) * 100)

for pluginName, pluginMetrics := range report.Plugins {
    fmt.Printf("Plugin %s:\n", pluginName)
    fmt.Printf("  Total requests: %d\n", pluginMetrics.TotalRequests)
    fmt.Printf("  Success rate: %.2f%%\n", pluginMetrics.SuccessRate)
    fmt.Printf("  Average latency: %v\n", pluginMetrics.AvgLatency)
    fmt.Printf("  Circuit breaker trips: %d\n", pluginMetrics.CircuitBreakerTrips)
}
```

## Integrated Components

### Manager Observability

The `Manager` automatically tracks:

```go
// All these operations are automatically tracked when observability is enabled:
manager.Register(plugin)          // Plugin registration metrics
manager.Execute(ctx, name, req)   // Request metrics, latency, errors
manager.Unregister(name)         // Plugin deregistration metrics
manager.Health()                 // Health check metrics

// Access manager-specific metrics
managerMetrics := manager.GetObservabilityMetrics()
```

### Plugin Registry Observability

The `PluginRegistry` automatically tracks:

```go
registry := goplugins.NewPluginRegistry(config)
registry.EnableEnhancedObservability()

// These operations are automatically tracked:
registry.RegisterFactory("http", factory)  // Factory registration metrics
registry.CreateClient(pluginConfig)        // Client creation metrics
registry.RemoveClient(clientName)          // Client removal metrics

// Access registry metrics
registryMetrics := registry.GetObservabilityMetrics()
fmt.Printf("Active clients: %d\n", registryMetrics["registry"].(map[string]interface{})["total_clients"])
```

### Request Tracker Observability

The `RequestTracker` automatically tracks active requests:

```go
// When observability is enabled, request tracking includes metrics
// This happens automatically in Manager and PluginRegistry

// Manual usage:
tracker := goplugins.NewRequestTrackerWithObservability(metricsCollector, "myapp")

tracker.StartRequest("plugin-name", ctx)
defer tracker.EndRequest("plugin-name", ctx)

// Get tracker metrics
trackerMetrics := tracker.GetObservabilityMetrics()
```

## Metrics

### Built-in Metrics

When observability is enabled, the following metrics are automatically collected:

#### Manager Metrics
- `{prefix}_requests_total` (counter) - Total plugin requests
- `{prefix}_request_duration_seconds` (histogram) - Request latency distribution
- `{prefix}_errors_total` (counter) - Total errors by plugin and error type
- `{prefix}_plugin_health_status` (gauge) - Plugin health status (1=healthy, 0.5=degraded, 0=unhealthy, -1=offline)
- `{prefix}_health_checks_total` (counter) - Total health checks
- `{prefix}_health_check_failures_total` (counter) - Failed health checks
- `{prefix}_health_check_duration_seconds` (histogram) - Health check duration

#### Enhanced Metrics (with EnhancedMetricsCollector)
- `plugin_requests_total` (counter) - Labels: plugin_name, status
- `plugin_request_duration_seconds` (histogram) - Labels: plugin_name
- `plugin_active_requests` (gauge) - Labels: plugin_name
- `plugin_errors_total` (counter) - Labels: plugin_name, error_type
- `plugin_circuit_breaker_state` (gauge) - Labels: plugin_name (0=closed, 1=open, 2=half-open)

#### Registry Metrics
- `{prefix}_plugin_factory_operations_total` (counter) - Factory registrations
- `{prefix}_plugin_client_operations_total` (counter) - Client lifecycle operations
- `{prefix}_plugin_clients_active` (gauge) - Current active client count

#### Request Tracker Metrics  
- `{prefix}_active_requests_started_total` (counter) - Requests started
- `{prefix}_active_requests_ended_total` (counter) - Requests ended
- `{prefix}_active_requests_current` (gauge) - Current active requests

### Custom Metrics

```go
// Using enhanced metrics collector for custom metrics
config := goplugins.EnhancedObservabilityConfig()
enhancedCollector := config.MetricsCollector.(goplugins.EnhancedMetricsCollector)

// Create custom counter
customCounter := enhancedCollector.CounterWithLabels(
    "my_custom_operations_total",
    "Custom operations counter", 
    "operation", "result")

// Create custom histogram
customHistogram := enhancedCollector.HistogramWithLabels(
    "my_custom_duration_seconds",
    "Custom operation duration",
    []float64{0.001, 0.01, 0.1, 1.0, 5.0},
    "operation")

// Use the metrics
customCounter.Inc("process", "success")
customHistogram.Observe(0.150, "process")

// Export to Prometheus format
promMetrics := enhancedCollector.GetPrometheusMetrics()
```

## Health Monitoring Integration

Health monitoring is automatically integrated with observability:

```go
// Health checks are automatically tracked as metrics
healthStatus := manager.Health()

// Access health metrics
observabilityMetrics := manager.GetObservabilityMetrics()
healthData := observabilityMetrics["health_status"].(map[string]goplugins.HealthStatus)

for pluginName, status := range healthData {
    fmt.Printf("Plugin %s: %s (response time: %v)\n", 
        pluginName, status.Status.String(), status.ResponseTime)
}
```

## Circuit Breaker Integration

Circuit breaker state changes are automatically tracked:

```go
// Circuit breaker metrics are automatically recorded
// Get current states
observabilityMetrics := manager.GetObservabilityMetrics()
cbStates := observabilityMetrics["circuit_breaker_states"].(map[string]string)

for plugin, state := range cbStates {
    fmt.Printf("Plugin %s circuit breaker: %s\n", plugin, state)
}

// Circuit breaker state changes trigger metrics:
// - plugin_circuit_breaker_state gauge updates
// - Circuit breaker trip counters increment when opening
```

## Distributed Tracing

### Enabling Tracing

```go
// Implement TracingProvider interface
type MyTracingProvider struct {
    tracer MyTracer
}

func (p *MyTracingProvider) StartSpan(ctx context.Context, operationName string) (context.Context, goplugins.Span) {
    span := p.tracer.StartSpan(operationName)
    ctx = context.WithValue(ctx, "span", span)
    return ctx, &MySpan{span: span}
}

func (p *MyTracingProvider) ExtractContext(headers map[string]string) context.Context {
    // Extract tracing context from headers
    return p.tracer.ExtractFromHeaders(headers)
}

func (p *MyTracingProvider) InjectContext(ctx context.Context) map[string]string {
    // Inject tracing context into headers
    return p.tracer.InjectToHeaders(ctx)
}

// Enable tracing
tracingProvider := &MyTracingProvider{tracer: myTracer}
config := goplugins.EnhancedObservabilityConfig()
config.TracingEnabled = true
config.TracingProvider = tracingProvider
config.TracingSampleRate = 0.1 // 10% sampling

manager.ConfigureObservability(config)
```

### Automatic Trace Correlation

When tracing is enabled:
- Each plugin execution automatically creates a span
- Tracing headers are automatically injected into plugin requests
- Spans include plugin name, request ID, and timing information
- Errors are automatically recorded in spans

## Configuration

### ObservabilityConfig

```go
type ObservabilityConfig struct {
    // Metrics
    MetricsEnabled           bool
    MetricsCollector         MetricsCollector
    EnhancedMetricsCollector EnhancedMetricsCollector
    MetricsPrefix            string

    // Tracing  
    TracingEnabled    bool
    TracingProvider   TracingProvider
    TracingSampleRate float64

    // Logging
    LoggingEnabled    bool
    LogLevel          string
    StructuredLogging bool

    // Feature flags
    HealthMetrics      bool
    PerformanceMetrics bool
    ErrorMetrics       bool
}
```

### Default Configurations

```go
// Default configuration
defaultConfig := goplugins.DefaultObservabilityConfig()

// Enhanced configuration with better metrics collector
enhancedConfig := goplugins.EnhancedObservabilityConfig()

// Custom configuration
customConfig := goplugins.ObservabilityConfig{
    MetricsEnabled:     true,
    MetricsCollector:   myCustomCollector,
    MetricsPrefix:      "myapp_plugins",
    TracingEnabled:     true,
    TracingProvider:    myTracingProvider,
    TracingSampleRate:  0.05, // 5% sampling
    LoggingEnabled:     true,
    LogLevel:           "info",
    StructuredLogging:  true,
    HealthMetrics:      true,
    PerformanceMetrics: true,
    ErrorMetrics:       true,
}
```

## Best Practices

### 1. Enable Observability Early

```go
// Enable observability immediately after manager creation
manager := goplugins.NewManager[MyReq, MyResp](logger)
if err := manager.EnableEnhancedObservability(); err != nil {
    log.Fatal("Failed to enable observability:", err)
}
```

### 2. Use Appropriate Sampling Rates

```go
// Adjust tracing sample rate based on traffic volume
config := goplugins.EnhancedObservabilityConfig()
if isProduction {
    config.TracingSampleRate = 0.01 // 1% in production
} else {
    config.TracingSampleRate = 0.1  // 10% in development
}
```

### 3. Monitor Key Metrics

Focus on these key metrics for production systems:

- **Request Rate**: `{prefix}_requests_total` rate
- **Error Rate**: `{prefix}_errors_total` rate / `{prefix}_requests_total` rate  
- **Latency**: `{prefix}_request_duration_seconds` percentiles (p50, p95, p99)
- **Health**: `{prefix}_plugin_health_status` (should be 1.0 for healthy plugins)
- **Circuit Breakers**: `plugin_circuit_breaker_state` (should be 0 for closed)

### 4. Use Labels Wisely

```go
// Good: Use high-cardinality labels sparingly
counter.Inc("plugin-name", "success") // plugin name is bounded

// Avoid: Don't use unbounded labels  
// counter.Inc("plugin-name", requestID) // request ID is unbounded
```

### 5. Regular Metrics Review

```go
// Periodically review metrics for performance insights
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        metrics := manager.GetObservabilityMetrics()
        // Log or alert on key metrics
        analyzeMetrics(metrics)
    }
}()
```

## Troubleshooting

### High Memory Usage

If observability causes high memory usage:

1. Reduce tracing sample rate
2. Use bounded labels in custom metrics
3. Limit histogram bucket counts
4. Enable metric rotation if using time-series data

### Performance Impact

To minimize performance impact:

1. Use enhanced metrics collector for better performance
2. Sample tracing appropriately
3. Use async metric recording where possible
4. Monitor the monitoring (meta-observability)

### Missing Metrics

If metrics are not appearing:

1. Verify observability is enabled: `manager.GetObservabilityStatus()`
2. Check metrics collector configuration
3. Ensure proper metric prefix configuration
4. Verify enhanced collector vs basic collector usage

## Integration Examples

### Prometheus Integration

```go
// Example Prometheus metrics collector
type PrometheusCollector struct {
    registry *prometheus.Registry
    counters map[string]*prometheus.CounterVec
    gauges   map[string]*prometheus.GaugeVec
    histograms map[string]*prometheus.HistogramVec
    mutex    sync.RWMutex
}

func (p *PrometheusCollector) IncrementCounter(name string, labels map[string]string, value int64) {
    // Implementation...
}

// Use with go-plugins
config := goplugins.ObservabilityConfig{
    MetricsEnabled:   true,
    MetricsCollector: &PrometheusCollector{registry: prometheus.NewRegistry()},
    MetricsPrefix:    "myapp_plugins",
}
```

### OpenTelemetry Integration

```go
// Example OpenTelemetry tracing provider
type OTelTracingProvider struct {
    tracer trace.Tracer
}

func (p *OTelTracingProvider) StartSpan(ctx context.Context, operationName string) (context.Context, goplugins.Span) {
    ctx, span := p.tracer.Start(ctx, operationName)
    return ctx, &OTelSpan{span: span}
}

// Use with go-plugins
tracingProvider := &OTelTracingProvider{tracer: otel.Tracer("go-plugins")}
manager.EnableObservabilityWithTracing(tracingProvider)
```

This comprehensive observability system provides production-ready monitoring capabilities that scale with your plugin-based applications.