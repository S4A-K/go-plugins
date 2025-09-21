---
title: Observability & Monitoring
description: Comprehensive observability features including metrics, tracing, and health monitoring
weight: 40
---

# Observability & Monitoring Guide

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

Enable observability with the Simple API:

```go
manager, err := goplugins.Production[Req, Resp]().
    WithMetrics().
    WithPlugin("service", goplugins.Subprocess("./service")).
    Build()
```

### Advanced Observability Configuration

```go
observabilityConfig := goplugins.ObservabilityConfig{
    Enabled: true,
    MetricsConfig: goplugins.MetricsConfig{
        Enabled:       true,
        CollectAll:    true,
        ExportInterval: 30 * time.Second,
        Namespace:     "myapp",
        Subsystem:     "plugins",
    },
    TracingConfig: goplugins.TracingConfig{
        Enabled:     true,
        ServiceName: "plugin-manager",
        SampleRate:  0.1, // 10% sampling
    },
    HealthConfig: goplugins.HealthObservabilityConfig{
        Enabled:        true,
        CheckInterval:  30 * time.Second,
        MetricsEnabled: true,
    },
}

manager := goplugins.NewManager[Req, Resp](logger)
// Use the convenience method for default settings
err := manager.EnableObservability()

// Or configure with custom settings
err = manager.ConfigureObservability(observabilityConfig)
```

## Metrics Collection

### Built-in Metrics

The library automatically collects these metrics:

#### Manager-Level Metrics
- `plugin_requests_total`: Total number of plugin requests
- `plugin_requests_success`: Number of successful requests
- `plugin_requests_failure`: Number of failed requests  
- `plugin_request_duration_seconds`: Request latency histogram
- `plugin_circuit_breaker_trips_total`: Circuit breaker activation count
- `plugin_health_check_failures_total`: Health check failure count

#### Plugin-Level Metrics  
- `plugin_status`: Current plugin status (healthy/degraded/unhealthy/offline)
- `plugin_response_time_seconds`: Plugin response time histogram
- `plugin_error_rate`: Plugin error rate gauge
- `plugin_active_requests`: Number of active requests per plugin

#### Circuit Breaker Metrics
- `plugin_circuit_breaker_state`: Current state (closed/open/half-open)
- `plugin_circuit_breaker_requests_total`: Requests processed by circuit breaker
- `plugin_circuit_breaker_failures_total`: Failures tracked by circuit breaker

### Accessing Metrics Programmatically

```go
// Get manager metrics
metrics := manager.GetMetrics()
fmt.Printf("Total requests: %d\n", metrics.RequestsTotal.Load())
fmt.Printf("Success rate: %.2f%%\n", 
    float64(metrics.RequestsSuccess.Load()) / 
    float64(metrics.RequestsTotal.Load()) * 100)

// Get plugin-specific metrics
pluginMetrics := manager.GetPluginMetrics("auth-service")
fmt.Printf("Plugin requests: %d\n", pluginMetrics.RequestsTotal.Load())
fmt.Printf("Plugin errors: %d\n", pluginMetrics.RequestsFailure.Load())
```

## Metrics Exporters

### Prometheus Exporter

```go
// Enable Prometheus metrics export
prometheusExporter := goplugins.NewPrometheusExporter(goplugins.PrometheusConfig{
    Namespace: "myapp",
    Subsystem: "plugins", 
    Port:      9090,
    Path:      "/metrics",
})

// Note: Prometheus exporter integration is available through the MetricsCollector interface
// Implement a custom Prometheus exporter by implementing MetricsCollector

// Metrics will be available through the observability system
```

### OpenTelemetry Exporter

```go
// Enable OpenTelemetry metrics export
otlpExporter := goplugins.NewOTLPExporter(goplugins.OTLPConfig{
    Endpoint: "http://otel-collector:4317",
    Headers: map[string]string{
        "api-key": "your-api-key",
    },
    Timeout: 10 * time.Second,
})

// Note: Implement custom OTLP exporter using MetricsCollector interface
```

### StatsD/DogStatsD Exporter

```go
// Enable StatsD export
statsdExporter := goplugins.NewStatsDExporter(goplugins.StatsDConfig{
    Address: "localhost:8125",
    Prefix:  "myapp.plugins",
    Tags:    map[string]string{"env": "production"},
})

// Note: Implement custom StatsD exporter using MetricsCollector interface
```

### Custom Metrics Exporter

```go
// Implement custom exporter
type CustomExporter struct {
    endpoint string
}

func (e *CustomExporter) Export(metrics *goplugins.MetricsSnapshot) error {
    // Custom export logic
    return e.sendToCustomSystem(metrics)
}

func (e *CustomExporter) Name() string {
    return "custom-exporter"
}

// Register custom exporter
customExporter := &CustomExporter{endpoint: "https://metrics.mycompany.com"}
// Note: Custom exporters can be implemented using the MetricsCollector interface
```

## Distributed Tracing

### Enabling Tracing

```go
tracingConfig := goplugins.TracingConfig{
    Enabled:     true,
    ServiceName: "my-service",
    Endpoint:    "http://jaeger:14268/api/traces",
    SampleRate:  0.1, // 10% sampling
    Tags: map[string]string{
        "version":     "1.2.3",
        "environment": "production",
    },
}

err := manager.EnableTracing(tracingConfig)
```

### Automatic Trace Propagation

Tracing is automatically propagated through plugin calls:

```go
// Create a traced context
ctx, span := manager.StartSpan(context.Background(), "user-operation")
defer span.Finish()

// Plugin execution will automatically inherit the trace
response, err := manager.Execute(ctx, "auth-service", request)

// Span will include plugin execution details
```

### Manual Span Creation

```go
// Create custom spans for detailed tracing
ctx, span := manager.StartSpan(ctx, "validate-user")
span.SetTag("user.id", userID)
span.SetTag("operation", "validation")

// Your business logic here
result, err := validateUser(ctx, userID)

if err != nil {
    span.SetTag("error", true)
    span.LogFields(
        trace.String("error.kind", "validation_error"),
        trace.String("error.message", err.Error()),
    )
}

span.Finish()
```

## Health Monitoring

### Automatic Health Checks

Health checks are performed automatically when enabled:

```go
healthConfig := goplugins.HealthObservabilityConfig{
    Enabled:        true,
    CheckInterval:  30 * time.Second,
    Timeout:        5 * time.Second,
    MetricsEnabled: true,
    AlertThreshold: 3, // Alert after 3 consecutive failures
}

err := manager.EnableHealthMonitoring(healthConfig)
```

### Health Status API

```go
// Get overall health status
healthStatus := manager.Health()
for pluginName, status := range healthStatus {
    fmt.Printf("Plugin %s: %s - %s\n", 
        pluginName, status.Status.String(), status.Message)
    
    if status.Status != goplugins.StatusHealthy {
        fmt.Printf("  Last check: %v\n", status.LastCheck)
        fmt.Printf("  Response time: %v\n", status.ResponseTime)
        
        // Check metadata for additional details
        for key, value := range status.Metadata {
            fmt.Printf("  %s: %s\n", key, value)
        }
    }
}
```

### Custom Health Checks

```go
// Implement custom health check logic in your plugin
func (p *MyPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    // Check database connectivity
    if err := p.db.PingContext(ctx); err != nil {
        return goplugins.HealthStatus{
            Status:       goplugins.StatusUnhealthy,
            Message:      "Database connection failed",
            LastCheck:    time.Now(),
            ResponseTime: time.Since(start),
            Metadata: map[string]string{
                "database_error": err.Error(),
                "connection_pool": fmt.Sprintf("%d/%d", p.db.Stats().OpenConnections, p.db.Stats().MaxOpenConnections),
            },
        }
    }
    
    // Check external service dependency
    if !p.isExternalServiceHealthy(ctx) {
        return goplugins.HealthStatus{
            Status:    goplugins.StatusDegraded,
            Message:   "External service unavailable, using cache",
            LastCheck: time.Now(),
            Metadata: map[string]string{
                "external_service": "unavailable",
                "fallback_mode":   "cache_only",
            },
        }
    }
    
    return goplugins.HealthStatus{
        Status:    goplugins.StatusHealthy,
        Message:   "All systems operational",
        LastCheck: time.Now(),
        Metadata: map[string]string{
            "database":        "connected",
            "external_service": "available",
            "cache_size":      fmt.Sprintf("%d entries", p.cache.Size()),
        },
    }
}
```

## Structured Logging

### Contextual Logging

The library provides contextual logging with automatic correlation:

```go
// Enable structured logging
logger := goplugins.NewStructuredLogger(goplugins.LoggerConfig{
    Level:      "info",
    Format:     "json",
    Output:     os.Stdout,
    AddCaller:  true,
    AddStack:   true,
})

manager := goplugins.NewManager[Req, Resp](logger)
```

### Request Correlation

```go
// Logs automatically include request correlation
ctx, span := manager.StartSpan(context.Background(), "user-request")
ctx = goplugins.WithRequestID(ctx, "req-12345")

// All plugin operations will include the request ID
response, err := manager.Execute(ctx, "auth-service", request)

// Log output will include:
// {"level":"info","request_id":"req-12345","plugin":"auth-service","operation":"execute","duration":"45ms"}
```

### Custom Log Fields

```go
// Add custom fields to logs
ctx = goplugins.WithLogFields(ctx, map[string]interface{}{
    "user_id":    "user123",
    "tenant_id":  "tenant456", 
    "operation":  "user_auth",
    "ip_address": "192.168.1.100",
})

// All subsequent logs will include these fields
response, err := manager.Execute(ctx, "auth-service", request)
```

## Alerting Integration

### Webhook Alerts

```go
// Configure webhook alerting
alertConfig := goplugins.AlertConfig{
    Enabled: true,
    Webhooks: []goplugins.WebhookConfig{
        {
            URL:     "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
            Events:  []string{"plugin_unhealthy", "circuit_breaker_open"},
            Headers: map[string]string{"Content-Type": "application/json"},
        },
        {
            URL:    "https://api.pagerduty.com/generic/2010-04-15/create_event.json",
            Events: []string{"plugin_critical_failure"},
            Headers: map[string]string{
                "Authorization": "Token token=YOUR_PAGERDUTY_TOKEN",
            },
        },
    },
}

err := manager.EnableAlerting(alertConfig)
```

### Custom Alert Handlers

```go
// Implement custom alert handler
type SlackAlertHandler struct {
    webhookURL string
}

func (h *SlackAlertHandler) HandleAlert(alert *goplugins.Alert) error {
    message := fmt.Sprintf("🚨 Plugin Alert: %s - %s", alert.PluginName, alert.Message)
    
    payload := map[string]interface{}{
        "text":    message,
        "channel": "#alerts",
        "username": "go-plugins-bot",
    }
    
    return h.sendToSlack(payload)
}

// Register custom alert handler
slackHandler := &SlackAlertHandler{webhookURL: "https://hooks.slack.com/..."}
err := manager.RegisterAlertHandler("slack", slackHandler)
```

## Performance Monitoring

### Request Performance Tracking

```go
// Enable detailed performance monitoring
perfConfig := goplugins.PerformanceConfig{
    Enabled:           true,
    TrackMemoryUsage:  true,
    TrackGoroutines:   true,
    ProfileCPU:        true,
    ProfileMemory:     true,
    SampleRate:        0.01, // 1% sampling for profiling
}

err := manager.EnablePerformanceMonitoring(perfConfig)
```

### Performance Metrics

```go
// Access performance metrics
perfMetrics := manager.GetPerformanceMetrics()

fmt.Printf("Memory usage: %d bytes\n", perfMetrics.MemoryUsage)
fmt.Printf("Goroutines: %d\n", perfMetrics.GoroutineCount)
fmt.Printf("GC cycles: %d\n", perfMetrics.GCCycles)
fmt.Printf("Heap size: %d bytes\n", perfMetrics.HeapSize)

// Plugin-specific performance
for pluginName, metrics := range perfMetrics.PluginMetrics {
    fmt.Printf("Plugin %s:\n", pluginName)
    fmt.Printf("  CPU usage: %.2f%%\n", metrics.CPUUsage)
    fmt.Printf("  Memory: %d bytes\n", metrics.MemoryUsage)
    fmt.Printf("  Avg response time: %v\n", metrics.AvgResponseTime)
}
```

## Dashboard Integration

### Grafana Dashboard

Example Grafana dashboard configuration:

```json
{
  "dashboard": {
    "title": "go-plugins Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(plugin_requests_total[5m])",
            "legendFormat": "{{plugin_name}}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph", 
        "targets": [
          {
            "expr": "rate(plugin_requests_failure[5m]) / rate(plugin_requests_total[5m])",
            "legendFormat": "{{plugin_name}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, plugin_request_duration_seconds)",
            "legendFormat": "95th percentile"
          }
        ]
      }
    ]
  }
}
```

## Best Practices

### 1. Use Appropriate Sampling Rates

```go
// High-volume services should use lower sampling rates
tracingConfig := goplugins.TracingConfig{
    SampleRate: 0.01, // 1% for high-volume services
}

// Low-volume services can use higher sampling rates  
tracingConfig := goplugins.TracingConfig{
    SampleRate: 0.5, // 50% for low-volume services
}
```

### 2. Set Up Proper Alerting

```go
// Configure alerts for critical metrics
alertConfig := goplugins.AlertConfig{
    Rules: []goplugins.AlertRule{
        {
            Name:        "high_error_rate",
            Condition:   "error_rate > 0.05", // 5% error rate
            Duration:    "5m",
            Severity:    "warning",
        },
        {
            Name:        "plugin_down",
            Condition:   "plugin_status == 0", // Offline status
            Duration:    "1m",
            Severity:    "critical",
        },
    },
}
```

### 3. Monitor Resource Usage

```go
// Set up resource monitoring
resourceConfig := goplugins.ResourceMonitoringConfig{
    Enabled:           true,
    MemoryThreshold:   "1GB",
    CPUThreshold:      80.0, // 80% CPU
    GoroutineThreshold: 10000,
}

err := manager.EnableResourceMonitoring(resourceConfig)
```

### 4. Use Proper Log Levels

```go
// Configure appropriate log levels for different environments
var logLevel string
switch os.Getenv("ENVIRONMENT") {
case "development":
    logLevel = "debug"
case "staging":
    logLevel = "info"  
case "production":
    logLevel = "warn"
default:
    logLevel = "info"
}

logger := goplugins.NewStructuredLogger(goplugins.LoggerConfig{
    Level: logLevel,
})
```

## Troubleshooting

### Common Issues

**High Memory Usage:**
```go
// Check for memory leaks in metrics collection
perfMetrics := manager.GetPerformanceMetrics()
if perfMetrics.MemoryUsage > threshold {
    // Reduce metrics retention or sampling rate
    manager.UpdateMetricsConfig(goplugins.MetricsConfig{
        RetentionPeriod: 5 * time.Minute, // Reduce retention
        SampleRate:     0.1,              // Reduce sampling
    })
}
```

**Missing Traces:**
```go
// Verify tracing configuration
tracingConfig := manager.GetTracingConfig()
if !tracingConfig.Enabled {
    log.Warn("Tracing is disabled")
}
if tracingConfig.SampleRate < 0.01 {
    log.Warn("Sample rate might be too low:", tracingConfig.SampleRate)
}
```

**Health Check Failures:**
```go
// Debug health check issues
healthStatus := manager.Health()
for pluginName, status := range healthStatus {
    if status.Status != goplugins.StatusHealthy {
        log.Printf("Plugin %s health check failed:", pluginName)
        log.Printf("  Error: %s", status.Message)
        log.Printf("  Response time: %v", status.ResponseTime)
        log.Printf("  Metadata: %+v", status.Metadata)
    }
}
```

## Next Steps

- Learn about [Production Deployment](/guides/production/) for production monitoring setup
- Explore [Security Monitoring](/guides/security/#audit-logging) for security event tracking
- Check out the [Observability API Reference](/api/observability/) for detailed configuration options

{{% alert title="Performance Note" %}}
Enable observability features gradually in production. Start with basic metrics and health checks, then add tracing and detailed performance monitoring as needed.
{{% /alert %}}
