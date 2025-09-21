---
title: Production Deployment
description: Deploy go-plugins in production environments with best practices
weight: 60
---

# Production Deployment Guide

This guide covers best practices for deploying go-plugins in production environments, including security, monitoring, performance optimization, and operational procedures.

## Table of Contents

- [Production Checklist](#production-checklist)
- [Security Configuration](#security-configuration)
- [Performance Optimization](#performance-optimization)
- [Monitoring & Observability](#monitoring--observability)
- [High Availability](#high-availability)
- [Deployment Strategies](#deployment-strategies)
- [Operational Procedures](#operational-procedures)
- [Troubleshooting](#troubleshooting)

## Production Checklist

Before deploying to production, ensure you have:

### ✅ Security
- [ ] Plugin security system enabled with strict policy
- [ ] Plugin whitelist configured and up-to-date
- [ ] Authentication configured for all plugin communications
- [ ] Audit logging enabled
- [ ] Security monitoring alerts configured
- [ ] TLS/mTLS enabled for network communications

### ✅ Configuration
- [ ] Production-appropriate timeouts configured
- [ ] Circuit breakers enabled with proper thresholds
- [ ] Health checks configured for all plugins
- [ ] Resource limits set for plugins
- [ ] Rate limiting configured where appropriate
- [ ] Configuration hot-reload tested

### ✅ Observability
- [ ] Metrics collection enabled
- [ ] Distributed tracing configured (with appropriate sampling)
- [ ] Structured logging implemented
- [ ] Dashboards created for key metrics
- [ ] Alerting rules configured
- [ ] Log aggregation set up

### ✅ Reliability
- [ ] Error handling and retry logic tested
- [ ] Graceful shutdown procedures implemented
- [ ] Backup and recovery procedures documented
- [ ] Load testing completed
- [ ] Failover scenarios tested

## Security Configuration

### Strict Security Policy

```go
// Production security configuration
manager, err := goplugins.Production[Req, Resp]().
    WithSecurity("./config/plugins.whitelist").
    WithPlugin("auth", goplugins.Subprocess("./plugins/auth-service")).
    Build()
```

### Comprehensive Security Setup

```go
securityConfig := goplugins.SecurityConfig{
    Enabled:       true,
    Policy:        goplugins.SecurityPolicyStrict,
    WhitelistFile: "/etc/go-plugins/plugins.whitelist",
    WatchConfig:   true,
    HashAlgorithm: goplugins.HashAlgorithmSHA256,
    
    // Production audit configuration
    AuditConfig: goplugins.SecurityAuditConfig{
        Enabled:    true,
        LogFile:    "/var/log/go-plugins/security-audit.log",
        LogFormat:  "json",
        MaxSize:    100, // MB
        MaxBackups: 30,  // Keep 30 days
        MaxAge:     30,  // days
        Compress:   true,
    },
}

err := manager.EnablePluginSecurity(securityConfig)
```

### mTLS Configuration

```go
// Configure mTLS for plugin communications
tlsConfig := goplugins.AuthConfig{
    Method:   goplugins.AuthMTLS,
    CertFile: "/etc/ssl/certs/client.crt",
    KeyFile:  "/etc/ssl/private/client.key",
    CAFile:   "/etc/ssl/certs/ca.crt",
}

pluginConfig := goplugins.PluginConfig{
    Name:      "secure-service",
    Transport: goplugins.TransportGRPCTLS,
    Endpoint:  "secure-service.internal:9090",
    Auth:      tlsConfig,
}
```

## Performance Optimization

### Production Builder Configuration

```go
manager, err := goplugins.Production[Req, Resp]().
    WithPlugin("service", goplugins.Subprocess("./service")).
    WithTimeout(10 * time.Second).  // Aggressive timeout for production
    WithMetrics().                  // Enable metrics collection
    Build()
```

### Advanced Performance Configuration

```go
config := goplugins.GetDefaultManagerConfig()

// Optimize for production workloads
for i := range config.Plugins {
    plugin := &config.Plugins[i]
    
    // Connection pooling
    plugin.Connection = goplugins.ConnectionConfig{
        MaxConnections:     20,  // Higher for production
        MaxIdleConnections: 10,
        IdleTimeout:        60 * time.Second,
        ConnectionTimeout:  5 * time.Second,   // Fast connection establishment
        RequestTimeout:     30 * time.Second,  // Reasonable request timeout
        KeepAlive:          true,
    }
    
    // Circuit breaker tuning
    plugin.CircuitBreaker = goplugins.CircuitBreakerConfig{
        Enabled:             true,
        FailureThreshold:    5,    // Fail fast
        RecoveryTimeout:     30 * time.Second,
        MinRequestThreshold: 10,   // Higher threshold for production
        SuccessThreshold:    3,
    }
    
    // Health check optimization
    plugin.HealthCheck = goplugins.HealthCheckConfig{
        Enabled:      true,
        Interval:     15 * time.Second,  // More frequent checks
        Timeout:      3 * time.Second,   // Fast health checks
        FailureLimit: 2,                 // Quick failure detection
    }
    
    // Rate limiting for protection
    plugin.RateLimit = goplugins.RateLimitConfig{
        Enabled:           true,
        RequestsPerSecond: 100.0,  // Adjust based on capacity
        BurstSize:         200,
        TimeWindow:        time.Second,
    }
}
```

### Resource Limits

```go
// Set resource limits for plugins
resourceConfig := goplugins.ResourceConfig{
    MaxMemoryMB:    1024,  // 1GB memory limit
    MaxCPUPercent:  50,    // 50% CPU limit
    MaxGoroutines:  5000,
    MaxFileHandles: 1000,
}

err := manager.SetResourceLimits(resourceConfig)
```

## Monitoring & Observability

### Comprehensive Observability Setup

```go
// Production observability configuration
observabilityConfig := goplugins.ObservabilityConfig{
    Enabled: true,
    
    MetricsConfig: goplugins.MetricsConfig{
        Enabled:        true,
        CollectAll:     true,
        ExportInterval: 15 * time.Second,  // Frequent exports
        Namespace:      "myapp",
        Subsystem:      "plugins",
        
        // Production metric retention
        RetentionPeriod: 24 * time.Hour,
        MaxSeries:       10000,
    },
    
    TracingConfig: goplugins.TracingConfig{
        Enabled:     true,
        ServiceName: "plugin-manager",
        SampleRate:  0.01,  // 1% sampling for high-volume production
        Endpoint:    "http://jaeger-collector:14268/api/traces",
        
        Tags: map[string]string{
            "environment": "production",
            "version":     "1.0.0",
            "datacenter":  "us-east-1",
        },
    },
    
    HealthConfig: goplugins.HealthObservabilityConfig{
        Enabled:         true,
        CheckInterval:   10 * time.Second,
        MetricsEnabled:  true,
        AlertThreshold:  2,  // Alert quickly in production
    },
}

err := manager.EnableObservability(observabilityConfig)
```

### Metrics Exporters

```go
// Prometheus exporter for monitoring
prometheusExporter := goplugins.NewPrometheusExporter(goplugins.PrometheusConfig{
    Namespace: "myapp",
    Subsystem: "plugins",
    Port:      9090,
    Path:      "/metrics",
    
    // Production-specific configuration
    EnableCollectorMetrics: true,
    EnableGoMetrics:       true,
    EnableProcessMetrics:  true,
})

// StatsD for real-time metrics
statsdExporter := goplugins.NewStatsDExporter(goplugins.StatsDConfig{
    Address: "statsd.internal:8125",
    Prefix:  "myapp.plugins",
    
    Tags: map[string]string{
        "environment": "production",
        "service":     "plugin-manager",
    },
})

// Note: Implement custom exporters using the MetricsCollector interface
// The observability system supports custom metrics collection and export
```

### Production Logging

```go
// Structured JSON logging for production
logger := goplugins.NewStructuredLogger(goplugins.LoggerConfig{
    Level:      "info",  // Info level for production
    Format:     "json",
    Output:     os.Stdout,
    AddCaller:  false,   // Reduce log size in production
    AddStack:   false,
    
    // Production log configuration
    MaxSize:    100,     // MB
    MaxBackups: 10,
    MaxAge:     30,      // days
    Compress:   true,
})
```

## High Availability

### Multi-Instance Deployment

```go
// Configure for high availability
haConfig := goplugins.HighAvailabilityConfig{
    Enabled:           true,
    ReplicationFactor: 3,
    LoadBalancing:     goplugins.LoadBalancingRoundRobin,
    HealthCheckMode:   goplugins.HealthCheckActive,
    FailoverTimeout:   5 * time.Second,
}

err := manager.EnableHighAvailability(haConfig)
```

### Load Balancing

```go
// Configure load balancing across plugin instances
lbConfig := goplugins.LoadBalancerConfig{
    Strategy: goplugins.LoadBalancingWeightedRoundRobin,
    
    Instances: []goplugins.PluginInstance{
        {
            Name:     "auth-service-1",
            Endpoint: "auth1.internal:9090",
            Weight:   100,
        },
        {
            Name:     "auth-service-2", 
            Endpoint: "auth2.internal:9090",
            Weight:   100,
        },
        {
            Name:     "auth-service-3",
            Endpoint: "auth3.internal:9090",
            Weight:   50,  // Lower capacity instance
        },
    },
    
    HealthCheck: goplugins.LoadBalancerHealthConfig{
        Enabled:      true,
        Interval:     10 * time.Second,
        Timeout:      3 * time.Second,
        FailureLimit: 2,
    },
}

err := manager.ConfigureLoadBalancer("auth-service", lbConfig)
```

## Deployment Strategies

### Blue-Green Deployment

```go
// Blue-green deployment with plugin manager
func blueGreenDeploy(manager *goplugins.Manager, newVersion string) error {
    // 1. Deploy new version alongside current
    err := manager.RegisterPlugin("auth-service-green", newPluginInstance)
    if err != nil {
        return fmt.Errorf("failed to register green instance: %w", err)
    }
    
    // 2. Health check new version
    health := manager.Health()
    if health["auth-service-green"].Status != goplugins.StatusHealthy {
        manager.Unregister("auth-service-green")
        return fmt.Errorf("green instance failed health check")
    }
    
    // 3. Switch traffic to green
    err = manager.SetActivePlugin("auth-service", "auth-service-green")
    if err != nil {
        return fmt.Errorf("failed to switch to green: %w", err)
    }
    
    // 4. Gracefully drain blue instance
    err = manager.GracefulUnregister("auth-service-blue", 30*time.Second)
    if err != nil {
        log.Printf("Warning: failed to gracefully drain blue instance: %v", err)
    }
    
    return nil
}
```

### Rolling Updates

```go
// Rolling update with zero downtime
func rollingUpdate(manager *goplugins.Manager, pluginName, newVersion string) error {
    // 1. Get current instances
    instances := manager.GetPluginInstances(pluginName)
    
    // 2. Update instances one by one
    for i, instance := range instances {
        newInstanceName := fmt.Sprintf("%s-v%s-%d", pluginName, newVersion, i)
        
        // Deploy new instance
        err := manager.RegisterPlugin(newInstanceName, newPluginConfig)
        if err != nil {
            return fmt.Errorf("failed to deploy new instance: %w", err)
        }
        
        // Health check
        if !waitForHealthy(manager, newInstanceName, 30*time.Second) {
            manager.Unregister(newInstanceName)
            return fmt.Errorf("new instance failed health check")
        }
        
        // Remove old instance
        err = manager.GracefulUnregister(instance.Name, 30*time.Second)
        if err != nil {
            log.Printf("Warning: failed to remove old instance: %v", err)
        }
        
        // Brief pause between updates
        time.Sleep(5 * time.Second)
    }
    
    return nil
}
```

### Canary Deployment

```go
// Canary deployment with gradual traffic shifting
func canaryDeploy(manager *goplugins.Manager, pluginName, newVersion string, trafficPercent int) error {
    // 1. Deploy canary instance
    canaryName := fmt.Sprintf("%s-canary", pluginName)
    err := manager.RegisterPlugin(canaryName, newPluginConfig)
    if err != nil {
        return fmt.Errorf("failed to deploy canary: %w", err)
    }
    
    // 2. Configure traffic splitting
    trafficConfig := goplugins.TrafficSplitConfig{
        Routes: []goplugins.TrafficRoute{
            {
                Plugin:  pluginName,
                Weight:  100 - trafficPercent,
            },
            {
                Plugin:  canaryName,
                Weight:  trafficPercent,
            },
        },
    }
    
    err = manager.ConfigureTrafficSplit(pluginName, trafficConfig)
    if err != nil {
        return fmt.Errorf("failed to configure traffic split: %w", err)
    }
    
    // 3. Monitor canary metrics
    return monitorCanaryMetrics(manager, canaryName, 10*time.Minute)
}
```

## Operational Procedures

### Graceful Shutdown

```go
// Production graceful shutdown
func gracefulShutdown(manager *goplugins.Manager) error {
    log.Println("Starting graceful shutdown...")
    
    // 1. Stop accepting new requests (if applicable)
    // This would be handled at the application level
    
    // 2. Wait for active requests to complete
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()
    
    // 3. Shutdown plugin manager
    err := manager.Shutdown(ctx)
    if err != nil {
        log.Printf("Shutdown completed with warnings: %v", err)
        return err
    }
    
    log.Println("Graceful shutdown completed")
    return nil
}
```

### Health Monitoring

```go
// Continuous health monitoring
func startHealthMonitoring(manager *goplugins.Manager) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        health := manager.Health()
        
        for pluginName, status := range health {
            switch status.Status {
            case goplugins.StatusHealthy:
                // Plugin is healthy, continue
                
            case goplugins.StatusDegraded:
                log.Printf("WARNING: Plugin %s is degraded: %s", pluginName, status.Message)
                // Send warning alert
                
            case goplugins.StatusUnhealthy:
                log.Printf("ERROR: Plugin %s is unhealthy: %s", pluginName, status.Message)
                // Send critical alert
                
            case goplugins.StatusOffline:
                log.Printf("CRITICAL: Plugin %s is offline: %s", pluginName, status.Message)
                // Send critical alert and attempt recovery
                go attemptPluginRecovery(manager, pluginName)
            }
        }
    }
}
```

### Automated Recovery

```go
// Automated plugin recovery
func attemptPluginRecovery(manager *goplugins.Manager, pluginName string) {
    log.Printf("Attempting recovery for plugin: %s", pluginName)
    
    // 1. Try to restart the plugin
    plugin, err := manager.GetPlugin(pluginName)
    if err != nil {
        log.Printf("Failed to get plugin %s: %v", pluginName, err)
        return
    }
    
    // 2. Close and re-register
    plugin.Close()
    err = manager.Unregister(pluginName)
    if err != nil {
        log.Printf("Failed to unregister plugin %s: %v", pluginName, err)
    }
    
    // 3. Wait before retry
    time.Sleep(5 * time.Second)
    
    // 4. Re-register plugin
    // This would use the original plugin configuration
    err = manager.Register(plugin)
    if err != nil {
        log.Printf("Failed to re-register plugin %s: %v", pluginName, err)
        // Send alert for manual intervention
        return
    }
    
    log.Printf("Plugin %s recovery completed", pluginName)
}
```

## Troubleshooting

### Performance Issues

```go
// Diagnose performance issues
func diagnosePerformance(manager *goplugins.Manager) {
    metrics := manager.GetMetrics()
    
    // Check request rates
    totalRequests := metrics.RequestsTotal.Load()
    successRequests := metrics.RequestsSuccess.Load()
    failureRequests := metrics.RequestsFailure.Load()
    
    successRate := float64(successRequests) / float64(totalRequests) * 100
    
    log.Printf("Performance Summary:")
    log.Printf("  Total requests: %d", totalRequests)
    log.Printf("  Success rate: %.2f%%", successRate)
    log.Printf("  Failure rate: %.2f%%", float64(failureRequests)/float64(totalRequests)*100)
    
    // Check plugin-specific metrics
    for pluginName := range manager.ListPlugins() {
        pluginMetrics := manager.GetPluginMetrics(pluginName)
        log.Printf("Plugin %s:", pluginName)
        log.Printf("  Requests: %d", pluginMetrics.RequestsTotal.Load())
        log.Printf("  Avg duration: %v", pluginMetrics.AvgDuration)
        log.Printf("  Error rate: %.2f%%", pluginMetrics.ErrorRate)
    }
}
```

### Memory Leak Detection

```go
// Monitor memory usage
func monitorMemoryUsage(manager *goplugins.Manager) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    var m runtime.MemStats
    
    for range ticker.C {
        runtime.ReadMemStats(&m)
        
        log.Printf("Memory Stats:")
        log.Printf("  Alloc: %d KB", bToKb(m.Alloc))
        log.Printf("  TotalAlloc: %d KB", bToKb(m.TotalAlloc))
        log.Printf("  Sys: %d KB", bToKb(m.Sys))
        log.Printf("  NumGC: %d", m.NumGC)
        
        // Alert if memory usage is too high
        if m.Alloc > 1024*1024*1024 { // 1GB
            log.Printf("WARNING: High memory usage detected: %d KB", bToKb(m.Alloc))
            
            // Force garbage collection
            runtime.GC()
            
            // Get plugin-specific memory usage
            pluginMemory := manager.GetPluginMemoryUsage()
            for pluginName, usage := range pluginMemory {
                log.Printf("  Plugin %s: %d KB", pluginName, bToKb(usage))
            }
        }
    }
}

func bToKb(b uint64) uint64 {
    return b / 1024
}
```

### Circuit Breaker Issues

```go
// Diagnose circuit breaker issues
func diagnoseCircuitBreakers(manager *goplugins.Manager) {
    cbStatus := manager.GetCircuitBreakerStatus()
    
    for pluginName, status := range cbStatus {
        log.Printf("Circuit Breaker %s:", pluginName)
        log.Printf("  State: %s", status.State)
        log.Printf("  Failure count: %d", status.FailureCount)
        log.Printf("  Success count: %d", status.SuccessCount)
        log.Printf("  Last failure: %v", status.LastFailure)
        
        if status.State == "open" {
            log.Printf("  WARNING: Circuit breaker is OPEN")
            log.Printf("  Next attempt in: %v", status.NextAttempt.Sub(time.Now()))
        }
    }
}
```

## Production Checklist Summary

Before going live, verify:

1. **Security**: Whitelist configured, audit logging enabled
2. **Performance**: Timeouts optimized, resource limits set
3. **Monitoring**: Metrics, tracing, and alerting configured
4. **Reliability**: Circuit breakers, health checks, graceful shutdown
5. **Operations**: Deployment procedures, recovery plans documented

{{% alert title="Critical Production Note" %}}
Always test your production configuration in a staging environment that mirrors production as closely as possible. This includes load testing, failover scenarios, and recovery procedures.
{{% /alert %}}

## Next Steps

- Review [Security System](/guides/security/) for detailed security configuration
- Check [Observability Guide](/guides/observability/) for monitoring setup
- Explore the [Production API Reference](/api/production/) for advanced configuration options
