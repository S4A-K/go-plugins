---
title: Configuration
description: Learn how to configure plugins and the manager
weight: 20
---

# Configuration Guide

This guide covers the different ways to configure go-plugins for your specific needs.

## Simple API Configuration

The Simple API provides a fluent interface for common configurations:

### Development Configuration

```go
manager, err := goplugins.Development[Req, Resp]().
    WithPlugin("service1", goplugins.Subprocess("./service1")).
    WithPlugin("service2", goplugins.GRPC("localhost:9090")).
    WithLogger(myLogger).
    WithTimeout(60 * time.Second).
    Build()
```

**Development defaults:**
- 60-second timeout for debugging
- Verbose logging enabled
- Extended error messages

### Production Configuration

```go
manager, err := goplugins.Production[Req, Resp]().
    WithPlugin("service", goplugins.Subprocess("./service")).
    WithSecurity("./plugins.whitelist").
    WithMetrics().
    Build()
```

**Production defaults:**
- 10-second timeout for responsiveness
- Metrics collection enabled
- Optimized for performance

## Advanced Configuration

For complex scenarios, use the advanced configuration API:

```go
config := goplugins.GetDefaultManagerConfig()

// Customize global settings
config.LogLevel = "info"
config.MetricsPort = 9090

// Configure individual plugins
config.Plugins = []goplugins.PluginConfig{
    {
        Name:      "auth-service",
        Type:      "subprocess",
        Transport: goplugins.TransportExecutable,
        Executable: "./plugins/auth-service",
        Args:      []string{"--config", "/etc/auth.conf"},
        Env:       []string{"LOG_LEVEL=info", "MAX_MEMORY=1GB"},
        WorkDir:   "/var/lib/plugins",
        Enabled:   true,
        Priority:  1,
        
        // Authentication configuration
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

## Configuration File Support

You can also load configuration from YAML files:

### plugins.yaml
```yaml
log_level: info
metrics_port: 9090

default_retry:
  max_retries: 3
  initial_interval: 100ms
  max_interval: 5s
  multiplier: 2.0
  random_jitter: true

default_circuit_breaker:
  enabled: true
  failure_threshold: 5
  recovery_timeout: 30s
  min_request_threshold: 3
  success_threshold: 2

plugins:
  - name: auth-service
    type: subprocess
    transport: exec
    executable: ./plugins/auth-service
    args: ["--config", "/etc/auth.conf"]
    env: ["LOG_LEVEL=info"]
    enabled: true
    priority: 1
    
    auth:
      method: api-key
      api_key: "${AUTH_API_KEY}"
    
    health_check:
      enabled: true
      interval: 30s
      timeout: 5s
      failure_limit: 3
```

### Loading from file
```go
// Load from YAML file
config, err := goplugins.LoadConfigFromFile("plugins.yaml")
if err != nil {
    log.Fatal(err)
}

manager := goplugins.NewManager[AuthRequest, AuthResponse](logger)
err = manager.LoadFromConfig(config)
```

## Environment Variables

Many configuration options can be overridden with environment variables:

```bash
# Security settings
export GOPLUGINS_SECURITY_ENABLED=true
export GOPLUGINS_WHITELIST_FILE=./plugins.whitelist

# Logging
export GOPLUGINS_LOG_LEVEL=debug

# Metrics
export GOPLUGINS_METRICS_PORT=9090
export GOPLUGINS_METRICS_ENABLED=true

# Default timeouts
export GOPLUGINS_DEFAULT_TIMEOUT=30s
export GOPLUGINS_HEALTH_CHECK_INTERVAL=30s
```

## Transport Configuration

### Subprocess Transport (Recommended)

```go
config := goplugins.PluginConfig{
    Name:       "service",
    Transport:  goplugins.TransportExecutable,
    Executable: "./service-plugin",
    Args:       []string{"--port", "8080"},
    Env:        []string{"LOG_LEVEL=info"},
    WorkDir:    "/var/lib/plugins",
}
```

### gRPC Transport

```go
config := goplugins.PluginConfig{
    Name:      "service",
    Transport: goplugins.TransportGRPC,
    Endpoint:  "localhost:9090",
    
    Auth: goplugins.AuthConfig{
        Method:   goplugins.AuthMTLS,
        CertFile: "/etc/certs/client.crt",
        KeyFile:  "/etc/certs/client.key",
        CAFile:   "/etc/certs/ca.crt",
    },
}
```

## Best Practices

### 1. Use Environment-Specific Builders
```go
// Development
manager := goplugins.Development[Req, Resp]()

// Production  
manager := goplugins.Production[Req, Resp]()
```

### 2. Configure Appropriate Timeouts
```go
// Short timeout for fast services
.WithTimeout(5 * time.Second)

// Longer timeout for complex operations
.WithTimeout(60 * time.Second)
```

### 3. Enable Security in Production
```go
manager := goplugins.Production[Req, Resp]().
    WithSecurity("./plugins.whitelist").
    Build()
```

### 4. Use Configuration Files for Complex Setups
- Keep configuration in version control
- Use environment variables for secrets
- Validate configuration at startup

### 5. Monitor Your Configuration
```go
// Enable metrics to monitor configuration effectiveness
manager := goplugins.Production[Req, Resp]().
    WithMetrics().
    Build()
```

{{% alert title="Security Note" %}}
Never hardcode secrets in configuration files. Use environment variables or secure secret management systems.
{{% /alert %}}

## Next Steps

- Learn about [Security Configuration](/guides/security/)
- Explore [Observability Setup](/guides/observability/)
- Check out [Production Deployment](/guides/production/)
