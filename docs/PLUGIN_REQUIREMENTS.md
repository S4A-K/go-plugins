# Plugin Requirements Guide

This guide describes the technical requirements and best practices for correctly configuring plugins in the go-plugins system with Argus integration.

## Table of Contents

1. [Mandatory Minimum Requirements](#mandatory-minimum-requirements)
2. [Transport-Specific Configuration](#transport-specific-configuration)
3. [Authentication](#authentication)
4. [Resilience and Performance](#resilience-and-performance)
5. [Hot Reload Requirements](#hot-reload-requirements)
6. [Common Pitfalls and Troubleshooting](#common-pitfalls-and-troubleshooting)
7. [Complete Examples](#complete-examples)

## Mandatory Minimum Requirements

### Required Fields

Every plugin **MUST** have these fields configured correctly:

#### 1. **Plugin Name (name)**
```json
{
  "name": "my-plugin"
}
```
- **Requirement**: Cannot be empty
- **Validation**: Generates `PLUGIN_1001` error if missing
- **Best Practice**: Use descriptive and unique names in the system

#### 2. **Plugin Type (type)** 
```json
{
  "type": "http"
}
```
- **Requirement**: Mandatory for hot reload and plugin factories
- **Importance**: During development we discovered that without this field the system cannot properly register plugins
- **Common values**: `"http"`, `"grpc"`, `"unix"`, `"exec"`, or custom types

#### 3. **Transport**
```json
{
  "transport": "http"
}
```
- **Requirement**: Cannot be empty
- **Validation**: Generates `PLUGIN_1002` error if missing
- **Supported values**: `http`, `https`, `grpc`, `grpc-tls`, `unix`, `exec`

## Transport-Specific Configuration

### HTTP/HTTPS Plugins

**Mandatory requirements:**
```json
{
  "name": "api-service",
  "type": "http",
  "transport": "https",
  "endpoint": "https://api.example.com/v1/endpoint"
}
```

**Applied validations:**
- `endpoint` cannot be empty (error `PLUGIN_1003`)
- `endpoint` must be a valid URL (error `PLUGIN_1004`)
- URL must have `scheme` and `host` (error `PLUGIN_1005`)

**Recommended optional fields:**
```json
{
  "auth": {
    "method": "api-key",
    "api_key": "your-api-key"
  },
  "connection": {
    "request_timeout": "30s",
    "connection_timeout": "10s"
  },
  "retry": {
    "max_retries": 3
  }
}
```

### gRPC Plugins

**Mandatory requirements:**
```json
{
  "name": "grpc-service",
  "type": "grpc",
  "transport": "grpc",
  "endpoint": "grpc.example.com:443"
}
```

**For gRPC with TLS:**
```json
{
  "transport": "grpc-tls",
  "auth": {
    "method": "mtls",
    "cert_file": "/path/to/client.crt",
    "key_file": "/path/to/client.key"
  }
}
```

### Unix Socket Plugins

**Mandatory requirements:**
```json
{
  "name": "unix-service",
  "type": "unix",
  "transport": "unix",
  "endpoint": "/tmp/plugin.sock"
}
```

**Applied validations:**
- `endpoint` (socket path) cannot be empty (error `PLUGIN_1006`)

### Executable Plugins

**Mandatory requirements:**
```json
{
  "name": "exec-service",
  "type": "exec",
  "transport": "exec",
  "executable": "/path/to/executable"
}
```

**Applied validations:**
- `executable` cannot be empty (error `PLUGIN_1007`)

**Optional fields:**
```json
{
  "args": ["--config", "/etc/config.json"],
  "env": ["LOG_LEVEL=info"],
  "work_dir": "/tmp/plugin"
}
```

## Authentication

### No Authentication
```json
{
  "auth": {
    "method": "none"
  }
}
```

### API Key
```json
{
  "auth": {
    "method": "api-key",
    "api_key": "your-api-key-here"
  }
}
```
- **Validation**: `api_key` cannot be empty (error `AUTH_1101`)

### Bearer Token
```json
{
  "auth": {
    "method": "bearer",
    "token": "your-jwt-token"
  }
}
```
- **Validation**: `token` cannot be empty (error `AUTH_1102`)

### Basic Authentication
```json
{
  "auth": {
    "method": "basic",
    "username": "user",
    "password": "pass"
  }
}
```
- **Validation**: Both `username` and `password` are required (error `AUTH_1103`)

### Mutual TLS (mTLS)
```json
{
  "auth": {
    "method": "mtls",
    "cert_file": "/path/to/client.crt",
    "key_file": "/path/to/client.key",
    "ca_file": "/path/to/ca.crt"
  }
}
```
- **Validation**: `cert_file` and `key_file` are required (error `AUTH_1104`)

## Resilience and Performance

### Retry Configuration
```json
{
  "retry": {
    "max_retries": 3,
    "initial_interval": "100ms",
    "max_interval": "5s",
    "multiplier": 2.0,
    "random_jitter": true
  }
}
```

### Circuit Breaker
```json
{
  "circuit_breaker": {
    "enabled": true,
    "failure_threshold": 5,
    "recovery_timeout": "30s",
    "half_open_requests": 3
  }
}
```

### Connection Pooling
```json
{
  "connection": {
    "max_connections": 10,
    "max_idle_connections": 5,
    "idle_timeout": "30s",
    "connection_timeout": "10s",
    "request_timeout": "30s",
    "keep_alive": true
  }
}
```

### Rate Limiting
```json
{
  "rate_limit": {
    "enabled": true,
    "requests_per_second": 10.0,
    "burst_size": 20,
    "time_window": "1s"
  }
}
```

## Hot Reload Requirements

For proper hot reload functionality with Argus:

### 1. Plugin Factory Registration
Plugins must be registered with a factory before enabling hot reload:

```go
manager.RegisterPluginFactory("http", &HTTPPluginFactory{})
manager.RegisterPluginFactory("grpc", &GRPCPluginFactory{})
// Etc. for all types used
```

### 2. Manager Configuration
```go
config := &ManagerConfig{
  Plugins: []PluginConfig{
    // Your plugins...
  },
}

// Enable hot reload AFTER configuring the manager
err = manager.EnableDynamicConfiguration("/path/to/config.json", &DynamicConfigOptions{
  Strategy:     ReloadStrategyGraceful,
  PollInterval: 50 * time.Millisecond,
  CacheTTL:     10 * time.Millisecond,
})
```

### 3. File Configuration Structure
The JSON file must be correctly structured:
```json
{
  "plugins": [
    {
      "name": "plugin-1",
      "type": "http",
      "transport": "https",
      "endpoint": "https://httpbin.org/get",
      "enabled": true,
      "priority": 1
    }
  ]
}
```

## Common Pitfalls and Troubleshooting

### 1. Error: "Plugin validation failed [PLUGIN_1001]"
**Cause**: Missing or empty `name` field
**Solution**: 
```json
{
  "name": "my-plugin-name"  // Make sure it's not empty
}
```

### 2. Error: "failed to start config watcher: failed to load initial configuration"
**Cause**: Plugin factories not registered before enabling hot reload
**Solution**: Register factories first:
```go
manager.RegisterPluginFactory("http", &HTTPPluginFactory{})
err := manager.EnableDynamicConfiguration(...)
```

### 3. Hot Reload not working
**Common causes**:
- Missing `type` field in plugin
- Factory not registered for plugin type
- Configuration file with invalid JSON format

**Debug steps**:
1. Verify that every plugin has the `type` field
2. Verify that the factory is registered: `manager.GetPluginFactory(pluginType)`
3. Validate JSON: `json.Unmarshal(configContent, &config)`

### 4. Plugin not updating during hot reload
**Cause**: Argus cache TTL too high
**Solution**: Use aggressive settings for testing:
```go
&DynamicConfigOptions{
  PollInterval: 50 * time.Millisecond,
  CacheTTL:     10 * time.Millisecond,
}
```

### 5. Flaky tests
**Cause**: Race condition between file write and Argus detection
**Solution**: Use `ReloadConfig()` for deterministic tests:
```go
// Instead of modifying the file:
manager.ReloadConfig(newConfig)
```

## Complete Examples

### Complete HTTP Plugin
```json
{
  "name": "payment-api",
  "type": "http",
  "transport": "https",
  "endpoint": "https://api.payments.com/v1/process",
  "enabled": true,
  "priority": 1,
  "auth": {
    "method": "bearer",
    "token": "eyJhbGciOiJIUzI1NiIs..."
  },
  "retry": {
    "max_retries": 3,
    "initial_interval": "100ms",
    "max_interval": "5s",
    "multiplier": 2.0,
    "random_jitter": true
  },
  "circuit_breaker": {
    "enabled": true,
    "failure_threshold": 5,
    "recovery_timeout": "30s",
    "half_open_requests": 3
  },
  "connection": {
    "max_connections": 10,
    "max_idle_connections": 5,
    "idle_timeout": "30s",
    "connection_timeout": "10s",
    "request_timeout": "30s",
    "keep_alive": true
  },
  "health_check": {
    "enabled": true,
    "endpoint": "/health",
    "interval": "30s",
    "timeout": "5s",
    "healthy_threshold": 2,
    "unhealthy_threshold": 3
  },
  "labels": {
    "environment": "production",
    "service": "payments",
    "version": "v1.2.3"
  }
}
```

### Complete Manager Configuration
```json
{
  "plugins": [
    {
      "name": "payment-api",
      "type": "http",
      "transport": "https",
      "endpoint": "https://api.payments.com/v1/process",
      "enabled": true,
      "priority": 1,
      "auth": {
        "method": "api-key",
        "api_key": "prod-key-123"
      }
    },
    {
      "name": "user-service",
      "type": "grpc",
      "transport": "grpc-tls",
      "endpoint": "users.internal:443",
      "enabled": true,
      "priority": 2,
      "auth": {
        "method": "mtls",
        "cert_file": "/etc/ssl/client.crt",
        "key_file": "/etc/ssl/client.key",
        "ca_file": "/etc/ssl/ca.crt"
      }
    }
  ],
  "load_balancer": {
    "strategy": "round-robin",
    "health_check_enabled": true
  },
  "observability": {
    "metrics_enabled": true,
    "tracing_enabled": true,
    "log_level": "info"
  }
}
```

## Performance Notes

- **Argus Performance**: The Argus library used for hot reload has 12.10ns/op performance
- **Poll Interval**: For production, use higher intervals (e.g. 5s) to reduce load
- **Cache TTL**: Balance between responsiveness and performance
- **Connection Pooling**: Configure appropriately to avoid excessive connections

## Monitoring

The system provides metrics and statistics via:
```go
// Argus statistics
stats := manager.GetArgusStats()
fmt.Printf("Entries: %d, Age: %v\n", stats.Entries, stats.OldestAge)

// Plugin statistics
pluginStats := manager.GetPluginStats("plugin-name")
```

This documentation covers all requirements identified during development and resolves common issues encountered during Argus integration.