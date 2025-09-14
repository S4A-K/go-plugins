# Plugin Configuration Quick Reference

## Minimal Required Fields

Every plugin **MUST** have these fields:

```json
{
  "name": "unique-plugin-name",     // ❌ Cannot be empty (PLUGIN_1001)
  "type": "http",                   // ❌ Required for hot reload 
  "transport": "https",             // ❌ Cannot be empty (PLUGIN_1002)  
  "endpoint": "https://api.com/v1"  // ❌ Required for network transports (PLUGIN_1003)
}
```

## Transport-Specific Requirements

### HTTP/HTTPS
```json
{
  "transport": "https",
  "endpoint": "https://api.example.com/v1/endpoint"  // Must be valid URL
}
```

### gRPC
```json
{
  "transport": "grpc",
  "endpoint": "grpc.example.com:443"  // host:port format
}
```

### Unix Socket
```json
{
  "transport": "unix", 
  "endpoint": "/tmp/plugin.sock"      // Socket path
}
```

### Executable
```json
{
  "transport": "exec",
  "executable": "/path/to/binary",    // ❌ Cannot be empty (PLUGIN_1007)
  "args": ["--config", "/etc/app.conf"],  // Optional
  "work_dir": "/tmp"                       // Optional
}
```

## Authentication Quick Setup

### API Key
```json
{
  "auth": {
    "method": "api-key",
    "api_key": "your-key-here"        // ❌ Cannot be empty (AUTH_1101)
  }
}
```

### Bearer Token
```json
{
  "auth": {
    "method": "bearer", 
    "token": "your-jwt-token"         // ❌ Cannot be empty (AUTH_1102)
  }
}
```

### Basic Auth
```json
{
  "auth": {
    "method": "basic",
    "username": "user",               // ❌ Required (AUTH_1103)
    "password": "pass"                // ❌ Required (AUTH_1103) 
  }
}
```

### mTLS
```json
{
  "auth": {
    "method": "mtls",
    "cert_file": "/path/to/client.crt", // ❌ Required (AUTH_1104)
    "key_file": "/path/to/client.key"   // ❌ Required (AUTH_1104)
  }
}
```

## Hot Reload Setup Checklist

### 1. Register Plugin Factories First
```go
manager.RegisterPluginFactory("http", &HTTPPluginFactory{})
manager.RegisterPluginFactory("grpc", &GRPCPluginFactory{})
```

### 2. Enable Dynamic Configuration
```go
err = manager.EnableDynamicConfiguration("/config.json", &DynamicConfigOptions{
  Strategy:     ReloadStrategyGraceful,
  PollInterval: 50 * time.Millisecond,  // Aggressive for testing
  CacheTTL:     10 * time.Millisecond,  // Aggressive for testing
})
```

### 3. Config File Structure
```json
{
  "plugins": [
    {
      "name": "my-plugin",
      "type": "http",                    // ❌ Don't forget this!
      "transport": "https", 
      "endpoint": "https://httpbin.org/get",
      "enabled": true,
      "priority": 1
    }
  ]
}
```

## Common Error Codes

| Error Code | Issue | Solution |
|------------|-------|----------|
| `PLUGIN_1001` | Missing/empty `name` | Add non-empty plugin name |
| `PLUGIN_1002` | Missing/empty `transport` | Add valid transport type |
| `PLUGIN_1003` | Missing `endpoint` | Add endpoint URL for network transports |
| `PLUGIN_1007` | Missing `executable` | Add executable path for exec transport |
| `AUTH_1101` | Missing API key | Add `api_key` field |
| `AUTH_1102` | Missing bearer token | Add `token` field |
| `AUTH_1103` | Missing basic auth credentials | Add both `username` and `password` |
| `AUTH_1104` | Missing mTLS certificates | Add both `cert_file` and `key_file` |

## Performance Tips

### Production Settings
```json
{
  "connection": {
    "max_connections": 10,
    "max_idle_connections": 5, 
    "connection_timeout": "10s",
    "request_timeout": "30s"
  },
  "retry": {
    "max_retries": 3,
    "initial_interval": "100ms"
  }
}
```

### Hot Reload Production Settings  
```go
&DynamicConfigOptions{
  PollInterval: 5 * time.Second,      // Less aggressive for production
  CacheTTL:     30 * time.Second,     // Balance performance vs responsiveness
}
```

## Testing Best Practices

### Deterministic Testing
```go
// Instead of file modification:
manager.ReloadConfig(newConfig)  // Direct config reload for tests
```

### Test Configuration
```go
&DynamicConfigOptions{
  PollInterval: 50 * time.Millisecond,   // Fast detection
  CacheTTL:     10 * time.Millisecond,   // Quick cache refresh
}
```

## Template Examples

### Basic HTTP Plugin
```json
{
  "name": "api-service",
  "type": "http", 
  "transport": "https",
  "endpoint": "https://api.example.com/v1",
  "enabled": true,
  "priority": 1,
  "auth": {
    "method": "api-key",
    "api_key": "your-api-key"
  }
}
```

### Resilient Plugin with Circuit Breaker
```json
{
  "name": "payment-service",
  "type": "http",
  "transport": "https", 
  "endpoint": "https://payments.com/api/v1",
  "enabled": true,
  "retry": {
    "max_retries": 3,
    "initial_interval": "100ms"
  },
  "circuit_breaker": {
    "enabled": true,
    "failure_threshold": 5,
    "recovery_timeout": "30s"
  }
}
```