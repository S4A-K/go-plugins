# Configuration Guide

go-plugins provides flexible, multi-format configuration support with automatic format detection and hot reloading capabilities.

## Supported Formats

The library supports multiple configuration formats with identical functionality across all formats:

| Format | Extensions | Parser | Complex Structures | Hot Reload |
|--------|------------|--------|-------------------|------------|
| JSON   | `.json`    | Argus  | ✅ Full Support   | ✅ Yes     |
| YAML   | `.yaml`, `.yml` | gopkg.in/yaml.v3 | ✅ Full Support | ✅ Yes |
| TOML   | `.toml`    | github.com/BurntSushi/toml | ✅ Full Support | ✅ Yes |

## Hybrid Parsing Strategy

go-plugins uses a sophisticated hybrid parsing approach that combines the strengths of different parsers:

### Format Detection
- **File Extension Based**: Automatic detection using file extensions
- **Argus Integration**: Leverages Argus for file watching across all formats
- **Fallback Strategy**: Default to Argus parser for unknown formats

### Parser Selection
```go
// Simplified parser selection logic
switch filepath.Ext(configFile) {
case ".yaml", ".yml":
    return parseYAMLConfig(data, config)
case ".toml":
    return parseTOMLConfig(data, config)
default: // .json or unknown
    return argus.ParseConfig(data, config)
}
```

### Specialized Parsers
- **YAML**: Uses `gopkg.in/yaml.v3` for complex nested structures
- **TOML**: Uses `github.com/BurntSushi/toml` for structured data
- **JSON**: Uses optimized Argus parser for performance

## Configuration Structure

All configuration formats support the same complete structure hierarchy:

### Manager Configuration
```go
type ManagerConfig struct {
    Version   string           `json:"version" yaml:"version" toml:"version"`
    LogLevel  string           `json:"log_level" yaml:"log_level" toml:"log_level"`
    Plugins   []PluginConfig   `json:"plugins" yaml:"plugins" toml:"plugins"`
    Discovery DiscoveryConfig  `json:"discovery" yaml:"discovery" toml:"discovery"`
}
```

### Plugin Configuration
```go
type PluginConfig struct {
    Name           string                `json:"name" yaml:"name" toml:"name"`
    Enabled        bool                  `json:"enabled" yaml:"enabled" toml:"enabled"`
    Type           string                `json:"type" yaml:"type" toml:"type"`
    Path           string                `json:"path" yaml:"path" toml:"path"`
    Args           []string              `json:"args,omitempty" yaml:"args,omitempty" toml:"args,omitempty"`
    Env            map[string]string     `json:"env,omitempty" yaml:"env,omitempty" toml:"env,omitempty"`
    Auth           AuthConfig            `json:"auth,omitempty" yaml:"auth,omitempty" toml:"auth,omitempty"`
    Retry          RetryConfig           `json:"retry,omitempty" yaml:"retry,omitempty" toml:"retry,omitempty"`
    CircuitBreaker CircuitBreakerConfig  `json:"circuit_breaker,omitempty" yaml:"circuit_breaker,omitempty" toml:"circuit_breaker,omitempty"`
    HealthCheck    HealthCheckConfig     `json:"health_check,omitempty" yaml:"health_check,omitempty" toml:"health_check,omitempty"`
    Connection     ConnectionConfig      `json:"connection,omitempty" yaml:"connection,omitempty" toml:"connection,omitempty"`
    RateLimit      RateLimitConfig       `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty" toml:"rate_limit,omitempty"`
}
```

## Format Examples

### Complete JSON Configuration
```json
{
  "version": "1.0.0",
  "log_level": "INFO",
  "discovery": {
    "enabled": true,
    "directories": ["/plugins", "/extensions"],
    "patterns": ["*.so", "*.dll"],
    "watch_mode": true
  },
  "plugins": [
    {
      "name": "calculator-plugin",
      "enabled": true,
      "type": "grpc",
      "path": "localhost:50051",
      "args": ["--verbose"],
      "env": {
        "PLUGIN_ENV": "production"
      },
      "auth": {
        "method": "api_key",
        "api_key": "your-secure-api-key",
        "headers": {
          "X-Custom-Header": "value"
        }
      },
      "retry": {
        "max_retries": 3,
        "initial_interval": "100ms",
        "max_interval": "10s",
        "multiplier": 2.0,
        "random_jitter": true
      },
      "circuit_breaker": {
        "enabled": true,
        "failure_threshold": 5,
        "recovery_timeout": "30s",
        "min_request_threshold": 10,
        "success_threshold": 3
      },
      "health_check": {
        "enabled": true,
        "interval": "30s",
        "timeout": "5s",
        "endpoint": "/health",
        "method": "GET",
        "success_codes": [200, 204]
      },
      "connection": {
        "connect_timeout": "10s",
        "read_timeout": "30s",
        "write_timeout": "30s",
        "idle_timeout": "90s",
        "max_idle_conns": 10,
        "max_conns": 100,
        "tls_enabled": true
      },
      "rate_limit": {
        "enabled": true,
        "requests_per_second": 100.5,
        "burst_size": 10,
        "algorithm": "token_bucket"
      }
    }
  ]
}
```

### Complete YAML Configuration
```yaml
version: "1.0.0"
log_level: INFO

discovery:
  enabled: true
  directories:
    - /plugins
    - /extensions
  patterns:
    - "*.so"
    - "*.dll"
  watch_mode: true

plugins:
  - name: calculator-plugin
    enabled: true
    type: grpc
    path: localhost:50051
    args:
      - "--verbose"
    env:
      PLUGIN_ENV: production
    auth:
      method: api_key
      api_key: your-secure-api-key
      headers:
        X-Custom-Header: value
    retry:
      max_retries: 3
      initial_interval: 100ms
      max_interval: 10s
      multiplier: 2.0
      random_jitter: true
    circuit_breaker:
      enabled: true
      failure_threshold: 5
      recovery_timeout: 30s
      min_request_threshold: 10
      success_threshold: 3
    health_check:
      enabled: true
      interval: 30s
      timeout: 5s
      endpoint: /health
      method: GET
      success_codes:
        - 200
        - 204
    connection:
      connect_timeout: 10s
      read_timeout: 30s
      write_timeout: 30s
      idle_timeout: 90s
      max_idle_conns: 10
      max_conns: 100
      tls_enabled: true
    rate_limit:
      enabled: true
      requests_per_second: 100.5
      burst_size: 10
      algorithm: token_bucket
```

### Complete TOML Configuration
```toml
version = "1.0.0"
log_level = "INFO"

[discovery]
enabled = true
directories = ["/plugins", "/extensions"]
patterns = ["*.so", "*.dll"]
watch_mode = true

[[plugins]]
name = "calculator-plugin"
enabled = true
type = "grpc"
path = "localhost:50051"
args = ["--verbose"]

[plugins.env]
PLUGIN_ENV = "production"

[plugins.auth]
method = "api_key"
api_key = "your-secure-api-key"

[plugins.auth.headers]
X-Custom-Header = "value"

[plugins.retry]
max_retries = 3
initial_interval = "100ms"
max_interval = "10s"
multiplier = 2.0
random_jitter = true

[plugins.circuit_breaker]
enabled = true
failure_threshold = 5
recovery_timeout = "30s"
min_request_threshold = 10
success_threshold = 3

[plugins.health_check]
enabled = true
interval = "30s"
timeout = "5s"
endpoint = "/health"
method = "GET"
success_codes = [200, 204]

[plugins.connection]
connect_timeout = "10s"
read_timeout = "30s"
write_timeout = "30s"
idle_timeout = "90s"
max_idle_conns = 10
max_conns = 100
tls_enabled = true

[plugins.rate_limit]
enabled = true
requests_per_second = 100.5
burst_size = 10
algorithm = "token_bucket"
```

## Hot Reload Support

All configuration formats support hot reloading through Argus file watching:

```go
// Enable hot reload for any format
manager, err := goplugins.NewManager(config)
if err != nil {
    log.Fatal(err)
}

// Works with .json, .yaml, .yml, .toml files
err = manager.EnableDynamicConfiguration("config.yaml", goplugins.DrainOptions{
    DrainTimeout: 30 * time.Second,
    GracefulStop: true,
})
```

### Hot Reload Features
- **Format Detection**: Automatic detection when config file changes
- **Graceful Transitions**: Smooth plugin transitions without service interruption
- **Validation**: Invalid configurations are rejected with rollback
- **Audit Logging**: Complete change tracking and history

## Migration Between Formats

Converting between formats is straightforward since all use the same structure:

### JSON to YAML
```bash
# Using yq (recommended)
yq eval -P '.' config.json > config.yaml

# Manual conversion using go-plugins
go run convert.go --from config.json --to config.yaml --format yaml
```

### JSON to TOML
```bash
# Using go-plugins converter
go run convert.go --from config.json --to config.toml --format toml
```

### YAML to TOML
```bash
# Via go-plugins converter
go run convert.go --from config.yaml --to config.toml --format toml
```

## Validation and Error Handling

The library provides consistent validation across all formats:

```go
func (c *ConfigLoader) ValidateConfig(config *ManagerConfig) error {
    // Validation works identically for JSON, YAML, TOML
    return c.validateManagerConfig(config)
}
```

### Common Validation Rules
- Plugin names must be unique
- Authentication methods must be valid
- Timeout values must be parseable durations
- Network addresses must be valid
- Required fields cannot be empty

## Performance Considerations

| Format | Parse Speed | Memory Usage | File Size | Readability |
|--------|-------------|--------------|-----------|-------------|
| JSON   | Fastest     | Lowest       | Smallest  | Good        |
| YAML   | Medium      | Medium       | Medium    | Excellent   |
| TOML   | Good        | Low          | Medium    | Very Good   |

### Recommendations
- **JSON**: Best for production with frequent hot reloads
- **YAML**: Best for human-readable configurations and development
- **TOML**: Best balance of readability and performance

## Troubleshooting

### Format Detection Issues
```bash
# Check file extension
ls -la config.*
# Ensure proper extension: .json, .yaml, .yml, .toml
```

### YAML Parsing Errors
```bash
# Validate YAML syntax
yq eval '.' config.yaml
```

### TOML Parsing Errors
```bash
# Validate TOML syntax
toml-test config.toml
```

### Debug Parsing
```go
// Enable debug logging
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
configLoader := goplugins.NewConfigLoader(logger)
```

## Advanced Features

### Custom Parser Registration
```go
// Register custom format parser
configLoader.RegisterParser(".custom", func(data []byte, config interface{}) error {
    // Custom parsing logic
    return nil
})
```

### Format-Specific Options
```go
// YAML-specific options
yamlOptions := &yaml.DecodeOptions{
    KnownFields: true,
    Strict: true,
}

// TOML-specific options  
tomlOptions := &toml.DecodeOptions{
    DisallowUnknownFields: true,
}
```

### Programmatic Format Detection
```go
format, err := configLoader.DetectFormat("config.unknown")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Detected format: %s\n", format)
```

## Dependencies

The multi-format support introduces these additional dependencies:

- `gopkg.in/yaml.v3 v3.0.1` - YAML parsing
- `github.com/BurntSushi/toml v1.5.0` - TOML parsing
- `github.com/agilira/argus` - File watching and JSON parsing

All dependencies are lightweight and production-ready with excellent performance characteristics.

## Migration Guide

### From v1.x to v2.x
The multi-format support is fully backward compatible:

- Existing JSON configurations continue to work
- No API changes required
- Hot reload functionality unchanged
- Performance improvements across all formats

### New Projects
For new projects, we recommend:
1. **Development**: Use YAML for readability
2. **Production**: Use JSON for performance
3. **Configuration Management**: Use TOML for structured data

The hybrid parsing strategy ensures optimal performance regardless of format choice.