# Hot Reload Plugin Example

This example demonstrates how to implement Argus-powered hot reload functionality with the go-plugins library. It shows how to create plugins that can be dynamically reloaded at runtime through configuration file changes.

## Features

- **Ultra-Fast Hot Reload**: Powered by Argus file watcher (12.10ns/op performance)
- **Dynamic Configuration**: Runtime plugin management through JSON configuration
- **Graceful Updates**: Plugins are updated without service interruption
- **HTTP API**: REST endpoints for plugin interaction
- **Comprehensive Testing**: Full test suite with realistic scenarios
- **Production Ready**: Battle-tested with forensic audit system

## Project Structure

```
hot-reload-plugin/
├── main.go           # HTTP server with Argus hot reload
├── main_test.go      # Comprehensive test suite
├── go.mod           # Module configuration
├── config.json      # Dynamic configuration file
└── README.md        # This documentation
```

## Implementation Details

### Counter Plugin

The example implements a thread-safe counter plugin with the following features:

- **Increment Operations**: Add values to the counter
- **Get Operations**: Retrieve current counter value  
- **Reset Operations**: Reset counter to zero
- **Health Checks**: Monitor plugin status
- **Structured Logging**: Comprehensive operation logging

### HTTP API Endpoints

```bash
# Increment counter (POST with JSON body: {"value": N})
curl -X POST http://localhost:8080/plugins/counter-1/increment \
     -H "Content-Type: application/json" \
     -d '{"value": 5}'

# Get current value
curl http://localhost:8080/plugins/counter-1/get

# Reset counter
curl -X POST http://localhost:8080/plugins/counter-1/reset
```

### Hot Reload Configuration

The `config.json` file defines the plugin configuration:

```json
{
  "plugins": [
    {
      "name": "counter-1",
      "type": "counter", 
      "transport": "http",
      "endpoint": "http://localhost:9001",
      "enabled": true,
      "auth": {
        "method": "none"
      },
      "connection": {
        "max_connections": 10,
        "max_idle_connections": 5,
        "idle_timeout": "30s",
        "connection_timeout": "10s", 
        "request_timeout": "30s",
        "keep_alive": true
      },
      "options": {
        "increment": 1
      }
    }
  ]
}
```

## Running the Example

### Start the Server

```bash
cd examples/hot-reload-plugin
go run main.go
```

The server starts on `http://localhost:8080` with hot reload enabled.

### Test Hot Reload

1. **Make a request**:
   ```bash
   curl -X POST http://localhost:8080/plugins/counter-1/increment \
        -H "Content-Type: application/json" \
        -d '{"value": 5}'
   ```

2. **Modify config.json** (change the increment value):
   ```json
   {
     "plugins": [{
       "name": "counter-1",
       "type": "counter",
       "transport": "http", 
       "endpoint": "http://localhost:9001",
       "enabled": true,
       "options": {
         "increment": 10  // Changed from 1 to 10
       }
     }]
   }
   ```

3. **Configuration is automatically reloaded** - no server restart needed!

4. **Test the change**:
   ```bash
   curl -X POST http://localhost:8080/plugins/counter-1/increment \
        -H "Content-Type: application/json" \
        -d '{"value": 1}'
   ```

## Running Tests

### Run All Tests
```bash
go test -v
```

### Run Specific Tests
```bash
# Test counter plugin functionality
go test -v -run TestCounterPlugin

# Test plugin factory
go test -v -run TestCounterPluginFactory

# Test hot reload functionality  
go test -v -run TestHotReloadFunctionality
```

### Run Benchmarks
```bash
# Performance benchmarks
go test -run=^$ -bench=. -benchmem

# Results show ultra-high performance:
# BenchmarkCounterIncrement-8    48676    23674 ns/op    32 B/op    1 allocs/op
# BenchmarkCounterGet-8       1000000000    1.088 ns/op     0 B/op    0 allocs/op
```

### Test Coverage
```bash
go test -cover
# PASS
# coverage: XX% of statements
```

## ⚡ Performance Characteristics

- **Argus File Monitoring**: 12.10ns/op (ultra-fast detection)
- **Counter Increment**: ~23,674 ns/op with logging
- **Counter Get**: ~1.088 ns/op (near zero-cost)
- **Memory Efficiency**: Minimal allocations per operation
- **Concurrent Safe**: Full thread-safety with atomic operations

## Key Learning Points

### 1. Plugin Interface Implementation

```go
type CounterPlugin struct {
    name      string
    increment int
    counter   atomic.Int64
    logger    *slog.Logger
}

// Execute implements the Plugin interface
func (cp *CounterPlugin) Execute(ctx plugins.ExecutionContext, req CounterRequest) (CounterResponse, error) {
    switch req.Operation {
    case "increment":
        newValue := cp.counter.Add(int64(req.Value * cp.increment))
        return CounterResponse{Value: int(newValue)}, nil
    case "get":
        return CounterResponse{Value: int(cp.counter.Load())}, nil  
    case "reset":
        cp.counter.Store(0)
        return CounterResponse{Value: 0}, nil
    default:
        return CounterResponse{}, fmt.Errorf("unknown operation: %s", req.Operation)
    }
}
```

### 2. Factory Pattern for Plugin Creation

```go
type CounterPluginFactory struct{}

func (f *CounterPluginFactory) CreatePlugin(config plugins.PluginConfig, logger *slog.Logger) (plugins.Plugin[CounterRequest, CounterResponse], error) {
    increment := 1
    if val, ok := config.Options["increment"].(float64); ok {
        increment = int(val)
    }
    
    return &CounterPlugin{
        name:      config.Name,
        increment: increment, 
        logger:    logger,
    }, nil
}
```

### 3. Argus-Powered Hot Reload Setup

```go
func setupHotReload(manager *plugins.Manager[CounterRequest, CounterResponse]) error {
    options := plugins.DefaultDynamicConfigOptions()
    options.PollInterval = 100 * time.Millisecond  // Fast detection
    options.ReloadStrategy = plugins.ReloadStrategyGraceful
    
    return manager.EnableDynamicConfiguration("config.json", options)
}
```

## Error Handling

The example demonstrates comprehensive error handling:

- **Configuration Validation**: Invalid configs are rejected
- **Plugin Creation Errors**: Graceful factory error handling  
- **Runtime Errors**: Request/response error management
- **Hot Reload Failures**: Automatic rollback on configuration errors
- **Graceful Shutdown**: Clean resource cleanup

## Dependencies

- **Go 1.21+**: Modern Go language features
- **Argus**: Ultra-fast file monitoring system
- **slog**: Structured logging (Go standard library)
- **atomic**: Thread-safe operations (Go standard library)
- **net/http**: HTTP server capabilities

## Production Deployment

For production use:

1. **Adjust polling interval**: Use `5s` instead of `100ms`
2. **Enable audit logging**: Track all configuration changes
3. **Configure rollback**: Enable automatic error recovery
4. **Monitor performance**: Use Argus statistics for insights
5. **Secure config files**: Appropriate file permissions

```go
options := plugins.DefaultDynamicConfigOptions()
options.PollInterval = 5 * time.Second      // Less aggressive
options.RollbackOnFailure = true            // Safety net
options.AuditConfig.Enabled = true          // Compliance
```

This example provides a complete foundation for implementing dynamic, hot-reloadable plugins in production Go applications with enterprise-grade performance and reliability.