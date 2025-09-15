# gRPC Plugin Example

This example demonstrates how to implement a plugin using gRPC transport with the go-plugins library.

## Overview

The example implements a simple calculator service that supports:
- Addition (`add`)
- Multiplication (`multiply`)  
- Division (`divide`) with proper error handling for division by zero
- Health checks
- Service information retrieval

## Architecture

The example consists of:
- **Protocol Buffers Definition** (`proto/calculator.proto`): Defines the gRPC service interface
- **gRPC Server** (`server.go`): Implements the calculator service
- **gRPC Client Plugin** (`client.go`): Wraps the gRPC client to implement the Plugin interface
- **Data Types** (`types.go`): Request/response structures
- **Main Application** (`main.go`): Demonstrates the plugin usage
- **Comprehensive Tests** (`main_test.go`): Full test suite with benchmarks

## Features Demonstrated

### 1. **gRPC Service Implementation**
- Protocol buffer definitions for type safety
- Server implementation with proper error handling
- Service registration and lifecycle management

### 2. **Plugin Interface Compliance**
- Full implementation of the `Plugin[Req, Resp]` interface
- Proper health checking with gRPC health protocol
- Plugin information retrieval from remote service
- Graceful connection management

### 3. **Error Handling**
- gRPC status code mapping to plugin errors
- Division by zero handling
- Timeout and cancellation support
- Connection failure recovery

### 4. **Production Features**
- Structured logging with slog
- Concurrent operation support
- Proper resource cleanup
- Signal handling for graceful shutdown

## Quick Start

### 1. Install Dependencies

```bash
go mod tidy
```

### 2. Run the Example

```bash
go run .
```

The example will:
1. Start a gRPC server on `localhost:50051`
2. Create a plugin client
3. Demonstrate various operations
4. Show health monitoring
5. Perform concurrent operations
6. Gracefully shutdown on SIGINT/SIGTERM

### 3. Run Tests

```bash
# Run all tests
go test -v

# Run tests with race detection
go test -v -race

# Run with coverage
go test -v -cover

# Run benchmarks
go test -v -bench=.
```

## Configuration

The example uses these default settings:
- **Server Address**: `localhost:50051`
- **Transport**: Insecure gRPC (for simplicity)
- **Timeout**: 10 seconds for operations
- **Health Check**: 5 seconds timeout

For production usage, you would typically:
- Use TLS transport (`TransportGRPCTLS`)
- Configure mTLS authentication
- Add proper certificate management
- Use service discovery
- Add monitoring and metrics

## Example Output

```
2025/09/15 10:30:00 INFO Starting gRPC server address=localhost:50051
2025/09/15 10:30:00 INFO Creating gRPC plugin client...
2025/09/15 10:30:00 INFO Plugin Information name="Calculator gRPC Plugin" version=1.0.0 description="A simple calculator service running for 1s" capabilities="[add multiply divide health_check]"
2025/09/15 10:30:00 INFO Plugin Health Check status=healthy message="Calculator service is healthy" response_time=1.234ms
2025/09/15 10:30:00 INFO Executing calculation operation=add a=10 b=5 request_id=demo-request-001
2025/09/15 10:30:00 INFO Calculation completed request_id=demo-request-001 result=15 duration=2.567ms
```

## Integration with go-plugins Library

This example shows how to:

### 1. **Use with Plugin Manager**

```go
manager := goplugins.NewManager[CalculationRequest, CalculationResponse](logger)

// Register the plugin
plugin, err := NewCalculatorPlugin("localhost:50051", logger)
if err != nil {
    log.Fatal(err)
}

err = manager.Register(plugin)
if err != nil {
    log.Fatal(err)
}

// Use through manager
response, err := manager.Execute(ctx, "calculator-grpc", request)
```

### 2. **Configure with PluginConfig**

```go
config := goplugins.PluginConfig{
    Name:      "calculator",
    Transport: goplugins.TransportGRPC,
    Endpoint:  "calculator.company.com:443",
    Auth: goplugins.AuthConfig{
        Method:   goplugins.AuthMTLS,
        CertFile: "/etc/ssl/client.crt",
        KeyFile:  "/etc/ssl/client.key",
        CAFile:   "/etc/ssl/ca.crt",
    },
}

factory := goplugins.NewGRPCPluginFactory[CalculationRequest, CalculationResponse](logger)
plugin, err := factory.CreatePlugin(config)
```

## Testing Strategy

The test suite covers:

### **Unit Tests**
- Plugin creation and initialization
- All operation types (add, multiply, divide)
- Error conditions (division by zero, unsupported operations)
- Health checking
- Resource cleanup

### **Integration Tests**  
- End-to-end gRPC communication
- Timeout handling
- Concurrent operations
- Server lifecycle management

### **Benchmark Tests**
- Operation performance
- Health check performance
- Memory allocation patterns

### **Expected Performance**
- Operations: < 5ms per call
- Health checks: < 2ms per call  
- Concurrent operations: Linear scaling
- Memory: Minimal allocations per call

## Production Considerations

### **Security**
- Use TLS transport in production
- Implement proper certificate validation
- Add authentication and authorization
- Consider network policies and firewall rules

### **Reliability**
- Add circuit breaker patterns
- Implement retry with exponential backoff
- Add connection pooling
- Monitor connection health

### **Observability**
- Add distributed tracing (OpenTelemetry)
- Implement comprehensive metrics
- Add structured logging
- Monitor resource usage

### **Scalability**
- Use connection pooling
- Implement load balancing
- Add horizontal scaling support
- Consider message compression

## Protocol Buffer Schema

The example uses a simple calculator schema:

```protobuf
service CalculatorService {
  rpc Add(AddRequest) returns (AddResponse);
  rpc Multiply(MultiplyRequest) returns (MultiplyResponse);
  rpc Divide(DivideRequest) returns (DivideResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Info(InfoRequest) returns (InfoResponse);
}
```

This provides type safety, efficient serialization, and cross-language compatibility.

## Troubleshooting

### **Common Issues**

1. **Connection Refused**
   - Ensure gRPC server is running
   - Check firewall and network connectivity
   - Verify correct address and port

2. **Proto Compilation Errors**
   - Install protoc compiler: `sudo apt install protobuf-compiler`
   - Install Go plugins: `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`
   - Add to PATH: `export PATH=$PATH:$(go env GOPATH)/bin`

3. **TLS Errors**
   - Check certificate validity
   - Verify CA certificate chain
   - Ensure proper mTLS configuration

4. **Performance Issues**
   - Monitor connection pooling
   - Check network latency
   - Profile gRPC call overhead
   - Consider message compression