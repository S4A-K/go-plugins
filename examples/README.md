# Plugin Examples

This directory contains comprehensive, self-contained examples demonstrating different plugin types and features supported by the go-plugins library.

## Examples

### 1. gRPC Plugin (`grpc-plugin/`)
Demonstrates how to implement a plugin using gRPC transport with:
- Protocol buffer definitions
- Server and client implementations
- Health checks and observability
- Circuit breaker integration
- Comprehensive test suite

### 2. HTTP Plugin (`http-plugin/`)
Shows implementation of an HTTP-based plugin with:
- RESTful API endpoints
- JSON request/response handling
- Middleware integration
- Load balancing capabilities
- Complete testing framework

### 3. Unix Socket Plugin (`unix-socket-plugin/`)
Illustrates Unix domain socket communication with:
- Local socket file management
- Binary protocol implementation
- Low-latency communication patterns
- Error handling and recovery
- Performance benchmarks

### 4. Hot Reload Plugin (`hot-reload-plugin/`)
Demonstrates dynamic plugin reloading with Argus-powered file watching:
- **Argus Integration**: Ultra-fast file monitoring (12.10ns/op)
- **Dynamic Configuration**: Hot reload plugins without application restart
- **Counter Plugin**: Simple plugin demonstrating increment, reset, and arithmetic operations  
- **HTTP API**: REST endpoints to test plugin functionality
- **Graceful Updates**: Seamless plugin reloading with zero downtime
- **Configuration Management**: JSON-based configuration with validation

## Running Examples

Each example is self-contained with its own:
- `go.mod` file for dependency management
- `main.go` entry point
- Complete test suite with benchmarks
- README with specific instructions

To run any example:

```bash
cd <example-directory>
go mod tidy
go run main.go
```

To run tests:

```bash
cd <example-directory>
go test -v -race -cover ./...
```

## Requirements

- Go 1.21+
- Access to the parent go-plugins library
- Platform-specific requirements mentioned in individual example READMEs

## Quality Standards

All examples follow:
- 100% test coverage for critical paths
- Race condition detection
- Memory leak prevention
- Comprehensive error handling
- Performance benchmarking
- Documentation standards