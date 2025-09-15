# Unix Socket Plugin Example

This example demonstrates how to create and use a plugin with Unix Socket transport using the go-plugins library. The plugin implements a file manager service that provides file system operations over Unix domain sockets.

## Features

- **Unix Domain Socket Communication**: High-performance inter-process communication
- **File System Operations**: Complete file management functionality
- **Structured JSON Protocol**: Type-safe communication over sockets
- **Production-Ready Logging**: Comprehensive structured logging with slog
- **Health Monitoring**: Built-in health checks and monitoring
- **Error Handling**: Robust error handling with detailed error responses
- **Concurrent Operations**: Support for multiple simultaneous operations
- **Security**: Local socket with proper permission controls

## File Manager Operations

The plugin provides the following file system operations:

- **list**: List files and directories in a given path
- **read**: Read the contents of a file
- **write**: Write content to a file
- **create_dir**: Create a new directory
- **delete**: Delete a file or directory
- **move**: Move/rename files and directories
- **copy**: Copy files
- **stat**: Get file/directory information
- **exists**: Check if a file or directory exists

## Installation

1. Navigate to the unix-socket-plugin directory:
```bash
cd examples/unix-socket-plugin
```

2. Install dependencies:
```bash
go mod tidy
```

## Usage

### Running the Example

Start both server and client:
```bash
go run .
```

### Running Server Only

```bash
go run . server
```

### Running Client Only

```bash
go run . client
```

### Running Tests

```bash
# Run all tests
go test -v

# Run tests with coverage
go test -v -cover

# Run tests with race detection
go test -v -race

# Run benchmarks
go test -v -bench=.
```

## Architecture

The example consists of:

- **server.go**: Unix socket server implementing the file manager service
- **client.go**: Unix socket client plugin wrapper
- **main.go**: Example application demonstrating usage
- **protocol.go**: JSON protocol definitions for socket communication
- **server_test.go**: Comprehensive test suite for server functionality
- **client_test.go**: Test suite for client functionality
- **integration_test.go**: End-to-end integration tests

## Socket Protocol

The plugin uses a JSON-based protocol over Unix domain sockets:

```json
{
  "id": "request-123",
  "operation": "read",
  "params": {
    "path": "/path/to/file"
  }
}
```

Response:
```json
{
  "id": "request-123",
  "success": true,
  "result": "file content",
  "error": null,
  "metadata": {
    "file_size": 1024,
    "operation_time": "2ms"
  }
}
```

## Performance

The Unix socket transport provides excellent performance characteristics:

- **Low Latency**: Direct kernel-level communication
- **High Throughput**: Efficient binary protocol
- **Memory Efficient**: No network protocol overhead
- **Local Only**: Secure local inter-process communication

## Security

- **Local Access Only**: Unix sockets are accessible only locally
- **Permission Control**: Socket file permissions control access
- **No Network Exposure**: Completely isolated from network access
- **Process-Level Security**: Operating system process isolation

## Examples

See the main.go file for comprehensive usage examples including:

- Basic file operations
- Directory management
- Error handling
- Concurrent operations
- Health monitoring
- Performance benchmarking