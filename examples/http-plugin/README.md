# HTTP Plugin Example

This example demonstrates how to implement a plugin using HTTP transport with the go-plugins library.

## Overview

The example implements a text processing service that supports various text manipulation operations:
- **Uppercase/Lowercase**: Convert text case
- **Reverse**: Reverse text character order  
- **Word Count**: Count words, characters, and lines
- **Clean Whitespace**: Remove extra whitespace and trim
- **Extract Emails**: Find email addresses using regex
- **Capitalize**: Title case conversion
- Health checks and service information

## Architecture

The example consists of:
- **HTTP Server** (`server.go`): RESTful API implementing text processing operations
- **HTTP Client Plugin** (`client.go`): Wraps the HTTP client to implement the Plugin interface
- **Data Types** (`types.go`): Request/response structures
- **Main Application** (`main.go`): Demonstrates the plugin usage
- **Comprehensive Tests** (`main_test.go`): Full test suite with benchmarks

## Features Demonstrated

### 1. **HTTP RESTful API**
- JSON request/response handling
- Proper HTTP status codes and error responses
- CORS middleware for cross-origin requests
- Request logging and monitoring
- Graceful server shutdown

### 2. **Plugin Interface Compliance**
- Full implementation of the `Plugin[Req, Resp]` interface
- HTTP-based health checking with detailed status
- Plugin information retrieval via REST endpoint
- Proper timeout and context handling
- Connection management and cleanup

### 3. **Production Features**
- Structured logging with request correlation
- Concurrent request handling
- Proper error handling and validation
- HTTP middleware (logging, CORS)
- Configurable timeouts and connection pooling

### 4. **Text Processing Operations**
- Multiple string manipulation algorithms
- Regex-based pattern extraction
- Metadata reporting for operations
- Input validation and error handling

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
1. Start an HTTP server on `localhost:8080`
2. Create a plugin client
3. Demonstrate various text processing operations
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
- **Server Address**: `localhost:8080`
- **Transport**: HTTP (unencrypted for simplicity)
- **Timeout**: 30 seconds for requests
- **Health Check**: `/health` endpoint
- **Info Endpoint**: `/info`
- **Main Endpoint**: `/process`

For production usage, you would typically:
- Use HTTPS transport with proper TLS configuration
- Add authentication (API keys, JWT tokens, etc.)
- Implement rate limiting
- Add request/response compression
- Use reverse proxy (nginx, etc.)
- Add monitoring and metrics

## Example Output

```
2025/09/15 10:30:00 INFO Starting HTTP server address=localhost:8080
2025/09/15 10:30:00 INFO Creating HTTP plugin client...
2025/09/15 10:30:00 INFO Plugin Information name="Text Processor HTTP Plugin" version=1.0.0 description="HTTP-based text processing service running for 1s" capabilities="[uppercase lowercase reverse word_count clean_whitespace extract_emails capitalize]"
2025/09/15 10:30:00 INFO Plugin Health Check status=healthy message="Text processor is running normally" response_time=1.234ms metadata="map[endpoint:http://localhost:8080/health transport:HTTP uptime:1s]"
2025/09/15 10:30:00 INFO Executing text processing operation=uppercase text="Hello World! This is a test." request_id=demo-request-001
2025/09/15 10:30:00 INFO Text processing completed request_id=demo-request-001 operation=uppercase result="HELLO WORLD! THIS IS A TEST." metadata="map[original_length:27]" duration=2.567ms
```

## API Endpoints

### 1. **Process Text** - `POST /process`

Request format (following go-plugins HTTP standard):
```json
{
  "data": {
    "operation": "uppercase",
    "text": "hello world",
    "options": {}
  },
  "request_id": "req-123",
  "timeout": "30s",
  "headers": {},
  "metadata": {}
}
```

Response format:
```json
{
  "data": {
    "result": "HELLO WORLD",
    "metadata": {
      "original_length": "11"
    }
  },
  "request_id": "req-123",
  "metadata": {
    "processing_time": "1.2ms",
    "operation": "uppercase"
  }
}
```

### 2. **Health Check** - `GET /health`

```json
{
  "status": "healthy",
  "message": "Text processor is running normally",
  "checks": {
    "uptime": "5m30s",
    "version": "1.0.0",
    "timestamp": "2025-09-15T10:30:00Z"
  }
}
```

### 3. **Service Info** - `GET /info`

```json
{
  "name": "Text Processor HTTP Plugin",
  "version": "1.0.0",
  "description": "HTTP-based text processing service running for 5m30s",
  "capabilities": [
    "uppercase", "lowercase", "reverse", "word_count",
    "clean_whitespace", "extract_emails", "capitalize"
  ]
}
```

## Integration with go-plugins Library

### 1. **Use with Plugin Manager**

```go
manager := goplugins.NewManager[TextProcessingRequest, TextProcessingResponse](logger)

// Register the plugin
plugin, err := NewTextProcessorPlugin("http://localhost:8080", logger)
if err != nil {
    log.Fatal(err)
}

err = manager.Register(plugin)
if err != nil {
    log.Fatal(err)
}

// Use through manager
response, err := manager.Execute(ctx, "text-processor", request)
```

### 2. **Configure with PluginConfig**

```go
config := goplugins.PluginConfig{
    Name:      "text-processor",
    Transport: goplugins.TransportHTTPS,
    Endpoint:  "https://text-api.company.com/v1/process",
    Auth: goplugins.AuthConfig{
        Method: goplugins.AuthBearer,
        Token:  "jwt-token-here",
    },
    Connection: goplugins.ConnectionConfig{
        RequestTimeout:    30 * time.Second,
        ConnectionTimeout: 10 * time.Second,
        MaxConnections:    20,
    },
}

factory := goplugins.NewHTTPPluginFactory[TextProcessingRequest, TextProcessingResponse]()
plugin, err := factory.CreatePlugin(config)
```

## Testing Strategy

The test suite covers:

### **Unit Tests**
- Plugin creation and initialization
- All text processing operations
- Health checking
- Error conditions (unsupported operations, timeouts)
- Resource cleanup

### **Integration Tests**
- End-to-end HTTP communication
- Server lifecycle management
- Concurrent request handling
- Timeout and context handling

### **Benchmark Tests**
- Operation performance
- Health check performance
- Memory allocation patterns

### **Expected Performance**
- Text operations: < 5ms per call
- Health checks: < 2ms per call
- Concurrent operations: Linear scaling
- Memory: Minimal allocations per call

## Supported Operations

### **Text Transformation**
- `uppercase` - Convert to uppercase
- `lowercase` - Convert to lowercase  
- `capitalize` - Title case conversion
- `reverse` - Reverse character order
- `clean_whitespace` - Remove extra whitespace

### **Text Analysis**
- `word_count` - Count words, characters, lines
- `extract_emails` - Find email addresses

### **Operation Examples**

```bash
# Test with curl
curl -X POST http://localhost:8080/process \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "operation": "uppercase",
      "text": "hello world"
    },
    "request_id": "test-001"
  }'

# Expected response:
{
  "data": {
    "result": "HELLO WORLD",
    "metadata": {
      "original_length": "11"
    }
  },
  "request_id": "test-001"
}
```

## Production Considerations

### **Security**
- Use HTTPS in production
- Implement proper authentication (API keys, JWT)
- Add input validation and sanitization
- Rate limiting to prevent abuse
- Request size limits

### **Performance**
- Connection pooling
- Response compression (gzip)
- Caching for expensive operations
- Horizontal scaling with load balancer
- Database connection pooling

### **Reliability**
- Health check endpoints for load balancers
- Graceful shutdown handling
- Request timeout configuration
- Circuit breaker patterns
- Retry logic with exponential backoff

### **Observability**
- Structured logging with correlation IDs
- Metrics collection (Prometheus)
- Distributed tracing (OpenTelemetry)
- Error tracking and alerting
- Performance monitoring

## Error Handling

The service handles various error conditions:

### **Client Errors (4xx)**
- `400 Bad Request` - Invalid JSON or missing fields
- `404 Not Found` - Unknown endpoints
- `405 Method Not Allowed` - Wrong HTTP method

### **Server Errors (5xx)**
- `500 Internal Server Error` - Processing failures

### **Plugin Errors**
- Unsupported operations return descriptive errors
- Timeout handling with context cancellation
- Connection failures mapped to appropriate statuses

## Troubleshooting

### **Common Issues**

1. **Connection Refused**
   - Ensure HTTP server is running on correct port
   - Check firewall rules and network connectivity
   - Verify server startup logs

2. **Request Timeouts**
   - Check network latency
   - Adjust timeout configurations
   - Monitor server resource usage

3. **JSON Parsing Errors**
   - Validate request format matches expected schema
   - Check Content-Type headers
   - Ensure proper JSON encoding

4. **Performance Issues**
   - Monitor concurrent connections
   - Check for memory leaks
   - Profile request processing time
   - Consider connection pooling optimization