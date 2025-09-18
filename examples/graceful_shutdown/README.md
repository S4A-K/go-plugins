# Graceful Shutdown Integration Example

This example demonstrates how to implement graceful shutdown patterns with the go-plugins library.

## Features Demonstrated

- **Plugin Registry Management**: Creating and managing a plugin registry with proper lifecycle
- **Signal Handling**: Intercepting OS signals (SIGINT, SIGTERM) for graceful shutdown
- **Context Cancellation**: Using Go contexts to coordinate shutdown across goroutines
- **Resource Cleanup**: Proper cleanup of plugin registry resources
- **Work Completion**: Allowing ongoing work to complete gracefully before shutdown

## Running the Example

```bash
# Build the example
go build

# Run the example
./graceful_shutdown_example

# Press Ctrl+C to trigger graceful shutdown
```

## Code Structure

- `main()`: Entry point that coordinates the example execution
- `gracefulShutdownExample()`: Main logic demonstrating graceful shutdown patterns
- `simulateWork()`: Simulates ongoing work that respects context cancellation

## Key Concepts

### Signal Handling
The example sets up signal handlers for common termination signals:
```go
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
```

### Context Cancellation
Uses Go contexts to coordinate shutdown:
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
```

### Graceful Work Completion
Allows ongoing work to finish gracefully or times out:
```go
select {
case <-workDone:
    fmt.Println("Work completed gracefully")
case <-time.After(10 * time.Second):
    fmt.Println("Work timed out, forcing shutdown")
}
```

## Production Usage

In production applications, you would typically:

1. **Register actual plugins** instead of just starting an empty registry
2. **Implement proper work queues** with context-aware processing
3. **Add monitoring and metrics** to track shutdown progress
4. **Configure timeouts** based on your application's requirements
5. **Add persistence** to save state before shutdown

## Related Examples

- See `../security_demo/` for security integration examples
- See the main library documentation for advanced plugin management patterns