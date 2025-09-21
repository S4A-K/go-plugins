---
title: Advanced Components
description: Advanced components and utility functions for specialized use cases
weight: 80
---

# Advanced Components Guide

This guide covers the advanced components and utility functions available in go-plugins for specialized use cases and custom implementations.

## Table of Contents

- [Configuration Management](#configuration-management)
- [Health Monitoring Components](#health-monitoring-components)
- [Circuit Breaker Components](#circuit-breaker-components)
- [Request Tracking](#request-tracking)
- [Communication Components](#communication-components)
- [Environment Configuration](#environment-configuration)
- [Logging Utilities](#logging-utilities)
- [gRPC Components](#grpc-components)
- [Utility Functions](#utility-functions)

## Configuration Management

### Dynamic Configuration with Hot-Reload

```go
// Enable dynamic configuration powered by Argus
options := goplugins.DefaultDynamicConfigOptions()
watcher, err := goplugins.EnableDynamicConfig(manager, "config.json", options, logger)
if err != nil {
    log.Fatal("Failed to enable dynamic config:", err)
}
defer watcher.Stop()

// Configuration will be hot-reloaded automatically
```

### Configuration Loading

```go
// Load configuration from file
config, err := goplugins.LoadConfigFromFile("plugins.yaml")
if err != nil {
    log.Fatal("Failed to load config:", err)
}

// Create sample configuration file
err = goplugins.CreateSampleConfig("sample-config.json")
if err != nil {
    log.Fatal("Failed to create sample config:", err)
}
```

### Configuration Watcher

```go
// Create custom configuration watcher
options := goplugins.DynamicConfigOptions{
    PollInterval: 5 * time.Second,
    CacheTTL:     2 * time.Second,
    EnableCache:  true,
    MaxRetries:   3,
}

watcher, err := goplugins.NewConfigWatcher(manager, "config.json", options, logger)
if err != nil {
    log.Fatal("Failed to create config watcher:", err)
}

// Start watching
err = watcher.Start()
if err != nil {
    log.Fatal("Failed to start config watcher:", err)
}
```

## Health Monitoring Components

### Health Checker

Create custom health checkers for individual plugins:

```go
// Create health checker for a plugin
healthConfig := goplugins.HealthCheckConfig{
    Enabled:      true,
    Interval:     30 * time.Second,
    Timeout:      5 * time.Second,
    FailureLimit: 3,
}

healthChecker := goplugins.NewHealthChecker(plugin, healthConfig)

// Start health monitoring
err := healthChecker.Start()
if err != nil {
    log.Fatal("Failed to start health checker:", err)
}

// Get current health status
status := healthChecker.GetStatus()
fmt.Printf("Plugin health: %s - %s\n", status.Status.String(), status.Message)
```

### Health Monitor

Manage multiple health checkers:

```go
// Create health monitor
monitor := goplugins.NewHealthMonitor()

// Add plugins to monitor
err := monitor.AddPlugin("auth-service", authPlugin, healthConfig)
if err != nil {
    log.Printf("Failed to add plugin to monitor: %v", err)
}

err = monitor.AddPlugin("payment-service", paymentPlugin, healthConfig)
if err != nil {
    log.Printf("Failed to add plugin to monitor: %v", err)
}

// Start monitoring all plugins
err = monitor.StartAll()
if err != nil {
    log.Fatal("Failed to start health monitoring:", err)
}

// Get overall health status
allHealth := monitor.GetAllStatus()
for pluginName, status := range allHealth {
    fmt.Printf("%s: %s\n", pluginName, status.Status.String())
}
```

## Circuit Breaker Components

### Custom Circuit Breaker

```go
// Create circuit breaker with custom configuration
cbConfig := goplugins.CircuitBreakerConfig{
    Enabled:             true,
    FailureThreshold:    5,
    RecoveryTimeout:     30 * time.Second,
    MinRequestThreshold: 10,
    SuccessThreshold:    3,
}

circuitBreaker := goplugins.NewCircuitBreaker(cbConfig)

// Use circuit breaker
if circuitBreaker.AllowRequest() {
    // Execute operation
    err := performOperation()
    
    if err != nil {
        circuitBreaker.RecordFailure()
    } else {
        circuitBreaker.RecordSuccess()
    }
} else {
    // Circuit breaker is open, fail fast
    return fmt.Errorf("circuit breaker is open")
}
```

### Circuit Breaker States

```go
// Monitor circuit breaker state
state := circuitBreaker.GetState()
switch state {
case goplugins.StateClosed:
    fmt.Println("Circuit breaker is closed (normal operation)")
case goplugins.StateOpen:
    fmt.Println("Circuit breaker is open (failing fast)")
case goplugins.StateHalfOpen:
    fmt.Println("Circuit breaker is half-open (testing recovery)")
}

// Get detailed statistics
stats := circuitBreaker.GetStats()
fmt.Printf("Failure count: %d\n", stats.FailureCount)
fmt.Printf("Success count: %d\n", stats.SuccessCount)
fmt.Printf("Last failure: %v\n", stats.LastFailure)
```

## Request Tracking

### Basic Request Tracking

```go
// Create request tracker
tracker := goplugins.NewRequestTracker()

// Track requests
tracker.StartRequest("plugin-name", ctx)
defer tracker.EndRequest("plugin-name", ctx)

// Get active request count
activeCount := tracker.GetActiveRequestCount("plugin-name")
fmt.Printf("Active requests: %d\n", activeCount)
```

### Request Tracking with Observability

```go
// Create request tracker with metrics
metricsCollector := &MyMetricsCollector{} // Implement MetricsCollector interface
tracker := goplugins.NewRequestTrackerWithObservability(metricsCollector, "myapp")

// Track requests with automatic metrics
tracker.StartRequest("plugin-name", ctx)
defer tracker.EndRequest("plugin-name", ctx)

// Metrics are automatically recorded
```

### Graceful Draining

```go
// Drain requests gracefully
drainOptions := goplugins.DrainOptions{
    DrainTimeout:            30 * time.Second,
    ForceTimeout:            60 * time.Second,
    CheckInterval:           100 * time.Millisecond,
    ProgressCallback:        func(remaining int) {
        fmt.Printf("Draining... %d requests remaining\n", remaining)
    },
}

err := tracker.DrainPlugin("plugin-name", drainOptions)
if err != nil {
    log.Printf("Drain completed with warnings: %v", err)
}
```

## Communication Components

### Communication Bridge

For custom plugin communication:

```go
// Create communication bridge
bridgeConfig := goplugins.BridgeConfig{
    ListenAddress:   "127.0.0.1",
    ListenPort:      0, // Auto-assign
    Protocol:        "tcp",
    ReadTimeout:     30 * time.Second,
    WriteTimeout:    30 * time.Second,
    MaxConnections:  100,
}

bridge := goplugins.NewCommunicationBridge(bridgeConfig, logger)

// Start bridge
err := bridge.Start()
if err != nil {
    log.Fatal("Failed to start communication bridge:", err)
}

// Get bridge information
address := bridge.GetAddress()
port := bridge.GetPort()
fmt.Printf("Bridge listening on %s:%d\n", address, port)
```

### Handshake Management

```go
// Create handshake manager
handshakeConfig := goplugins.HandshakeConfig{
    ProtocolVersion:  1,
    MagicCookieKey:   "MY_PLUGIN",
    MagicCookieValue: "my-plugin-v1",
}

handshakeManager := goplugins.NewHandshakeManager(handshakeConfig, logger)

// Perform handshake
err := handshakeManager.PerformHandshake(conn)
if err != nil {
    log.Printf("Handshake failed: %v", err)
}
```

## Environment Configuration

### Environment Variable Processing

```go
// Get default environment options
envOptions := goplugins.DefaultEnvConfigOptions()

// Expand environment variables in configuration
expanded, err := goplugins.ExpandEnvironmentVariables("${HOME}/plugins", envOptions)
if err != nil {
    log.Fatal("Failed to expand environment variables:", err)
}

// Process configuration with environment overrides
config := &MyConfig{}
err = goplugins.ProcessConfigurationWithEnv(config, envOptions)
if err != nil {
    log.Fatal("Failed to process environment config:", err)
}
```

### Environment Utilities

```go
// Use standard Go environment variable handling
dbURL := os.Getenv("DATABASE_URL")
if dbURL == "" {
    dbURL = "postgres://localhost/mydb"
}

// For more advanced environment handling, use the Argus library
// which provides GetEnvWithDefault and other utilities
```

## Logging Utilities

### Logger Creation and Management

```go
// Create different types of loggers
noOpLogger := goplugins.NewNoOpLogger()        // Silent logger
testLogger := goplugins.NewTestLogger()        // For testing
defaultLogger := goplugins.DefaultLogger()     // Default logger
discardLogger := goplugins.DiscardLogger()     // Discard all output

// Adapt any logger type
adaptedLogger := goplugins.NewLogger(mySlogLogger)

// Use logger with context
ctx = goplugins.ContextWithLogger(ctx, logger)
contextLogger := goplugins.LoggerFromContext(ctx)
```

### Test Logger

```go
// Use test logger for unit tests
testLogger := goplugins.NewTestLogger()

// Create plugin with test logger
plugin := &MyPlugin{logger: testLogger}

// Execute plugin
response, err := plugin.Execute(ctx, execCtx, request)

// Verify log messages
messages := testLogger.GetMessages()
assert.Contains(t, messages[0].Message, "Processing request")
assert.Equal(t, "info", messages[0].Level)
```

## gRPC Components

### gRPC Plugin Factory

```go
// Create gRPC plugin factory for protobuf messages
factory := goplugins.NewGRPCPluginFactory[MyProtoRequest, MyProtoResponse](logger)

// Register with manager
err := manager.RegisterFactory("grpc", factory)
if err != nil {
    log.Fatal("Failed to register gRPC factory:", err)
}
```

### gRPC Native Plugin

```go
// Create native gRPC plugin
config := goplugins.PluginConfig{
    Name:      "grpc-service",
    Transport: goplugins.TransportGRPC,
    Endpoint:  "localhost:9090",
}

plugin, err := goplugins.NewGRPCNativePlugin[MyProtoRequest, MyProtoResponse](config, logger)
if err != nil {
    log.Fatal("Failed to create gRPC plugin:", err)
}

// Register with manager
err = manager.Register(plugin)
```

### gRPC Registration Helpers

```go
// Register gRPC plugin directly
err := goplugins.RegisterGRPCNativePlugin(manager, config, logger)
if err != nil {
    log.Fatal("Failed to register gRPC plugin:", err)
}

// Register gRPC factory
err = goplugins.RegisterGRPCNativeFactory(manager, "grpc", logger)
if err != nil {
    log.Fatal("Failed to register gRPC factory:", err)
}
```

## Utility Functions

### Stream Synchronization

```go
// Create stream syncer for subprocess communication
syncConfig := goplugins.StreamSyncConfig{
    SyncStdout:      true,
    SyncStderr:      true,
    LogPrefix:       "[plugin]",
    BufferSize:      4096,
    FlushInterval:   100 * time.Millisecond,
}

syncer := goplugins.NewStreamSyncer(syncConfig, logger)

// Sync process streams
err := syncer.SyncProcess(process)
if err != nil {
    log.Printf("Stream sync failed: %v", err)
}
```

### Shutdown Coordination

```go
// Create shutdown coordinator for plugin registry
registry := goplugins.NewPluginRegistry(registryConfig)
coordinator := goplugins.NewShutdownCoordinator(registry)

// Perform coordinated shutdown
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

err := coordinator.Shutdown(ctx)
if err != nil {
    log.Printf("Shutdown completed with warnings: %v", err)
}
```

### Secure ID Generation

```go
// Generate secure IDs for sessions or requests
sessionID, err := goplugins.GenerateSecureID()
if err != nil {
    log.Fatal("Failed to generate secure ID:", err)
}

fmt.Printf("Session ID: %s\n", sessionID)
```

## Plugin Registry

For advanced plugin management scenarios:

```go
// Create plugin registry
registryConfig := goplugins.RegistryConfig{
    DiscoveryPaths:    []string{"./plugins", "/opt/plugins"},
    AutoDiscovery:     true,
    DiscoveryInterval: 30 * time.Second,
    MaxPlugins:        100,
    HealthCheckConfig: goplugins.HealthCheckConfig{
        Enabled:  true,
        Interval: 30 * time.Second,
        Timeout:  5 * time.Second,
    },
}

registry := goplugins.NewPluginRegistry(registryConfig)

// Start registry
err := registry.Start()
if err != nil {
    log.Fatal("Failed to start registry:", err)
}

// Get registry statistics
stats := registry.GetStats()
fmt.Printf("Total plugins: %d\n", stats.TotalClients)
fmt.Printf("Healthy plugins: %d\n", stats.HealthyClients)
```

## Best Practices

### 1. Use Appropriate Components for Your Use Case

```go
// For simple scenarios - use Manager
manager := goplugins.NewManager[Req, Resp](logger)

// For advanced plugin management - use PluginRegistry
registry := goplugins.NewPluginRegistry(config)

// For custom communication - use CommunicationBridge
bridge := goplugins.NewCommunicationBridge(bridgeConfig, logger)
```

### 2. Implement Proper Error Handling

```go
// Check for specific error types
if goplugins.IsHandshakeTimeoutError(err) {
    log.Printf("Handshake timeout - plugin may be slow to start")
    // Implement retry or fallback logic
}

// Use structured errors
if protocolErr, ok := err.(*goplugins.ProtocolError); ok {
    log.Printf("Protocol error - expected: %v, actual: %v", 
        protocolErr.Expected, protocolErr.Actual)
}
```

### 3. Monitor Component Health

```go
// Monitor all components
components := []string{"manager", "registry", "discovery", "security"}

for _, component := range components {
    health := getComponentHealth(component)
    if health.Status != goplugins.StatusHealthy {
        log.Printf("Component %s unhealthy: %s", component, health.Message)
    }
}
```

### 4. Use Environment Configuration

```go
// Load configuration from environment
envOptions := goplugins.DefaultEnvConfigOptions()
envOptions.Prefix = "MYAPP_"
envOptions.FailOnMissing = true

err := goplugins.ProcessConfigurationWithEnv(&config, envOptions)
if err != nil {
    log.Fatal("Environment configuration failed:", err)
}
```

## Custom Implementations

### Custom MetricsCollector

```go
type CustomMetricsCollector struct {
    metrics map[string]interface{}
    mu      sync.RWMutex
}

func (c *CustomMetricsCollector) IncrementCounter(name string, labels map[string]string, value int64) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    key := c.buildMetricKey(name, labels)
    if current, exists := c.metrics[key]; exists {
        c.metrics[key] = current.(int64) + value
    } else {
        c.metrics[key] = value
    }
}

func (c *CustomMetricsCollector) SetGauge(name string, labels map[string]string, value float64) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    key := c.buildMetricKey(name, labels)
    c.metrics[key] = value
}

func (c *CustomMetricsCollector) GetMetrics() map[string]interface{} {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    result := make(map[string]interface{})
    for k, v := range c.metrics {
        result[k] = v
    }
    return result
}

// Register custom metrics collector
manager.SetMetricsCollector(customCollector)
```

### Custom Logger Implementation

```go
type CustomLogger struct {
    output io.Writer
    level  string
}

func (l *CustomLogger) Debug(msg string, args ...any) {
    if l.level == "debug" {
        l.log("DEBUG", msg, args...)
    }
}

func (l *CustomLogger) Info(msg string, args ...any) {
    l.log("INFO", msg, args...)
}

func (l *CustomLogger) Warn(msg string, args ...any) {
    l.log("WARN", msg, args...)
}

func (l *CustomLogger) Error(msg string, args ...any) {
    l.log("ERROR", msg, args...)
}

func (l *CustomLogger) With(args ...any) goplugins.Logger {
    // Create new logger with additional context
    return &CustomLogger{
        output: l.output,
        level:  l.level,
    }
}

// Use custom logger
customLogger := &CustomLogger{
    output: os.Stdout,
    level:  "info",
}

manager := goplugins.NewManager[Req, Resp](customLogger)
```

## Troubleshooting

### Component Diagnostics

```go
// Diagnose component issues
func diagnoseComponents(manager *goplugins.Manager) {
    // Check manager status
    if manager.IsShutdown() {
        log.Println("Manager is shut down")
        return
    }
    
    // Check plugin registry
    plugins := manager.ListPlugins()
    log.Printf("Registered plugins: %d", len(plugins))
    
    // Check health checkers
    health := manager.Health()
    for name, status := range health {
        log.Printf("Plugin %s: %s", name, status.Status.String())
    }
    
    // Check circuit breakers
    cbStatus := manager.GetCircuitBreakerStatus()
    for name, status := range cbStatus {
        log.Printf("Circuit breaker %s: %s", name, status.State)
    }
}
```

### Performance Monitoring

```go
// Monitor component performance
func monitorPerformance(manager *goplugins.Manager) {
    metrics := manager.GetMetrics()
    
    log.Printf("Performance Metrics:")
    log.Printf("  Total requests: %d", metrics.RequestsTotal.Load())
    log.Printf("  Success rate: %.2f%%", 
        float64(metrics.RequestsSuccess.Load())/float64(metrics.RequestsTotal.Load())*100)
    log.Printf("  Avg duration: %v", 
        time.Duration(metrics.RequestDuration.Load()/metrics.RequestsTotal.Load()))
}
```

## Next Steps

- Explore [Plugin Development Examples](/examples/) for complete implementations
- Learn about [Security System](/guides/security/) for securing custom components
- Check out [Production Deployment](/guides/production/) for deploying custom components

{{% alert title="Advanced Usage Note" %}}
These advanced components are for specialized use cases. For most applications, the standard Manager and Simple API provide all necessary functionality.
{{% /alert %}}

{{% alert title="Performance Note" %}}
When using multiple advanced components, monitor resource usage and performance impact. Some components like health checkers and request trackers run background tasks.
{{% /alert %}}
