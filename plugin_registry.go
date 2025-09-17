// plugin_registry.go: Host-side plugin registry and client management system
//
// This file implements the host-side plugin registry that manages plugin clients,
// discovery, loading, and lifecycle. It provides standard plugin
// client architecture while using generic terminology and integrating with
// the existing go-plugins infrastructure.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PluginRegistry manages plugin clients on the host side.
//
// This is the host-side counterpart to the plugin serve interface. It handles
// plugin discovery, client creation, lifecycle management, and provides a
// unified interface for interacting with subprocess-based plugins.
//
// Key responsibilities:
//   - Plugin discovery and registration
//   - Client lifecycle management (start/stop/restart)
//   - Health monitoring and automatic recovery
//   - Request routing to appropriate plugin instances
//   - Integration with existing Manager and Discovery systems
type PluginRegistry struct {
	// Configuration
	config RegistryConfig
	logger Logger

	// Plugin management
	clients      map[string]*PluginClient
	factories    map[string]PluginFactory[any, any]
	clientMutex  sync.RWMutex
	factoryMutex sync.RWMutex

	// Discovery integration
	discoveryEngine *DiscoveryEngine

	// Request tracking for graceful draining
	requestTracker *RequestTracker

	// Observability integration
	observabilityConfig ObservabilityConfig
	metricsCollector    MetricsCollector
	commonMetrics       *CommonPluginMetrics
	tracingProvider     TracingProvider

	// Lifecycle
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool
	runMutex sync.Mutex
	draining bool
}

// RegistryConfig configures the plugin registry behavior.
type RegistryConfig struct {
	// Plugin discovery settings
	DiscoveryPaths    []string      `json:"discovery_paths" yaml:"discovery_paths"`
	AutoDiscovery     bool          `json:"auto_discovery" yaml:"auto_discovery"`
	DiscoveryInterval time.Duration `json:"discovery_interval" yaml:"discovery_interval"`

	// Client management
	MaxClients        int               `json:"max_clients" yaml:"max_clients"`
	ClientTimeout     time.Duration     `json:"client_timeout" yaml:"client_timeout"`
	HealthCheckConfig HealthCheckConfig `json:"health_check" yaml:"health_check"`

	// Subprocess settings
	HandshakeConfig HandshakeConfig `json:"handshake" yaml:"handshake"`

	// Plugin type mappings
	TypeMappings map[string]string `json:"type_mappings" yaml:"type_mappings"`

	// Graceful draining configuration
	DrainOptions DrainOptions `json:"drain_options" yaml:"drain_options"`

	// Logging
	Logger Logger `json:"-" yaml:"-"`
}

// PluginClient manages a single plugin instance on the host side.
//
// Each PluginClient represents a connection to a subprocess plugin instance.
// It handles the communication, health checking, and provides a unified
// interface for making requests to the plugin.
type PluginClient struct {
	// Identity
	ID   string
	Name string
	Type string

	// Configuration
	config     PluginConfig
	executable string
	args       []string

	// Communication
	bridge     *CommunicationBridge
	subprocess *SubprocessPlugin[any, any]

	// State management
	status    PluginStatus
	startTime time.Time
	lastPing  time.Time
	mutex     sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	logger Logger

	// Health monitoring
	healthChecker *HealthChecker
}

// ClientStats provides statistics about a plugin client.
type ClientStats struct {
	Status       PluginStatus  `json:"status"`
	StartTime    time.Time     `json:"start_time"`
	LastPing     time.Time     `json:"last_ping"`
	Uptime       time.Duration `json:"uptime"`
	RequestCount int64         `json:"request_count"`
	ErrorCount   int64         `json:"error_count"`
	LastError    string        `json:"last_error,omitempty"`
}

// RegistryStats provides overall registry statistics.
type RegistryStats struct {
	TotalClients    int                    `json:"total_clients"`
	ActiveClients   int                    `json:"active_clients"`
	HealthyClients  int                    `json:"healthy_clients"`
	ClientsByType   map[string]int         `json:"clients_by_type"`
	ClientsByStatus map[PluginStatus]int   `json:"clients_by_status"`
	ClientStats     map[string]ClientStats `json:"client_stats"`
}

// NewPluginRegistry creates a new plugin registry.
func NewPluginRegistry(config RegistryConfig) *PluginRegistry {
	if config.Logger == nil {
		config.Logger = DefaultLogger()
	}

	if config.MaxClients == 0 {
		config.MaxClients = 100
	}

	if config.ClientTimeout == 0 {
		config.ClientTimeout = 30 * time.Second
	}

	if config.DiscoveryInterval == 0 {
		config.DiscoveryInterval = 60 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Set default drain options if not provided
	if config.DrainOptions.DrainTimeout == 0 {
		config.DrainOptions.DrainTimeout = 30 * time.Second
	}

	// Initialize observability with default configuration
	observabilityConfig := DefaultObservabilityConfig()
	metricsCollector := observabilityConfig.MetricsCollector

	// Create common metrics if advanced features are supported
	var commonMetrics *CommonPluginMetrics
	if metricsCollector.CounterWithLabels("test", "test") != nil {
		commonMetrics = CreateCommonPluginMetrics(metricsCollector)
	}

	return &PluginRegistry{
		config:              config,
		logger:              config.Logger,
		clients:             make(map[string]*PluginClient),
		factories:           make(map[string]PluginFactory[any, any]),
		requestTracker:      NewRequestTrackerWithObservability(metricsCollector, observabilityConfig.MetricsPrefix),
		observabilityConfig: observabilityConfig,
		metricsCollector:    metricsCollector,
		commonMetrics:       commonMetrics,
		tracingProvider:     observabilityConfig.TracingProvider,
		ctx:                 ctx,
		cancel:              cancel,
	}
}

// Start initializes the plugin registry and begins discovery.
func (pr *PluginRegistry) Start() error {
	pr.runMutex.Lock()
	defer pr.runMutex.Unlock()

	if pr.running {
		return NewRegistryError("plugin registry is already running", nil)
	}

	pr.logger.Info("Starting plugin registry",
		"max_clients", pr.config.MaxClients,
		"auto_discovery", pr.config.AutoDiscovery)

	// Initialize discovery engine if auto-discovery is enabled
	if pr.config.AutoDiscovery {
		if err := pr.initializeDiscovery(); err != nil {
			return NewDiscoveryError("failed to initialize discovery", err)
		}
	}

	// Initialize factory registration
	if err := pr.initializeFactories(); err != nil {
		return NewFactoryError("", "failed to initialize factories", err)
	}

	pr.running = true
	pr.logger.Info("Plugin registry started successfully")
	return nil
}

// Stop gracefully shuts down the plugin registry.
func (pr *PluginRegistry) Stop() error {
	return pr.StopWithContext(context.Background())
}

// StopWithContext gracefully shuts down the plugin registry with context for timeout control.
func (pr *PluginRegistry) StopWithContext(ctx context.Context) error {
	pr.runMutex.Lock()
	defer pr.runMutex.Unlock()

	if !pr.running {
		return nil
	}

	pr.logger.Info("Stopping plugin registry")

	// Begin graceful shutdown phase
	pr.draining = true

	// Cancel registry context
	pr.cancel()

	// Perform graceful draining for all clients
	drainErrors := pr.performGracefulDraining(ctx)

	// Stop all clients after draining
	pr.clientMutex.Lock()
	var stopErrors []error
	for id, client := range pr.clients {
		if err := client.Stop(); err != nil {
			stopErrors = append(stopErrors, NewClientError(id, "failed to stop client", err))
		}
	}
	pr.clientMutex.Unlock()

	// Stop discovery engine (no explicit stop method needed)
	if pr.discoveryEngine != nil {
		pr.logger.Info("Discovery engine stopped")
	}

	pr.running = false
	pr.draining = false

	// Combine all errors
	allErrors := append(drainErrors, stopErrors...)
	if len(allErrors) > 0 {
		return NewRegistryError(fmt.Sprintf("errors during registry shutdown: %v", allErrors), nil)
	}

	pr.logger.Info("Plugin registry stopped successfully")
	return nil
}

// RegisterFactory registers a plugin factory for a specific type.
func (pr *PluginRegistry) RegisterFactory(pluginType string, factory PluginFactory[any, any]) error {
	pr.factoryMutex.Lock()
	defer pr.factoryMutex.Unlock()

	if _, exists := pr.factories[pluginType]; exists {
		return NewFactoryError(pluginType, "factory for type already registered", nil)
	}

	pr.factories[pluginType] = factory
	pr.logger.Info("Registered plugin factory", "type", pluginType)

	// Record factory registration metrics
	pr.recordFactoryMetrics("register", pluginType)

	return nil
}

// CreateClient creates a new plugin client.
func (pr *PluginRegistry) CreateClient(config PluginConfig) (*PluginClient, error) {
	pr.clientMutex.Lock()
	defer pr.clientMutex.Unlock()

	// Check client limits
	if len(pr.clients) >= pr.config.MaxClients {
		return nil, NewRegistryError(fmt.Sprintf("maximum number of clients (%d) reached", pr.config.MaxClients), nil)
	}

	// Check if client already exists
	if _, exists := pr.clients[config.Name]; exists {
		return nil, NewClientError(config.Name, "client with name already exists", nil)
	}

	// Create client
	client, err := pr.createClientInstance(config)
	if err != nil {
		return nil, NewClientError("", "failed to create client instance", err)
	}

	// Register client
	pr.clients[config.Name] = client
	clientCount := len(pr.clients)

	// Record client creation metrics
	pr.recordClientMetrics("create", config.Name, config.Type)

	pr.logger.Info("Created plugin client",
		"name", config.Name,
		"type", config.Type,
		"transport", config.Transport)

	// Update client count gauge after releasing the lock
	defer func() {
		pr.updateClientCountGaugeWithCount(clientCount)
	}()

	return client, nil
}

// GetClient retrieves a plugin client by name.
func (pr *PluginRegistry) GetClient(name string) (*PluginClient, error) {
	pr.clientMutex.RLock()
	defer pr.clientMutex.RUnlock()

	client, exists := pr.clients[name]
	if !exists {
		return nil, NewClientError(name, "client not found", nil)
	}

	return client, nil
}

// ListClients returns all registered clients.
func (pr *PluginRegistry) ListClients() map[string]*PluginClient {
	pr.clientMutex.RLock()
	defer pr.clientMutex.RUnlock()

	clients := make(map[string]*PluginClient, len(pr.clients))
	for name, client := range pr.clients {
		clients[name] = client
	}

	return clients
}

// RemoveClient removes a plugin client.
func (pr *PluginRegistry) RemoveClient(name string) error {
	pr.clientMutex.Lock()
	defer pr.clientMutex.Unlock()

	client, exists := pr.clients[name]
	if !exists {
		return NewClientError(name, "client not found", nil)
	}

	// Stop the client
	if err := client.Stop(); err != nil {
		pr.logger.Warn("Error stopping client during removal",
			"name", name,
			"error", err)
	}

	// Remove from registry
	clientType := client.Type
	delete(pr.clients, name)

	// Record client removal metrics
	pr.recordClientMetrics("remove", name, clientType)

	pr.logger.Info("Removed plugin client", "name", name)
	return nil
}

// GetStats returns registry statistics.
func (pr *PluginRegistry) GetStats() RegistryStats {
	pr.clientMutex.RLock()
	defer pr.clientMutex.RUnlock()

	stats := RegistryStats{
		TotalClients:    len(pr.clients),
		ClientsByType:   make(map[string]int),
		ClientsByStatus: make(map[PluginStatus]int),
		ClientStats:     make(map[string]ClientStats),
	}

	for name, client := range pr.clients {
		client.mutex.RLock()

		// Count by type
		stats.ClientsByType[client.Type]++

		// Count by status
		stats.ClientsByStatus[client.status]++

		// Collect client stats
		clientStats := ClientStats{
			Status:    client.status,
			StartTime: client.startTime,
			LastPing:  client.lastPing,
		}

		if !client.startTime.IsZero() {
			clientStats.Uptime = time.Since(client.startTime)
		}

		stats.ClientStats[name] = clientStats

		// Count active and healthy
		if client.status != StatusOffline {
			stats.ActiveClients++
		}
		if client.status == StatusHealthy {
			stats.HealthyClients++
		}

		client.mutex.RUnlock()
	}

	return stats
}

// performGracefulDraining performs graceful draining on all active clients.
func (pr *PluginRegistry) performGracefulDraining(ctx context.Context) []error {
	var drainErrors []error

	// Get list of clients to drain
	pr.clientMutex.RLock()
	clientNames := make([]string, 0, len(pr.clients))
	for name := range pr.clients {
		clientNames = append(clientNames, name)
	}
	pr.clientMutex.RUnlock()

	pr.logger.Info("Starting graceful draining", "clients", len(clientNames))

	// Drain each client
	for _, clientName := range clientNames {
		activeRequests := pr.requestTracker.GetActiveRequestCount(clientName)
		if activeRequests > 0 {
			pr.logger.Info("Draining client",
				"client", clientName,
				"active_requests", activeRequests)

			// Create drain options with progress callback
			drainOptions := pr.config.DrainOptions
			drainOptions.ProgressCallback = func(pluginName string, activeCount int64) {
				pr.logger.Info("Drain progress",
					"client", pluginName,
					"remaining_requests", activeCount)
			}

			// Use context timeout for draining if provided
			if deadline, ok := ctx.Deadline(); ok {
				// Reduce drain timeout to fit within context deadline
				remaining := time.Until(deadline)
				if remaining < drainOptions.DrainTimeout {
					drainOptions.DrainTimeout = remaining
				}
			}

			if err := pr.requestTracker.GracefulDrain(clientName, drainOptions); err != nil {
				drainErrors = append(drainErrors, NewClientError(clientName, "failed to drain client", err))
			} else {
				pr.logger.Info("Client drained successfully", "client", clientName)
			}
		}
	}

	if len(drainErrors) == 0 {
		pr.logger.Info("All clients drained successfully")
	} else {
		pr.logger.Warn("Some clients failed to drain gracefully", "errors", len(drainErrors))
	}

	return drainErrors
}

// StartDraining begins the draining process without stopping the registry.
// This allows new requests to be rejected while existing ones complete.
func (pr *PluginRegistry) StartDraining() error {
	pr.runMutex.Lock()
	defer pr.runMutex.Unlock()

	if !pr.running {
		return NewRegistryError("registry is not running", nil)
	}

	if pr.draining {
		return NewRegistryError("registry is already draining", nil)
	}

	pr.logger.Info("Starting registry draining mode")
	pr.draining = true
	return nil
}

// IsDraining returns true if the registry is in draining mode.
func (pr *PluginRegistry) IsDraining() bool {
	pr.runMutex.Lock()
	defer pr.runMutex.Unlock()
	return pr.draining
}

// GetActiveRequestsCount returns the total number of active requests across all clients.
func (pr *PluginRegistry) GetActiveRequestsCount() map[string]int64 {
	return pr.requestTracker.GetAllActiveRequests()
}

// CallClient makes a tracked method call to a specific plugin client.
// This method automatically handles request tracking for graceful draining.
func (pr *PluginRegistry) CallClient(ctx context.Context, clientName, method string, args interface{}) (interface{}, error) {
	// Check if registry is draining - reject new requests
	if pr.IsDraining() {
		return nil, NewRegistryError("registry is draining, not accepting new requests", nil)
	}

	client, err := pr.GetClient(clientName)
	if err != nil {
		return nil, err
	}

	return client.Call(ctx, method, args, pr.requestTracker)
}

// CallClientAsync makes an asynchronous tracked method call to a specific plugin client.
// Returns a channel that will receive the result or error.
func (pr *PluginRegistry) CallClientAsync(ctx context.Context, clientName, method string, args interface{}) (<-chan AsyncResult, error) {
	// Check if registry is draining - reject new requests
	if pr.IsDraining() {
		return nil, NewRegistryError("registry is draining, not accepting new requests", nil)
	}

	client, err := pr.GetClient(clientName)
	if err != nil {
		return nil, err
	}

	resultChan := make(chan AsyncResult, 1)

	go func() {
		defer close(resultChan)

		result, err := client.Call(ctx, method, args, pr.requestTracker)
		resultChan <- AsyncResult{
			Result: result,
			Error:  err,
		}
	}()

	return resultChan, nil
}

// AsyncResult represents the result of an asynchronous call.
type AsyncResult struct {
	Result interface{}
	Error  error
}

// ShutdownCoordinator manages coordinated shutdown of the entire plugin system.
type ShutdownCoordinator struct {
	registry *PluginRegistry
	logger   Logger
}

// NewShutdownCoordinator creates a new shutdown coordinator.
func NewShutdownCoordinator(registry *PluginRegistry) *ShutdownCoordinator {
	return &ShutdownCoordinator{
		registry: registry,
		logger:   registry.logger,
	}
}

// GracefulShutdown performs a coordinated graceful shutdown of the entire system.
// It follows the proper order: draining -> clients -> protocols -> processes.
func (sc *ShutdownCoordinator) GracefulShutdown(ctx context.Context) error {
	sc.logger.Info("Starting coordinated graceful shutdown")

	// Phase 1: Start draining (stop accepting new requests)
	if err := sc.registry.StartDraining(); err != nil {
		sc.logger.Warn("Failed to start draining", "error", err)
	}

	// Phase 2: Wait for active requests to complete or timeout
	activeRequests := sc.registry.GetActiveRequestsCount()
	totalActive := int64(0)
	for _, count := range activeRequests {
		totalActive += count
	}

	if totalActive > 0 {
		sc.logger.Info("Waiting for active requests to complete",
			"total_active", totalActive,
			"per_client", activeRequests)
	}

	// Phase 3: Perform graceful registry shutdown
	if err := sc.registry.StopWithContext(ctx); err != nil {
		sc.logger.Error("Registry shutdown encountered errors", "error", err)
		return NewRegistryError("registry shutdown failed", err)
	}

	sc.logger.Info("Coordinated graceful shutdown completed successfully")
	return nil
}

// ForceShutdown performs an immediate shutdown with minimal cleanup.
// Use only when graceful shutdown fails or in emergency situations.
func (sc *ShutdownCoordinator) ForceShutdown() error {
	sc.logger.Warn("Performing force shutdown")

	// Force cancel all requests
	activeRequests := sc.registry.GetActiveRequestsCount()
	totalCanceled := 0

	for clientName := range activeRequests {
		canceled := sc.registry.requestTracker.ForceCancel(clientName)
		totalCanceled += canceled
		if canceled > 0 {
			sc.logger.Info("Force canceled requests",
				"client", clientName,
				"canceled", canceled)
		}
	}

	// Force stop registry
	if err := sc.registry.Stop(); err != nil {
		sc.logger.Error("Force shutdown encountered errors", "error", err)
		return NewRegistryError("force shutdown failed", err)
	}

	sc.logger.Info("Force shutdown completed", "canceled_requests", totalCanceled)
	return nil
}

// GetShutdownStatus returns the current shutdown status of the system.
func (sc *ShutdownCoordinator) GetShutdownStatus() ShutdownStatus {
	activeRequests := sc.registry.GetActiveRequestsCount()
	totalActive := int64(0)
	for _, count := range activeRequests {
		totalActive += count
	}

	status := ShutdownStatus{
		IsRunning:      sc.registry.running,
		IsDraining:     sc.registry.IsDraining(),
		ActiveRequests: totalActive,
		ActiveByClient: activeRequests,
		TotalClients:   len(sc.registry.clients),
	}

	// Determine phase
	if !status.IsRunning {
		status.Phase = ShutdownPhaseComplete
	} else if status.IsDraining {
		status.Phase = ShutdownPhaseDraining
	} else {
		status.Phase = ShutdownPhaseRunning
	}

	return status
}

// ShutdownStatus represents the current shutdown status.
type ShutdownStatus struct {
	Phase          ShutdownPhase    `json:"phase"`
	IsRunning      bool             `json:"is_running"`
	IsDraining     bool             `json:"is_draining"`
	ActiveRequests int64            `json:"active_requests"`
	ActiveByClient map[string]int64 `json:"active_by_client"`
	TotalClients   int              `json:"total_clients"`
}

// ShutdownPhase represents the current phase of shutdown.
type ShutdownPhase string

const (
	ShutdownPhaseRunning  ShutdownPhase = "running"
	ShutdownPhaseDraining ShutdownPhase = "draining"
	ShutdownPhaseComplete ShutdownPhase = "complete"
)

// initializeDiscovery sets up the discovery engine.
func (pr *PluginRegistry) initializeDiscovery() error {
	if len(pr.config.DiscoveryPaths) == 0 {
		pr.logger.Warn("No discovery paths configured, skipping auto-discovery")
		return nil
	}

	// Create discovery config
	discoveryConfig := ExtendedDiscoveryConfig{
		DiscoveryConfig: DiscoveryConfig{
			Enabled:     true,
			Directories: pr.config.DiscoveryPaths,
			Patterns:    []string{"*.so", "plugin-*", "*-plugin"},
			WatchMode:   true,
		},
		SearchPaths:          pr.config.DiscoveryPaths,
		FilePatterns:         []string{"*.so", "plugin-*", "*-plugin", "*.exe"},
		MaxDepth:             3,
		FollowSymlinks:       false,
		AllowedTransports:    []TransportType{TransportExecutable},
		ValidateManifests:    true,
		RequiredCapabilities: []string{},
		ExcludePaths:         []string{},
		DiscoveryTimeout:     pr.config.DiscoveryInterval,
	}

	// Create discovery engine
	engine := NewDiscoveryEngine(discoveryConfig, pr.logger)

	pr.discoveryEngine = engine
	pr.logger.Info("Discovery engine initialized",
		"paths", pr.config.DiscoveryPaths,
		"interval", pr.config.DiscoveryInterval)

	return nil
}

// initializeFactories sets up the factory registration.
func (pr *PluginRegistry) initializeFactories() error {
	// Register subprocess factory
	subprocessFactory := NewSubprocessPluginFactory[any, any](pr.logger)
	if err := pr.RegisterFactory("subprocess", subprocessFactory); err != nil {
		return NewFactoryError("subprocess", "failed to register subprocess factory", err)
	}

	pr.logger.Info("Factory registration initialized")
	return nil
}

// createClientInstance creates a new plugin client instance.
func (pr *PluginRegistry) createClientInstance(config PluginConfig) (*PluginClient, error) {
	ctx, cancel := context.WithCancel(pr.ctx)

	client := &PluginClient{
		ID:     fmt.Sprintf("%s-%d", config.Name, time.Now().UnixNano()),
		Name:   config.Name,
		Type:   config.Type,
		config: config,
		ctx:    ctx,
		cancel: cancel,
		logger: pr.logger,
		status: StatusOffline,
	}

	// Set executable and args for subprocess plugins
	if config.Transport == TransportExecutable {
		client.executable = config.Executable
		client.args = config.Args
	}

	// Initialize health checker if enabled
	if pr.config.HealthCheckConfig.Enabled {
		client.healthChecker = NewHealthChecker(client, pr.config.HealthCheckConfig)
	}

	return client, nil
}

// PluginClient methods

// Start starts the plugin client.
func (pc *PluginClient) Start() error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.status != StatusOffline {
		return NewClientError("", "client is already running", nil)
	}

	pc.logger.Info("Starting plugin client", "name", pc.Name, "type", pc.Type)

	// Create subprocess for executable plugins
	if pc.config.Transport == TransportExecutable {
		if err := pc.startSubprocess(); err != nil {
			return NewProcessError("failed to start subprocess", err)
		}
	}

	pc.status = StatusHealthy
	pc.startTime = time.Now()
	pc.lastPing = time.Now()

	pc.logger.Info("Plugin client started", "name", pc.Name)
	return nil
}

// Stop stops the plugin client.
func (pc *PluginClient) Stop() error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.status == StatusOffline {
		return nil
	}

	pc.logger.Info("Stopping plugin client", "name", pc.Name)

	// Cancel context
	pc.cancel()

	// Stop health checker
	if pc.healthChecker != nil {
		pc.healthChecker.Stop()
	}

	// Stop communication bridge
	if pc.bridge != nil {
		if err := pc.bridge.Stop(); err != nil {
			pc.logger.Warn("Error stopping communication bridge",
				"name", pc.Name,
				"error", err)
		}
	}

	// Stop subprocess
	if pc.subprocess != nil {
		if err := pc.subprocess.Close(); err != nil {
			pc.logger.Warn("Error stopping subprocess",
				"name", pc.Name,
				"error", err)
		}
	}

	pc.status = StatusOffline
	pc.logger.Info("Plugin client stopped", "name", pc.Name)
	return nil
}

// Health returns the current health status (required by HealthChecker).
func (pc *PluginClient) Health(ctx context.Context) HealthStatus {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	return HealthStatus{
		Status:       pc.status,
		Message:      fmt.Sprintf("Plugin client %s is %s", pc.Name, pc.status),
		LastCheck:    time.Now(),
		ResponseTime: 0, // Could implement actual ping time
		Metadata: map[string]string{
			"plugin_name": pc.Name,
			"plugin_type": pc.Type,
			"uptime":      time.Since(pc.startTime).String(),
		},
	}
}

// Close closes the plugin client (required by HealthChecker).
func (pc *PluginClient) Close() error {
	return pc.Stop()
}

// Call makes a method call to the plugin via gRPC or subprocess with request tracking.
func (pc *PluginClient) Call(ctx context.Context, method string, args interface{}, tracker *RequestTracker) (interface{}, error) {
	pc.mutex.RLock()
	subprocess := pc.subprocess
	pc.mutex.RUnlock()

	if subprocess == nil {
		return nil, NewClientError("", "plugin client not initialized", nil)
	}

	if pc.status != StatusHealthy {
		return nil, NewClientError("", fmt.Sprintf("plugin client is not healthy: %s", pc.status), nil)
	}

	// Track request if tracker provided
	if tracker != nil {
		tracker.StartRequest(pc.Name, ctx)
		defer tracker.EndRequest(pc.Name, ctx)
	}

	// Create execution context for the call
	execCtx := ExecutionContext{
		RequestID: fmt.Sprintf("registry_%d", time.Now().UnixNano()),
		Timeout:   30 * time.Second,
		Metadata:  map[string]string{"method": method},
	}

	// Make call using subprocess plugin
	result, err := subprocess.Execute(ctx, execCtx, args)
	if err != nil {
		pc.logger.Error("Plugin call failed",
			"name", pc.Name,
			"method", method,
			"error", err)
		return nil, err
	}

	// Update last ping time
	pc.mutex.Lock()
	pc.lastPing = time.Now()
	pc.mutex.Unlock()

	return result, nil
} // startSubprocess starts the subprocess for executable plugins.
func (pc *PluginClient) startSubprocess() error {
	if pc.executable == "" {
		return NewConfigValidationError("executable path not specified", nil)
	}

	// Create subprocess plugin config
	subprocessConfig := PluginConfig{
		Name:       pc.Name,
		Type:       pc.Type,
		Transport:  TransportExecutable,
		Executable: pc.executable,
		Args:       pc.args,
	}

	// Create subprocess plugin factory
	factory := &SubprocessPluginFactory[any, any]{}

	// Create subprocess plugin
	subprocess, err := factory.CreatePlugin(subprocessConfig)
	if err != nil {
		return NewProcessError("failed to create subprocess plugin", err)
	}

	// Type assert to subprocess plugin
	subprocessPlugin, ok := subprocess.(*SubprocessPlugin[any, any])
	if !ok {
		return NewFactoryError("subprocess", fmt.Sprintf("expected SubprocessPlugin, got %T", subprocess), nil)
	}
	pc.subprocess = subprocessPlugin

	// Create communication bridge
	bridgeConfig := BridgeConfig{
		ListenAddress:  "127.0.0.1",
		ListenPort:     0, // Auto-assign
		MaxChannels:    10,
		ChannelTimeout: 30 * time.Second,
		AcceptTimeout:  10 * time.Second,
	}

	bridge := NewCommunicationBridge(bridgeConfig, pc.logger)
	if err := bridge.Start(); err != nil {
		return NewCommunicationError("failed to start communication bridge", err)
	}

	pc.bridge = bridge

	// Note: RPC protocol removed - using gRPC/subprocess communication only

	pc.logger.Info("Subprocess started",
		"name", pc.Name,
		"executable", pc.executable,
		"bridge_port", bridge.GetPort())

	return nil
}

// Observability methods for PluginRegistry

// ConfigureObservability configures comprehensive observability for the plugin registry
func (pr *PluginRegistry) ConfigureObservability(config ObservabilityConfig) error {
	pr.clientMutex.Lock()
	defer pr.clientMutex.Unlock()

	pr.observabilityConfig = config
	pr.metricsCollector = config.MetricsCollector
	pr.tracingProvider = config.TracingProvider

	// Create common metrics if advanced features are available
	if config.MetricsCollector.CounterWithLabels("test", "test") != nil {
		pr.commonMetrics = CreateCommonPluginMetrics(config.MetricsCollector)
	}

	pr.logger.Info("Plugin registry observability configured",
		"level", string(config.Level),
		"metrics_enabled", config.IsMetricsEnabled(),
		"tracing_enabled", config.IsTracingEnabled(),
		"logging_enabled", config.IsLoggingEnabled())

	return nil
}

// recordFactoryMetrics records plugin factory operations
func (pr *PluginRegistry) recordFactoryMetrics(operation, pluginType string) {
	if !pr.observabilityConfig.IsMetricsEnabled() || pr.metricsCollector == nil {
		return
	}

	labels := map[string]string{
		"operation":   operation,
		"plugin_type": pluginType,
	}

	pr.metricsCollector.IncrementCounter(
		pr.observabilityConfig.MetricsPrefix+"_plugin_factory_operations_total",
		labels,
		1,
	)
}

// recordClientMetrics records client lifecycle operations
func (pr *PluginRegistry) recordClientMetrics(operation, clientName, clientType string) {
	if !pr.observabilityConfig.IsMetricsEnabled() || pr.metricsCollector == nil {
		return
	}

	labels := map[string]string{
		"operation":   operation,
		"client_name": clientName,
		"client_type": clientType,
	}

	pr.metricsCollector.IncrementCounter(
		pr.observabilityConfig.MetricsPrefix+"_plugin_client_operations_total",
		labels,
		1,
	)

	// Note: updateClientCountGaugeWithCount is called with explicit count
	// to avoid re-entrant locking issues
}

// updateClientCountGaugeWithCount updates the gauge with the provided count (no additional locking)
func (pr *PluginRegistry) updateClientCountGaugeWithCount(count int) {
	if !pr.observabilityConfig.IsMetricsEnabled() || pr.metricsCollector == nil {
		return
	}

	pr.metricsCollector.SetGauge(
		pr.observabilityConfig.MetricsPrefix+"_plugin_clients_active",
		map[string]string{},
		float64(count),
	)
}

// GetObservabilityMetrics returns comprehensive observability metrics from the registry
func (pr *PluginRegistry) GetObservabilityMetrics() map[string]interface{} {
	pr.clientMutex.RLock()
	pr.factoryMutex.RLock()
	defer pr.clientMutex.RUnlock()
	defer pr.factoryMutex.RUnlock()

	metrics := make(map[string]interface{})

	// Client metrics
	clientsByType := make(map[string]int)
	clientsByStatus := make(map[string]int)

	for _, client := range pr.clients {
		clientsByType[client.Type]++
		clientsByStatus[client.status.String()]++
	}

	metrics["registry"] = map[string]interface{}{
		"total_clients":     len(pr.clients),
		"max_clients":       pr.config.MaxClients,
		"clients_by_type":   clientsByType,
		"clients_by_status": clientsByStatus,
		"factory_count":     len(pr.factories),
		"is_running":        pr.running,
		"is_draining":       pr.draining,
	}

	// Get metrics from collector if available
	if pr.metricsCollector != nil {
		metrics["collector"] = pr.metricsCollector.GetMetrics()
	}

	// Get Prometheus metrics if available
	if pr.commonMetrics != nil && pr.observabilityConfig.MetricsCollector != nil {
		if prometheusMetrics := pr.observabilityConfig.MetricsCollector.GetPrometheusMetrics(); prometheusMetrics != nil {
			metrics["prometheus"] = prometheusMetrics
		}
	}

	return metrics
}

// EnableObservability is a convenience method to enable observability with default settings
func (pr *PluginRegistry) EnableObservability() error {
	config := DefaultObservabilityConfig()
	return pr.ConfigureObservability(config)
}

// EnableEnhancedObservability enables observability with advanced metrics collector
func (pr *PluginRegistry) EnableEnhancedObservability() error {
	config := DefaultObservabilityConfig()
	return pr.ConfigureObservability(config)
}
