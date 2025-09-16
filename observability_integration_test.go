package goplugins

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestObservabilityIntegration tests the complete integration of observability across all components
func TestObservabilityIntegration(t *testing.T) {
	t.Parallel()

	manager := setupManagerWithObservability(t)
	registerTestPlugin(t, manager)

	executeTestRequests(t, manager)
	metrics := getAndVerifyMetrics(t, manager)

	verifyCollectorMetrics(t, metrics)
	verifyPrometheusMetrics(t, metrics)
	verifyHealthStatusMetrics(t, metrics)
	verifyCircuitBreakerMetrics(t, metrics)
}

// setupManagerWithObservability creates and configures a manager with observability enabled
func setupManagerWithObservability(t *testing.T) *Manager[TestRequest, TestResponse] {
	manager := NewManager[TestRequest, TestResponse](nil)

	err := manager.EnableEnhancedObservability()
	if err != nil {
		t.Fatalf("Failed to enable enhanced observability: %v", err)
	}

	initialMetrics := manager.GetObservabilityMetrics()
	t.Logf("Initial metrics: %+v", initialMetrics)

	verifyObservabilityStatus(t, manager)
	return manager
}

// verifyObservabilityStatus checks that observability is properly enabled
func verifyObservabilityStatus(t *testing.T, manager *Manager[TestRequest, TestResponse]) {
	status := manager.GetObservabilityStatus()

	metricsEnabled, ok := status["metrics_enabled"].(bool)
	if !ok {
		t.Fatal("Expected metrics_enabled to be a bool")
	}
	if !metricsEnabled {
		t.Error("Metrics should be enabled")
	}

	hasCommonMetrics, ok := status["has_common_metrics"].(bool)
	if !ok {
		t.Fatal("Expected has_common_metrics to be a bool")
	}
	if !hasCommonMetrics {
		t.Error("Common metrics should be available")
	}
}

// registerTestPlugin creates and registers a test plugin
func registerTestPlugin(t *testing.T, manager *Manager[TestRequest, TestResponse]) *TestPluginWithHealth {
	testPlugin := &TestPluginWithHealth{
		name:     "integration-test-plugin",
		version:  "1.0.0",
		healthy:  true,
		response: TestResponse{Result: "success", Data: map[string]string{"test": "data"}},
	}

	err := manager.Register(testPlugin)
	if err != nil {
		t.Fatalf("Failed to register test plugin: %v", err)
	}

	return testPlugin
}

// executeTestRequests runs multiple test requests to generate metrics
func executeTestRequests(t *testing.T, manager *Manager[TestRequest, TestResponse]) {
	ctx := context.Background()
	request := TestRequest{Action: "test", Data: map[string]string{"input": "test"}}

	for i := 0; i < 5; i++ {
		t.Logf("Executing request %d", i+1)
		response, err := manager.Execute(ctx, "integration-test-plugin", request)
		if err != nil {
			t.Errorf("Request %d failed: %v", i+1, err)
		} else {
			t.Logf("Request %d succeeded with response: %+v", i+1, response)
		}
	}
}

// getAndVerifyMetrics retrieves metrics and performs basic verification
func getAndVerifyMetrics(t *testing.T, manager *Manager[TestRequest, TestResponse]) map[string]interface{} {
	time.Sleep(200 * time.Millisecond) // Wait for metrics to be processed

	metrics := manager.GetObservabilityMetrics()
	t.Logf("Final metrics: %+v", metrics)

	return metrics
}

// verifyCollectorMetrics checks that collector metrics are working correctly
func verifyCollectorMetrics(t *testing.T, metrics map[string]interface{}) {
	collectorMetrics, ok := metrics["collector"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected collector metrics to be a map[string]interface{}")
	}

	// Look for request count in collector metrics
	var totalRequests int64 = 0
	for key, value := range collectorMetrics {
		if strings.Contains(key, "requests_total") && strings.Contains(key, "integration-test-plugin") {
			if v, ok := value.(int64); ok {
				totalRequests = v
			}
		}
	}

	if totalRequests < 5 {
		t.Errorf("Expected at least 5 total requests in collector metrics, got %d", totalRequests)
	}

	if len(collectorMetrics) == 0 {
		t.Error("Collector metrics should not be empty")
	}
}

// verifyPrometheusMetrics checks that Prometheus metrics are properly exported
func verifyPrometheusMetrics(t *testing.T, metrics map[string]interface{}) {
	promMetrics, ok := metrics["prometheus"]
	if !ok {
		t.Error("Prometheus metrics should be present with enhanced collector")
		return
	}

	promArray, ok := promMetrics.([]PrometheusMetric)
	if !ok {
		t.Fatal("Expected promMetrics to be []PrometheusMetric")
	}
	if len(promArray) == 0 {
		t.Error("Prometheus metrics array should not be empty")
		return
	}

	// Check for expected metric names
	foundRequestMetric := false
	for _, metric := range promArray {
		if metric.Name == "plugin_requests_total" {
			foundRequestMetric = true
		}
	}

	if !foundRequestMetric {
		t.Error("Should find plugin_requests_total metric")
	}
}

// verifyHealthStatusMetrics checks that health status integration works
func verifyHealthStatusMetrics(t *testing.T, metrics map[string]interface{}) {
	healthStatus, ok := metrics["health_status"]
	if !ok {
		t.Error("Health status should be present")
		return
	}

	healthMap, ok := healthStatus.(map[string]HealthStatus)
	if !ok {
		t.Error("Health status should be map[string]HealthStatus")
		return
	}

	pluginHealth, exists := healthMap["integration-test-plugin"]
	if !exists {
		t.Error("Plugin health status should be present")
		return
	}

	if pluginHealth.Status != StatusHealthy {
		t.Errorf("Plugin should be healthy, got %s", pluginHealth.Status.String())
	}
}

// verifyCircuitBreakerMetrics checks that circuit breaker state tracking works
func verifyCircuitBreakerMetrics(t *testing.T, metrics map[string]interface{}) {
	cbStates, ok := metrics["circuit_breaker_states"]
	if !ok {
		t.Error("Circuit breaker states should be present")
		return
	}

	cbMap, ok := cbStates.(map[string]string)
	if !ok {
		t.Error("Circuit breaker states should be map[string]string")
		return
	}

	pluginState, exists := cbMap["integration-test-plugin"]
	if !exists {
		t.Error("Plugin circuit breaker state should be present")
		return
	}

	if pluginState != "closed" {
		t.Errorf("Plugin circuit breaker should be closed, got %s", pluginState)
	}
}

// TestPluginRegistryObservabilityIntegration tests observability in plugin registry
func TestPluginRegistryObservabilityIntegration(t *testing.T) {
	t.Parallel()

	// Create registry config
	config := RegistryConfig{
		MaxClients:    10,
		ClientTimeout: 30 * time.Second,
	}

	registry := NewPluginRegistry(config)

	// Enable observability
	err := registry.EnableEnhancedObservability()
	if err != nil {
		t.Fatalf("Failed to enable observability: %v", err)
	}

	// Register a factory (this should generate metrics)
	factory := &MockPluginFactory{}
	err = registry.RegisterFactory("test", factory)
	if err != nil {
		t.Fatalf("Failed to register factory: %v", err)
	}

	// Get observability metrics
	metrics := registry.GetObservabilityMetrics()

	// Verify registry metrics
	registryMetrics, ok := metrics["registry"].(map[string]interface{})
	if !ok {
		t.Fatal("Registry metrics should be map[string]interface{}")
	}
	factoryCount, ok := registryMetrics["factory_count"].(int)
	if !ok {
		t.Fatal("Factory count should be int")
	}

	if factoryCount != 1 {
		t.Errorf("Expected 1 factory, got %d", factoryCount)
	}

	// Verify collector metrics
	if _, ok := metrics["collector"]; !ok {
		t.Error("Collector metrics should be present")
	}
}

// TestRequestTrackerObservabilityIntegration tests observability in request tracker
func TestRequestTrackerObservabilityIntegration(t *testing.T) {
	t.Parallel()

	// Create metrics collector
	collector := NewDefaultMetricsCollector()

	// Create request tracker with observability
	tracker := NewRequestTrackerWithObservability(collector, "test")

	// Simulate request tracking
	ctx := context.Background()

	tracker.StartRequest("test-plugin", ctx)
	time.Sleep(10 * time.Millisecond)
	tracker.EndRequest("test-plugin", ctx)

	// Get metrics
	metrics := tracker.GetObservabilityMetrics()

	// Verify tracker metrics
	trackerMetrics, ok := metrics["request_tracker"].(map[string]interface{})
	if !ok {
		t.Fatal("Tracker metrics should be map[string]interface{}")
	}
	observabilityEnabled, ok := trackerMetrics["observability_enabled"].(bool)
	if !ok {
		t.Fatal("Observability enabled should be bool")
	}

	if !observabilityEnabled {
		t.Error("Observability should be enabled")
	}

	// Verify collector metrics
	if _, ok := metrics["collector"]; !ok {
		t.Error("Collector metrics should be present")
	}
}

// TestObservableManagerIntegration tests the ObservableManager specifically
func TestObservableManagerIntegration(t *testing.T) {
	t.Parallel()

	// Create base manager
	baseManager := NewManager[TestRequest, TestResponse](nil)

	// Create observable manager
	config := EnhancedObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	// Register test plugin
	testPlugin := &TestPluginWithHealth{
		name:     "observable-test-plugin",
		version:  "1.0.0",
		healthy:  true,
		response: TestResponse{Result: "success"},
	}

	err := baseManager.Register(testPlugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Execute with observability
	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID:  "test-request-123",
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}
	request := TestRequest{Action: "test"}

	_, err = observableManager.ExecuteWithObservability(ctx, "observable-test-plugin", execCtx, request)
	if err != nil {
		t.Fatalf("Observable execution failed: %v", err)
	}

	// Get detailed observability report
	report := observableManager.GetObservabilityMetrics()

	// Verify global metrics
	if report.Global.TotalRequests == 0 {
		t.Error("Should have recorded at least one request")
	}

	// Verify plugin-specific metrics
	if pluginMetrics, exists := report.Plugins["observable-test-plugin"]; !exists {
		t.Error("Should have plugin-specific metrics")
	} else {
		if pluginMetrics.TotalRequests == 0 {
			t.Error("Plugin should have recorded at least one request")
		}
		if pluginMetrics.SuccessRate != 100.0 {
			t.Errorf("Expected 100%% success rate, got %.2f%%", pluginMetrics.SuccessRate)
		}
	}
}

// MockPluginFactory for testing
type MockPluginFactory struct{}

func (f *MockPluginFactory) CreatePlugin(config PluginConfig) (Plugin[any, any], error) {
	return &MockPluginAny{name: config.Name}, nil
}

func (f *MockPluginFactory) SupportsTransport(transport TransportType) bool {
	return true
}

func (f *MockPluginFactory) SupportedTransports() []string {
	return []string{"subprocess", "grpc"}
}

func (f *MockPluginFactory) ValidateConfig(config PluginConfig) error {
	return nil
}

// MockPluginAny for testing with any types
type MockPluginAny struct {
	name string
}

func (p *MockPluginAny) Execute(ctx context.Context, execCtx ExecutionContext, request any) (any, error) {
	return "mock response", nil
}

func (p *MockPluginAny) Health(ctx context.Context) HealthStatus {
	return HealthStatus{
		Status:    StatusHealthy,
		Message:   "Mock plugin is healthy",
		LastCheck: time.Now(),
	}
}

func (p *MockPluginAny) Info() PluginInfo {
	return PluginInfo{
		Name:    p.name,
		Version: "1.0.0",
	}
}

func (p *MockPluginAny) Close() error {
	return nil
}

// TestPluginWithHealth for more comprehensive testing
type TestPluginWithHealth struct {
	name     string
	version  string
	healthy  bool
	response TestResponse
	delay    time.Duration
}

func (p *TestPluginWithHealth) Execute(ctx context.Context, execCtx ExecutionContext, request TestRequest) (TestResponse, error) {
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	return p.response, nil
}

func (p *TestPluginWithHealth) Health(ctx context.Context) HealthStatus {
	status := StatusHealthy
	message := "Plugin is healthy"

	if !p.healthy {
		status = StatusUnhealthy
		message = "Plugin is not healthy"
	}

	return HealthStatus{
		Status:       status,
		Message:      message,
		LastCheck:    time.Now(),
		ResponseTime: 10 * time.Millisecond,
	}
}

func (p *TestPluginWithHealth) Info() PluginInfo {
	return PluginInfo{
		Name:        p.name,
		Version:     p.version,
		Description: "Test plugin with health monitoring",
	}
}

func (p *TestPluginWithHealth) Close() error {
	return nil
}

// TestRequest and TestResponse for testing
type TestRequest struct {
	Action string            `json:"action"`
	Data   map[string]string `json:"data,omitempty"`
}

type TestResponse struct {
	Result string            `json:"result"`
	Data   map[string]string `json:"data,omitempty"`
}
