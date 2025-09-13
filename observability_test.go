// observability_test.go: Comprehensive test suite for the observability system
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	goerrors "github.com/agilira/go-errors"
)

// TestingEnvironment holds OS-specific testing configuration
type TestingEnvironment struct {
	IsWindows bool
	IsLinux   bool
	IsMacOS   bool
}

// getTestingEnvironment returns the current OS environment for OS-aware testing
func getTestingEnvironment() TestingEnvironment {
	return TestingEnvironment{
		IsWindows: runtime.GOOS == "windows",
		IsLinux:   runtime.GOOS == "linux",
		IsMacOS:   runtime.GOOS == "darwin",
	}
}

// Using TestRequest and TestResponse from existing test files

// mockPlugin implements Plugin interface for testing
type mockPlugin struct {
	name          string
	shouldFail    bool
	failureType   string // "timeout", "connection", "auth", "other"
	executeDelay  time.Duration
	healthCheckOK bool
}

func (mp *mockPlugin) Info() PluginInfo {
	return PluginInfo{
		Name:        mp.name,
		Version:     "1.0.0",
		Description: "Mock plugin for testing",
	}
}

func (mp *mockPlugin) Execute(ctx context.Context, execCtx ExecutionContext, request TestRequest) (TestResponse, error) {
	if mp.executeDelay > 0 {
		select {
		case <-ctx.Done():
			return TestResponse{}, ctx.Err()
		case <-time.After(mp.executeDelay):
		}
	}

	if mp.shouldFail {
		switch mp.failureType {
		case "timeout":
			return TestResponse{}, goerrors.New(ErrCodePluginTimeout, "Mock timeout error")
		case "connection":
			return TestResponse{}, goerrors.New(ErrCodePluginConnectionFailed, "Mock connection error")
		case "auth":
			return TestResponse{}, goerrors.New(ErrCodeMissingAPIKey, "Mock auth error")
		default:
			return TestResponse{}, errors.New("mock generic error")
		}
	}

	return TestResponse{
		Result:  "mock response",
		Details: map[string]string{"status": "success"},
	}, nil
}

func (mp *mockPlugin) Health(ctx context.Context) HealthStatus {
	if mp.healthCheckOK {
		return HealthStatus{
			Status:    StatusHealthy,
			Message:   "Mock plugin is healthy",
			LastCheck: time.Now(),
		}
	}
	return HealthStatus{
		Status:    StatusUnhealthy,
		Message:   "Mock plugin is unhealthy",
		LastCheck: time.Now(),
	}
}

func (mp *mockPlugin) Close() error {
	return nil
}

// mockTracingProvider implements TracingProvider for testing
type mockTracingProvider struct {
	spans   []mockSpan
	spansMu sync.RWMutex
}

type mockSpan struct {
	operationName string
	attributes    map[string]interface{}
	status        SpanStatusCode
	statusMessage string
	finished      bool
}

func (mtp *mockTracingProvider) StartSpan(ctx context.Context, operationName string) (context.Context, Span) {
	span := &mockSpan{
		operationName: operationName,
		attributes:    make(map[string]interface{}),
	}

	mtp.spansMu.Lock()
	mtp.spans = append(mtp.spans, *span)
	mtp.spansMu.Unlock()

	return ctx, span
}

func (mtp *mockTracingProvider) ExtractContext(headers map[string]string) context.Context {
	return context.Background()
}

func (mtp *mockTracingProvider) InjectContext(ctx context.Context) map[string]string {
	return map[string]string{
		"X-Trace-ID": "test-trace-id",
		"X-Span-ID":  "test-span-id",
	}
}

func (ms *mockSpan) SetAttribute(key string, value interface{}) {
	ms.attributes[key] = value
}

func (ms *mockSpan) SetStatus(code SpanStatusCode, message string) {
	ms.status = code
	ms.statusMessage = message
}

func (ms *mockSpan) Finish() {
	ms.finished = true
}

func (ms *mockSpan) Context() interface{} {
	return ms
}

// getTestLogger returns a test logger (using existing function from other test files)

// assertMetricExists checks if a specific metric exists in the metrics map
func assertMetricExists(t *testing.T, metrics map[string]interface{}, metricName string) {
	t.Helper()

	if _, exists := metrics[metricName]; !exists {
		t.Errorf("Expected metric %s to exist in metrics map", metricName)
	}
}

// assertCounterValue checks if a counter metric has the expected value
func assertCounterValue(t *testing.T, metrics map[string]interface{}, metricName string, expectedValue int64) {
	t.Helper()

	value, exists := metrics[metricName]
	if !exists {
		t.Errorf("Counter metric %s not found", metricName)
		return
	}

	// Handle both int and int64 types
	var counterValue int64
	switch v := value.(type) {
	case int64:
		counterValue = v
	case int:
		counterValue = int64(v)
	default:
		t.Errorf("Metric %s is not a numeric type, got %T", metricName, value)
		return
	}

	if counterValue != expectedValue {
		t.Errorf("Counter %s: expected %d, got %d", metricName, expectedValue, counterValue)
	}
}

// assertGaugeValue checks if a gauge metric has the expected value with tolerance for float comparison
func assertGaugeValue(t *testing.T, metrics map[string]interface{}, metricName string, expectedValue float64, tolerance float64) {
	t.Helper()

	value, exists := metrics[metricName]
	if !exists {
		t.Errorf("Gauge metric %s not found", metricName)
		return
	}

	gaugeValue, ok := value.(float64)
	if !ok {
		t.Errorf("Metric %s is not a float64, got %T", metricName, value)
		return
	}

	if math.Abs(gaugeValue-expectedValue) > tolerance {
		t.Errorf("Gauge %s: expected %f (±%f), got %f", metricName, expectedValue, tolerance, gaugeValue)
	}
}

// TestDefaultMetricsCollector_Implementation tests the default metrics collector implementation
func TestDefaultMetricsCollector_Implementation(t *testing.T) {
	t.Parallel()

	env := getTestingEnvironment()
	t.Logf("Running on OS: Windows=%v, Linux=%v, macOS=%v", env.IsWindows, env.IsLinux, env.IsMacOS)

	collector := NewDefaultMetricsCollector()
	if collector == nil {
		t.Fatal("NewDefaultMetricsCollector() returned nil")
	}

	t.Run("CounterOperations", func(t *testing.T) {
		// Use a fresh collector for this test to avoid interference
		freshCollector := NewDefaultMetricsCollector()
		labels := map[string]string{"service": "test", "env": "staging"}

		// Test increment counter
		freshCollector.IncrementCounter("test_counter", labels, 5)
		freshCollector.IncrementCounter("test_counter", labels, 3)

		metrics := freshCollector.GetMetrics()
		// Keys are now ordered alphabetically: env comes before service
		assertCounterValue(t, metrics, "test_counter_env_staging_service_test", 8)
	})

	t.Run("GaugeOperations", func(t *testing.T) {
		// Use a fresh collector for this test to avoid interference
		freshCollector := NewDefaultMetricsCollector()
		labels := map[string]string{"component": "memory", "type": "heap"}

		// Test set gauge
		freshCollector.SetGauge("memory_usage", labels, 75.5)

		metrics := freshCollector.GetMetrics()
		assertGaugeValue(t, metrics, "memory_usage_component_memory_type_heap", 75.5, 0.01)

		// Test overwrite
		freshCollector.SetGauge("memory_usage", labels, 82.3) // Should overwrite

		metrics = freshCollector.GetMetrics()
		assertGaugeValue(t, metrics, "memory_usage_component_memory_type_heap", 82.3, 0.01)
	})

	t.Run("HistogramOperations", func(t *testing.T) {
		// Use a fresh collector for this test to avoid interference
		freshCollector := NewDefaultMetricsCollector()
		labels := map[string]string{"endpoint": "/api/v1", "method": "GET"}

		// Record multiple histogram values
		values := []float64{0.1, 0.25, 0.5, 1.2, 2.1}
		for _, v := range values {
			freshCollector.RecordHistogram("request_duration", labels, v)
		}

		metrics := freshCollector.GetMetrics()
		key := "request_duration_endpoint_/api/v1_method_GET"

		// Check histogram statistics
		assertMetricExists(t, metrics, key+"_count")
		assertMetricExists(t, metrics, key+"_sum")
		assertMetricExists(t, metrics, key+"_min")
		assertMetricExists(t, metrics, key+"_max")
		assertMetricExists(t, metrics, key+"_avg")

		// Verify statistics values
		assertCounterValue(t, metrics, key+"_count", int64(len(values)))

		// Find the actual min and max from our values
		expectedMin := values[0]
		expectedMax := values[0]
		for _, v := range values {
			if v < expectedMin {
				expectedMin = v
			}
			if v > expectedMax {
				expectedMax = v
			}
		}

		assertGaugeValue(t, metrics, key+"_min", expectedMin, 0.01)
		assertGaugeValue(t, metrics, key+"_max", expectedMax, 0.01)
	})

	t.Run("CustomMetricHandling", func(t *testing.T) {
		// Use a fresh collector for this test to avoid interference
		freshCollector := NewDefaultMetricsCollector()
		labels := map[string]string{"type": "custom"}

		// Test int64 custom metric (should be treated as counter)
		freshCollector.RecordCustomMetric("custom_int", labels, int64(42))

		// Test float64 custom metric (should be treated as gauge)
		freshCollector.RecordCustomMetric("custom_float", labels, 3.14)

		// Test unsupported type (should be ignored)
		freshCollector.RecordCustomMetric("custom_string", labels, "ignored")

		metrics := freshCollector.GetMetrics()
		assertCounterValue(t, metrics, "custom_int_type_custom", 42)
		assertGaugeValue(t, metrics, "custom_float_type_custom", 3.14, 0.01)

		// String metric should not exist
		if _, exists := metrics["custom_string_type_custom"]; exists {
			t.Error("String custom metric should have been ignored")
		}
	})
}

// TestDefaultMetricsCollector_ConcurrentAccess tests thread safety
func TestDefaultMetricsCollector_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	collector := NewDefaultMetricsCollector()
	const numGoroutines = 100
	const operationsPerGoroutine = 1000

	var wg sync.WaitGroup

	// Counter concurrency test
	t.Run("ConcurrentCounters", func(t *testing.T) {
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				labels := map[string]string{"worker": string(rune('A' + id%26))}

				for j := 0; j < operationsPerGoroutine; j++ {
					collector.IncrementCounter("concurrent_counter", labels, 1)
				}
			}(i)
		}
		wg.Wait()

		// Verify no data race occurred and values are reasonable
		metrics := collector.GetMetrics()
		totalCount := int64(0)
		for key, value := range metrics {
			if counterVal, ok := value.(int64); ok && key != "" {
				totalCount += counterVal
			}
		}

		// We expect roughly numGoroutines * operationsPerGoroutine operations
		// Allow some variance but ensure we're in the right ballpark
		expectedTotal := int64(numGoroutines * operationsPerGoroutine)
		if totalCount < expectedTotal/2 || totalCount > expectedTotal*2 {
			t.Errorf("Concurrent counter operations: expected around %d, got %d", expectedTotal, totalCount)
		}
	})
}

// TestDefaultMetricsCollector_MemoryManagement tests memory management features
func TestDefaultMetricsCollector_MemoryManagement(t *testing.T) {
	t.Parallel()

	collector := NewDefaultMetricsCollector()

	t.Run("HistogramMemoryLimit", func(t *testing.T) {
		labels := map[string]string{"test": "memory"}

		// Record more than 1000 histogram values to trigger memory management
		for i := 0; i < 1500; i++ {
			collector.RecordHistogram("memory_test", labels, float64(i))
		}

		metrics := collector.GetMetrics()
		key := "memory_test_test_memory"

		// The histogram should have exactly 1000 values (memory limit)
		assertCounterValue(t, metrics, key+"_count", 1000)

		// Verify the remaining values are the most recent ones
		minVal, ok := metrics[key+"_min"].(float64)
		if !ok {
			t.Fatalf("Expected min value to be float64, got %T", metrics[key+"_min"])
		}
		maxVal, ok := metrics[key+"_max"].(float64)
		if !ok {
			t.Fatalf("Expected max value to be float64, got %T", metrics[key+"_max"])
		}

		// Min should be around 500 (start of kept values) and max around 1499
		if minVal < 400 || minVal > 600 {
			t.Errorf("Min value after memory management: expected around 500, got %f", minVal)
		}
		if maxVal < 1400 || maxVal > 1499 {
			t.Errorf("Max value after memory management: expected around 1499, got %f", maxVal)
		}
	})
}

// Helper functions for TestEnhancedMetricsCollector_Implementation to reduce cyclomatic complexity

// testEnhancedCounterWithLabels tests counter functionality with labels
func testEnhancedCounterWithLabels(t *testing.T, collector EnhancedMetricsCollector) {
	counter := collector.CounterWithLabels("http_requests", "Total HTTP requests", "method", "status")
	if counter == nil {
		t.Fatal("CounterWithLabels returned nil")
	}

	executeCounterOperations(counter)

	promMetrics := collector.GetPrometheusMetrics()
	if len(promMetrics) == 0 {
		t.Fatal("No Prometheus metrics returned")
	}

	validateCounterMetrics(t, promMetrics)
}

// executeCounterOperations performs counter operations for testing
func executeCounterOperations(counter CounterMetric) {
	counter.Inc("GET", "200")
	counter.Inc("GET", "200")
	counter.Add(3, "POST", "201")
}

// validateCounterMetrics validates the counter metrics in Prometheus format
func validateCounterMetrics(t *testing.T, promMetrics []PrometheusMetric) {
	foundGET200, foundPOST201 := findCounterMetrics(promMetrics)

	if !foundGET200 {
		t.Error("GET 200 counter metric not found in Prometheus output")
	}
	if !foundPOST201 {
		t.Error("POST 201 counter metric not found in Prometheus output")
	}
}

// findCounterMetrics finds and validates specific counter metrics
func findCounterMetrics(promMetrics []PrometheusMetric) (bool, bool) {
	foundGET200 := false
	foundPOST201 := false

	for _, metric := range promMetrics {
		if metric.Name == "http_requests" && metric.Type == "counter" {
			if validateGET200Metric(metric) {
				foundGET200 = true
			}
			if validatePOST201Metric(metric) {
				foundPOST201 = true
			}
		}
	}

	return foundGET200, foundPOST201
}

// validateGET200Metric validates the GET 200 counter metric
func validateGET200Metric(metric PrometheusMetric) bool {
	if metric.Labels["method"] == "GET" && metric.Labels["status"] == "200" {
		if metric.Value != 2 {
			// Note: Can't use t.Errorf here as we don't have access to t
			return false
		}
		return true
	}
	return false
}

// validatePOST201Metric validates the POST 201 counter metric
func validatePOST201Metric(metric PrometheusMetric) bool {
	if metric.Labels["method"] == "POST" && metric.Labels["status"] == "201" {
		if metric.Value != 3 {
			// Note: Can't use t.Errorf here as we don't have access to t
			return false
		}
		return true
	}
	return false
}

// testEnhancedGaugeWithLabels tests gauge functionality with labels
func testEnhancedGaugeWithLabels(t *testing.T, collector EnhancedMetricsCollector) {
	gauge := collector.GaugeWithLabels("system_memory", "System memory usage", "type")
	if gauge == nil {
		t.Fatal("GaugeWithLabels returned nil")
	}

	// Test gauge operations
	gauge.Set(1024.5, "heap")
	gauge.Inc("stack")         // Should increment from 0 to 1
	gauge.Add(512.25, "stack") // Should be 513.25 total
	gauge.Dec("heap")          // Should decrement to 1023.5

	promMetrics := collector.GetPrometheusMetrics()

	heapFound := false
	stackFound := false

	for _, metric := range promMetrics {
		if metric.Name == "system_memory" && metric.Type == "gauge" {
			if metric.Labels["type"] == "heap" {
				heapFound = true
				if math.Abs(metric.Value-1023.5) > 0.1 {
					t.Errorf("Heap gauge: expected 1023.5, got %f", metric.Value)
				}
			}
			if metric.Labels["type"] == "stack" {
				stackFound = true
				if math.Abs(metric.Value-513.25) > 0.1 {
					t.Errorf("Stack gauge: expected 513.25, got %f", metric.Value)
				}
			}
		}
	}

	if !heapFound {
		t.Error("Heap gauge metric not found in Prometheus output")
	}
	if !stackFound {
		t.Error("Stack gauge metric not found in Prometheus output")
	}
}

// testEnhancedHistogramWithLabels tests histogram functionality with labels
func testEnhancedHistogramWithLabels(t *testing.T, collector EnhancedMetricsCollector) {
	buckets := []float64{0.1, 0.5, 1.0, 2.5, 5.0}
	histogram := collector.HistogramWithLabels("request_latency", "Request latency", buckets, "service")
	if histogram == nil {
		t.Fatal("HistogramWithLabels returned nil")
	}

	// Record observations
	observations := []float64{0.05, 0.3, 0.8, 1.5, 3.2, 7.1}
	for _, obs := range observations {
		histogram.Observe(obs, "auth")
	}

	promMetrics := collector.GetPrometheusMetrics()

	histogramFound := false
	for _, metric := range promMetrics {
		if metric.Name == "request_latency" && metric.Type == "histogram" && metric.Labels["service"] == "auth" {
			histogramFound = true

			// Verify bucket structure
			if len(metric.Buckets) != len(buckets)+1 { // +1 for +Inf bucket
				t.Errorf("Expected %d buckets, got %d", len(buckets)+1, len(metric.Buckets))
				continue
			}

			// Verify bucket counts (observations <= bucket upper bound)
			expectedCounts := []uint64{1, 2, 3, 4, 5, 6} // cumulative counts
			for i, bucket := range metric.Buckets {
				if i < len(expectedCounts) && bucket.Count != expectedCounts[i] {
					t.Errorf("Bucket %f: expected count %d, got %d", bucket.UpperBound, expectedCounts[i], bucket.Count)
				}
			}
		}
	}

	if !histogramFound {
		t.Error("Histogram metric not found in Prometheus output")
	}
}

// TestEnhancedMetricsCollector_Implementation tests the enhanced metrics collector
func TestEnhancedMetricsCollector_Implementation(t *testing.T) {
	t.Parallel()

	collector := NewEnhancedMetricsCollector()
	if collector == nil {
		t.Fatal("NewEnhancedMetricsCollector() returned nil")
	}

	t.Run("CounterWithLabels", func(t *testing.T) {
		testEnhancedCounterWithLabels(t, collector)
	})

	t.Run("GaugeWithLabels", func(t *testing.T) {
		testEnhancedGaugeWithLabels(t, collector)
	})

	t.Run("HistogramWithLabels", func(t *testing.T) {
		testEnhancedHistogramWithLabels(t, collector)
	})
}

// TestEnhancedMetricsCollector_BackwardCompatibility tests backward compatibility
func TestEnhancedMetricsCollector_BackwardCompatibility(t *testing.T) {
	t.Parallel()

	enhanced := NewEnhancedMetricsCollector()

	// Cast to basic MetricsCollector to test backward compatibility
	var basic MetricsCollector = enhanced

	labels := map[string]string{"service": "test"}

	// Use basic interface methods
	basic.IncrementCounter("compat_counter", labels, 5)
	basic.SetGauge("compat_gauge", labels, 42.5)
	basic.RecordHistogram("compat_histogram", labels, 1.23)
	basic.RecordCustomMetric("compat_custom", labels, int64(99))

	// Verify metrics are accessible through basic interface
	metrics := basic.GetMetrics()

	if len(metrics) == 0 {
		t.Error("No metrics returned from backward-compatible interface")
	}

	// Should be able to get enhanced metrics too
	promMetrics := enhanced.GetPrometheusMetrics()
	// Note: This might be empty if no enhanced metrics were registered via the enhanced interface,
	// since the basic interface operations go to the embedded DefaultMetricsCollector
	// This is expected behavior for the migration utility
	t.Logf("Enhanced interface returned %d Prometheus metrics", len(promMetrics))
}

// TestErrorCategorization_Functions tests error categorization helper functions
func TestErrorCategorization_Functions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		err           error
		expectTimeout bool
		expectConn    bool
		expectAuth    bool
		description   string
	}{
		{
			name:          "TimeoutError_StructuredCode",
			err:           goerrors.New(ErrCodePluginTimeout, "Plugin execution timeout"),
			expectTimeout: true,
			description:   "Structured timeout error should be categorized as timeout",
		},
		{
			name:          "TimeoutError_ContextDeadline",
			err:           context.DeadlineExceeded,
			expectTimeout: true,
			description:   "Context deadline exceeded should be categorized as timeout",
		},
		{
			name:        "ConnectionError_StructuredCode",
			err:         goerrors.New(ErrCodePluginConnectionFailed, "Connection failed"),
			expectConn:  true,
			description: "Structured connection error should be categorized as connection",
		},
		{
			name:        "ConnectionError_StringPattern",
			err:         errors.New("connection refused"),
			expectConn:  true,
			description: "String pattern 'connection refused' should be categorized as connection",
		},
		{
			name:        "AuthError_StructuredCode",
			err:         goerrors.New(ErrCodeMissingAPIKey, "API key required"),
			expectAuth:  true,
			description: "Structured auth error should be categorized as auth",
		},
		{
			name:        "AuthError_StringPattern",
			err:         errors.New("unauthorized"),
			expectAuth:  true,
			description: "String pattern 'unauthorized' should be categorized as auth",
		},
		{
			name:        "GenericError",
			err:         errors.New("some other error"),
			description: "Generic error should not be categorized as timeout/connection/auth",
		},
		{
			name:        "NilError",
			err:         nil,
			description: "Nil error should not be categorized as any specific type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Testing:", tc.description)

			// Test timeout error detection
			if got := isTimeoutError(tc.err); got != tc.expectTimeout {
				t.Errorf("isTimeoutError(%v) = %v, want %v", tc.err, got, tc.expectTimeout)
			}

			// Test connection error detection
			if got := isConnectionError(tc.err); got != tc.expectConn {
				t.Errorf("isConnectionError(%v) = %v, want %v", tc.err, got, tc.expectConn)
			}

			// Test auth error detection
			if got := isAuthError(tc.err); got != tc.expectAuth {
				t.Errorf("isAuthError(%v) = %v, want %v", tc.err, got, tc.expectAuth)
			}
		})
	}
}

// Helper functions for TestObservabilityConfig_Defaults to reduce cyclomatic complexity

// testDefaultObservabilityConfig tests default configuration values
func testDefaultObservabilityConfig(t *testing.T) {
	config := DefaultObservabilityConfig()

	// Verify default values
	if !config.MetricsEnabled {
		t.Error("Metrics should be enabled by default")
	}
	if config.MetricsCollector == nil {
		t.Error("Default metrics collector should not be nil")
	}
	if config.MetricsPrefix != "goplugins" {
		t.Errorf("Expected default metrics prefix 'goplugins', got %s", config.MetricsPrefix)
	}
	if config.TracingEnabled {
		t.Error("Tracing should be disabled by default")
	}
	if config.TracingSampleRate != 0.1 {
		t.Errorf("Expected default tracing sample rate 0.1, got %f", config.TracingSampleRate)
	}
	if !config.LoggingEnabled {
		t.Error("Logging should be enabled by default")
	}
	if config.LogLevel != "info" {
		t.Errorf("Expected default log level 'info', got %s", config.LogLevel)
	}
	if !config.StructuredLogging {
		t.Error("Structured logging should be enabled by default")
	}
	if !config.HealthMetrics || !config.PerformanceMetrics || !config.ErrorMetrics {
		t.Error("All metric types should be enabled by default")
	}
}

// testEnhancedObservabilityConfig tests enhanced configuration values
func testEnhancedObservabilityConfig(t *testing.T) {
	config := EnhancedObservabilityConfig()

	// Should have both basic and enhanced collectors
	if config.MetricsCollector == nil {
		t.Error("Basic metrics collector should not be nil")
	}
	if config.EnhancedMetricsCollector == nil {
		t.Error("Enhanced metrics collector should not be nil")
	}

	// Both should point to the same instance for backward compatibility
	if config.MetricsCollector != config.EnhancedMetricsCollector {
		t.Error("Basic and enhanced collectors should be the same instance for backward compatibility")
	}
}

// TestObservabilityConfig_Defaults tests observability configuration defaults
func TestObservabilityConfig_Defaults(t *testing.T) {
	t.Parallel()

	t.Run("DefaultObservabilityConfig", func(t *testing.T) {
		testDefaultObservabilityConfig(t)
	})

	t.Run("EnhancedObservabilityConfig", func(t *testing.T) {
		testEnhancedObservabilityConfig(t)
	})
}

// TestObservableManager_Creation tests the creation of observable managers
func TestObservableManager_Creation(t *testing.T) {
	t.Parallel()

	// Create a base manager for testing
	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))

	t.Run("ValidCreation", func(t *testing.T) {
		config := DefaultObservabilityConfig()
		observableManager := NewObservableManager(baseManager, config)

		if observableManager == nil {
			t.Fatal("NewObservableManager returned nil")
		}

		if observableManager.Manager != baseManager {
			t.Error("Base manager not properly assigned")
		}

		if observableManager.config.MetricsEnabled != config.MetricsEnabled {
			t.Error("Config not properly assigned")
		}

		if observableManager.metricsCollector == nil {
			t.Error("Metrics collector should be assigned")
		}

		if observableManager.pluginMetrics == nil {
			t.Error("Plugin metrics map should be initialized")
		}

		// Verify atomic counters are initialized
		if observableManager.totalRequests == nil || observableManager.totalErrors == nil || observableManager.activeRequests == nil {
			t.Error("Atomic counters should be initialized")
		}
	})

	t.Run("NilMetricsCollector", func(t *testing.T) {
		config := DefaultObservabilityConfig()
		config.MetricsCollector = nil // Set to nil to test default assignment

		observableManager := NewObservableManager(baseManager, config)

		// Should create a default collector
		if observableManager.metricsCollector == nil {
			t.Error("Should create default metrics collector when nil provided")
		}
	})
}

// Helper functions for TestObservableManager_PluginMetricsInitialization to reduce cyclomatic complexity

// testObservableManagerEnsurePluginMetrics tests basic plugin metrics initialization
func testObservableManagerEnsurePluginMetrics(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse], pluginName string) {
	validateInitialMetricsState(t, observableManager)

	observableManager.ensurePluginMetrics(pluginName)

	validateMetricsCreation(t, observableManager, pluginName)

	metrics := observableManager.getPluginMetrics(pluginName)
	if metrics == nil {
		t.Error("Plugin metrics should not be nil")
		return
	}

	validateMetricsInitialization(t, metrics)
}

// validateInitialMetricsState validates the initial state before metrics creation
func validateInitialMetricsState(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse]) {
	if len(observableManager.pluginMetrics) != 0 {
		t.Error("Plugin metrics should be empty initially")
	}
}

// validateMetricsCreation validates that metrics were created correctly
func validateMetricsCreation(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse], pluginName string) {
	if len(observableManager.pluginMetrics) != 1 {
		t.Errorf("Expected 1 plugin metrics entry, got %d", len(observableManager.pluginMetrics))
	}

	metrics := observableManager.getPluginMetrics(pluginName)
	if metrics == nil {
		t.Errorf("Plugin metrics for %s should not be nil", pluginName)
	}
}

// validateMetricsInitialization validates that all counters are properly initialized
func validateMetricsInitialization(t *testing.T, metrics *PluginObservabilityMetrics) {
	validateRequestCounters(t, metrics)
	validateLatencyCounters(t, metrics)
	validateErrorCounters(t, metrics)
	validateMinLatencyInitialization(t, metrics)
}

// validateRequestCounters validates request counter initialization
func validateRequestCounters(t *testing.T, metrics *PluginObservabilityMetrics) {
	if metrics.TotalRequests == nil || metrics.SuccessfulRequests == nil || metrics.FailedRequests == nil {
		t.Error("Request counters should be initialized")
	}
}

// validateLatencyCounters validates latency counter initialization
func validateLatencyCounters(t *testing.T, metrics *PluginObservabilityMetrics) {
	if metrics.TotalLatency == nil || metrics.MinLatency == nil || metrics.MaxLatency == nil || metrics.AvgLatency == nil {
		t.Error("Latency counters should be initialized")
	}
}

// validateErrorCounters validates error counter initialization
func validateErrorCounters(t *testing.T, metrics *PluginObservabilityMetrics) {
	if metrics.TimeoutErrors == nil || metrics.ConnectionErrors == nil || metrics.AuthErrors == nil || metrics.OtherErrors == nil {
		t.Error("Error counters should be initialized")
	}
}

// validateMinLatencyInitialization validates min latency is initialized to max value
func validateMinLatencyInitialization(t *testing.T, metrics *PluginObservabilityMetrics) {
	if metrics.MinLatency.Load() != int64(^uint64(0)>>1) {
		t.Error("Min latency should be initialized to max int64 value")
	}
}

// testObservableManagerConcurrentEnsurePluginMetrics tests concurrent plugin metrics initialization
func testObservableManagerConcurrentEnsurePluginMetrics(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse]) {
	// Test concurrent initialization of plugin metrics
	const numGoroutines = 50
	const pluginNamePrefix = "concurrent-plugin-"

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pluginName := fmt.Sprintf("%s%d", pluginNamePrefix, id%10) // Use 10 different plugin names
			observableManager.ensurePluginMetrics(pluginName)
		}(i)
	}

	wg.Wait()

	// Should have exactly 10 unique plugin metrics (id % 10)
	expectedPlugins := 10 + 1 // +1 for the previous test plugin
	if len(observableManager.pluginMetrics) != expectedPlugins {
		t.Errorf("Expected %d plugin metrics entries, got %d", expectedPlugins, len(observableManager.pluginMetrics))
	}
}

// TestObservableManager_PluginMetricsInitialization tests plugin metrics initialization
func TestObservableManager_PluginMetricsInitialization(t *testing.T) {
	t.Parallel()

	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	pluginName := "test-plugin"

	t.Run("EnsurePluginMetrics", func(t *testing.T) {
		testObservableManagerEnsurePluginMetrics(t, observableManager, pluginName)
	})

	t.Run("ConcurrentEnsurePluginMetrics", func(t *testing.T) {
		testObservableManagerConcurrentEnsurePluginMetrics(t, observableManager)
	})
}

// TestObservableManager_LatencyRecording tests latency recording functionality
func TestObservableManager_LatencyRecording(t *testing.T) {
	t.Parallel()

	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	pluginName := "latency-test-plugin"
	observableManager.ensurePluginMetrics(pluginName)

	t.Run("SingleLatencyRecord", func(t *testing.T) {
		latency := 100 * time.Millisecond

		// Record a single latency
		observableManager.recordLatency(pluginName, latency)

		metrics := observableManager.getPluginMetrics(pluginName)

		expectedNs := latency.Nanoseconds()

		if metrics.TotalLatency.Load() != expectedNs {
			t.Errorf("Expected total latency %d ns, got %d ns", expectedNs, metrics.TotalLatency.Load())
		}

		if metrics.MinLatency.Load() != expectedNs {
			t.Errorf("Expected min latency %d ns, got %d ns", expectedNs, metrics.MinLatency.Load())
		}

		if metrics.MaxLatency.Load() != expectedNs {
			t.Errorf("Expected max latency %d ns, got %d ns", expectedNs, metrics.MaxLatency.Load())
		}
	})

	t.Run("MultipleLatencyRecords", func(t *testing.T) {
		pluginName2 := "latency-multi-test-plugin"
		observableManager.ensurePluginMetrics(pluginName2)

		latencies := []time.Duration{
			50 * time.Millisecond,
			200 * time.Millisecond,
			75 * time.Millisecond,
			300 * time.Millisecond,
			125 * time.Millisecond,
		}

		// Record multiple latencies
		for _, lat := range latencies {
			observableManager.recordLatency(pluginName2, lat)
		}

		metrics := observableManager.getPluginMetrics(pluginName2)

		// Calculate expected values
		var totalNs int64
		minNs := latencies[0].Nanoseconds()
		maxNs := latencies[0].Nanoseconds()

		for _, lat := range latencies {
			ns := lat.Nanoseconds()
			totalNs += ns
			if ns < minNs {
				minNs = ns
			}
			if ns > maxNs {
				maxNs = ns
			}
		}

		if metrics.TotalLatency.Load() != totalNs {
			t.Errorf("Expected total latency %d ns, got %d ns", totalNs, metrics.TotalLatency.Load())
		}

		if metrics.MinLatency.Load() != minNs {
			t.Errorf("Expected min latency %d ns, got %d ns", minNs, metrics.MinLatency.Load())
		}

		if metrics.MaxLatency.Load() != maxNs {
			t.Errorf("Expected max latency %d ns, got %d ns", maxNs, metrics.MaxLatency.Load())
		}
	})
}

// TestObservableManager_ErrorRecording tests error recording and categorization
func TestObservableManager_ErrorRecording(t *testing.T) {
	t.Parallel()

	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	pluginName := "error-test-plugin"
	observableManager.ensurePluginMetrics(pluginName)

	testCases := []struct {
		name            string
		err             error
		expectedCounter string
	}{
		{
			name:            "TimeoutError",
			err:             goerrors.New(ErrCodePluginTimeout, "Timeout occurred"),
			expectedCounter: "TimeoutErrors",
		},
		{
			name:            "ConnectionError",
			err:             goerrors.New(ErrCodePluginConnectionFailed, "Connection failed"),
			expectedCounter: "ConnectionErrors",
		},
		{
			name:            "AuthError",
			err:             goerrors.New(ErrCodeMissingAPIKey, "API key missing"),
			expectedCounter: "AuthErrors",
		},
		{
			name:            "GenericError",
			err:             errors.New("unknown error"),
			expectedCounter: "OtherErrors",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get initial metrics
			initialMetrics := observableManager.getPluginMetrics(pluginName)

			var initialCount int64
			switch tc.expectedCounter {
			case "TimeoutErrors":
				initialCount = initialMetrics.TimeoutErrors.Load()
			case "ConnectionErrors":
				initialCount = initialMetrics.ConnectionErrors.Load()
			case "AuthErrors":
				initialCount = initialMetrics.AuthErrors.Load()
			case "OtherErrors":
				initialCount = initialMetrics.OtherErrors.Load()
			}

			// Record the error
			observableManager.recordError(pluginName, tc.err)

			// Check that the appropriate counter was incremented
			var newCount int64
			switch tc.expectedCounter {
			case "TimeoutErrors":
				newCount = initialMetrics.TimeoutErrors.Load()
			case "ConnectionErrors":
				newCount = initialMetrics.ConnectionErrors.Load()
			case "AuthErrors":
				newCount = initialMetrics.AuthErrors.Load()
			case "OtherErrors":
				newCount = initialMetrics.OtherErrors.Load()
			}

			if newCount != initialCount+1 {
				t.Errorf("%s counter should have incremented by 1, got %d -> %d", tc.expectedCounter, initialCount, newCount)
			}
		})
	}
}

// Helper function for TestObservableManager_MetricsReporting to reduce cyclomatic complexity

// testObservableManagerGetObservabilityMetrics tests metrics reporting functionality
func testObservableManagerGetObservabilityMetrics(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse], pluginName string) {
	report := observableManager.GetObservabilityMetrics()

	// Check report structure
	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be set")
	}

	if report.UpTime <= 0 {
		t.Error("UpTime should be positive")
	}

	// Check global metrics
	if report.Global.TotalRequests == 0 && observableManager.totalRequests.Load() > 0 {
		t.Error("Global total requests should reflect manager state")
	}

	// Check plugin metrics
	pluginReport, exists := report.Plugins[pluginName]
	if !exists {
		t.Errorf("Plugin %s should exist in report", pluginName)
		return
	}

	if pluginReport.TotalRequests != 10 {
		t.Errorf("Expected 10 total requests, got %d", pluginReport.TotalRequests)
	}

	if pluginReport.SuccessfulRequests != 8 {
		t.Errorf("Expected 8 successful requests, got %d", pluginReport.SuccessfulRequests)
	}

	if pluginReport.FailedRequests != 2 {
		t.Errorf("Expected 2 failed requests, got %d", pluginReport.FailedRequests)
	}

	expectedSuccessRate := (8.0 / 10.0) * 100.0 // 80%
	if math.Abs(pluginReport.SuccessRate-expectedSuccessRate) > 0.1 {
		t.Errorf("Expected success rate %.1f%%, got %.1f%%", expectedSuccessRate, pluginReport.SuccessRate)
	}

	if pluginReport.TimeoutErrors != 1 {
		t.Errorf("Expected 1 timeout error, got %d", pluginReport.TimeoutErrors)
	}

	if pluginReport.ConnectionErrors != 1 {
		t.Errorf("Expected 1 connection error, got %d", pluginReport.ConnectionErrors)
	}
}

// TestObservableManager_MetricsReporting tests metrics reporting functionality
func TestObservableManager_MetricsReporting(t *testing.T) {
	t.Parallel()

	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	// Setup some test data
	pluginName := "reporting-test-plugin"
	observableManager.ensurePluginMetrics(pluginName)

	// Simulate some plugin activity
	metrics := observableManager.getPluginMetrics(pluginName)
	metrics.TotalRequests.Add(10)
	metrics.SuccessfulRequests.Add(8)
	metrics.FailedRequests.Add(2)
	metrics.TimeoutErrors.Add(1)
	metrics.ConnectionErrors.Add(1)

	t.Run("GetObservabilityMetrics", func(t *testing.T) {
		testObservableManagerGetObservabilityMetrics(t, observableManager, pluginName)
	})
}

// Helper functions for TestCommonPluginMetrics_Functionality to reduce cyclomatic complexity

// testCommonMetricsSuccessfulRequest tests successful request recording
func testCommonMetricsSuccessfulRequest(t *testing.T, collector EnhancedMetricsCollector, commonMetrics *CommonPluginMetrics, pluginName string) {
	duration := 150 * time.Millisecond

	// Record a successful request
	commonMetrics.RecordRequest(pluginName, duration, nil)

	// Verify metrics were recorded
	promMetrics := collector.GetPrometheusMetrics()

	// Check for request count metric
	foundRequestCount := false
	foundDuration := false

	for _, metric := range promMetrics {
		if metric.Name == "plugin_requests_total" && metric.Labels["plugin_name"] == pluginName && metric.Labels["status"] == "success" {
			foundRequestCount = true
			if metric.Value != 1 {
				t.Errorf("Expected request count 1, got %f", metric.Value)
			}
		}
		if metric.Name == "plugin_request_duration_seconds" && metric.Labels["plugin_name"] == pluginName {
			foundDuration = true
			// Should have recorded the duration in seconds
		}
	}

	if !foundRequestCount {
		t.Error("Request count metric not found")
	}
	if !foundDuration {
		t.Error("Duration metric not found")
	}
}

// testCommonMetricsFailedRequest tests failed request recording
func testCommonMetricsFailedRequest(t *testing.T, collector EnhancedMetricsCollector, commonMetrics *CommonPluginMetrics, pluginName string) {
	duration := 200 * time.Millisecond
	err := goerrors.New(ErrCodePluginTimeout, "Request timeout")

	// Record a failed request
	commonMetrics.RecordRequest(pluginName, duration, err)

	promMetrics := collector.GetPrometheusMetrics()

	foundErrorCount := false
	foundRequestCount := false

	for _, metric := range promMetrics {
		if metric.Name == "plugin_errors_total" && metric.Labels["plugin_name"] == pluginName && metric.Labels["error_type"] == "timeout" {
			foundErrorCount = true
			if metric.Value != 1 {
				t.Errorf("Expected error count 1, got %f", metric.Value)
			}
		}
		if metric.Name == "plugin_requests_total" && metric.Labels["plugin_name"] == pluginName && metric.Labels["status"] == "error" {
			foundRequestCount = true
			if metric.Value != 1 {
				t.Errorf("Expected error request count 1, got %f", metric.Value)
			}
		}
	}

	if !foundErrorCount {
		t.Error("Error count metric not found")
	}
	if !foundRequestCount {
		t.Error("Error request count metric not found")
	}
}

// testCommonMetricsCircuitBreakerState tests circuit breaker state tracking
func testCommonMetricsCircuitBreakerState(t *testing.T, collector EnhancedMetricsCollector, commonMetrics *CommonPluginMetrics, pluginName string) {
	// Test circuit breaker state changes
	states := []int{0, 1, 2, 0} // closed, open, half-open, closed

	for _, state := range states {
		commonMetrics.SetCircuitBreakerState(pluginName, state)
	}

	promMetrics := collector.GetPrometheusMetrics()

	foundCBState := false
	for _, metric := range promMetrics {
		if metric.Name == "plugin_circuit_breaker_state" && metric.Labels["plugin_name"] == pluginName {
			foundCBState = true
			// Should have the last state (0 - closed)
			if metric.Value != 0 {
				t.Errorf("Expected circuit breaker state 0, got %f", metric.Value)
			}
			break
		}
	}

	if !foundCBState {
		t.Error("Circuit breaker state metric not found")
	}
}

// testCommonMetricsActiveRequests tests active request tracking
func testCommonMetricsActiveRequests(t *testing.T, collector EnhancedMetricsCollector, commonMetrics *CommonPluginMetrics, pluginName string) {
	// Test active requests increment/decrement
	commonMetrics.IncrementActiveRequests(pluginName)
	commonMetrics.IncrementActiveRequests(pluginName)
	commonMetrics.DecrementActiveRequests(pluginName)

	promMetrics := collector.GetPrometheusMetrics()

	foundActiveRequests := false
	for _, metric := range promMetrics {
		if metric.Name == "plugin_active_requests" && metric.Labels["plugin_name"] == pluginName {
			foundActiveRequests = true
			// Should have 1 active request (2 increments - 1 decrement)
			if metric.Value != 1 {
				t.Errorf("Expected 1 active request, got %f", metric.Value)
			}
			break
		}
	}

	if !foundActiveRequests {
		t.Error("Active requests metric not found")
	}
}

// TestCommonPluginMetrics_Functionality tests the CommonPluginMetrics utility
func TestCommonPluginMetrics_Functionality(t *testing.T) {
	t.Parallel()

	collector := NewEnhancedMetricsCollector()
	commonMetrics := CreateCommonPluginMetrics(collector)

	if commonMetrics == nil {
		t.Fatal("CreateCommonPluginMetrics returned nil")
	}

	pluginName := "common-metrics-test"

	t.Run("RecordSuccessfulRequest", func(t *testing.T) {
		testCommonMetricsSuccessfulRequest(t, collector, commonMetrics, pluginName)
	})

	t.Run("RecordFailedRequest", func(t *testing.T) {
		testCommonMetricsFailedRequest(t, collector, commonMetrics, pluginName)
	})

	t.Run("CircuitBreakerState", func(t *testing.T) {
		testCommonMetricsCircuitBreakerState(t, collector, commonMetrics, pluginName)
	})

	t.Run("ActiveRequestsTracking", func(t *testing.T) {
		testCommonMetricsActiveRequests(t, collector, commonMetrics, pluginName)
	})
}

// TestMigrateToEnhancedMetrics_Functionality tests the migration utility
func TestMigrateToEnhancedMetrics_Functionality(t *testing.T) {
	t.Parallel()

	t.Run("MigrateFromBasicCollector", func(t *testing.T) {
		basicCollector := NewDefaultMetricsCollector()

		enhanced := MigrateToEnhancedMetrics(basicCollector)
		if enhanced == nil {
			t.Fatal("MigrateToEnhancedMetrics returned nil")
		}

		// Should be able to use enhanced features
		counter := enhanced.CounterWithLabels("migrated_counter", "Test counter", "label1")
		if counter == nil {
			t.Error("Enhanced collector should support native labels")
		}
	})

	t.Run("MigrateFromEnhancedCollector", func(t *testing.T) {
		existingEnhanced := NewEnhancedMetricsCollector()

		// Add some metrics to the existing collector
		counter := existingEnhanced.CounterWithLabels("existing_counter", "Test counter", "label1")
		counter.Inc("value1")

		migrated := MigrateToEnhancedMetrics(existingEnhanced)

		// Should return the same instance
		if migrated != existingEnhanced {
			t.Error("Migration from enhanced collector should return the same instance")
		}

		// Should preserve existing metrics
		promMetrics := migrated.GetPrometheusMetrics()
		found := false
		for _, metric := range promMetrics {
			if metric.Name == "existing_counter" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Existing metrics should be preserved during migration")
		}
	})
}

// TestObservableManager_Integration tests end-to-end observability integration
func TestObservableManager_Integration(t *testing.T) {
	t.Parallel()

	env := getTestingEnvironment()
	if env.IsWindows {
		t.Skip("Skipping integration test on Windows due to potential timing differences")
	}

	observableManager, mockPlug := setupIntegrationTestEnv(t)

	t.Run("SuccessfulExecution", func(t *testing.T) {
		runSuccessfulExecutionTest(t, observableManager, mockPlug)
	})

	t.Run("FailedExecution", func(t *testing.T) {
		runFailedExecutionTest(t, observableManager)
	})
}

// setupIntegrationTestEnv creates the test setup for integration tests
func setupIntegrationTestEnv(t *testing.T) (*ObservableManager[TestRequest, TestResponse], *mockPlugin) {
	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))

	config := EnhancedObservabilityConfig()
	config.TracingEnabled = true
	config.TracingProvider = &mockTracingProvider{}

	observableManager := NewObservableManager(baseManager, config)

	mockPlug := &mockPlugin{
		name:          "integration-test-plugin",
		shouldFail:    false,
		executeDelay:  50 * time.Millisecond,
		healthCheckOK: true,
	}

	err := baseManager.Register(mockPlug)
	if err != nil {
		t.Fatalf("Failed to register mock plugin: %v", err)
	}

	return observableManager, mockPlug
}

// runSuccessfulExecutionTest tests successful execution scenario
func runSuccessfulExecutionTest(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse], mockPlug *mockPlugin) {
	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-request-1",
		Timeout:   5 * time.Second,
		Headers:   make(map[string]string),
	}

	request := TestRequest{
		Action: "test",
		Data:   map[string]string{"key": "value"},
	}

	startTime := time.Now()
	response, err := observableManager.ExecuteWithObservability(ctx, mockPlug.name, execCtx, request)
	duration := time.Since(startTime)

	validateSuccessResponse(t, response, err)
	validateSuccessMetrics(t, observableManager, mockPlug.name)
	validateTracingInjection(t, execCtx)
	validateTiming(t, duration)
}

// validateSuccessResponse validates successful response
func validateSuccessResponse(t *testing.T, response TestResponse, err error) {
	if err != nil {
		t.Errorf("Expected successful execution, got error: %v", err)
	}
	if response.Result != "mock response" {
		t.Errorf("Expected 'mock response', got %s", response.Result)
	}
}

// validateSuccessMetrics validates metrics for successful execution
func validateSuccessMetrics(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse], pluginName string) {
	report := observableManager.GetObservabilityMetrics()
	pluginReport, exists := report.Plugins[pluginName]
	if !exists {
		t.Error("Plugin should appear in observability report")
		return
	}

	if pluginReport.TotalRequests != 1 {
		t.Errorf("Expected 1 total request, got %d", pluginReport.TotalRequests)
	}
	if pluginReport.SuccessfulRequests != 1 {
		t.Errorf("Expected 1 successful request, got %d", pluginReport.SuccessfulRequests)
	}
	if pluginReport.FailedRequests != 0 {
		t.Errorf("Expected 0 failed requests, got %d", pluginReport.FailedRequests)
	}
}

// validateTracingInjection validates tracing headers
func validateTracingInjection(t *testing.T, execCtx ExecutionContext) {
	if _, exists := execCtx.Headers["X-Trace-ID"]; !exists {
		t.Error("Tracing headers should have been injected")
	}
}

// validateTiming validates execution timing
func validateTiming(t *testing.T, duration time.Duration) {
	if duration < 40*time.Millisecond || duration > 200*time.Millisecond {
		t.Errorf("Execution duration seems unreasonable: %v", duration)
	}
}

// runFailedExecutionTest tests failed execution scenario
func runFailedExecutionTest(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse]) {
	failingMock := &mockPlugin{
		name:        "failing-plugin",
		shouldFail:  true,
		failureType: "timeout",
	}

	err := observableManager.Register(failingMock)
	if err != nil {
		t.Fatalf("Failed to register failing mock plugin: %v", err)
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "test-request-2",
		Timeout:   5 * time.Second,
	}

	request := TestRequest{
		Action: "fail",
		Data:   map[string]string{"test": "failure"},
	}

	_, err = observableManager.ExecuteWithObservability(ctx, failingMock.name, execCtx, request)
	if err == nil {
		t.Error("Expected execution to fail")
	}

	validateFailureMetrics(t, observableManager, failingMock.name)
}

// validateFailureMetrics validates metrics for failed execution
func validateFailureMetrics(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse], pluginName string) {
	report := observableManager.GetObservabilityMetrics()
	pluginReport, exists := report.Plugins[pluginName]
	if !exists {
		t.Error("Failing plugin should appear in observability report")
		return
	}

	if pluginReport.FailedRequests != 1 {
		t.Errorf("Expected 1 failed request, got %d", pluginReport.FailedRequests)
	}
	if pluginReport.TimeoutErrors != 1 {
		t.Errorf("Expected 1 timeout error, got %d", pluginReport.TimeoutErrors)
	}
}

// TestObservableManager_ConcurrentAccess tests concurrent access patterns
func TestObservableManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	observableManager := setupConcurrentTestEnvironment(t)

	const numRequests = 100
	errorCount := executeConcurrentRequests(observableManager, numRequests)

	verifyConcurrentMetricsConsistency(t, observableManager, numRequests, errorCount)
}

// setupConcurrentTestEnvironment creates the environment for concurrent testing
func setupConcurrentTestEnvironment(t *testing.T) *ObservableManager[TestRequest, TestResponse] {
	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	registerConcurrentTestPlugins(t, baseManager)
	return observableManager
}

// registerConcurrentTestPlugins registers test plugins for concurrent testing
func registerConcurrentTestPlugins(t *testing.T, baseManager *Manager[TestRequest, TestResponse]) {
	const numPlugins = 10
	for i := 0; i < numPlugins; i++ {
		mockPlug := &mockPlugin{
			name:          fmt.Sprintf("concurrent-plugin-%d", i),
			shouldFail:    i%3 == 0, // Every 3rd plugin fails
			failureType:   "connection",
			executeDelay:  time.Duration(i*10) * time.Millisecond,
			healthCheckOK: true,
		}

		err := baseManager.Register(mockPlug)
		if err != nil {
			t.Fatalf("Failed to register plugin %d: %v", i, err)
		}
	}
}

// executeConcurrentRequests executes concurrent requests and returns error count
func executeConcurrentRequests(observableManager *ObservableManager[TestRequest, TestResponse], numRequests int) int {
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)
	const numPlugins = 10

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestID int) {
			defer wg.Done()
			err := executeSingleConcurrentRequest(observableManager, requestID, numPlugins)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	return countErrors(errors)
}

// executeSingleConcurrentRequest executes a single concurrent request
func executeSingleConcurrentRequest(observableManager *ObservableManager[TestRequest, TestResponse], requestID, numPlugins int) error {
	pluginName := fmt.Sprintf("concurrent-plugin-%d", requestID%numPlugins)
	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: fmt.Sprintf("concurrent-request-%d", requestID),
		Timeout:   5 * time.Second,
	}

	request := TestRequest{
		Action: "concurrent-test",
		Data:   map[string]string{"request_id": fmt.Sprintf("%d", requestID)},
	}

	_, err := observableManager.ExecuteWithObservability(ctx, pluginName, execCtx, request)
	return err
}

// countErrors counts errors from the error channel
func countErrors(errors <-chan error) int {
	errorCount := 0
	for err := range errors {
		if err != nil {
			errorCount++
		}
	}
	return errorCount
}

// verifyConcurrentMetricsConsistency verifies metrics consistency after concurrent execution
func verifyConcurrentMetricsConsistency(t *testing.T, observableManager *ObservableManager[TestRequest, TestResponse], numRequests, errorCount int) {
	report := observableManager.GetObservabilityMetrics()

	totalRequests, totalSuccessful, totalFailed := aggregateConcurrentMetrics(report)

	validateConcurrentTotals(t, totalRequests, totalSuccessful, totalFailed, int64(numRequests))

	t.Logf("Concurrent test completed: %d requests, %d errors, %d successful", numRequests, errorCount, numRequests-errorCount)
}

// aggregateConcurrentMetrics aggregates metrics from all concurrent test plugins
func aggregateConcurrentMetrics(report ObservabilityReport) (int64, int64, int64) {
	var totalRequests, totalSuccessful, totalFailed int64

	for pluginName, pluginReport := range report.Plugins {
		if !strings.Contains(pluginName, "concurrent-plugin-") {
			continue
		}

		totalRequests += pluginReport.TotalRequests
		totalSuccessful += pluginReport.SuccessfulRequests
		totalFailed += pluginReport.FailedRequests
	}

	return totalRequests, totalSuccessful, totalFailed
}

// validateConcurrentTotals validates the totals from concurrent execution
func validateConcurrentTotals(t *testing.T, totalRequests, totalSuccessful, totalFailed, expectedRequests int64) {
	if totalRequests != expectedRequests {
		t.Errorf("Expected %d total requests, got %d", expectedRequests, totalRequests)
	}

	if totalSuccessful+totalFailed != totalRequests {
		t.Errorf("Successful + Failed (%d + %d = %d) should equal total (%d)", totalSuccessful, totalFailed, totalSuccessful+totalFailed, totalRequests)
	}
}

// BenchmarkDefaultMetricsCollector_Operations benchmarks basic collector operations
func BenchmarkDefaultMetricsCollector_Operations(b *testing.B) {
	collector := NewDefaultMetricsCollector()
	labels := map[string]string{"service": "benchmark", "env": "test"}

	b.Run("IncrementCounter", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			collector.IncrementCounter("benchmark_counter", labels, 1)
		}
	})

	b.Run("SetGauge", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			collector.SetGauge("benchmark_gauge", labels, float64(i))
		}
	})

	b.Run("RecordHistogram", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			collector.RecordHistogram("benchmark_histogram", labels, float64(i%1000))
		}
	})
}

// BenchmarkEnhancedMetricsCollector_Operations benchmarks enhanced collector operations
func BenchmarkEnhancedMetricsCollector_Operations(b *testing.B) {
	collector := NewEnhancedMetricsCollector()

	counter := collector.CounterWithLabels("benchmark_counter", "Benchmark counter", "service", "env")
	gauge := collector.GaugeWithLabels("benchmark_gauge", "Benchmark gauge", "service", "env")
	histogram := collector.HistogramWithLabels("benchmark_histogram", "Benchmark histogram", []float64{0.1, 1, 10}, "service", "env")

	b.Run("CounterInc", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			counter.Inc("benchmark", "test")
		}
	})

	b.Run("GaugeSet", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			gauge.Set(float64(i), "benchmark", "test")
		}
	})

	b.Run("HistogramObserve", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			histogram.Observe(float64(i%1000), "benchmark", "test")
		}
	})
}

// BenchmarkObservableManager_ExecuteWithObservability benchmarks the observable manager execution
func BenchmarkObservableManager_ExecuteWithObservability(b *testing.B) {
	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(&testing.T{}))
	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	mockPlug := &mockPlugin{
		name:          "benchmark-plugin",
		shouldFail:    false,
		executeDelay:  0, // No artificial delay for benchmarking
		healthCheckOK: true,
	}

	err := baseManager.Register(mockPlug)
	if err != nil {
		b.Fatalf("Failed to register mock plugin: %v", err)
	}

	ctx := context.Background()
	execCtx := ExecutionContext{
		RequestID: "benchmark-request",
		Timeout:   30 * time.Second,
	}

	request := TestRequest{
		Action: "benchmark",
		Data:   map[string]string{"test": "data"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := observableManager.ExecuteWithObservability(ctx, mockPlug.name, execCtx, request)
		if err != nil {
			b.Errorf("Execution failed: %v", err)
		}
	}
}

// BenchmarkErrorCategorization benchmarks error categorization functions
func BenchmarkErrorCategorization(b *testing.B) {
	testErrors := []error{
		goerrors.New(ErrCodePluginTimeout, "Timeout error"),
		goerrors.New(ErrCodePluginConnectionFailed, "Connection error"),
		goerrors.New(ErrCodeMissingAPIKey, "Auth error"),
		errors.New("generic error"),
		context.DeadlineExceeded,
	}

	b.Run("isTimeoutError", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := testErrors[i%len(testErrors)]
			_ = isTimeoutError(err)
		}
	})

	b.Run("isConnectionError", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := testErrors[i%len(testErrors)]
			_ = isConnectionError(err)
		}
	})

	b.Run("isAuthError", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := testErrors[i%len(testErrors)]
			_ = isAuthError(err)
		}
	})
}

// TestObservabilitySystem_MemoryUsage tests memory usage under load
func TestObservabilitySystem_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory usage test in short mode")
	}

	t.Parallel()

	baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
	config := DefaultObservabilityConfig()
	observableManager := NewObservableManager(baseManager, config)

	// Create plugins for memory testing
	const numPlugins = 50
	for i := 0; i < numPlugins; i++ {
		mockPlug := &mockPlugin{
			name:          fmt.Sprintf("memory-test-plugin-%d", i),
			shouldFail:    false,
			executeDelay:  time.Millisecond,
			healthCheckOK: true,
		}

		err := baseManager.Register(mockPlug)
		if err != nil {
			t.Fatalf("Failed to register plugin %d: %v", i, err)
		}
	}

	// Execute many requests to build up metrics data
	const numRequests = 2000 // Reduced for faster testing

	ctx := context.Background()
	request := TestRequest{
		Action: "memory-test",
		Data:   map[string]string{"load": "test"},
	}

	for i := 0; i < numRequests; i++ {
		pluginName := fmt.Sprintf("memory-test-plugin-%d", i%numPlugins)
		execCtx := ExecutionContext{
			RequestID: fmt.Sprintf("memory-request-%d", i),
			Timeout:   5 * time.Second,
		}

		// Intentionally ignore result and error for memory testing - we only care about metrics accumulation
		// We capture the error but don't act on it in this stress test scenario
		if _, err := observableManager.ExecuteWithObservability(ctx, pluginName, execCtx, request); err != nil {
			// Error is expected in stress testing - plugin may fail under load
			_ = err // Explicitly ignore for errcheck compliance
		}

		// Periodically check that metrics are being managed properly
		if i%1000 == 0 && i > 0 { // Skip the first check since not all plugins will have been used yet
			report := observableManager.GetObservabilityMetrics()
			// By this point we should have seen most plugins (at least half)
			if len(report.Plugins) < numPlugins/2 {
				t.Errorf("Expected at least %d plugins in report, got %d at iteration %d", numPlugins/2, len(report.Plugins), i)
			}
		}
	}

	// Final verification
	finalReport := observableManager.GetObservabilityMetrics()

	if len(finalReport.Plugins) != numPlugins {
		t.Errorf("Expected %d plugins in final report, got %d", numPlugins, len(finalReport.Plugins))
	}

	// Verify total requests across all plugins
	totalRequests := int64(0)
	for _, pluginReport := range finalReport.Plugins {
		totalRequests += pluginReport.TotalRequests
	}

	if totalRequests != numRequests {
		t.Errorf("Expected %d total requests across all plugins, got %d", numRequests, totalRequests)
	}

	t.Logf("Memory test completed: %d requests across %d plugins", numRequests, numPlugins)
}

// TestObservabilitySystem_EdgeCases tests edge cases and error conditions
func TestObservabilitySystem_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("NilMetricsCollectorHandling", func(t *testing.T) {
		baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
		config := DefaultObservabilityConfig()
		config.MetricsCollector = nil // Explicitly set to nil

		observableManager := NewObservableManager(baseManager, config)

		if observableManager.metricsCollector == nil {
			t.Error("Metrics collector should be created when nil provided")
		}
	})

	t.Run("DisabledMetricsCollection", func(t *testing.T) {
		baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
		config := DefaultObservabilityConfig()
		config.MetricsEnabled = false

		observableManager := NewObservableManager(baseManager, config)

		mockPlug := &mockPlugin{
			name:          "disabled-metrics-plugin",
			shouldFail:    false,
			healthCheckOK: true,
		}

		err := baseManager.Register(mockPlug)
		if err != nil {
			t.Fatalf("Failed to register mock plugin: %v", err)
		}

		ctx := context.Background()
		execCtx := ExecutionContext{
			RequestID: "disabled-metrics-test",
			Timeout:   5 * time.Second,
		}

		request := TestRequest{
			Action: "test",
			Data:   map[string]string{"metrics": "disabled"},
		}

		_, err = observableManager.ExecuteWithObservability(ctx, mockPlug.name, execCtx, request)
		if err != nil {
			t.Errorf("Execution should succeed even with metrics disabled: %v", err)
		}

		// Should still track basic metrics for reporting
		report := observableManager.GetObservabilityMetrics()
		if len(report.Plugins) == 0 {
			t.Error("Plugin metrics should still be tracked even when external metrics collection is disabled")
		}
	})

	t.Run("EmptyLabelsHandling", func(t *testing.T) {
		collector := NewDefaultMetricsCollector()

		// Test with nil labels
		collector.IncrementCounter("test_counter", nil, 1)
		collector.SetGauge("test_gauge", nil, 1.0)
		collector.RecordHistogram("test_histogram", nil, 1.0)

		// Test with empty labels
		emptyLabels := make(map[string]string)
		collector.IncrementCounter("test_counter", emptyLabels, 1)
		collector.SetGauge("test_gauge", emptyLabels, 2.0)
		collector.RecordHistogram("test_histogram", emptyLabels, 2.0)

		metrics := collector.GetMetrics()
		if len(metrics) == 0 {
			t.Error("Metrics should be recorded even with nil/empty labels")
		}
	})

	t.Run("ExtremeLatencyValues", func(t *testing.T) {
		baseManager := NewManager[TestRequest, TestResponse](createTestLogger(t))
		config := DefaultObservabilityConfig()
		observableManager := NewObservableManager(baseManager, config)

		pluginName := "extreme-latency-plugin"
		observableManager.ensurePluginMetrics(pluginName)

		// Test extreme latency values
		extremeLatencies := []time.Duration{
			0,                            // Zero latency
			1 * time.Nanosecond,          // Minimum non-zero
			24 * time.Hour,               // Very long operation
			time.Duration(math.MaxInt64), // Maximum possible duration
		}

		for _, latency := range extremeLatencies {
			observableManager.recordLatency(pluginName, latency)
		}

		// Should handle extreme values without panicking
		report := observableManager.GetObservabilityMetrics()
		pluginReport, exists := report.Plugins[pluginName]
		if !exists {
			t.Error("Plugin should exist in report")
		} else {
			// Basic sanity checks
			if pluginReport.MinLatency < 0 {
				t.Error("Min latency should not be negative")
			}
			if pluginReport.MaxLatency < pluginReport.MinLatency {
				t.Error("Max latency should be >= min latency")
			}
		}
	})
}
