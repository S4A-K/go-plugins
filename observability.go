// observability.go: Comprehensive observability system with metrics, logging, and tracing
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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	goerrors "github.com/agilira/go-errors"
	"github.com/agilira/go-timecache"
)

// MetricsCollector defines the core interface for collecting plugin metrics across different providers.
//
// This interface provides a standardized way to collect performance and operational
// metrics from plugins, supporting various backend systems like Prometheus, StatsD,
// or custom metrics solutions. It enables consistent metric collection regardless
// of the underlying metrics infrastructure.
//
// Supported metric types:
//   - Counter: Monotonically increasing values (requests, errors, operations)
//   - Gauge: Current state values (active connections, memory usage, queue depth)
//   - Histogram: Distribution of values (response times, request sizes, processing duration)
//   - Custom: Provider-specific metrics with flexible value types
//
// Example usage:
//
//	collector.IncrementCounter("plugin_requests_total",
//	    map[string]string{"plugin": "auth", "method": "validate"}, 1)
//	collector.SetGauge("plugin_connections_active",
//	    map[string]string{"plugin": "database"}, 42)
//	collector.RecordHistogram("plugin_response_time_seconds",
//	    map[string]string{"plugin": "api"}, 0.125)
type MetricsCollector interface {
	// Counter metrics
	IncrementCounter(name string, labels map[string]string, value int64)

	// Gauge metrics
	SetGauge(name string, labels map[string]string, value float64)

	// Histogram metrics
	RecordHistogram(name string, labels map[string]string, value float64)

	// Custom metrics
	RecordCustomMetric(name string, labels map[string]string, value interface{})

	// Get current metrics snapshot
	GetMetrics() map[string]interface{}
}

// EnhancedMetricsCollector extends MetricsCollector with native label support and type safety.
//
// This interface is designed to be compatible with Prometheus and other modern metrics
// systems that support strongly-typed metrics with predefined label schemas. It provides
// better performance and type safety compared to the basic MetricsCollector interface
// by avoiding map allocations and string-based label handling.
//
// Key advantages:
//   - Type-safe metric creation with predefined label names
//   - Better performance through reduced allocations
//   - Prometheus-compatible metric definitions
//   - Compile-time validation of metric usage
//
// Example usage:
//
//	counter := collector.CounterWithLabels("plugin_requests_total",
//	    "Total plugin requests", "plugin", "method", "status")
//	counter.With("auth", "validate", "success").Inc()
//
//	gauge := collector.GaugeWithLabels("plugin_connections",
//	    "Active plugin connections", "plugin")
//	gauge.With("database").Set(42)
type EnhancedMetricsCollector interface {
	MetricsCollector // Embed the original interface for backward compatibility

	// Enhanced metrics with native label support
	CounterWithLabels(name, description string, labelNames ...string) CounterMetric
	GaugeWithLabels(name, description string, labelNames ...string) GaugeMetric
	HistogramWithLabels(name, description string, buckets []float64, labelNames ...string) HistogramMetric

	// Get metrics in Prometheus-compatible format
	GetPrometheusMetrics() []PrometheusMetric
}

// CounterMetric represents a counter with native label support
type CounterMetric interface {
	Inc(labelValues ...string)
	Add(value float64, labelValues ...string)
}

// GaugeMetric represents a gauge with native label support
type GaugeMetric interface {
	Set(value float64, labelValues ...string)
	Inc(labelValues ...string)
	Dec(labelValues ...string)
	Add(value float64, labelValues ...string)
}

// HistogramMetric represents a histogram with native label support
type HistogramMetric interface {
	Observe(value float64, labelValues ...string)
}

// PrometheusMetric represents a metric in Prometheus format
type PrometheusMetric struct {
	Name        string             `json:"name"`
	Type        string             `json:"type"` // counter, gauge, histogram
	Description string             `json:"description"`
	Value       float64            `json:"value,omitempty"`
	Labels      map[string]string  `json:"labels,omitempty"`
	Buckets     []PrometheusBucket `json:"buckets,omitempty"` // For histograms
}

// PrometheusBucket represents a histogram bucket
type PrometheusBucket struct {
	UpperBound float64 `json:"upper_bound"`
	Count      uint64  `json:"count"`
}

// MetricsExporter defines the interface for exporting metrics to external systems.
//
// This interface enables flexible integration with various observability backends
// without coupling the core metrics collection to specific implementations.
// Exporters can be chained, filtered, or replaced without affecting metric collection.
//
// Key design principles:
//   - Zero dependencies: Interface has no external dependencies
//   - Async-friendly: Export operations can be batched and async
//   - Error resilient: Export failures don't affect metric collection
//   - Pluggable: Multiple exporters can be registered simultaneously
//
// Example implementations:
//   - PrometheusExporter: HTTP endpoint for Prometheus scraping
//   - OpenTelemetryExporter: OTLP protocol for OpenTelemetry collectors
//   - StatsDExporter: UDP/TCP exporter for StatsD/DogStatsD
//   - LogExporter: Structured logging of metrics
//   - CloudExporter: AWS CloudWatch, GCP Cloud Monitoring, Azure Monitor
//
// Example usage:
//
//	registry := NewMetricsRegistry()
//	registry.RegisterExporter(NewPrometheusExporter())
//	registry.RegisterExporter(NewOpenTelemetryExporter())
//
//	// Metrics are automatically exported to all registered exporters
//	registry.Counter("requests_total").Inc("handler", "api")
type MetricsExporter interface {
	// Export metrics in the exporter's native format
	Export(ctx context.Context, metrics []ExportableMetric) error

	// Name returns the exporter identifier for logging and debugging
	Name() string

	// Supports returns true if the exporter can handle the given metric type
	Supports(metricType MetricType) bool

	// Close gracefully shuts down the exporter, flushing any pending metrics
	Close(ctx context.Context) error
}

// MetricsRegistry defines the interface for managing metric lifecycle and export.
//
// The registry acts as the central coordinator between metric collection and export,
// providing lifecycle management, batching, filtering, and error handling.
// It enables complex observability setups while maintaining simple interfaces.
//
// Key capabilities:
//   - Metric registration and deregistration
//   - Automatic export scheduling and batching
//   - Exporter health monitoring and failover
//   - Metric filtering and transformation
//   - Performance optimizations (sampling, aggregation)
//
// Example usage:
//
//	registry := NewMetricsRegistry(RegistryConfig{
//	    ExportInterval: 15 * time.Second,
//	    BatchSize:      1000,
//	    ErrorPolicy:    ErrorPolicyRetry,
//	})
//
//	counter := registry.Counter("api_requests", "Tracks API requests", "method", "status")
//	gauge := registry.Gauge("queue_depth", "Current queue depth", "queue")
//	histogram := registry.Histogram("response_time", "Response times", DefaultBuckets, "endpoint")
type MetricsRegistry interface {
	// Metric creation with type safety and metadata
	Counter(name, description string, labelNames ...string) CounterMetric
	Gauge(name, description string, labelNames ...string) GaugeMetric
	Histogram(name, description string, buckets []float64, labelNames ...string) HistogramMetric

	// Exporter management
	RegisterExporter(exporter MetricsExporter) error
	UnregisterExporter(name string) error
	ListExporters() []string

	// Registry lifecycle
	Start(ctx context.Context) error
	Stop(ctx context.Context) error

	// Metrics introspection
	ListMetrics() []MetricInfo
	GetMetric(name string) (ExportableMetric, bool)
}

// ExportableMetric represents a metric in a standardized format for export.
//
// This format is designed to be easily convertible to various observability
// formats (Prometheus, OpenTelemetry, StatsD, etc.) while preserving
// all necessary metadata and type information.
type ExportableMetric struct {
	Name        string            `json:"name"`
	Type        MetricType        `json:"type"`
	Description string            `json:"description"`
	Value       interface{}       `json:"value"` // Type depends on MetricType
	Labels      map[string]string `json:"labels"`
	Timestamp   time.Time         `json:"timestamp"`

	// Type-specific data
	Buckets   []MetricBucket `json:"buckets,omitempty"`   // For histograms
	Quantiles []Quantile     `json:"quantiles,omitempty"` // For summaries
	Exemplars []Exemplar     `json:"exemplars,omitempty"` // For trace correlation
}

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// MetricBucket represents a histogram bucket
type MetricBucket struct {
	UpperBound float64 `json:"upper_bound"`
	Count      uint64  `json:"count"`
}

// Quantile represents a summary quantile
type Quantile struct {
	Quantile float64 `json:"quantile"`
	Value    float64 `json:"value"`
}

// Exemplar represents a trace exemplar for metric correlation
type Exemplar struct {
	Labels    map[string]string `json:"labels"`
	Value     float64           `json:"value"`
	Timestamp time.Time         `json:"timestamp"`
	TraceID   string            `json:"trace_id,omitempty"`
}

// MetricInfo provides metadata about registered metrics
type MetricInfo struct {
	Name        string     `json:"name"`
	Type        MetricType `json:"type"`
	Description string     `json:"description"`
	LabelNames  []string   `json:"label_names"`
	CreatedAt   time.Time  `json:"created_at"`
}

// TracingProvider defines interface for distributed tracing
type TracingProvider interface {
	// Start a new span
	StartSpan(ctx context.Context, operationName string) (context.Context, Span)

	// Extract tracing context from headers/metadata
	ExtractContext(headers map[string]string) context.Context

	// Inject tracing context into headers/metadata
	InjectContext(ctx context.Context) map[string]string
}

// Span represents a tracing span
type Span interface {
	// Set span attributes
	SetAttribute(key string, value interface{})

	// Set span status
	SetStatus(code SpanStatusCode, message string)

	// Finish the span
	Finish()

	// Get span context for propagation
	Context() interface{}
}

// SpanStatusCode represents span status
// SpanStatusCode represents the status of a distributed tracing span.
//
// These status codes are used to categorize the outcome of operations
// for distributed tracing analysis and monitoring dashboards.
type SpanStatusCode int

const (
	SpanStatusOK SpanStatusCode = iota
	SpanStatusError
	SpanStatusTimeout
)

// ObservabilityConfig configures the observability system
type ObservabilityConfig struct {
	// Metrics
	MetricsEnabled           bool                     `json:"metrics_enabled"`
	MetricsCollector         MetricsCollector         `json:"-"`
	EnhancedMetricsCollector EnhancedMetricsCollector `json:"-"` // Optional: for native label support
	MetricsPrefix            string                   `json:"metrics_prefix"`

	// Tracing
	TracingEnabled    bool            `json:"tracing_enabled"`
	TracingProvider   TracingProvider `json:"-"`
	TracingSampleRate float64         `json:"tracing_sample_rate"`

	// Logging
	LoggingEnabled    bool   `json:"logging_enabled"`
	LogLevel          string `json:"log_level"`
	StructuredLogging bool   `json:"structured_logging"`

	// Health monitoring
	HealthMetrics      bool `json:"health_metrics"`
	PerformanceMetrics bool `json:"performance_metrics"`
	ErrorMetrics       bool `json:"error_metrics"`
}

// DefaultObservabilityConfig returns default observability configuration
func DefaultObservabilityConfig() ObservabilityConfig {
	return ObservabilityConfig{
		MetricsEnabled:     true,
		MetricsCollector:   NewDefaultMetricsCollector(),
		MetricsPrefix:      "goplugins",
		TracingEnabled:     false, // Disabled by default
		TracingSampleRate:  0.1,   // 10% sampling
		LoggingEnabled:     true,
		LogLevel:           "info",
		StructuredLogging:  true,
		HealthMetrics:      true,
		PerformanceMetrics: true,
		ErrorMetrics:       true,
	}
}

// EnhancedObservabilityConfig returns observability configuration with enhanced metrics collector
func EnhancedObservabilityConfig() ObservabilityConfig {
	enhancedCollector := NewEnhancedMetricsCollector()
	return ObservabilityConfig{
		MetricsEnabled:           true,
		MetricsCollector:         enhancedCollector, // Backward compatibility
		EnhancedMetricsCollector: enhancedCollector, // Native label support
		MetricsPrefix:            "goplugins",
		TracingEnabled:           false, // Disabled by default
		TracingSampleRate:        0.1,   // 10% sampling
		LoggingEnabled:           true,
		LogLevel:                 "info",
		StructuredLogging:        true,
		HealthMetrics:            true,
		PerformanceMetrics:       true,
		ErrorMetrics:             true,
	}
}

// ObservableManager extends Manager with comprehensive observability
type ObservableManager[Req, Resp any] struct {
	*Manager[Req, Resp]
	config           ObservabilityConfig
	metricsCollector MetricsCollector
	tracingProvider  TracingProvider
	logger           Logger

	// Runtime metrics
	startTime      time.Time
	totalRequests  *atomic.Int64
	totalErrors    *atomic.Int64
	activeRequests *atomic.Int64

	// Plugin-specific metrics
	pluginMetrics map[string]*PluginObservabilityMetrics
	metricsMu     sync.RWMutex
}

// PluginObservabilityMetrics contains detailed metrics for a single plugin
type PluginObservabilityMetrics struct {
	// Request metrics
	TotalRequests      *atomic.Int64
	SuccessfulRequests *atomic.Int64
	FailedRequests     *atomic.Int64
	ActiveRequests     *atomic.Int64

	// Timing metrics
	TotalLatency *atomic.Int64 // Total latency in nanoseconds
	MinLatency   *atomic.Int64
	MaxLatency   *atomic.Int64
	AvgLatency   *atomic.Int64

	// Error metrics
	TimeoutErrors    *atomic.Int64
	ConnectionErrors *atomic.Int64
	AuthErrors       *atomic.Int64
	OtherErrors      *atomic.Int64

	// Circuit breaker metrics
	CircuitBreakerTrips *atomic.Int64
	CircuitBreakerState string

	// Health metrics
	HealthCheckTotal  *atomic.Int64
	HealthCheckFailed *atomic.Int64
	LastHealthCheck   *atomic.Int64 // Unix timestamp
	HealthStatus      string
}

// NewObservableManager creates a new observable manager
func NewObservableManager[Req, Resp any](baseManager *Manager[Req, Resp], config ObservabilityConfig) *ObservableManager[Req, Resp] {
	if config.MetricsCollector == nil {
		config.MetricsCollector = NewDefaultMetricsCollector()
	}

	return &ObservableManager[Req, Resp]{
		Manager:          baseManager,
		config:           config,
		metricsCollector: config.MetricsCollector,
		tracingProvider:  config.TracingProvider,
		logger:           baseManager.logger,
		startTime:        timecache.CachedTime(),
		totalRequests:    &atomic.Int64{},
		totalErrors:      &atomic.Int64{},
		activeRequests:   &atomic.Int64{},
		pluginMetrics:    make(map[string]*PluginObservabilityMetrics),
	}
}

// ExecuteWithObservability executes a request with full observability
func (om *ObservableManager[Req, Resp]) ExecuteWithObservability(ctx context.Context, pluginName string, execCtx ExecutionContext, request Req) (Resp, error) {
	startTime := timecache.CachedTime()

	// Setup observability tracking
	om.startObservabilityTracking(pluginName)
	defer om.activeRequests.Add(-1)

	pluginMetrics := om.getPluginMetrics(pluginName)
	pluginMetrics.TotalRequests.Add(1)
	pluginMetrics.ActiveRequests.Add(1)
	defer pluginMetrics.ActiveRequests.Add(-1)

	// Setup tracing
	ctx, span := om.setupTracing(ctx, pluginName, execCtx)
	if span != nil {
		defer span.Finish()
		om.injectTracingHeaders(ctx, &execCtx)
	}

	// Execute request
	response, err := om.Manager.ExecuteWithOptions(ctx, pluginName, execCtx, request)
	latency := time.Since(startTime)

	// Handle result and cleanup
	om.handleExecutionResult(pluginName, pluginMetrics, span, latency, err, execCtx)

	return response, err
}

// startObservabilityTracking initializes request tracking metrics
func (om *ObservableManager[Req, Resp]) startObservabilityTracking(pluginName string) {
	om.totalRequests.Add(1)
	om.activeRequests.Add(1)
	om.ensurePluginMetrics(pluginName)
}

// setupTracing initializes tracing span if enabled
func (om *ObservableManager[Req, Resp]) setupTracing(ctx context.Context, pluginName string, execCtx ExecutionContext) (context.Context, Span) {
	if !om.config.TracingEnabled || om.tracingProvider == nil {
		return ctx, nil
	}

	ctx, span := om.tracingProvider.StartSpan(ctx, fmt.Sprintf("plugin.execute.%s", pluginName))
	span.SetAttribute("plugin.name", pluginName)
	span.SetAttribute("request.id", execCtx.RequestID)
	span.SetAttribute("request.timeout", execCtx.Timeout.String())

	return ctx, span
}

// injectTracingHeaders adds tracing context to execution context
func (om *ObservableManager[Req, Resp]) injectTracingHeaders(ctx context.Context, execCtx *ExecutionContext) {
	if execCtx.Headers == nil {
		execCtx.Headers = make(map[string]string)
	}
	tracingHeaders := om.tracingProvider.InjectContext(ctx)
	for k, v := range tracingHeaders {
		execCtx.Headers[k] = v
	}
}

// handleExecutionResult processes the result of plugin execution and updates metrics
func (om *ObservableManager[Req, Resp]) handleExecutionResult(pluginName string, pluginMetrics *PluginObservabilityMetrics, span Span, latency time.Duration, err error, execCtx ExecutionContext) {
	if err != nil {
		om.handleExecutionError(pluginName, pluginMetrics, span, err)
	} else {
		om.handleExecutionSuccess(pluginMetrics, span)
	}

	om.recordLatency(pluginName, latency)
	om.recordMetricsIfEnabled(pluginName, latency, err)
	om.logRequestIfEnabled(pluginName, execCtx, latency, err)
}

// handleExecutionError processes failed execution
func (om *ObservableManager[Req, Resp]) handleExecutionError(pluginName string, pluginMetrics *PluginObservabilityMetrics, span Span, err error) {
	om.totalErrors.Add(1)
	pluginMetrics.FailedRequests.Add(1)
	om.recordError(pluginName, err)

	if span != nil {
		span.SetStatus(SpanStatusError, err.Error())
		span.SetAttribute("error", true)
		span.SetAttribute("error.message", err.Error())
	}
}

// handleExecutionSuccess processes successful execution
func (om *ObservableManager[Req, Resp]) handleExecutionSuccess(pluginMetrics *PluginObservabilityMetrics, span Span) {
	pluginMetrics.SuccessfulRequests.Add(1)
	if span != nil {
		span.SetStatus(SpanStatusOK, "success")
	}
}

// recordMetricsIfEnabled records metrics if enabled
func (om *ObservableManager[Req, Resp]) recordMetricsIfEnabled(pluginName string, latency time.Duration, err error) {
	if om.config.MetricsEnabled && om.metricsCollector != nil {
		om.recordToMetricsCollector(pluginName, latency, err)
	}
}

// logRequestIfEnabled logs request if enabled
func (om *ObservableManager[Req, Resp]) logRequestIfEnabled(pluginName string, execCtx ExecutionContext, latency time.Duration, err error) {
	if om.config.LoggingEnabled {
		om.logRequest(pluginName, execCtx, latency, err)
	}
}

// ensurePluginMetrics ensures plugin metrics exist
func (om *ObservableManager[Req, Resp]) ensurePluginMetrics(pluginName string) {
	om.metricsMu.RLock()
	_, exists := om.pluginMetrics[pluginName]
	om.metricsMu.RUnlock()

	if !exists {
		om.metricsMu.Lock()
		if _, exists := om.pluginMetrics[pluginName]; !exists {
			om.pluginMetrics[pluginName] = &PluginObservabilityMetrics{
				TotalRequests:       &atomic.Int64{},
				SuccessfulRequests:  &atomic.Int64{},
				FailedRequests:      &atomic.Int64{},
				ActiveRequests:      &atomic.Int64{},
				TotalLatency:        &atomic.Int64{},
				MinLatency:          &atomic.Int64{},
				MaxLatency:          &atomic.Int64{},
				AvgLatency:          &atomic.Int64{},
				TimeoutErrors:       &atomic.Int64{},
				ConnectionErrors:    &atomic.Int64{},
				AuthErrors:          &atomic.Int64{},
				OtherErrors:         &atomic.Int64{},
				CircuitBreakerTrips: &atomic.Int64{},
				HealthCheckTotal:    &atomic.Int64{},
				HealthCheckFailed:   &atomic.Int64{},
				LastHealthCheck:     &atomic.Int64{},
			}
			// Initialize min latency to max value
			om.pluginMetrics[pluginName].MinLatency.Store(int64(^uint64(0) >> 1))
		}
		om.metricsMu.Unlock()
	}
}

// getPluginMetrics safely retrieves plugin metrics
func (om *ObservableManager[Req, Resp]) getPluginMetrics(pluginName string) *PluginObservabilityMetrics {
	om.metricsMu.RLock()
	defer om.metricsMu.RUnlock()
	return om.pluginMetrics[pluginName]
}

// recordError categorizes and records error metrics
func (om *ObservableManager[Req, Resp]) recordError(pluginName string, err error) {
	pluginMetrics := om.getPluginMetrics(pluginName)

	// Categorize error
	switch {
	case isTimeoutError(err):
		pluginMetrics.TimeoutErrors.Add(1)
	case isConnectionError(err):
		pluginMetrics.ConnectionErrors.Add(1)
	case isAuthError(err):
		pluginMetrics.AuthErrors.Add(1)
	default:
		pluginMetrics.OtherErrors.Add(1)
	}
}

// recordLatency records latency metrics with min/max/avg calculations
func (om *ObservableManager[Req, Resp]) recordLatency(pluginName string, latency time.Duration) {
	pluginMetrics := om.getPluginMetrics(pluginName)
	latencyNs := latency.Nanoseconds()

	// Update total latency
	pluginMetrics.TotalLatency.Add(latencyNs)

	// Update min latency
	for {
		currentMin := pluginMetrics.MinLatency.Load()
		if latencyNs >= currentMin {
			break
		}
		if pluginMetrics.MinLatency.CompareAndSwap(currentMin, latencyNs) {
			break
		}
	}

	// Update max latency
	for {
		currentMax := pluginMetrics.MaxLatency.Load()
		if latencyNs <= currentMax {
			break
		}
		if pluginMetrics.MaxLatency.CompareAndSwap(currentMax, latencyNs) {
			break
		}
	}

	// Calculate and update average latency
	totalRequests := pluginMetrics.TotalRequests.Load()
	if totalRequests > 0 {
		totalLatency := pluginMetrics.TotalLatency.Load()
		avgLatency := totalLatency / totalRequests
		pluginMetrics.AvgLatency.Store(avgLatency)
	}
}

// recordToMetricsCollector records metrics to the external collector
func (om *ObservableManager[Req, Resp]) recordToMetricsCollector(pluginName string, latency time.Duration, err error) {
	labels := map[string]string{
		"plugin_name": pluginName,
	}

	// Record request counter
	om.metricsCollector.IncrementCounter(
		om.config.MetricsPrefix+"_requests_total",
		labels,
		1,
	)

	// Record latency histogram
	om.metricsCollector.RecordHistogram(
		om.config.MetricsPrefix+"_request_duration_seconds",
		labels,
		latency.Seconds(),
	)

	// Record error metrics
	if err != nil {
		errorLabels := make(map[string]string)
		for k, v := range labels {
			errorLabels[k] = v
		}

		// Add error type
		switch {
		case isTimeoutError(err):
			errorLabels["error_type"] = "timeout"
		case isConnectionError(err):
			errorLabels["error_type"] = "connection"
		case isAuthError(err):
			errorLabels["error_type"] = "authentication"
		default:
			errorLabels["error_type"] = "other"
		}

		om.metricsCollector.IncrementCounter(
			om.config.MetricsPrefix+"_errors_total",
			errorLabels,
			1,
		)
	}
}

// logRequest logs structured request information
func (om *ObservableManager[Req, Resp]) logRequest(pluginName string, execCtx ExecutionContext, latency time.Duration, err error) {
	if err != nil {
		om.logger.Warn("Plugin request failed",
			"plugin", pluginName,
			"request_id", execCtx.RequestID,
			"latency", latency,
			"success", false,
			"error", err.Error())
	} else {
		om.logger.Debug("Plugin request completed",
			"plugin", pluginName,
			"request_id", execCtx.RequestID,
			"latency", latency,
			"success", true)
	}
}

// GetObservabilityMetrics returns comprehensive metrics
func (om *ObservableManager[Req, Resp]) GetObservabilityMetrics() ObservabilityReport {
	om.metricsMu.RLock()
	defer om.metricsMu.RUnlock()

	report := ObservabilityReport{
		GeneratedAt: timecache.CachedTime(),
		UpTime:      time.Since(om.startTime),
		Global: GlobalMetrics{
			TotalRequests:  om.totalRequests.Load(),
			TotalErrors:    om.totalErrors.Load(),
			ActiveRequests: om.activeRequests.Load(),
		},
		Plugins: make(map[string]PluginMetricsReport),
	}

	for pluginName, metrics := range om.pluginMetrics {
		totalReq := metrics.TotalRequests.Load()
		successReq := metrics.SuccessfulRequests.Load()
		failedReq := metrics.FailedRequests.Load()

		var successRate float64
		if totalReq > 0 {
			successRate = (float64(successReq) / float64(totalReq)) * 100
		}

		report.Plugins[pluginName] = PluginMetricsReport{
			TotalRequests:       totalReq,
			SuccessfulRequests:  successReq,
			FailedRequests:      failedReq,
			ActiveRequests:      metrics.ActiveRequests.Load(),
			SuccessRate:         successRate,
			MinLatency:          time.Duration(metrics.MinLatency.Load()),
			MaxLatency:          time.Duration(metrics.MaxLatency.Load()),
			AvgLatency:          time.Duration(metrics.AvgLatency.Load()),
			TimeoutErrors:       metrics.TimeoutErrors.Load(),
			ConnectionErrors:    metrics.ConnectionErrors.Load(),
			AuthErrors:          metrics.AuthErrors.Load(),
			OtherErrors:         metrics.OtherErrors.Load(),
			CircuitBreakerTrips: metrics.CircuitBreakerTrips.Load(),
			HealthCheckTotal:    metrics.HealthCheckTotal.Load(),
			HealthCheckFailed:   metrics.HealthCheckFailed.Load(),
		}
	}

	return report
}

// ObservabilityReport contains comprehensive metrics report
type ObservabilityReport struct {
	GeneratedAt time.Time                      `json:"generated_at"`
	UpTime      time.Duration                  `json:"uptime"`
	Global      GlobalMetrics                  `json:"global"`
	Plugins     map[string]PluginMetricsReport `json:"plugins"`
}

// GlobalMetrics contains system-wide metrics
type GlobalMetrics struct {
	TotalRequests  int64 `json:"total_requests"`
	TotalErrors    int64 `json:"total_errors"`
	ActiveRequests int64 `json:"active_requests"`
}

// PluginMetricsReport contains metrics for a single plugin
type PluginMetricsReport struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	ActiveRequests      int64         `json:"active_requests"`
	SuccessRate         float64       `json:"success_rate_percent"`
	MinLatency          time.Duration `json:"min_latency"`
	MaxLatency          time.Duration `json:"max_latency"`
	AvgLatency          time.Duration `json:"avg_latency"`
	TimeoutErrors       int64         `json:"timeout_errors"`
	ConnectionErrors    int64         `json:"connection_errors"`
	AuthErrors          int64         `json:"auth_errors"`
	OtherErrors         int64         `json:"other_errors"`
	CircuitBreakerTrips int64         `json:"circuit_breaker_trips"`
	HealthCheckTotal    int64         `json:"health_check_total"`
	HealthCheckFailed   int64         `json:"health_check_failed"`
}

// DefaultMetricsCollector provides a basic in-memory metrics collector
type DefaultMetricsCollector struct {
	mu         sync.RWMutex
	counters   map[string]int64
	gauges     map[string]float64
	histograms map[string][]float64
}

// NewDefaultMetricsCollector creates a new default metrics collector
func NewDefaultMetricsCollector() *DefaultMetricsCollector {
	return &DefaultMetricsCollector{
		counters:   make(map[string]int64),
		gauges:     make(map[string]float64),
		histograms: make(map[string][]float64),
	}
}

// NewEnhancedMetricsCollector creates a new enhanced metrics collector with native label support
func NewEnhancedMetricsCollector() EnhancedMetricsCollector {
	return NewDefaultEnhancedMetricsCollector()
}

// IncrementCounter implements MetricsCollector
func (dmc *DefaultMetricsCollector) IncrementCounter(name string, labels map[string]string, value int64) {
	dmc.mu.Lock()
	defer dmc.mu.Unlock()

	key := dmc.buildKey(name, labels)
	dmc.counters[key] += value
}

// SetGauge implements MetricsCollector
func (dmc *DefaultMetricsCollector) SetGauge(name string, labels map[string]string, value float64) {
	dmc.mu.Lock()
	defer dmc.mu.Unlock()

	key := dmc.buildKey(name, labels)
	dmc.gauges[key] = value
}

// RecordHistogram implements MetricsCollector
func (dmc *DefaultMetricsCollector) RecordHistogram(name string, labels map[string]string, value float64) {
	dmc.mu.Lock()
	defer dmc.mu.Unlock()

	key := dmc.buildKey(name, labels)
	dmc.histograms[key] = append(dmc.histograms[key], value)

	// Keep only last 1000 values to prevent memory growth
	if len(dmc.histograms[key]) > 1000 {
		dmc.histograms[key] = dmc.histograms[key][len(dmc.histograms[key])-1000:]
	}
}

// RecordCustomMetric implements MetricsCollector
func (dmc *DefaultMetricsCollector) RecordCustomMetric(name string, labels map[string]string, value interface{}) {
	// For the default implementation, we convert to appropriate type
	switch v := value.(type) {
	case int64:
		dmc.IncrementCounter(name, labels, v)
	case float64:
		dmc.SetGauge(name, labels, v)
	default:
		// Ignore unsupported types in default implementation
	}
}

// GetMetrics implements MetricsCollector
func (dmc *DefaultMetricsCollector) GetMetrics() map[string]interface{} {
	dmc.mu.RLock()
	defer dmc.mu.RUnlock()

	metrics := make(map[string]interface{})

	for k, v := range dmc.counters {
		metrics[k] = v
	}

	for k, v := range dmc.gauges {
		metrics[k] = v
	}

	for k, v := range dmc.histograms {
		if len(v) > 0 {
			// Calculate basic histogram stats
			sum := 0.0
			minVal := v[0]
			maxVal := v[0]

			for _, val := range v {
				sum += val
				if val < minVal {
					minVal = val
				}
				if val > maxVal {
					maxVal = val
				}
			}

			metrics[k+"_count"] = len(v)
			metrics[k+"_sum"] = sum
			metrics[k+"_min"] = minVal
			metrics[k+"_max"] = maxVal
			metrics[k+"_avg"] = sum / float64(len(v))
		}
	}

	return metrics
}

// buildKey builds a metric key from name and labels
func (dmc *DefaultMetricsCollector) buildKey(name string, labels map[string]string) string {
	key := name
	// Sort labels by key to ensure consistent ordering
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		key += fmt.Sprintf("_%s_%s", k, labels[k])
	}
	return key
}

// DefaultEnhancedMetricsCollector provides an enhanced metrics collector with native label support
type DefaultEnhancedMetricsCollector struct {
	*DefaultMetricsCollector // Embed for backward compatibility

	mu         sync.RWMutex
	counters   map[string]*enhancedCounter
	gauges     map[string]*enhancedGauge
	histograms map[string]*enhancedHistogram
}

// enhancedCounter implements CounterMetric
type enhancedCounter struct {
	name        string
	description string
	labelNames  []string
	values      map[string]float64 // label values hash -> value
	mu          sync.RWMutex
}

// enhancedGauge implements GaugeMetric
type enhancedGauge struct {
	name        string
	description string
	labelNames  []string
	values      map[string]float64 // label values hash -> value
	mu          sync.RWMutex
}

// enhancedHistogram implements HistogramMetric
type enhancedHistogram struct {
	name         string
	description  string
	labelNames   []string
	buckets      []float64
	observations map[string][]float64 // label values hash -> observations
	mu           sync.RWMutex
}

// NewDefaultEnhancedMetricsCollector creates a new enhanced metrics collector
func NewDefaultEnhancedMetricsCollector() *DefaultEnhancedMetricsCollector {
	return &DefaultEnhancedMetricsCollector{
		DefaultMetricsCollector: NewDefaultMetricsCollector(),
		counters:                make(map[string]*enhancedCounter),
		gauges:                  make(map[string]*enhancedGauge),
		histograms:              make(map[string]*enhancedHistogram),
	}
}

// CounterWithLabels implements EnhancedMetricsCollector
func (demc *DefaultEnhancedMetricsCollector) CounterWithLabels(name, description string, labelNames ...string) CounterMetric {
	demc.mu.Lock()
	defer demc.mu.Unlock()

	if counter, exists := demc.counters[name]; exists {
		return counter
	}

	counter := &enhancedCounter{
		name:        name,
		description: description,
		labelNames:  labelNames,
		values:      make(map[string]float64),
	}
	demc.counters[name] = counter
	return counter
}

// GaugeWithLabels implements EnhancedMetricsCollector
func (demc *DefaultEnhancedMetricsCollector) GaugeWithLabels(name, description string, labelNames ...string) GaugeMetric {
	demc.mu.Lock()
	defer demc.mu.Unlock()

	if gauge, exists := demc.gauges[name]; exists {
		return gauge
	}

	gauge := &enhancedGauge{
		name:        name,
		description: description,
		labelNames:  labelNames,
		values:      make(map[string]float64),
	}
	demc.gauges[name] = gauge
	return gauge
}

// HistogramWithLabels implements EnhancedMetricsCollector
func (demc *DefaultEnhancedMetricsCollector) HistogramWithLabels(name, description string, buckets []float64, labelNames ...string) HistogramMetric {
	demc.mu.Lock()
	defer demc.mu.Unlock()

	if histogram, exists := demc.histograms[name]; exists {
		return histogram
	}

	histogram := &enhancedHistogram{
		name:         name,
		description:  description,
		labelNames:   labelNames,
		buckets:      buckets,
		observations: make(map[string][]float64),
	}
	demc.histograms[name] = histogram
	return histogram
}

// GetPrometheusMetrics implements EnhancedMetricsCollector
func (demc *DefaultEnhancedMetricsCollector) GetPrometheusMetrics() []PrometheusMetric {
	demc.mu.RLock()
	defer demc.mu.RUnlock()

	var metrics []PrometheusMetric

	// Process counters
	for _, counter := range demc.counters {
		counter.mu.RLock()
		for labelHash, value := range counter.values {
			labels := demc.parseLabelHash(labelHash)
			metrics = append(metrics, PrometheusMetric{
				Name:        counter.name,
				Type:        "counter",
				Description: counter.description,
				Value:       value,
				Labels:      labels,
			})
		}
		counter.mu.RUnlock()
	}

	// Process gauges
	for _, gauge := range demc.gauges {
		gauge.mu.RLock()
		for labelHash, value := range gauge.values {
			labels := demc.parseLabelHash(labelHash)
			metrics = append(metrics, PrometheusMetric{
				Name:        gauge.name,
				Type:        "gauge",
				Description: gauge.description,
				Value:       value,
				Labels:      labels,
			})
		}
		gauge.mu.RUnlock()
	}

	// Process histograms
	for _, histogram := range demc.histograms {
		histogram.mu.RLock()
		for labelHash, observations := range histogram.observations {
			if len(observations) == 0 {
				continue
			}

			labels := demc.parseLabelHash(labelHash)
			buckets := demc.calculateHistogramBuckets(observations, histogram.buckets)

			metrics = append(metrics, PrometheusMetric{
				Name:        histogram.name,
				Type:        "histogram",
				Description: histogram.description,
				Labels:      labels,
				Buckets:     buckets,
			})
		}
		histogram.mu.RUnlock()
	}

	return metrics
}

// Helper method to parse label hash back to map
func (demc *DefaultEnhancedMetricsCollector) parseLabelHash(labelHash string) map[string]string {
	labels := make(map[string]string)
	if labelHash == "" {
		return labels
	}

	parts := strings.Split(labelHash, ",")
	for _, part := range parts {
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			labels[kv[0]] = kv[1]
		}
	}
	return labels
}

// Helper method to calculate histogram buckets
func (demc *DefaultEnhancedMetricsCollector) calculateHistogramBuckets(observations []float64, bucketBounds []float64) []PrometheusBucket {
	var buckets []PrometheusBucket

	for _, bound := range bucketBounds {
		count := uint64(0)
		for _, obs := range observations {
			if obs <= bound {
				count++
			}
		}
		buckets = append(buckets, PrometheusBucket{
			UpperBound: bound,
			Count:      count,
		})
	}

	// Add +Inf bucket
	buckets = append(buckets, PrometheusBucket{
		UpperBound: math.Inf(1),
		Count:      uint64(len(observations)),
	})

	return buckets
}

// Implementation of CounterMetric methods
func (c *enhancedCounter) Inc(labelValues ...string) {
	c.Add(1, labelValues...)
}

func (c *enhancedCounter) Add(value float64, labelValues ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	hash := buildLabelHashForValues(c.labelNames, labelValues)
	c.values[hash] += value
}

// Helper function to build label hash from names and values
func buildLabelHashForValues(labelNames []string, labelValues []string) string {
	if len(labelNames) != len(labelValues) {
		return ""
	}

	var parts []string
	for i, name := range labelNames {
		if i < len(labelValues) {
			parts = append(parts, fmt.Sprintf("%s=%s", name, labelValues[i]))
		}
	}
	return strings.Join(parts, ",")
}

// Implementation of GaugeMetric methods
func (g *enhancedGauge) Set(value float64, labelValues ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	hash := buildLabelHashForValues(g.labelNames, labelValues)
	g.values[hash] = value
}

func (g *enhancedGauge) Inc(labelValues ...string) {
	g.Add(1, labelValues...)
}

func (g *enhancedGauge) Dec(labelValues ...string) {
	g.Add(-1, labelValues...)
}

func (g *enhancedGauge) Add(value float64, labelValues ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	hash := buildLabelHashForValues(g.labelNames, labelValues)
	g.values[hash] += value
}

// Implementation of HistogramMetric methods
func (h *enhancedHistogram) Observe(value float64, labelValues ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	hash := buildLabelHashForValues(h.labelNames, labelValues)
	h.observations[hash] = append(h.observations[hash], value)

	// Keep only last 10000 observations to prevent memory growth
	if len(h.observations[hash]) > 10000 {
		h.observations[hash] = h.observations[hash][len(h.observations[hash])-10000:]
	}
}

// Helper functions for error categorization using structured error codes
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// First check for our structured timeout errors
	var pluginErr *goerrors.Error
	if errors.As(err, &pluginErr) {
		code := pluginErr.Code
		return code == ErrCodePluginTimeout ||
			code == ErrCodeCircuitBreakerTimeout ||
			code == ErrCodeHealthCheckTimeout
	}

	// Fallback to standard Go context errors
	return errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "deadline exceeded")
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check structured connection errors first
	if isStructuredConnectionError(err) {
		return true
	}

	// Fallback to common connection error patterns
	return isCommonConnectionError(err)
}

// isStructuredConnectionError checks for our defined connection error codes
func isStructuredConnectionError(err error) bool {
	var pluginErr *goerrors.Error
	if errors.As(err, &pluginErr) {
		code := pluginErr.Code
		return code == ErrCodePluginConnectionFailed ||
			code == ErrCodeHTTPTransportError ||
			code == ErrCodeGRPCTransportError ||
			code == ErrCodeExecTransportError
	}
	return false
}

// isCommonConnectionError checks for common connection error patterns in error messages
func isCommonConnectionError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "service unavailable") ||
		strings.Contains(errStr, "network unreachable") ||
		strings.Contains(errStr, "connection reset")
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check structured authentication errors first
	if isStructuredAuthError(err) {
		return true
	}

	// Fallback to common authentication error patterns
	return isCommonAuthError(err)
}

// isStructuredAuthError checks for our defined authentication error codes
func isStructuredAuthError(err error) bool {
	var pluginErr *goerrors.Error
	if errors.As(err, &pluginErr) {
		code := pluginErr.Code
		return code == ErrCodeMissingAPIKey ||
			code == ErrCodeMissingBearerToken ||
			code == ErrCodeMissingBasicCredentials ||
			code == ErrCodeMissingMTLSCerts ||
			code == ErrCodeUnsupportedAuthMethod
	}
	return false
}

// isCommonAuthError checks for common authentication error patterns in error messages
func isCommonAuthError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "authentication failed") ||
		strings.Contains(errStr, "permission denied") ||
		strings.Contains(errStr, "access denied") ||
		strings.Contains(errStr, "invalid credentials")
}

// Migration utilities for gradual adoption of enhanced metrics

// MigrateToEnhancedMetrics helps migrate from legacy metrics to enhanced metrics
func MigrateToEnhancedMetrics(legacy MetricsCollector) EnhancedMetricsCollector {
	enhanced := NewDefaultEnhancedMetricsCollector()

	// If the legacy collector is already enhanced, return it
	if enhancedCollector, ok := legacy.(EnhancedMetricsCollector); ok {
		return enhancedCollector
	}

	// Otherwise, return a new enhanced collector
	// Note: existing metrics data cannot be migrated automatically
	// as the legacy collector doesn't expose its internal state
	return enhanced
}

// CreateCommonPluginMetrics creates commonly used plugin metrics with the enhanced collector
func CreateCommonPluginMetrics(collector EnhancedMetricsCollector) *CommonPluginMetrics {
	return &CommonPluginMetrics{
		RequestCount:        collector.CounterWithLabels("plugin_requests_total", "Total number of plugin requests", "plugin_name", "status"),
		RequestDuration:     collector.HistogramWithLabels("plugin_request_duration_seconds", "Duration of plugin requests", []float64{0.001, 0.01, 0.1, 1, 10}, "plugin_name"),
		ActiveRequests:      collector.GaugeWithLabels("plugin_active_requests", "Number of active plugin requests", "plugin_name"),
		ErrorCount:          collector.CounterWithLabels("plugin_errors_total", "Total number of plugin errors", "plugin_name", "error_type"),
		CircuitBreakerState: collector.GaugeWithLabels("plugin_circuit_breaker_state", "Circuit breaker state (0=closed, 1=open, 2=half-open)", "plugin_name"),
	}
}

// CommonPluginMetrics provides a set of commonly used metrics for plugin systems
type CommonPluginMetrics struct {
	RequestCount        CounterMetric
	RequestDuration     HistogramMetric
	ActiveRequests      GaugeMetric
	ErrorCount          CounterMetric
	CircuitBreakerState GaugeMetric
}

// RecordRequest records a plugin request with its outcome
func (cpm *CommonPluginMetrics) RecordRequest(pluginName string, duration time.Duration, err error) {
	durationSeconds := duration.Seconds()

	// Record duration
	cpm.RequestDuration.Observe(durationSeconds, pluginName)

	// Record request count with status
	status := "success"
	if err != nil {
		status = "error"

		// Categorize error type
		errorType := "other"
		if isTimeoutError(err) {
			errorType = "timeout"
		} else if isConnectionError(err) {
			errorType = "connection"
		} else if isAuthError(err) {
			errorType = "auth"
		}

		cpm.ErrorCount.Inc(pluginName, errorType)
	}

	cpm.RequestCount.Inc(pluginName, status)
}

// SetCircuitBreakerState sets the circuit breaker state for a plugin
func (cpm *CommonPluginMetrics) SetCircuitBreakerState(pluginName string, state int) {
	cpm.CircuitBreakerState.Set(float64(state), pluginName)
}

// IncrementActiveRequests increments the active request count
func (cpm *CommonPluginMetrics) IncrementActiveRequests(pluginName string) {
	cpm.ActiveRequests.Inc(pluginName)
}

// DecrementActiveRequests decrements the active request count
func (cpm *CommonPluginMetrics) DecrementActiveRequests(pluginName string) {
	cpm.ActiveRequests.Dec(pluginName)
}
