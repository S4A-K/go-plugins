// observability.go: Comprehensive observability system with metrics, logging, and tracing
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"time"
)

// MetricsCollector defines the unified interface for collecting plugin metrics across different providers.
//
// This interface combines basic and advanced metrics collection capabilities, providing
// a standardized way to collect performance and operational metrics from plugins.
// It supports various backend systems like Prometheus, StatsD, or custom metrics solutions
// while maintaining backward compatibility and enabling advanced features.
//
// The interface is designed with two tiers:
//  1. Basic methods (required): Standard map-based label handling for simple use cases
//  2. Advanced methods (optional): Type-safe, performance-optimized methods for production systems
//
// Supported metric types:
//   - Counter: Monotonically increasing values (requests, errors, operations)
//   - Gauge: Current state values (active connections, memory usage, queue depth)
//   - Histogram: Distribution of values (response times, request sizes, processing duration)
//   - Custom: Provider-specific metrics with flexible value types
//
// Basic usage (backward compatible):
//
//	collector.IncrementCounter("plugin_requests_total",
//	    map[string]string{"plugin": "auth", "method": "validate"}, 1)
//	collector.SetGauge("plugin_connections_active",
//	    map[string]string{"plugin": "database"}, 42)
//
// Advanced usage (type-safe, high-performance):
//
//	counter := collector.CounterWithLabels("plugin_requests_total",
//	    "Total plugin requests", "plugin", "method", "status")
//	if counter != nil { // Check if advanced features are supported
//	    counter.Inc("auth", "validate", "success")
//	}
type MetricsCollector interface {
	// ============================================================================
	// BASIC METHODS (Required - all implementations must support these)
	// ============================================================================

	// Counter metrics - increment monotonically increasing values
	IncrementCounter(name string, labels map[string]string, value int64)

	// Gauge metrics - set current state values
	SetGauge(name string, labels map[string]string, value float64)

	// Histogram metrics - record value distributions
	RecordHistogram(name string, labels map[string]string, value float64)

	// Custom metrics - provider-specific metric types
	RecordCustomMetric(name string, labels map[string]string, value interface{})

	// Get current metrics snapshot in generic format
	GetMetrics() map[string]interface{}

	// ============================================================================
	// ADVANCED METHODS (Optional - may return nil if not supported)
	// ============================================================================

	// Type-safe metric creation with predefined label schemas
	// Returns nil if the implementation doesn't support advanced features
	CounterWithLabels(name, description string, labelNames ...string) CounterMetric
	GaugeWithLabels(name, description string, labelNames ...string) GaugeMetric
	HistogramWithLabels(name, description string, buckets []float64, labelNames ...string) HistogramMetric

	// Get metrics in Prometheus-compatible format
	// Returns nil if the implementation doesn't support Prometheus format
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

// ObservabilityLevel defines the level of observability features to enable.
type ObservabilityLevel string

const (
	// ObservabilityDisabled disables all observability features
	ObservabilityDisabled ObservabilityLevel = "disabled"

	// ObservabilityBasic enables essential metrics and error tracking only
	ObservabilityBasic ObservabilityLevel = "basic"

	// ObservabilityStandard enables metrics, health checks, and basic tracing (default)
	ObservabilityStandard ObservabilityLevel = "standard"

	// ObservabilityAdvanced enables all features including detailed tracing and performance metrics
	ObservabilityAdvanced ObservabilityLevel = "advanced"
)

// ObservabilityConfig configures the observability system for the plugin manager.
//
// This configuration has been simplified to use observability levels instead of
// multiple boolean flags, making it easier to configure and maintain while
// providing the same functionality.
//
// The configuration supports various backends and can be customized for different
// deployment environments and monitoring requirements.
//
// Basic usage:
//
//	config := goplugins.DefaultObservabilityConfig()
//	manager.ConfigureObservability(config)
//
// Advanced usage with custom collectors:
//
//	config := goplugins.ObservabilityConfig{
//	    Level:            goplugins.ObservabilityAdvanced,
//	    MetricsCollector: myCustomCollector,
//	    TracingProvider:  myTracingProvider,
//	}
type ObservabilityConfig struct {
	// Observability level - controls which features are enabled
	Level ObservabilityLevel `json:"level"`

	// Metrics configuration
	MetricsCollector MetricsCollector `json:"-"`
	MetricsPrefix    string           `json:"metrics_prefix"`

	// Tracing configuration
	TracingProvider   TracingProvider `json:"-"`
	TracingSampleRate float64         `json:"tracing_sample_rate"`

	// Logging configuration
	LogLevel string `json:"log_level"`
}

// DefaultObservabilityConfig returns default observability configuration
func DefaultObservabilityConfig() ObservabilityConfig {
	return ObservabilityConfig{
		Level:             ObservabilityStandard, // Standard level by default
		MetricsCollector:  NewEnhancedMetricsCollector(),
		MetricsPrefix:     "goplugins",
		TracingSampleRate: 0.1, // 10% sampling when enabled
		LogLevel:          "info",
	}
}

// IsMetricsEnabled returns true if metrics collection is enabled for this level
func (c ObservabilityConfig) IsMetricsEnabled() bool {
	return c.Level != ObservabilityDisabled
}

// IsTracingEnabled returns true if distributed tracing is enabled for this level
func (c ObservabilityConfig) IsTracingEnabled() bool {
	return c.Level == ObservabilityStandard || c.Level == ObservabilityAdvanced
}

// IsHealthMetricsEnabled returns true if health metrics are enabled for this level
func (c ObservabilityConfig) IsHealthMetricsEnabled() bool {
	return c.Level != ObservabilityDisabled
}

// IsPerformanceMetricsEnabled returns true if performance metrics are enabled for this level
func (c ObservabilityConfig) IsPerformanceMetricsEnabled() bool {
	return c.Level == ObservabilityAdvanced
}

// IsErrorMetricsEnabled returns true if error metrics are enabled for this level
func (c ObservabilityConfig) IsErrorMetricsEnabled() bool {
	return c.Level != ObservabilityDisabled
}

// IsLoggingEnabled returns true if logging is enabled for this level
func (c ObservabilityConfig) IsLoggingEnabled() bool {
	return c.Level != ObservabilityDisabled
}

// IsStructuredLoggingEnabled returns true if structured logging is enabled for this level
func (c ObservabilityConfig) IsStructuredLoggingEnabled() bool {
	return c.Level != ObservabilityDisabled
}
