// observability_impl.go: Implementations for observability interfaces
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	goerrors "github.com/agilira/go-errors"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// DefaultMetricsCollector provides a basic implementation of MetricsCollector
type DefaultMetricsCollector struct {
	metrics map[string]interface{}
	mu      sync.RWMutex
}

// NewDefaultMetricsCollector creates a new default metrics collector
func NewDefaultMetricsCollector() MetricsCollector {
	return &DefaultMetricsCollector{
		metrics: make(map[string]interface{}),
	}
}

func (dmc *DefaultMetricsCollector) IncrementCounter(name string, labels map[string]string, value int64) {
	dmc.mu.Lock()
	defer dmc.mu.Unlock()
	key := dmc.buildKey(name, labels)
	if current, exists := dmc.metrics[key]; exists {
		if counter, ok := current.(int64); ok {
			dmc.metrics[key] = counter + value
		}
	} else {
		dmc.metrics[key] = value
	}
}

func (dmc *DefaultMetricsCollector) SetGauge(name string, labels map[string]string, value float64) {
	dmc.mu.Lock()
	defer dmc.mu.Unlock()
	key := dmc.buildKey(name, labels)
	dmc.metrics[key] = value
}

func (dmc *DefaultMetricsCollector) RecordHistogram(name string, labels map[string]string, value float64) {
	dmc.mu.Lock()
	defer dmc.mu.Unlock()
	key := dmc.buildKey(name, labels)
	if current, exists := dmc.metrics[key]; exists {
		if histogram, ok := current.([]float64); ok {
			dmc.metrics[key] = append(histogram, value)
		}
	} else {
		dmc.metrics[key] = []float64{value}
	}
}

func (dmc *DefaultMetricsCollector) RecordCustomMetric(name string, labels map[string]string, value interface{}) {
	dmc.mu.Lock()
	defer dmc.mu.Unlock()
	key := dmc.buildKey(name, labels)
	dmc.metrics[key] = value
}

func (dmc *DefaultMetricsCollector) GetMetrics() map[string]interface{} {
	dmc.mu.RLock()
	defer dmc.mu.RUnlock()
	result := make(map[string]interface{})
	for k, v := range dmc.metrics {
		result[k] = v
	}
	return result
}

// Advanced methods - return nil for basic collector
func (dmc *DefaultMetricsCollector) CounterWithLabels(name, description string, labelNames ...string) CounterMetric {
	return nil
}

func (dmc *DefaultMetricsCollector) GaugeWithLabels(name, description string, labelNames ...string) GaugeMetric {
	return nil
}

func (dmc *DefaultMetricsCollector) HistogramWithLabels(name, description string, buckets []float64, labelNames ...string) HistogramMetric {
	return nil
}

func (dmc *DefaultMetricsCollector) GetPrometheusMetrics() []PrometheusMetric {
	return nil
}

func (dmc *DefaultMetricsCollector) buildKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%s{%s}", name, strings.Join(parts, ","))
}

// DefaultEnhancedMetricsCollector provides an enhanced implementation with advanced features
type DefaultEnhancedMetricsCollector struct {
	*DefaultMetricsCollector
	counters   map[string]*EnhancedCounter
	gauges     map[string]*EnhancedGauge
	histograms map[string]*EnhancedHistogram
	mu         sync.RWMutex
}

// NewEnhancedMetricsCollector creates a new enhanced metrics collector
func NewEnhancedMetricsCollector() MetricsCollector {
	return &DefaultEnhancedMetricsCollector{
		DefaultMetricsCollector: &DefaultMetricsCollector{
			metrics: make(map[string]interface{}),
		},
		counters:   make(map[string]*EnhancedCounter),
		gauges:     make(map[string]*EnhancedGauge),
		histograms: make(map[string]*EnhancedHistogram),
	}
}

// Advanced methods implementation
func (demc *DefaultEnhancedMetricsCollector) CounterWithLabels(name, description string, labelNames ...string) CounterMetric {
	demc.mu.Lock()
	defer demc.mu.Unlock()

	key := fmt.Sprintf("%s:%s", name, strings.Join(labelNames, ","))
	if counter, exists := demc.counters[key]; exists {
		return counter
	}

	counter := &EnhancedCounter{
		name:       name,
		labelNames: labelNames,
		values:     make(map[string]*atomic.Int64),
	}
	demc.counters[key] = counter
	return counter
}

func (demc *DefaultEnhancedMetricsCollector) GaugeWithLabels(name, description string, labelNames ...string) GaugeMetric {
	demc.mu.Lock()
	defer demc.mu.Unlock()

	key := fmt.Sprintf("%s:%s", name, strings.Join(labelNames, ","))
	if gauge, exists := demc.gauges[key]; exists {
		return gauge
	}

	gauge := &EnhancedGauge{
		name:       name,
		labelNames: labelNames,
		values:     make(map[string]*atomic.Int64), // Store as int64 for atomic operations
	}
	demc.gauges[key] = gauge
	return gauge
}

func (demc *DefaultEnhancedMetricsCollector) HistogramWithLabels(name, description string, buckets []float64, labelNames ...string) HistogramMetric {
	demc.mu.Lock()
	defer demc.mu.Unlock()

	key := fmt.Sprintf("%s:%s", name, strings.Join(labelNames, ","))
	if histogram, exists := demc.histograms[key]; exists {
		return histogram
	}

	histogram := &EnhancedHistogram{
		name:       name,
		labelNames: labelNames,
		buckets:    buckets,
		values:     make(map[string][]float64),
		mu:         sync.RWMutex{},
	}
	demc.histograms[key] = histogram
	return histogram
}

func (demc *DefaultEnhancedMetricsCollector) GetPrometheusMetrics() []PrometheusMetric {
	demc.mu.RLock()
	defer demc.mu.RUnlock()

	var metrics []PrometheusMetric

	// Convert basic metrics from the default collector
	basicMetrics := demc.DefaultMetricsCollector.GetMetrics()
	metrics = append(metrics, demc.convertBasicMetrics(basicMetrics)...)

	// Convert advanced counters
	metrics = append(metrics, demc.convertAdvancedCounters()...)

	// Convert advanced gauges
	metrics = append(metrics, demc.convertAdvancedGauges()...)

	return metrics
}

// convertBasicMetrics converts basic metrics to Prometheus format
func (demc *DefaultEnhancedMetricsCollector) convertBasicMetrics(basicMetrics map[string]interface{}) []PrometheusMetric {
	var metrics []PrometheusMetric

	for name, value := range basicMetrics {
		if strings.Contains(name, "{") && strings.Contains(name, "}") {
			metrics = append(metrics, demc.convertLabeledMetric(name, value)...)
		} else {
			if metric := demc.convertSimpleMetric(name, value); metric != nil {
				metrics = append(metrics, *metric)
			}
		}
	}

	return metrics
}

// convertLabeledMetric converts a metric with labels to Prometheus format
func (demc *DefaultEnhancedMetricsCollector) convertLabeledMetric(name string, value interface{}) []PrometheusMetric {
	// Format: "metric_name{label1=value1,label2=value2}"
	parts := strings.SplitN(name, "{", 2)
	if len(parts) != 2 {
		return nil
	}

	metricName := parts[0]
	labelPart := strings.TrimSuffix(parts[1], "}")
	labels := demc.parseLabels(labelPart)

	metricType, metricValue := demc.determineTypeAndValue(metricName, value)
	if metricType == "" {
		return nil
	}

	return []PrometheusMetric{{
		Name:        metricName,
		Type:        metricType,
		Description: fmt.Sprintf("%s metric for %s", cases.Title(language.English).String(metricType), metricName),
		Value:       metricValue,
		Labels:      labels,
	}}
}

// convertSimpleMetric converts a simple metric to Prometheus format
func (demc *DefaultEnhancedMetricsCollector) convertSimpleMetric(name string, value interface{}) *PrometheusMetric {
	metricType, metricValue := demc.determineTypeAndValue(name, value)
	if metricType == "" {
		return nil
	}

	return &PrometheusMetric{
		Name:        name,
		Type:        metricType,
		Description: fmt.Sprintf("Gauge metric for %s", name),
		Value:       metricValue,
		Labels:      make(map[string]string),
	}
}

// parseLabels parses label string into map
func (demc *DefaultEnhancedMetricsCollector) parseLabels(labelPart string) map[string]string {
	labels := make(map[string]string)
	if labelPart == "" {
		return labels
	}

	labelPairs := strings.Split(labelPart, ",")
	for _, pair := range labelPairs {
		if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
			labels[kv[0]] = kv[1]
		}
	}
	return labels
}

// determineTypeAndValue determines metric type and converts value
func (demc *DefaultEnhancedMetricsCollector) determineTypeAndValue(metricName string, value interface{}) (string, float64) {
	switch v := value.(type) {
	case int64:
		metricType := "gauge"
		if strings.Contains(metricName, "total") || strings.Contains(metricName, "count") {
			metricType = "counter"
		}
		return metricType, float64(v)
	case float64:
		return "gauge", v
	case []float64:
		return "histogram", float64(len(v))
	default:
		return "", 0
	}
}

// convertAdvancedCounters converts advanced counters to Prometheus format
func (demc *DefaultEnhancedMetricsCollector) convertAdvancedCounters() []PrometheusMetric {
	var metrics []PrometheusMetric

	for key, counter := range demc.counters {
		parts := strings.Split(key, ":")
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		labelNames := strings.Split(parts[1], ",")
		metrics = append(metrics, demc.convertCounterValues(name, labelNames, counter)...)
	}

	return metrics
}

// convertAdvancedGauges converts advanced gauges to Prometheus format
func (demc *DefaultEnhancedMetricsCollector) convertAdvancedGauges() []PrometheusMetric {
	var metrics []PrometheusMetric

	for key, gauge := range demc.gauges {
		parts := strings.Split(key, ":")
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		labelNames := strings.Split(parts[1], ",")
		metrics = append(metrics, demc.convertGaugeValues(name, labelNames, gauge)...)
	}

	return metrics
}

// convertCounterValues converts counter values to Prometheus metrics
func (demc *DefaultEnhancedMetricsCollector) convertCounterValues(name string, labelNames []string, counter *EnhancedCounter) []PrometheusMetric {
	var metrics []PrometheusMetric

	counter.mu.RLock()
	defer counter.mu.RUnlock()

	for labelValues, value := range counter.values {
		labels := demc.buildLabelsMap(labelNames, labelValues)
		metrics = append(metrics, PrometheusMetric{
			Name:        name,
			Type:        "counter",
			Description: fmt.Sprintf("Counter metric for %s", name),
			Value:       float64(value.Load()),
			Labels:      labels,
		})
	}

	return metrics
}

// convertGaugeValues converts gauge values to Prometheus metrics
func (demc *DefaultEnhancedMetricsCollector) convertGaugeValues(name string, labelNames []string, gauge *EnhancedGauge) []PrometheusMetric {
	var metrics []PrometheusMetric

	gauge.mu.RLock()
	defer gauge.mu.RUnlock()

	for labelValues, value := range gauge.values {
		labels := demc.buildLabelsMap(labelNames, labelValues)
		metrics = append(metrics, PrometheusMetric{
			Name:        name,
			Type:        "gauge",
			Description: fmt.Sprintf("Gauge metric for %s", name),
			Value:       float64(value.Load()) / 1000.0, // Convert back from int64*1000 to float64
			Labels:      labels,
		})
	}

	return metrics
}

// buildLabelsMap builds labels map from names and values
func (demc *DefaultEnhancedMetricsCollector) buildLabelsMap(labelNames []string, labelValues string) map[string]string {
	labels := make(map[string]string)
	valuesParts := strings.Split(labelValues, ":")

	for i, labelName := range labelNames {
		if i < len(valuesParts) && labelName != "" {
			labels[labelName] = valuesParts[i]
		}
	}

	return labels
}

// Enhanced metric implementations

type EnhancedCounter struct {
	name       string
	labelNames []string
	values     map[string]*atomic.Int64
	mu         sync.RWMutex
}

func (ec *EnhancedCounter) Inc(labelValues ...string) {
	ec.Add(1, labelValues...)
}

func (ec *EnhancedCounter) Add(value float64, labelValues ...string) {
	key := strings.Join(labelValues, ":")
	ec.mu.RLock()
	counter, exists := ec.values[key]
	ec.mu.RUnlock()

	if !exists {
		ec.mu.Lock()
		if counter, exists = ec.values[key]; !exists {
			counter = &atomic.Int64{}
			ec.values[key] = counter
		}
		ec.mu.Unlock()
	}

	// Convert float64 to int64 for atomic operations
	counter.Add(int64(value))
}

type EnhancedGauge struct {
	name       string
	labelNames []string
	values     map[string]*atomic.Int64
	mu         sync.RWMutex
}

func (eg *EnhancedGauge) Set(value float64, labelValues ...string) {
	key := strings.Join(labelValues, ":")
	eg.mu.RLock()
	gauge, exists := eg.values[key]
	eg.mu.RUnlock()

	if !exists {
		eg.mu.Lock()
		if gauge, exists = eg.values[key]; !exists {
			gauge = &atomic.Int64{}
			eg.values[key] = gauge
		}
		eg.mu.Unlock()
	}

	// Store as int64 * 1000 to preserve precision
	gauge.Store(int64(value * 1000))
}

func (eg *EnhancedGauge) Inc(labelValues ...string) {
	eg.Add(1, labelValues...)
}

func (eg *EnhancedGauge) Dec(labelValues ...string) {
	eg.Add(-1, labelValues...)
}

func (eg *EnhancedGauge) Add(value float64, labelValues ...string) {
	key := strings.Join(labelValues, ":")
	eg.mu.RLock()
	gauge, exists := eg.values[key]
	eg.mu.RUnlock()

	if !exists {
		eg.mu.Lock()
		if gauge, exists = eg.values[key]; !exists {
			gauge = &atomic.Int64{}
			eg.values[key] = gauge
		}
		eg.mu.Unlock()
	}

	// Add as int64 * 1000 to preserve precision
	gauge.Add(int64(value * 1000))
}

type EnhancedHistogram struct {
	name       string
	labelNames []string
	buckets    []float64
	values     map[string][]float64
	mu         sync.RWMutex
}

func (eh *EnhancedHistogram) Observe(value float64, labelValues ...string) {
	key := strings.Join(labelValues, ":")
	eh.mu.Lock()
	defer eh.mu.Unlock()

	if _, exists := eh.values[key]; !exists {
		eh.values[key] = make([]float64, 0)
	}
	eh.values[key] = append(eh.values[key], value)
}

// CommonPluginMetrics provides common metrics for plugin operations
type CommonPluginMetrics struct {
	RequestsTotal       CounterMetric
	RequestsSuccess     CounterMetric
	RequestsFailure     CounterMetric
	RequestDuration     HistogramMetric
	ActiveRequests      GaugeMetric
	CircuitBreakerState GaugeMetric
}

// IncrementActiveRequests increments the active request count
func (cpm *CommonPluginMetrics) IncrementActiveRequests(pluginName string) {
	if cpm.ActiveRequests != nil {
		cpm.ActiveRequests.Inc(pluginName)
	}
}

// DecrementActiveRequests decrements the active request count
func (cpm *CommonPluginMetrics) DecrementActiveRequests(pluginName string) {
	if cpm.ActiveRequests != nil {
		cpm.ActiveRequests.Dec(pluginName)
	}
}

// RecordRequest records a plugin request with its duration and status
func (cpm *CommonPluginMetrics) RecordRequest(pluginName string, duration time.Duration, success bool) {
	if cpm.RequestsTotal != nil {
		cpm.RequestsTotal.Inc(pluginName)
	}

	if success {
		if cpm.RequestsSuccess != nil {
			cpm.RequestsSuccess.Inc(pluginName)
		}
	} else {
		if cpm.RequestsFailure != nil {
			cpm.RequestsFailure.Inc(pluginName)
		}
	}

	if cpm.RequestDuration != nil {
		cpm.RequestDuration.Observe(duration.Seconds(), pluginName)
	}
}

// SetCircuitBreakerState sets the circuit breaker state for a plugin
func (cpm *CommonPluginMetrics) SetCircuitBreakerState(pluginName string, state CircuitBreakerState) {
	if cpm.CircuitBreakerState != nil {
		var stateValue float64
		switch state {
		case StateClosed:
			stateValue = 0
		case StateOpen:
			stateValue = 1
		case StateHalfOpen:
			stateValue = 2
		}
		cpm.CircuitBreakerState.Set(stateValue, pluginName)
	}
}

// CreateCommonPluginMetrics creates common plugin metrics
func CreateCommonPluginMetrics(collector MetricsCollector) *CommonPluginMetrics {
	// Default histogram buckets for request duration
	defaultBuckets := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

	return &CommonPluginMetrics{
		RequestsTotal:       collector.CounterWithLabels("plugin_requests_total", "Total plugin requests", "plugin_name"),
		RequestsSuccess:     collector.CounterWithLabels("plugin_requests_success_total", "Successful plugin requests", "plugin_name"),
		RequestsFailure:     collector.CounterWithLabels("plugin_requests_failure_total", "Failed plugin requests", "plugin_name"),
		RequestDuration:     collector.HistogramWithLabels("plugin_request_duration_seconds", "Plugin request duration", defaultBuckets, "plugin_name"),
		ActiveRequests:      collector.GaugeWithLabels("plugin_active_requests", "Active plugin requests", "plugin_name"),
		CircuitBreakerState: collector.GaugeWithLabels("plugin_circuit_breaker_state", "Circuit breaker state (0=closed, 1=open, 2=half-open)", "plugin_name"),
	}
}

// Error classification functions for observability

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for go-errors connection errors
	if goErr, ok := err.(*goerrors.Error); ok {
		code := string(goErr.Code)
		return strings.Contains(code, "CONNECTION") || strings.Contains(code, "NETWORK")
	}

	// Check for common connection patterns in error messages
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "network") ||
		strings.Contains(errMsg, "dial") ||
		strings.Contains(errMsg, "connect") ||
		strings.Contains(errMsg, "refused") ||
		strings.Contains(errMsg, "unreachable")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// Check for go-errors timeout errors
	if goErr, ok := err.(*goerrors.Error); ok {
		code := string(goErr.Code)
		return strings.Contains(code, "TIMEOUT") ||
			code == ErrCodePluginTimeout ||
			code == ErrCodeCircuitBreakerTimeout ||
			code == ErrCodeHealthCheckTimeout
	}

	// Check for common timeout patterns in error messages
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "timed out") ||
		strings.Contains(errMsg, "deadline exceeded") ||
		strings.Contains(errMsg, "context deadline exceeded")
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check for go-errors auth errors
	if goErr, ok := err.(*goerrors.Error); ok {
		code := string(goErr.Code)
		return strings.Contains(code, "AUTH") ||
			strings.Contains(code, "UNAUTHORIZED") ||
			strings.Contains(code, "FORBIDDEN")
	}

	// Check for common auth patterns in error messages
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "unauthorized") ||
		strings.Contains(errMsg, "forbidden") ||
		strings.Contains(errMsg, "authentication") ||
		strings.Contains(errMsg, "permission") ||
		strings.Contains(errMsg, "access denied")
}

// ClassifyError classifies an error into specific error types for metrics
func ClassifyError(err error, pluginMetrics *PluginObservabilityMetrics) {
	if err == nil || pluginMetrics == nil {
		return
	}

	// Classify and increment appropriate error counter
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
