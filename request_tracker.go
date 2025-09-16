// request_tracker.go: request tracking and graceful draining
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const cancelKey contextKey = "cancel"

// RequestTracker monitors active requests for graceful draining
type RequestTracker struct {
	// Per-plugin active request counters
	activeRequests map[string]*atomic.Int64
	mu             sync.RWMutex

	// Request contexts for cancellation
	activeContexts map[string][]context.Context
	contextMu      sync.RWMutex

	// Observability integration
	metricsCollector MetricsCollector
	metricsEnabled   bool
	metricsPrefix    string
}

// NewRequestTracker creates a new request tracker
func NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		activeRequests: make(map[string]*atomic.Int64),
		activeContexts: make(map[string][]context.Context),
		metricsEnabled: false, // Disabled by default
		metricsPrefix:  "goplugins",
	}
}

// NewRequestTrackerWithObservability creates a request tracker with observability enabled
func NewRequestTrackerWithObservability(collector MetricsCollector, prefix string) *RequestTracker {
	return &RequestTracker{
		activeRequests:   make(map[string]*atomic.Int64),
		activeContexts:   make(map[string][]context.Context),
		metricsCollector: collector,
		metricsEnabled:   collector != nil,
		metricsPrefix:    prefix,
	}
}

// StartRequest increments the active request counter for a plugin
func (rt *RequestTracker) StartRequest(pluginName string, ctx context.Context) {
	rt.mu.RLock()
	counter, exists := rt.activeRequests[pluginName]
	rt.mu.RUnlock()

	if !exists {
		rt.mu.Lock()
		// Double-check after acquiring write lock
		if counter, exists = rt.activeRequests[pluginName]; !exists {
			counter = &atomic.Int64{}
			rt.activeRequests[pluginName] = counter
		}
		rt.mu.Unlock()
	}

	counter.Add(1)

	// Record metrics if enabled
	if rt.metricsEnabled && rt.metricsCollector != nil {
		rt.recordRequestStartMetrics(pluginName)
	}

	// Store context for potential cancellation
	rt.contextMu.Lock()
	rt.activeContexts[pluginName] = append(rt.activeContexts[pluginName], ctx)
	rt.contextMu.Unlock()
}

// EndRequest decrements the active request counter for a plugin
func (rt *RequestTracker) EndRequest(pluginName string, ctx context.Context) {
	rt.mu.RLock()
	counter, exists := rt.activeRequests[pluginName]
	rt.mu.RUnlock()

	if exists {
		counter.Add(-1)

		// Record metrics if enabled
		if rt.metricsEnabled && rt.metricsCollector != nil {
			rt.recordRequestEndMetrics(pluginName, counter.Load())
		}
	}

	// Remove context from active list
	rt.contextMu.Lock()
	contexts := rt.activeContexts[pluginName]
	for i, activeCtx := range contexts {
		if activeCtx == ctx {
			rt.activeContexts[pluginName] = append(contexts[:i], contexts[i+1:]...)
			break
		}
	}
	rt.contextMu.Unlock()
}

// GetActiveRequestCount returns the number of active requests for a plugin
func (rt *RequestTracker) GetActiveRequestCount(pluginName string) int64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if counter, exists := rt.activeRequests[pluginName]; exists {
		return counter.Load()
	}
	return 0
}

// WaitForDrain waits for all active requests to complete for a plugin
// Returns true if all requests completed within timeout, false if timeout occurred
func (rt *RequestTracker) WaitForDrain(pluginName string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false // Timeout reached
		case <-ticker.C:
			if rt.GetActiveRequestCount(pluginName) == 0 {
				return true // All requests completed
			}
		}
	}
}

// ForceCancel cancels all active requests for a plugin
// Should be used as a last resort when graceful draining fails
func (rt *RequestTracker) ForceCancel(pluginName string) int {
	rt.contextMu.Lock()
	defer rt.contextMu.Unlock()

	contexts := rt.activeContexts[pluginName]
	canceledCount := 0

	for _, ctx := range contexts {
		if ctx.Value(cancelKey) != nil {
			if cancelFunc, ok := ctx.Value(cancelKey).(context.CancelFunc); ok {
				cancelFunc()
				canceledCount++
			}
		}
	}

	// Clear the contexts list
	rt.activeContexts[pluginName] = nil

	return canceledCount
}

// GetAllActiveRequests returns a map of plugin names to active request counts
func (rt *RequestTracker) GetAllActiveRequests() map[string]int64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	result := make(map[string]int64)
	for pluginName, counter := range rt.activeRequests {
		result[pluginName] = counter.Load()
	}
	return result
}

// DrainOptions configures graceful draining behavior
type DrainOptions struct {
	// Maximum time to wait for active requests to complete
	DrainTimeout time.Duration

	// Whether to forcefully cancel remaining requests after timeout
	ForceCancelAfterTimeout bool

	// Callback to be notified of drain progress
	ProgressCallback func(pluginName string, activeCount int64)
}

// GracefulDrain performs intelligent draining of active requests
func (rt *RequestTracker) GracefulDrain(pluginName string, options DrainOptions) error {
	start := time.Now()

	// Default timeout if not specified
	if options.DrainTimeout == 0 {
		options.DrainTimeout = 30 * time.Second
	}

	// Initial progress callback
	if options.ProgressCallback != nil {
		options.ProgressCallback(pluginName, rt.GetActiveRequestCount(pluginName))
	}

	// Wait for graceful completion
	if rt.WaitForDrain(pluginName, options.DrainTimeout) {
		return nil // Successfully drained
	}

	// Timeout reached - decide on forced cancellation
	remainingRequests := rt.GetActiveRequestCount(pluginName)

	if options.ForceCancelAfterTimeout && remainingRequests > 0 {
		canceledCount := rt.ForceCancel(pluginName)
		return &DrainTimeoutError{
			PluginName:        pluginName,
			RemainingRequests: remainingRequests,
			CanceledRequests:  canceledCount,
			DrainDuration:     time.Since(start),
		}
	}

	return &DrainTimeoutError{
		PluginName:        pluginName,
		RemainingRequests: remainingRequests,
		DrainDuration:     time.Since(start),
	}
}

// DrainTimeoutError indicates that graceful draining timed out
type DrainTimeoutError struct {
	PluginName        string
	RemainingRequests int64
	CanceledRequests  int
	DrainDuration     time.Duration
}

func (e *DrainTimeoutError) Error() string {
	if e.CanceledRequests > 0 {
		return fmt.Sprintf("drain timeout for plugin %s: %d requests canceled after %v (forced)",
			e.PluginName, e.CanceledRequests, e.DrainDuration)
	}
	return fmt.Sprintf("drain timeout for plugin %s: %d requests still active after %v",
		e.PluginName, e.RemainingRequests, e.DrainDuration)
}

// Observability methods for RequestTracker

// EnableObservability enables observability features for the request tracker
func (rt *RequestTracker) EnableObservability(collector MetricsCollector, prefix string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.metricsCollector = collector
	rt.metricsEnabled = collector != nil
	if prefix != "" {
		rt.metricsPrefix = prefix
	}
}

// DisableObservability disables observability features
func (rt *RequestTracker) DisableObservability() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.metricsCollector = nil
	rt.metricsEnabled = false
}

// recordRequestStartMetrics records metrics when a request starts
func (rt *RequestTracker) recordRequestStartMetrics(pluginName string) {
	if !rt.metricsEnabled || rt.metricsCollector == nil {
		return
	}

	labels := map[string]string{
		"plugin_name": pluginName,
	}

	// Increment request counter
	rt.metricsCollector.IncrementCounter(
		rt.metricsPrefix+"_active_requests_started_total",
		labels,
		1,
	)

	// Update active requests gauge
	currentActive := rt.GetActiveRequestCount(pluginName)
	rt.metricsCollector.SetGauge(
		rt.metricsPrefix+"_active_requests_current",
		labels,
		float64(currentActive),
	)
}

// recordRequestEndMetrics records metrics when a request ends
func (rt *RequestTracker) recordRequestEndMetrics(pluginName string, remainingActive int64) {
	if !rt.metricsEnabled || rt.metricsCollector == nil {
		return
	}

	labels := map[string]string{
		"plugin_name": pluginName,
	}

	// Increment end counter
	rt.metricsCollector.IncrementCounter(
		rt.metricsPrefix+"_active_requests_ended_total",
		labels,
		1,
	)

	// Update active requests gauge
	rt.metricsCollector.SetGauge(
		rt.metricsPrefix+"_active_requests_current",
		labels,
		float64(remainingActive),
	)
}

// GetObservabilityMetrics returns comprehensive metrics from the request tracker
func (rt *RequestTracker) GetObservabilityMetrics() map[string]interface{} {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	metrics := make(map[string]interface{})

	// Get active request counts per plugin
	activeByPlugin := make(map[string]int64)
	totalActive := int64(0)

	for pluginName, counter := range rt.activeRequests {
		count := counter.Load()
		activeByPlugin[pluginName] = count
		totalActive += count
	}

	metrics["request_tracker"] = map[string]interface{}{
		"total_active":          totalActive,
		"active_by_plugin":      activeByPlugin,
		"tracked_plugins":       len(rt.activeRequests),
		"observability_enabled": rt.metricsEnabled,
	}

	// Get collector metrics if available
	if rt.metricsEnabled && rt.metricsCollector != nil {
		metrics["collector"] = rt.metricsCollector.GetMetrics()
	}

	return metrics
}
