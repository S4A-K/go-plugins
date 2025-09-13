// health_checker.go: Production-ready health monitoring implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/go-timecache"
)

// HealthChecker monitors the health of a plugin through periodic health checks.
//
// This component provides continuous monitoring of plugin availability and
// performance by executing health checks at regular intervals. It tracks
// consecutive failures and provides detailed health status information for
// operational visibility and automated recovery decisions.
//
// Key features:
//   - Periodic health checking with configurable intervals
//   - Consecutive failure tracking with automatic degradation detection
//   - Thread-safe operation with atomic counters
//   - Graceful start/stop lifecycle management
//   - Detailed health status reporting with response times
//
// Usage example:
//
//	config := HealthCheckConfig{
//	    Enabled:      true,
//	    Interval:     30 * time.Second,
//	    Timeout:      5 * time.Second,
//	    FailureLimit: 3,
//	}
//	checker := NewHealthChecker(plugin, config)
//
//	// Check current health status
//	status := checker.Check()
//	if status.Status != StatusHealthy {
//	    log.Printf("Plugin unhealthy: %s", status.Message)
//	}
//
//	// Stop monitoring when done
//	checker.Stop()
type HealthChecker struct {
	plugin interface {
		Health(ctx context.Context) HealthStatus
		Close() error
	}
	config HealthCheckConfig

	// State
	consecutiveFailures atomic.Int64
	lastCheck           atomic.Int64 // Unix timestamp
	running             atomic.Bool

	// Control channels
	stopChan chan struct{}
	doneChan chan struct{}
}

// NewHealthChecker creates a new health checker for monitoring a plugin's availability.
//
// The health checker will automatically start monitoring if health checking is
// enabled in the configuration. It runs in a separate goroutine and performs
// periodic health checks according to the specified interval.
//
// Parameters:
//   - plugin: Must implement Health() and Close() methods
//   - config: Health check configuration including interval, timeout, and failure limits
//
// The health checker maintains its own lifecycle and can be started/stopped
// independently of the plugin it monitors.
func NewHealthChecker(plugin interface {
	Health(ctx context.Context) HealthStatus
	Close() error
}, config HealthCheckConfig) *HealthChecker {
	hc := &HealthChecker{
		plugin:   plugin,
		config:   config,
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}

	if config.Enabled {
		hc.running.Store(true)
		go hc.run()
	}

	return hc
}

// Check performs a single synchronous health check and returns the current status.
//
// This method executes an immediate health check against the monitored plugin,
// respecting the configured timeout. It updates internal failure counters and
// determines the overall health status based on consecutive failure patterns.
//
// Health status determination:
//   - StatusHealthy: Plugin responds successfully within timeout
//   - StatusOffline: Consecutive failures exceed the configured limit
//   - Other statuses: Based on plugin's own health assessment
//
// The method is thread-safe and can be called independently of the periodic
// health checking goroutine. Response time and failure counts are tracked
// for operational visibility.
//
// Returns HealthStatus with detailed information including status, message,
// response time, and timestamp.
func (hc *HealthChecker) Check() HealthStatus {
	if !hc.config.Enabled {
		return HealthStatus{
			Status:       StatusHealthy,
			Message:      "Health checking disabled",
			LastCheck:    timecache.CachedTime(),
			ResponseTime: 0,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
	defer cancel()

	start := timecache.CachedTime()
	status := hc.plugin.Health(ctx)
	responseTime := time.Since(start)

	hc.lastCheck.Store(timecache.CachedTimeNano())

	// Update failure counter
	if status.Status != StatusHealthy {
		hc.consecutiveFailures.Add(1)

		// Check if we've exceeded the failure limit
		if hc.consecutiveFailures.Load() >= int64(hc.config.FailureLimit) {
			status.Status = StatusOffline
			status.Message = "Exceeded consecutive failure limit"
		}
	} else {
		// Reset failure counter on successful check
		hc.consecutiveFailures.Store(0)
	}

	// Ensure response time is set
	status.ResponseTime = responseTime
	status.LastCheck = timecache.CachedTime()

	return status
}

// Start initiates the health checker's periodic monitoring goroutine.
//
// This method starts continuous health monitoring according to the configured
// interval. If health checking is disabled in the configuration, this method
// has no effect. The method is idempotent - calling it multiple times is safe.
//
// The health checker runs in its own goroutine and performs checks at regular
// intervals until stopped. Each check updates the plugin's health status and
// maintains failure counters for degradation detection.
//
// Use Stop() to halt the monitoring when no longer needed.
func (hc *HealthChecker) Start() {
	if !hc.config.Enabled {
		return
	}

	if hc.running.CompareAndSwap(false, true) {
		hc.stopChan = make(chan struct{})
		hc.doneChan = make(chan struct{})
		go hc.run()
	}
}

// Stop halts the health checker's periodic monitoring and waits for cleanup.
//
// This method gracefully shuts down the health checking goroutine and waits
// for it to complete any in-flight health check before returning. The method
// is idempotent - calling it multiple times is safe.
//
// After stopping, the health checker can be restarted with Start() if needed.
// Any ongoing health check will complete before the goroutine exits.
func (hc *HealthChecker) Stop() {
	if hc.running.CompareAndSwap(true, false) {
		close(hc.stopChan)
		<-hc.doneChan // Wait for the health checker goroutine to finish
	}
}

// IsRunning returns true if the health checker is currently running
func (hc *HealthChecker) IsRunning() bool {
	return hc.running.Load()
}

// GetLastCheck returns the timestamp of the last health check
func (hc *HealthChecker) GetLastCheck() time.Time {
	timestamp := hc.lastCheck.Load()
	if timestamp == 0 {
		return time.Time{}
	}
	return time.Unix(0, timestamp)
}

// GetConsecutiveFailures returns the number of consecutive failures
func (hc *HealthChecker) GetConsecutiveFailures() int64 {
	return hc.consecutiveFailures.Load()
}

// Done returns a channel that will be closed when the health checker stops
func (hc *HealthChecker) Done() <-chan struct{} {
	return hc.doneChan
}

// run is the main health checking loop
func (hc *HealthChecker) run() {
	defer close(hc.doneChan)

	ticker := time.NewTicker(hc.config.Interval)
	defer ticker.Stop()

	// Perform initial health check
	hc.Check()

	for {
		select {
		case <-ticker.C:
			hc.Check()

		case <-hc.stopChan:
			return
		}
	}
}

// HealthMonitor provides centralized health monitoring for multiple components.
//
// This component manages multiple HealthChecker instances and provides a
// unified view of system health across all monitored plugins. It's designed
// for scenarios where you need to monitor multiple plugins and make system-wide
// decisions based on overall health status.
//
// Features:
//   - Centralized management of multiple health checkers
//   - Aggregated health status calculation
//   - Thread-safe operations with proper synchronization
//   - Individual and overall health status reporting
//   - Graceful shutdown of all managed checkers
//
// Usage example:
//
//	monitor := NewHealthMonitor()
//
//	// Add checkers for different plugins
//	monitor.AddChecker("auth-service", authHealthChecker)
//	monitor.AddChecker("payment-service", paymentHealthChecker)
//
//	// Get overall system health
//	overallHealth := monitor.GetOverallHealth()
//	if overallHealth.Status != StatusHealthy {
//	    log.Printf("System degraded: %s", overallHealth.Message)
//	}
//
//	// Cleanup when done
//	monitor.Shutdown()
type HealthMonitor struct {
	checkers map[string]*HealthChecker
	status   map[string]HealthStatus
	mu       sync.RWMutex
}

// NewHealthMonitor creates a new centralized health monitor instance.
//
// The health monitor starts empty and health checkers can be added dynamically
// using AddChecker(). It provides thread-safe operations for managing multiple
// health checkers and computing overall system health.
//
// Returns a ready-to-use HealthMonitor that can manage multiple plugin
// health checkers and provide unified health status reporting.
func NewHealthMonitor() *HealthMonitor {
	return &HealthMonitor{
		checkers: make(map[string]*HealthChecker),
		status:   make(map[string]HealthStatus),
	}
}

// AddChecker adds a health checker for a named component
func (hm *HealthMonitor) AddChecker(name string, checker *HealthChecker) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Stop existing checker if present
	if existing, ok := hm.checkers[name]; ok {
		existing.Stop()
	}

	hm.checkers[name] = checker
}

// RemoveChecker removes a health checker
func (hm *HealthMonitor) RemoveChecker(name string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if checker, ok := hm.checkers[name]; ok {
		checker.Stop()
		delete(hm.checkers, name)
		delete(hm.status, name)
	}
}

// GetStatus returns the health status of a specific component
func (hm *HealthMonitor) GetStatus(name string) (HealthStatus, bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	status, ok := hm.status[name]
	return status, ok
}

// GetAllStatus returns the health status of all monitored components
func (hm *HealthMonitor) GetAllStatus() map[string]HealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	result := make(map[string]HealthStatus)
	for name, status := range hm.status {
		result[name] = status
	}
	return result
}

// UpdateStatus updates the health status for a component
func (hm *HealthMonitor) UpdateStatus(name string, status HealthStatus) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.status[name] = status
}

// GetOverallHealth computes and returns the aggregated health status of all monitored components.
//
// This method analyzes the health status of all registered components and
// determines the overall system health using the following logic:
//   - StatusHealthy: All components are healthy
//   - StatusDegraded: Some components are degraded but none are offline/unhealthy
//   - StatusUnhealthy: One or more components are offline or unhealthy
//
// The returned status includes a summary message describing any issues found
// across the monitored components. This is useful for system-level health
// checks and determining if the entire service should be considered available.
//
// Returns HealthStatus representing the worst-case scenario across all
// monitored components, with an appropriate message describing the overall state.
func (hm *HealthMonitor) GetOverallHealth() HealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	overallStatus := StatusHealthy
	var messages []string

	for _, status := range hm.status {
		if status.Status == StatusOffline || status.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
			messages = append(messages, status.Message)
		} else if status.Status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
			messages = append(messages, status.Message)
		}
	}

	message := "All components healthy"
	if len(messages) > 0 {
		message = "Issues detected: " + joinStrings(messages, "; ")
	}

	return HealthStatus{
		Status:       overallStatus,
		Message:      message,
		LastCheck:    timecache.CachedTime(),
		ResponseTime: 0,
	}
}

// Shutdown stops all health checkers
func (hm *HealthMonitor) Shutdown() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	for _, checker := range hm.checkers {
		checker.Stop()
	}

	hm.checkers = make(map[string]*HealthChecker)
	hm.status = make(map[string]HealthStatus)
}

// Helper function to join strings (avoiding external dependencies)
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
