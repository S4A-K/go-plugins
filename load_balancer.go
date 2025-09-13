// load_balancer.go: Load balancing strategies for multiple plugins of the same type
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// LoadBalancingStrategy defines different load balancing algorithms for distributing requests.
//
// Each strategy implements a different approach to selecting which plugin instance
// should handle a request, optimizing for different goals like fairness, performance,
// locality, or consistency.
//
// Strategy descriptions:
//   - StrategyRoundRobin: Distributes requests evenly in circular order
//   - StrategyRandom: Selects plugins randomly for uniform distribution
//   - StrategyLeastConnections: Routes to plugin with fewest active connections
//   - StrategyLeastLatency: Routes to plugin with lowest average response time
//   - StrategyWeightedRandom: Random selection based on configured weights
//   - StrategyConsistentHash: Routes based on request key for session affinity
//   - StrategyPriority: Routes to highest priority healthy plugin
//
// Example usage:
//
//	lb := NewLoadBalancer(StrategyLeastLatency, logger)
//	lb.AddPlugin("fast-service", plugin1, 1, 10)      // weight=1, priority=10
//	lb.AddPlugin("backup-service", plugin2, 1, 5)     // weight=1, priority=5
//
//	request := LoadBalanceRequest{Key: "user-123"}
//	name, plugin, err := lb.SelectPlugin(request)
type LoadBalancingStrategy string

const (
	// StrategyRoundRobin distributes requests in round-robin fashion
	StrategyRoundRobin LoadBalancingStrategy = "round-robin"

	// StrategyRandom selects plugins randomly
	StrategyRandom LoadBalancingStrategy = "random"

	// StrategyLeastConnections selects plugin with least active connections
	StrategyLeastConnections LoadBalancingStrategy = "least-connections"

	// StrategyLeastLatency selects plugin with lowest average latency
	StrategyLeastLatency LoadBalancingStrategy = "least-latency"

	// StrategyWeightedRandom selects plugins based on weights with random distribution
	StrategyWeightedRandom LoadBalancingStrategy = "weighted-random"

	// StrategyConsistentHash uses consistent hashing for request routing
	StrategyConsistentHash LoadBalancingStrategy = "consistent-hash"

	// StrategyPriority selects highest priority healthy plugin
	StrategyPriority LoadBalancingStrategy = "priority"
)

// secureRandomInt generates a cryptographically secure random integer between 0 and max-1
func secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}

	// Check for potential overflow in conversion to uint32
	const maxSafeInt = int(^uint32(0)) // Maximum value that fits in uint32
	if max > maxSafeInt {
		return 0, fmt.Errorf("max value too large for secure generation")
	}

	// For small ranges, use a simple approach
	if max <= 256 {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		return int(b[0]) % max, nil
	}

	// For larger ranges, use rejection sampling to avoid modulo bias
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}

	n := binary.BigEndian.Uint32(buf[:])
	// Simple rejection sampling to avoid bias
	maxUint32 := uint32(^uint32(0)) // Maximum uint32 value
	// Safe conversion - we checked max <= maxSafeInt above
	var maxAsUint32 uint32
	if max >= 0 && max <= maxSafeInt {
		maxAsUint32 = uint32(max)
	} else {
		return 0, fmt.Errorf("invalid max value for uint32 conversion")
	}
	limit := maxUint32 - (maxUint32 % maxAsUint32)
	for n >= limit {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		n = binary.BigEndian.Uint32(buf[:])
	}

	return int(n) % max, nil
}

// LoadBalancer manages multiple plugins of the same type and distributes load using configurable strategies.
//
// This component provides intelligent request distribution across multiple plugin
// instances, implementing various load balancing algorithms and maintaining
// detailed metrics for operational visibility and decision-making.
//
// Key features:
//   - Multiple load balancing strategies (round-robin, least connections, etc.)
//   - Per-plugin metrics tracking (latency, success rate, health score)
//   - Dynamic plugin enable/disable without service interruption
//   - Weighted and priority-based routing
//   - Thread-safe operation with minimal contention
//   - Comprehensive statistics for monitoring and debugging
//
// Usage example:
//
//	lb := NewLoadBalancer[MyRequest, MyResponse](StrategyLeastLatency, logger)
//
//	// Add plugin instances with different weights and priorities
//	lb.AddPlugin("primary", plugin1, 10, 100)     // High weight, high priority
//	lb.AddPlugin("secondary", plugin2, 5, 50)     // Lower weight, lower priority
//
//	// Execute request with automatic plugin selection
//	request := LoadBalanceRequest{
//	    RequestID: "req-123",
//	    Key:       "user-456",  // For consistent hashing
//	}
//	response, err := lb.Execute(ctx, execCtx, request, myRequest)
//
//	// Monitor performance
//	stats := lb.GetStats()
//	for name, stat := range stats {
//	    fmt.Printf("Plugin %s: Success rate %.2f%%, Avg latency %v\n",
//	        name, stat.GetSuccessRate(), stat.AverageLatency)
//	}
type LoadBalancer[Req, Resp any] struct {
	strategy    LoadBalancingStrategy
	plugins     map[string]*PluginWrapper[Req, Resp]
	pluginOrder []string // For ordered strategies like round-robin
	logger      *slog.Logger

	// Strategy-specific state
	roundRobinCounter *atomic.Uint64
	mu                sync.RWMutex

	// Plugin metrics for intelligent load balancing
	pluginMetrics map[string]*PluginLoadMetrics
}

// PluginWrapper wraps a plugin with load balancing metadata
type PluginWrapper[Req, Resp any] struct {
	Plugin   Plugin[Req, Resp]
	Weight   int
	Priority int
	Active   *atomic.Int32 // Active connection count
	Enabled  *atomic.Bool
	LastUsed *atomic.Int64 // Unix timestamp
}

// PluginLoadMetrics tracks metrics for load balancing decisions
type PluginLoadMetrics struct {
	TotalRequests      atomic.Int64
	SuccessfulRequests atomic.Int64
	FailedRequests     atomic.Int64
	ActiveConnections  atomic.Int32
	AverageLatency     atomic.Int64 // Nanoseconds
	LastLatency        atomic.Int64 // Nanoseconds
	LastUpdate         atomic.Int64 // Unix timestamp
	HealthScore        atomic.Int32 // 0-100 scale
}

// LoadBalanceRequest contains request information for load balancing
type LoadBalanceRequest struct {
	RequestID   string
	Key         string   // For consistent hashing
	Priority    int      // Request priority
	Preferences []string // Preferred plugin names
}

// NewLoadBalancer creates a new load balancer instance with the specified strategy.
//
// The load balancer starts empty and plugins must be added using AddPlugin().
// It immediately begins tracking metrics and applying the selected load
// balancing strategy to distribute requests among registered plugins.
//
// Parameters:
//   - strategy: Load balancing algorithm to use for plugin selection
//   - logger: Logger instance for operational logging (uses default if nil)
//
// Returns a fully initialized LoadBalancer ready to accept plugin registrations
// and handle request routing.
func NewLoadBalancer[Req, Resp any](strategy LoadBalancingStrategy, logger *slog.Logger) *LoadBalancer[Req, Resp] {
	if logger == nil {
		logger = slog.Default()
	}

	return &LoadBalancer[Req, Resp]{
		strategy:          strategy,
		plugins:           make(map[string]*PluginWrapper[Req, Resp]),
		pluginOrder:       make([]string, 0),
		logger:            logger,
		roundRobinCounter: &atomic.Uint64{},
		pluginMetrics:     make(map[string]*PluginLoadMetrics),
	}
}

// AddPlugin adds a plugin to the load balancer
func (lb *LoadBalancer[Req, Resp]) AddPlugin(name string, plugin Plugin[Req, Resp], weight, priority int) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if _, exists := lb.plugins[name]; exists {
		return fmt.Errorf("plugin %s already exists in load balancer", name)
	}

	wrapper := &PluginWrapper[Req, Resp]{
		Plugin:   plugin,
		Weight:   weight,
		Priority: priority,
		Active:   &atomic.Int32{},
		Enabled:  &atomic.Bool{},
		LastUsed: &atomic.Int64{},
	}
	wrapper.Enabled.Store(true)
	wrapper.LastUsed.Store(time.Now().Unix())

	lb.plugins[name] = wrapper
	lb.pluginOrder = append(lb.pluginOrder, name)
	lb.pluginMetrics[name] = &PluginLoadMetrics{
		HealthScore: atomic.Int32{},
	}
	lb.pluginMetrics[name].HealthScore.Store(100) // Start with max health

	lb.logger.Info("Added plugin to load balancer",
		"name", name,
		"weight", weight,
		"priority", priority,
		"strategy", lb.strategy)

	return nil
}

// RemovePlugin removes a plugin from the load balancer
func (lb *LoadBalancer[Req, Resp]) RemovePlugin(name string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if _, exists := lb.plugins[name]; !exists {
		return fmt.Errorf("plugin %s not found in load balancer", name)
	}

	delete(lb.plugins, name)
	delete(lb.pluginMetrics, name)

	// Remove from order slice
	for i, pluginName := range lb.pluginOrder {
		if pluginName == name {
			lb.pluginOrder = append(lb.pluginOrder[:i], lb.pluginOrder[i+1:]...)
			break
		}
	}

	lb.logger.Info("Removed plugin from load balancer", "name", name)
	return nil
}

// EnablePlugin enables a plugin for load balancing
func (lb *LoadBalancer[Req, Resp]) EnablePlugin(name string) error {
	lb.mu.RLock()
	wrapper, exists := lb.plugins[name]
	lb.mu.RUnlock()

	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	wrapper.Enabled.Store(true)
	lb.logger.Info("Enabled plugin", "name", name)
	return nil
}

// DisablePlugin disables a plugin from load balancing
func (lb *LoadBalancer[Req, Resp]) DisablePlugin(name string) error {
	lb.mu.RLock()
	wrapper, exists := lb.plugins[name]
	lb.mu.RUnlock()

	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	wrapper.Enabled.Store(false)
	lb.logger.Info("Disabled plugin", "name", name)
	return nil
}

// SelectPlugin selects the best plugin based on the load balancing strategy
func (lb *LoadBalancer[Req, Resp]) SelectPlugin(lbReq LoadBalanceRequest) (string, Plugin[Req, Resp], error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.plugins) == 0 {
		return "", nil, fmt.Errorf("no plugins available")
	}

	candidates := lb.getHealthyCandidates()
	if len(candidates) == 0 {
		return "", nil, fmt.Errorf("no healthy plugins available")
	}

	selectedName, err := lb.selectByStrategy(candidates, lbReq)
	if err != nil {
		return "", nil, err
	}

	if selectedName == "" {
		return "", nil, fmt.Errorf("failed to select plugin")
	}

	plugin := lb.updatePluginUsage(selectedName, lbReq)
	return selectedName, plugin, nil
}

// selectByStrategy applies the configured load balancing strategy
func (lb *LoadBalancer[Req, Resp]) selectByStrategy(candidates []string, lbReq LoadBalanceRequest) (string, error) {
	switch lb.strategy {
	case StrategyRoundRobin:
		return lb.selectRoundRobin(candidates), nil
	case StrategyRandom:
		return lb.selectRandom(candidates), nil
	case StrategyLeastConnections:
		return lb.selectLeastConnections(candidates), nil
	case StrategyLeastLatency:
		return lb.selectLeastLatency(candidates), nil
	case StrategyWeightedRandom:
		return lb.selectWeightedRandom(candidates), nil
	case StrategyConsistentHash:
		return lb.selectConsistentHash(candidates, lbReq.Key), nil
	case StrategyPriority:
		return lb.selectPriority(candidates), nil
	default:
		return "", fmt.Errorf("unsupported load balancing strategy: %s", lb.strategy)
	}
}

// updatePluginUsage updates plugin usage metrics and returns the plugin
func (lb *LoadBalancer[Req, Resp]) updatePluginUsage(selectedName string, lbReq LoadBalanceRequest) Plugin[Req, Resp] {
	wrapper := lb.plugins[selectedName]
	wrapper.LastUsed.Store(time.Now().Unix())

	lb.logger.Debug("Selected plugin for request",
		"plugin", selectedName,
		"strategy", lb.strategy,
		"request_id", lbReq.RequestID)

	return wrapper.Plugin
}

// getHealthyCandidates returns list of healthy and enabled plugins
func (lb *LoadBalancer[Req, Resp]) getHealthyCandidates() []string {
	candidates := make([]string, 0, len(lb.plugins))

	for name, wrapper := range lb.plugins {
		if !wrapper.Enabled.Load() {
			continue
		}

		metrics := lb.pluginMetrics[name]
		if metrics.HealthScore.Load() > 20 { // Health score threshold
			candidates = append(candidates, name)
		}
	}

	return candidates
}

// selectRoundRobin implements round-robin selection
func (lb *LoadBalancer[Req, Resp]) selectRoundRobin(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	// Use pluginOrder to ensure consistent ordering
	orderedCandidates := make([]string, 0, len(candidates))
	for _, name := range lb.pluginOrder {
		for _, candidate := range candidates {
			if name == candidate {
				orderedCandidates = append(orderedCandidates, candidate)
				break
			}
		}
	}

	if len(orderedCandidates) == 0 {
		return candidates[0] // Fallback
	}

	counter := lb.roundRobinCounter.Add(1)
	// Safely calculate index to avoid integer overflow
	candidatesLen := uint64(len(orderedCandidates))
	indexUint := (counter - 1) % candidatesLen

	// Double-check that the result fits in an int
	const maxInt = int(^uint(0) >> 1) // Maximum positive int value
	if indexUint > uint64(maxInt) {
		// This should never happen since indexUint < candidatesLen and len() returns int
		// but gosec wants us to be extra careful
		return orderedCandidates[0]
	}

	index := int(indexUint)
	return orderedCandidates[index]
}

// selectRandom implements random selection
func (lb *LoadBalancer[Req, Resp]) selectRandom(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	index, err := secureRandomInt(len(candidates))
	if err != nil {
		// Fallback to first candidate if secure random fails
		lb.logger.Error("Failed to generate secure random number", "error", err)
		return candidates[0]
	}
	return candidates[index]
}

// selectLeastConnections implements least connections selection
func (lb *LoadBalancer[Req, Resp]) selectLeastConnections(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	var selectedName string
	minConnections := int32(1<<31 - 1) // Max int32

	for _, name := range candidates {
		wrapper := lb.plugins[name]
		connections := wrapper.Active.Load()

		if connections < minConnections {
			minConnections = connections
			selectedName = name
		}
	}

	return selectedName
}

// selectLeastLatency implements least latency selection
func (lb *LoadBalancer[Req, Resp]) selectLeastLatency(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	var selectedName string
	minLatency := int64(1<<63 - 1) // Max int64

	for _, name := range candidates {
		metrics := lb.pluginMetrics[name]
		latency := metrics.AverageLatency.Load()

		// If no latency data, use a default middle value
		if latency == 0 {
			latency = 100 * int64(time.Millisecond)
		}

		if latency < minLatency {
			minLatency = latency
			selectedName = name
		}
	}

	return selectedName
}

// selectWeightedRandom implements weighted random selection
func (lb *LoadBalancer[Req, Resp]) selectWeightedRandom(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	// Calculate total weight
	totalWeight := 0
	for _, name := range candidates {
		wrapper := lb.plugins[name]
		totalWeight += wrapper.Weight
	}

	if totalWeight == 0 {
		// If no weights set, fall back to random
		return lb.selectRandom(candidates)
	}

	// Select based on weight
	randomWeight, err := secureRandomInt(totalWeight)
	if err != nil {
		// Fallback to first candidate if secure random fails
		lb.logger.Error("Failed to generate secure random number for weights", "error", err)
		return candidates[0]
	}
	currentWeight := 0

	for _, name := range candidates {
		wrapper := lb.plugins[name]
		currentWeight += wrapper.Weight

		if randomWeight < currentWeight {
			return name
		}
	}

	// Fallback (should not happen)
	return candidates[0]
}

// selectConsistentHash implements consistent hash selection
func (lb *LoadBalancer[Req, Resp]) selectConsistentHash(candidates []string, key string) string {
	if len(candidates) == 0 {
		return ""
	}

	if key == "" {
		// No key provided, fall back to random
		return lb.selectRandom(candidates)
	}

	// Sort candidates to ensure consistent ordering for consistent hashing
	// This is critical because Go maps have undefined iteration order
	sortedCandidates := make([]string, len(candidates))
	copy(sortedCandidates, candidates)

	// Simple insertion sort for small arrays (typical plugin count)
	for i := 1; i < len(sortedCandidates); i++ {
		key := sortedCandidates[i]
		j := i - 1
		for j >= 0 && sortedCandidates[j] > key {
			sortedCandidates[j+1] = sortedCandidates[j]
			j--
		}
		sortedCandidates[j+1] = key
	}

	// Simple hash function
	hasher := fnv.New32a()
	if _, err := hasher.Write([]byte(key)); err != nil {
		// Hash write failed, fall back to random selection
		lb.logger.Error("Hash write failed", "error", err)
		return lb.selectRandom(candidates)
	}
	hash := hasher.Sum32()

	index := int(hash) % len(sortedCandidates)
	return sortedCandidates[index]
}

// selectPriority implements priority-based selection
func (lb *LoadBalancer[Req, Resp]) selectPriority(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	var selectedName string
	maxPriority := -1

	for _, name := range candidates {
		wrapper := lb.plugins[name]

		if wrapper.Priority > maxPriority {
			maxPriority = wrapper.Priority
			selectedName = name
		}
	}

	return selectedName
}

// Execute processes a request using intelligent load balancing and comprehensive metrics tracking.
//
// This method implements the complete request lifecycle including plugin selection,
// request execution, metrics collection, and health score updates. It provides
// automatic failover and detailed performance tracking for operational visibility.
//
// Request lifecycle:
//  1. Select optimal plugin using configured load balancing strategy
//  2. Track active connections and update metrics
//  3. Execute request through selected plugin
//  4. Record latency, success/failure, and update health scores
//  5. Return response or error with full traceability
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - execCtx: Execution context with request metadata and configuration
//   - lbReq: Load balancing request with selection hints (key, preferences)
//   - request: The actual request payload to be processed
//
// Returns the response from the selected plugin or an error if all plugins
// are unavailable or the request fails.
//
// Metrics collected:
//   - Request count, success/failure rates
//   - Response latency and connection counts
//   - Plugin health scores and availability
func (lb *LoadBalancer[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, lbReq LoadBalanceRequest, request Req) (Resp, error) {
	var zero Resp

	// Select plugin
	pluginName, plugin, err := lb.SelectPlugin(lbReq)
	if err != nil {
		return zero, fmt.Errorf("plugin selection failed: %w", err)
	}

	// Track connection
	wrapper := lb.plugins[pluginName]
	wrapper.Active.Add(1)
	defer wrapper.Active.Add(-1)

	// Track metrics
	startTime := time.Now()
	metrics := lb.pluginMetrics[pluginName]
	metrics.TotalRequests.Add(1)

	// Execute request
	response, execErr := plugin.Execute(ctx, execCtx, request)

	// Update metrics
	latency := time.Since(startTime)
	metrics.LastLatency.Store(latency.Nanoseconds())

	if execErr == nil {
		metrics.SuccessfulRequests.Add(1)
		lb.updateHealthScore(pluginName, true)
	} else {
		metrics.FailedRequests.Add(1)
		lb.updateHealthScore(pluginName, false)
	}

	// Update average latency (simple moving average)
	lb.updateAverageLatency(pluginName, latency)

	return response, execErr
}

// updateHealthScore updates the health score based on success/failure
func (lb *LoadBalancer[Req, Resp]) updateHealthScore(pluginName string, success bool) {
	metrics := lb.pluginMetrics[pluginName]
	currentScore := metrics.HealthScore.Load()

	var newScore int32
	if success {
		// Increase health score on success (max 100)
		newScore = currentScore + 1
		if newScore > 100 {
			newScore = 100
		}
	} else {
		// Decrease health score on failure
		newScore = currentScore - 5
		if newScore < 0 {
			newScore = 0
		}
	}

	metrics.HealthScore.Store(newScore)
	metrics.LastUpdate.Store(time.Now().Unix())
}

// updateAverageLatency updates the average latency using exponential moving average
func (lb *LoadBalancer[Req, Resp]) updateAverageLatency(pluginName string, latency time.Duration) {
	metrics := lb.pluginMetrics[pluginName]
	currentAvg := metrics.AverageLatency.Load()

	var newAvg int64
	if currentAvg == 0 {
		// First measurement
		newAvg = latency.Nanoseconds()
	} else {
		// Exponential moving average with α = 0.2
		newAvg = int64(0.8*float64(currentAvg) + 0.2*float64(latency.Nanoseconds()))
	}

	metrics.AverageLatency.Store(newAvg)
}

// GetStats returns current load balancing statistics
func (lb *LoadBalancer[Req, Resp]) GetStats() map[string]LoadBalancerStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	stats := make(map[string]LoadBalancerStats)

	for name := range lb.plugins {
		wrapper := lb.plugins[name]
		metrics := lb.pluginMetrics[name]

		stats[name] = LoadBalancerStats{
			PluginName:         name,
			Weight:             wrapper.Weight,
			Priority:           wrapper.Priority,
			Enabled:            wrapper.Enabled.Load(),
			ActiveConnections:  wrapper.Active.Load(),
			TotalRequests:      metrics.TotalRequests.Load(),
			SuccessfulRequests: metrics.SuccessfulRequests.Load(),
			FailedRequests:     metrics.FailedRequests.Load(),
			AverageLatency:     time.Duration(metrics.AverageLatency.Load()),
			HealthScore:        metrics.HealthScore.Load(),
			LastUsed:           time.Unix(wrapper.LastUsed.Load(), 0),
		}
	}

	return stats
}

// LoadBalancerStats contains comprehensive statistics for a plugin in the load balancer.
//
// This structure provides detailed metrics about plugin performance and usage
// patterns within the load balancer. The statistics are essential for monitoring,
// alerting, capacity planning, and debugging load balancing decisions.
//
// Statistical categories:
//   - Configuration: Weight, priority, and enabled status
//   - Performance: Request counts, success rates, and latency metrics
//   - Health: Health score and availability indicators
//   - Operational: Active connections and last usage timestamp
//
// Example usage:
//
//	stats := loadBalancer.GetStats()
//	for pluginName, stat := range stats {
//	    successRate := stat.GetSuccessRate()
//	    if successRate < 95.0 {
//	        log.Printf("Plugin %s has low success rate: %.2f%%",
//	            pluginName, successRate)
//	    }
//
//	    if stat.AverageLatency > 5*time.Second {
//	        log.Printf("Plugin %s has high latency: %v",
//	            pluginName, stat.AverageLatency)
//	    }
//	}
type LoadBalancerStats struct {
	PluginName         string        `json:"plugin_name"`
	Weight             int           `json:"weight"`
	Priority           int           `json:"priority"`
	Enabled            bool          `json:"enabled"`
	ActiveConnections  int32         `json:"active_connections"`
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
	FailedRequests     int64         `json:"failed_requests"`
	AverageLatency     time.Duration `json:"average_latency"`
	HealthScore        int32         `json:"health_score"`
	LastUsed           time.Time     `json:"last_used"`
}

// GetSuccessRate calculates the success rate as a percentage (0-100).
//
// This method computes the success rate based on successful requests divided
// by total requests. It returns 0.0 if no requests have been processed.
// The success rate is a key indicator of plugin health and reliability.
//
// Returns:
//   - 0.0: No requests processed yet
//   - 0.0-100.0: Success percentage based on successful vs total requests
//
// Usage for monitoring:
//
//	if stats.GetSuccessRate() < 99.0 {
//	    alert("Plugin success rate below threshold")
//	}
func (stats LoadBalancerStats) GetSuccessRate() float64 {
	if stats.TotalRequests == 0 {
		return 0.0
	}
	return (float64(stats.SuccessfulRequests) / float64(stats.TotalRequests)) * 100.0
}
