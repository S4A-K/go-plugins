package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	plugins "github.com/go-plugins"
)

// CounterPlugin is a simple plugin that maintains a counter
type CounterPlugin struct {
	name      string
	version   string
	counter   int64
	increment int64
	enabled   atomic.Bool
	logger    *slog.Logger
}

// CounterRequest represents a request to the counter plugin
type CounterRequest struct {
	Action string `json:"action"` // "increment", "get", "reset"
	Value  int64  `json:"value,omitempty"`
}

// CounterResponse represents a response from the counter plugin
type CounterResponse struct {
	Value   int64  `json:"value"`
	Message string `json:"message,omitempty"`
}

// NewCounterPlugin creates a new counter plugin instance
func NewCounterPlugin(config plugins.PluginConfig) *CounterPlugin {
	logger := slog.With("plugin", config.Name)

	// Parse increment from config (using Options instead of Config)
	increment := int64(1)
	if incrementValue, ok := config.Options["increment"]; ok {
		if inc, ok := incrementValue.(float64); ok {
			increment = int64(inc)
		}
	}

	plugin := &CounterPlugin{
		name:      config.Name,
		version:   "1.0.0",
		increment: increment,
		logger:    logger,
	}

	plugin.enabled.Store(true)

	logger.Info("Counter plugin created",
		"increment", increment,
		"version", plugin.version)

	return plugin
}

// Info returns plugin information
func (c *CounterPlugin) Info() plugins.PluginInfo {
	return plugins.PluginInfo{
		Name:         c.name,
		Version:      c.version,
		Description:  "A simple counter plugin for hot reload demonstration",
		Author:       "go-plugins examples",
		Capabilities: []string{"increment", "get", "reset", "add"},
		Metadata: map[string]string{
			"type":      "counter",
			"transport": "http",
		},
	}
}

// Execute processes a request with execution context
func (c *CounterPlugin) Execute(ctx context.Context, execCtx plugins.ExecutionContext, req CounterRequest) (CounterResponse, error) {
	if !c.enabled.Load() {
		return CounterResponse{}, fmt.Errorf("plugin is disabled")
	}

	switch req.Action {
	case "increment":
		newValue := atomic.AddInt64(&c.counter, c.increment)
		c.logger.Info("Counter incremented", "new_value", newValue)
		return CounterResponse{
			Value:   newValue,
			Message: fmt.Sprintf("Counter incremented by %d", c.increment),
		}, nil

	case "get":
		value := atomic.LoadInt64(&c.counter)
		return CounterResponse{
			Value:   value,
			Message: "Current counter value",
		}, nil

	case "reset":
		atomic.StoreInt64(&c.counter, 0)
		c.logger.Info("Counter reset")
		return CounterResponse{
			Value:   0,
			Message: "Counter reset to 0",
		}, nil

	case "add":
		if req.Value != 0 {
			newValue := atomic.AddInt64(&c.counter, req.Value)
			c.logger.Info("Counter updated", "added", req.Value, "new_value", newValue)
			return CounterResponse{
				Value:   newValue,
				Message: fmt.Sprintf("Added %d to counter", req.Value),
			}, nil
		}
		return CounterResponse{}, fmt.Errorf("value is required for add action")

	default:
		return CounterResponse{}, fmt.Errorf("unknown action: %s", req.Action)
	}
}

// Health returns the plugin health status
func (c *CounterPlugin) Health(ctx context.Context) plugins.HealthStatus {
	status := plugins.StatusHealthy
	message := "Plugin is healthy"

	if !c.enabled.Load() {
		status = plugins.StatusUnhealthy
		message = "Plugin is disabled"
	}

	return plugins.HealthStatus{
		Status:       status,
		Message:      message,
		ResponseTime: time.Millisecond,
	}
}

// Close gracefully shuts down the plugin
func (c *CounterPlugin) Close() error {
	c.enabled.Store(false)
	c.logger.Info("Counter plugin closed")
	return nil
}

// CounterPluginFactory creates counter plugin instances
type CounterPluginFactory struct{}

// CreatePlugin creates a new counter plugin instance
func (f *CounterPluginFactory) CreatePlugin(config plugins.PluginConfig) (plugins.Plugin[CounterRequest, CounterResponse], error) {
	return NewCounterPlugin(config), nil
}

// SupportedTransports returns supported transports
func (f *CounterPluginFactory) SupportedTransports() []string {
	return []string{"http"}
}

// ValidateConfig validates the plugin configuration
func (f *CounterPluginFactory) ValidateConfig(config plugins.PluginConfig) error {
	// Optional: validate increment value
	if incrementValue, ok := config.Options["increment"]; ok {
		if _, ok := incrementValue.(float64); !ok {
			return fmt.Errorf("increment must be a number")
		}
	}
	return nil
}
