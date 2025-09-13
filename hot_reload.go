// hot_reload.go: Intelligent hot-reloading system with diff-based updates
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// PluginDiff represents the differences between old and new plugin configurations
type PluginDiff struct {
	Added     []PluginConfig `json:"added"`
	Updated   []PluginUpdate `json:"updated"`
	Removed   []string       `json:"removed"`
	Unchanged []string       `json:"unchanged"`
}

// PluginUpdate represents an update to an existing plugin
type PluginUpdate struct {
	Name      string       `json:"name"`
	OldConfig PluginConfig `json:"old_config"`
	NewConfig PluginConfig `json:"new_config"`
	Changes   []string     `json:"changes"`
}

// ReloadStrategy defines how plugins should be reloaded
type ReloadStrategy string

const (
	// ReloadStrategyRecreate completely removes and recreates plugins (current behavior)
	ReloadStrategyRecreate ReloadStrategy = "recreate"

	// ReloadStrategyGraceful drains connections gracefully before updating
	ReloadStrategyGraceful ReloadStrategy = "graceful"

	// ReloadStrategyRolling performs rolling updates with zero downtime
	ReloadStrategyRolling ReloadStrategy = "rolling"
)

// ReloadOptions configures how hot-reload should behave
type ReloadOptions struct {
	Strategy             ReloadStrategy `json:"strategy"`
	DrainTimeout         time.Duration  `json:"drain_timeout"`
	GracefulTimeout      time.Duration  `json:"graceful_timeout"`
	MaxConcurrentReloads int            `json:"max_concurrent_reloads"`
	HealthCheckTimeout   time.Duration  `json:"health_check_timeout"`
	RollbackOnFailure    bool           `json:"rollback_on_failure"`
}

// DefaultReloadOptions returns sensible defaults for reload options
func DefaultReloadOptions() ReloadOptions {
	return ReloadOptions{
		Strategy:             ReloadStrategyGraceful,
		DrainTimeout:         30 * time.Second,
		GracefulTimeout:      60 * time.Second,
		MaxConcurrentReloads: 3,
		HealthCheckTimeout:   10 * time.Second,
		RollbackOnFailure:    true,
	}
}

// PluginReloader manages the hot-reload process
type PluginReloader[Req, Resp any] struct {
	manager *Manager[Req, Resp]
	options ReloadOptions
	logger  *slog.Logger

	// State tracking
	mu               sync.RWMutex
	reloadInProgress bool
	lastConfig       ManagerConfig
}

// NewPluginReloader creates a new plugin reloader
func NewPluginReloader[Req, Resp any](manager *Manager[Req, Resp], options ReloadOptions, logger *slog.Logger) *PluginReloader[Req, Resp] {
	if logger == nil {
		logger = slog.Default()
	}

	return &PluginReloader[Req, Resp]{
		manager: manager,
		options: options,
		logger:  logger,
	}
}

// ReloadWithIntelligentDiff performs intelligent hot-reload based on configuration diff
func (r *PluginReloader[Req, Resp]) ReloadWithIntelligentDiff(ctx context.Context, newConfig ManagerConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reloadInProgress {
		return fmt.Errorf("reload already in progress")
	}
	r.reloadInProgress = true
	defer func() { r.reloadInProgress = false }()

	// Validate new configuration
	if err := newConfig.Validate(); err != nil {
		return fmt.Errorf("invalid new configuration: %w", err)
	}

	r.logger.Info("Starting intelligent plugin reload",
		"strategy", r.options.Strategy,
		"plugins_count", len(newConfig.Plugins))

	// Calculate diff between old and new configurations
	diff := r.calculateDiff(r.lastConfig, newConfig)
	r.logger.Info("Configuration diff calculated",
		"added", len(diff.Added),
		"updated", len(diff.Updated),
		"removed", len(diff.Removed),
		"unchanged", len(diff.Unchanged))

	// Execute reload based on strategy
	switch r.options.Strategy {
	case ReloadStrategyRecreate:
		return r.executeRecreateStrategy(ctx, newConfig)
	case ReloadStrategyGraceful:
		return r.executeGracefulStrategy(ctx, newConfig, diff)
	case ReloadStrategyRolling:
		return r.executeRollingStrategy(ctx, newConfig, diff)
	default:
		return fmt.Errorf("unsupported reload strategy: %s", r.options.Strategy)
	}
}

// calculateDiff compares old and new configurations to determine changes
func (r *PluginReloader[Req, Resp]) calculateDiff(oldConfig, newConfig ManagerConfig) PluginDiff {
	diff := PluginDiff{
		Added:     make([]PluginConfig, 0),
		Updated:   make([]PluginUpdate, 0),
		Removed:   make([]string, 0),
		Unchanged: make([]string, 0),
	}

	// Build maps for easier comparison
	oldPlugins := make(map[string]PluginConfig)
	for _, plugin := range oldConfig.Plugins {
		oldPlugins[plugin.Name] = plugin
	}

	newPlugins := make(map[string]PluginConfig)
	for _, plugin := range newConfig.Plugins {
		newPlugins[plugin.Name] = plugin
	}

	// Find added and updated plugins
	for name, newPlugin := range newPlugins {
		if oldPlugin, exists := oldPlugins[name]; exists {
			if changes := r.comparePluginConfigs(oldPlugin, newPlugin); len(changes) > 0 {
				diff.Updated = append(diff.Updated, PluginUpdate{
					Name:      name,
					OldConfig: oldPlugin,
					NewConfig: newPlugin,
					Changes:   changes,
				})
			} else {
				diff.Unchanged = append(diff.Unchanged, name)
			}
		} else {
			diff.Added = append(diff.Added, newPlugin)
		}
	}

	// Find removed plugins
	for name := range oldPlugins {
		if _, exists := newPlugins[name]; !exists {
			diff.Removed = append(diff.Removed, name)
		}
	}

	return diff
}

// comparePluginConfigs compares two plugin configurations and returns list of changes
func (r *PluginReloader[Req, Resp]) comparePluginConfigs(old, new PluginConfig) []string {
	changes := make([]string, 0)

	if old.Endpoint != new.Endpoint {
		changes = append(changes, "endpoint")
	}
	if old.Transport != new.Transport {
		changes = append(changes, "transport")
	}
	if old.Enabled != new.Enabled {
		changes = append(changes, "enabled")
	}
	if old.Priority != new.Priority {
		changes = append(changes, "priority")
	}

	// Check auth changes
	if r.authConfigChanged(old.Auth, new.Auth) {
		changes = append(changes, "auth")
	}

	// Check retry config changes
	if old.Retry != new.Retry {
		changes = append(changes, "retry")
	}

	// Check circuit breaker changes
	if old.CircuitBreaker != new.CircuitBreaker {
		changes = append(changes, "circuit_breaker")
	}

	// Check health check changes
	if old.HealthCheck != new.HealthCheck {
		changes = append(changes, "health_check")
	}

	return changes
}

// authConfigChanged checks if authentication configuration has changed
func (r *PluginReloader[Req, Resp]) authConfigChanged(old, new AuthConfig) bool {
	return old.Method != new.Method ||
		old.APIKey != new.APIKey ||
		old.Token != new.Token ||
		old.Username != new.Username ||
		old.Password != new.Password ||
		old.CertFile != new.CertFile ||
		old.KeyFile != new.KeyFile ||
		old.CAFile != new.CAFile
}

// executeRecreateStrategy implements the simple recreate strategy (current behavior)
func (r *PluginReloader[Req, Resp]) executeRecreateStrategy(ctx context.Context, newConfig ManagerConfig) error {
	r.logger.Info("Executing recreate reload strategy")

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Store current config for rollback
	oldConfig := r.lastConfig

	// Use the manager's existing ReloadConfig method
	if err := r.manager.ReloadConfig(newConfig); err != nil {
		if r.options.RollbackOnFailure && oldConfig.Plugins != nil {
			r.logger.Warn("Reload failed, attempting rollback", "error", err)
			if rollbackErr := r.manager.ReloadConfig(oldConfig); rollbackErr != nil {
				return fmt.Errorf("reload failed and rollback failed: %w (original error: %v)", rollbackErr, err)
			}
		}
		return fmt.Errorf("recreate reload failed: %w", err)
	}

	r.lastConfig = newConfig
	return nil
}

// executeGracefulStrategy implements graceful reload with connection draining
func (r *PluginReloader[Req, Resp]) executeGracefulStrategy(ctx context.Context, newConfig ManagerConfig, diff PluginDiff) error {
	r.logger.Info("Executing graceful reload strategy")

	// Create timeout context
	reloadCtx, cancel := context.WithTimeout(ctx, r.options.GracefulTimeout)
	defer cancel()

	// Step 1: Add new plugins first
	if err := r.addPlugins(reloadCtx, diff.Added); err != nil {
		return fmt.Errorf("failed to add new plugins: %w", err)
	}

	// Step 2: Update existing plugins with graceful drain
	if err := r.updatePluginsGracefully(reloadCtx, diff.Updated); err != nil {
		return fmt.Errorf("failed to update plugins gracefully: %w", err)
	}

	// Step 3: Remove old plugins with graceful drain
	if err := r.removePluginsGracefully(reloadCtx, diff.Removed); err != nil {
		return fmt.Errorf("failed to remove plugins gracefully: %w", err)
	}

	r.lastConfig = newConfig
	r.logger.Info("Graceful reload completed successfully")
	return nil
}

// executeRollingStrategy implements zero-downtime rolling updates
func (r *PluginReloader[Req, Resp]) executeRollingStrategy(ctx context.Context, newConfig ManagerConfig, diff PluginDiff) error {
	r.logger.Info("Executing rolling reload strategy")

	// For rolling updates, we need to be even more careful
	// This is a simplified implementation - in production, you might want more sophisticated logic

	// Step 1: Add new plugins
	if err := r.addPlugins(ctx, diff.Added); err != nil {
		return fmt.Errorf("failed to add new plugins in rolling update: %w", err)
	}

	// Step 2: Rolling update of existing plugins
	if err := r.rollingUpdatePlugins(ctx, diff.Updated); err != nil {
		return fmt.Errorf("failed to perform rolling update: %w", err)
	}

	// Step 3: Graceful removal
	if err := r.removePluginsGracefully(ctx, diff.Removed); err != nil {
		return fmt.Errorf("failed to remove plugins in rolling update: %w", err)
	}

	r.lastConfig = newConfig
	r.logger.Info("Rolling reload completed successfully")
	return nil
}

// addPlugins adds new plugins to the manager
func (r *PluginReloader[Req, Resp]) addPlugins(ctx context.Context, plugins []PluginConfig) error {
	for _, config := range plugins {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !config.Enabled {
			continue
		}

		factory, exists := r.manager.factories[config.Type]
		if !exists {
			return fmt.Errorf("no factory registered for plugin type: %s", config.Type)
		}

		plugin, err := factory.CreatePlugin(config)
		if err != nil {
			return fmt.Errorf("failed to create plugin %s: %w", config.Name, err)
		}

		if err := r.manager.Register(plugin); err != nil {
			return fmt.Errorf("failed to register plugin %s: %w", config.Name, err)
		}

		r.logger.Info("Added new plugin", "name", config.Name, "type", config.Type)
	}

	return nil
}

// updatePluginsGracefully updates existing plugins with connection draining
func (r *PluginReloader[Req, Resp]) updatePluginsGracefully(ctx context.Context, updates []PluginUpdate) error {
	for _, update := range updates {
		r.logger.Info("Gracefully updating plugin",
			"name", update.Name,
			"changes", update.Changes)

		// Check if changes require recreation
		requiresRecreation := r.requiresRecreation(update.Changes)

		if !requiresRecreation {
			// Simple configuration update without recreation
			r.logger.Info("Plugin update doesn't require recreation", "name", update.Name)
			continue
		}

		// Wait for connections to drain
		if err := r.drainPluginConnections(ctx, update.Name); err != nil {
			r.logger.Warn("Failed to drain connections gracefully",
				"plugin", update.Name, "error", err)
		}

		// Remove old plugin
		if err := r.manager.Unregister(update.Name); err != nil {
			return fmt.Errorf("failed to unregister plugin %s: %w", update.Name, err)
		}

		// Create and register new plugin
		factory, exists := r.manager.factories[update.NewConfig.Type]
		if !exists {
			return fmt.Errorf("no factory registered for plugin type: %s", update.NewConfig.Type)
		}

		newPlugin, err := factory.CreatePlugin(update.NewConfig)
		if err != nil {
			return fmt.Errorf("failed to create updated plugin %s: %w", update.Name, err)
		}

		if err := r.manager.Register(newPlugin); err != nil {
			return fmt.Errorf("failed to register updated plugin %s: %w", update.Name, err)
		}

		r.logger.Info("Successfully updated plugin", "name", update.Name)
	}

	return nil
}

// removePluginsGracefully removes plugins after draining connections
func (r *PluginReloader[Req, Resp]) removePluginsGracefully(ctx context.Context, pluginNames []string) error {
	for _, name := range pluginNames {
		r.logger.Info("Gracefully removing plugin", "name", name)

		// Drain connections
		if err := r.drainPluginConnections(ctx, name); err != nil {
			r.logger.Warn("Failed to drain connections gracefully",
				"plugin", name, "error", err)
		}

		// Remove plugin
		if err := r.manager.Unregister(name); err != nil {
			r.logger.Warn("Failed to unregister plugin",
				"plugin", name, "error", err)
		} else {
			r.logger.Info("Successfully removed plugin", "name", name)
		}
	}

	return nil
}

// rollingUpdatePlugins performs rolling updates with zero downtime
func (r *PluginReloader[Req, Resp]) rollingUpdatePlugins(ctx context.Context, updates []PluginUpdate) error {
	// Limit concurrent updates
	semaphore := make(chan struct{}, r.options.MaxConcurrentReloads)
	var wg sync.WaitGroup
	var errors []error
	var errorsMu sync.Mutex

	for _, update := range updates {
		wg.Add(1)
		go func(upd PluginUpdate) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := r.performRollingUpdate(ctx, upd); err != nil {
				errorsMu.Lock()
				errors = append(errors, fmt.Errorf("rolling update failed for %s: %w", upd.Name, err))
				errorsMu.Unlock()
			}
		}(update)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("rolling update had %d failures: %v", len(errors), errors[0])
	}

	return nil
}

// performRollingUpdate performs a single rolling update
func (r *PluginReloader[Req, Resp]) performRollingUpdate(ctx context.Context, update PluginUpdate) error {
	// Create new plugin with temporary name
	tempName := update.Name + "_new"
	tempConfig := update.NewConfig
	tempConfig.Name = tempName

	factory, exists := r.manager.factories[tempConfig.Type]
	if !exists {
		return fmt.Errorf("no factory registered for plugin type: %s", tempConfig.Type)
	}

	newPlugin, err := factory.CreatePlugin(tempConfig)
	if err != nil {
		return fmt.Errorf("failed to create new plugin: %w", err)
	}

	// Register new plugin
	if err := r.manager.Register(newPlugin); err != nil {
		return fmt.Errorf("failed to register new plugin: %w", err)
	}

	// Wait for new plugin to be healthy
	if err := r.waitForPluginHealth(ctx, tempName); err != nil {
		if unregErr := r.manager.Unregister(tempName); unregErr != nil {
			r.logger.Error("Failed to unregister temp plugin after health check failure", "error", unregErr)
		}
		return fmt.Errorf("new plugin failed health check: %w", err)
	}

	// Drain old plugin and switch
	if err := r.drainPluginConnections(ctx, update.Name); err != nil {
		r.logger.Warn("Failed to drain old plugin gracefully", "error", err)
	}

	// Remove old plugin
	if err := r.manager.Unregister(update.Name); err != nil {
		r.logger.Warn("Failed to unregister old plugin", "error", err)
	}

	// Rename new plugin to original name
	// This is a simplification - in practice, you'd need a more sophisticated way to handle this
	if err := r.manager.Unregister(tempName); err != nil {
		return fmt.Errorf("failed to unregister temp plugin: %w", err)
	}

	if err := r.manager.Register(newPlugin); err != nil {
		return fmt.Errorf("failed to register plugin with original name: %w", err)
	}

	return nil
}

// requiresRecreation determines if a plugin needs to be recreated based on changes
func (r *PluginReloader[Req, Resp]) requiresRecreation(changes []string) bool {
	recreationChanges := []string{"endpoint", "transport", "auth", "executable"}

	for _, change := range changes {
		for _, recreationChange := range recreationChanges {
			if change == recreationChange {
				return true
			}
		}
	}

	return false
}

// drainPluginConnections waits for active connections to drain
func (r *PluginReloader[Req, Resp]) drainPluginConnections(ctx context.Context, pluginName string) error {
	drainCtx, cancel := context.WithTimeout(ctx, r.options.DrainTimeout)
	defer cancel()

	r.logger.Info("Draining connections for plugin", "name", pluginName)

	// In a real implementation, you would:
	// 1. Mark the plugin as "draining" to prevent new requests
	// 2. Wait for active requests to complete
	// 3. Monitor connection count/active requests

	// For now, we'll do a simple timeout
	select {
	case <-time.After(r.options.DrainTimeout):
		r.logger.Info("Connection drain timeout reached", "plugin", pluginName)
		return nil
	case <-drainCtx.Done():
		return drainCtx.Err()
	}
}

// waitForPluginHealth waits for a plugin to become healthy
func (r *PluginReloader[Req, Resp]) waitForPluginHealth(ctx context.Context, pluginName string) error {
	healthCtx, cancel := context.WithTimeout(ctx, r.options.HealthCheckTimeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-healthCtx.Done():
			return fmt.Errorf("health check timeout for plugin %s", pluginName)
		case <-ticker.C:
			health := r.manager.Health()
			if status, exists := health[pluginName]; exists && status.Status == StatusHealthy {
				return nil
			}
		}
	}
}
