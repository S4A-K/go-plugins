// shutdown_coordinator.go: Coordinated shutdown management
//
// This file implements the ShutdownCoordinator struct and its methods.
// It manages coordinated shutdown of the entire plugin system and handles the proper
// shutdown sequence: draining -> clients -> protocols -> processes.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
)

// ShutdownCoordinator manages coordinated shutdown of the entire plugin system.
type ShutdownCoordinator struct {
	registry *PluginRegistry
	logger   Logger
}

// NewShutdownCoordinator creates a new shutdown coordinator.
func NewShutdownCoordinator(registry *PluginRegistry) *ShutdownCoordinator {
	return &ShutdownCoordinator{
		registry: registry,
		logger:   registry.logger,
	}
}

// GracefulShutdown performs a coordinated graceful shutdown of the entire system.
// It follows the proper order: draining -> clients -> protocols -> processes.
func (sc *ShutdownCoordinator) GracefulShutdown(ctx context.Context) error {
	sc.logger.Info("Starting coordinated graceful shutdown")

	// Phase 1: Start draining (stop accepting new requests)
	if err := sc.registry.StartDraining(); err != nil {
		sc.logger.Warn("Failed to start draining", "error", err)
	}

	// Phase 2: Wait for active requests to complete or timeout
	activeRequests := sc.registry.GetActiveRequestsCount()
	totalActive := int64(0)
	for _, count := range activeRequests {
		totalActive += count
	}

	if totalActive > 0 {
		sc.logger.Info("Waiting for active requests to complete",
			"total_active", totalActive,
			"per_client", activeRequests)
	}

	// Phase 3: Perform graceful registry shutdown
	if err := sc.registry.StopWithContext(ctx); err != nil {
		sc.logger.Error("Registry shutdown encountered errors", "error", err)
		return NewRegistryError("registry shutdown failed", err)
	}

	sc.logger.Info("Coordinated graceful shutdown completed successfully")
	return nil
}

// ForceShutdown performs an immediate shutdown with minimal cleanup.
// Use only when graceful shutdown fails or in emergency situations.
func (sc *ShutdownCoordinator) ForceShutdown() error {
	sc.logger.Warn("Performing force shutdown")

	// Force cancel all requests
	activeRequests := sc.registry.GetActiveRequestsCount()
	totalCanceled := 0

	for clientName := range activeRequests {
		canceled := sc.registry.requestTracker.ForceCancel(clientName)
		totalCanceled += canceled
		if canceled > 0 {
			sc.logger.Info("Force canceled requests",
				"client", clientName,
				"canceled", canceled)
		}
	}

	// Force stop registry
	if err := sc.registry.Stop(); err != nil {
		sc.logger.Error("Force shutdown encountered errors", "error", err)
		return NewRegistryError("force shutdown failed", err)
	}

	sc.logger.Info("Force shutdown completed", "canceled_requests", totalCanceled)
	return nil
}

// GetShutdownStatus returns the current shutdown status of the system.
func (sc *ShutdownCoordinator) GetShutdownStatus() ShutdownStatus {
	activeRequests := sc.registry.GetActiveRequestsCount()
	totalActive := int64(0)
	for _, count := range activeRequests {
		totalActive += count
	}

	status := ShutdownStatus{
		IsRunning:      sc.registry.running,
		IsDraining:     sc.registry.IsDraining(),
		ActiveRequests: totalActive,
		ActiveByClient: activeRequests,
		TotalClients:   len(sc.registry.clients),
	}

	// Determine phase
	if !status.IsRunning {
		status.Phase = ShutdownPhaseComplete
	} else if status.IsDraining {
		status.Phase = ShutdownPhaseDraining
	} else {
		status.Phase = ShutdownPhaseRunning
	}

	return status
}

// ShutdownStatus represents the current shutdown status.
type ShutdownStatus struct {
	Phase          ShutdownPhase    `json:"phase"`
	IsRunning      bool             `json:"is_running"`
	IsDraining     bool             `json:"is_draining"`
	ActiveRequests int64            `json:"active_requests"`
	ActiveByClient map[string]int64 `json:"active_by_client"`
	TotalClients   int              `json:"total_clients"`
}

// ShutdownPhase represents the current phase of shutdown.
type ShutdownPhase string

const (
	ShutdownPhaseRunning  ShutdownPhase = "running"
	ShutdownPhaseDraining ShutdownPhase = "draining"
	ShutdownPhaseComplete ShutdownPhase = "complete"
)
