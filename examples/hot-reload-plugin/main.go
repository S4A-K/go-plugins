package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	plugins "github.com/go-plugins"
)

func main() {
	// Setup logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("Starting Hot Reload Plugin Example")

	// Create plugin manager
	manager := plugins.NewManager[CounterRequest, CounterResponse](logger)

	// Register counter plugin factory
	factory := &CounterPluginFactory{}
	if err := manager.RegisterFactory("counter", factory); err != nil {
		logger.Error("Failed to register factory", "error", err)
		os.Exit(1)
	}

	// Create initial configuration
	config := createInitialConfig()

	// Write initial config to file for hot reload
	configPath := "config.json"
	if err := writeConfigToFile(config, configPath); err != nil {
		logger.Error("Failed to write config file", "error", err)
		os.Exit(1)
	}

	// Enable dynamic configuration (hot reload) - this will load the config automatically
	options := plugins.DefaultDynamicConfigOptions()
	options.PollInterval = 2 * time.Second // Check every 2 seconds
	options.CacheTTL = 1 * time.Second

	if err := manager.EnableDynamicConfiguration(configPath, options); err != nil {
		logger.Warn("Hot reload disabled", "error", err)
		logger.Info("Loading config manually...")

		// Fallback: Load initial configuration manually if hot reload fails
		if err := manager.LoadFromConfig(config); err != nil {
			logger.Error("Failed to load initial config", "error", err)
			os.Exit(1)
		}
	} else {
		logger.Info("✅ Hot reload enabled! Edit config.json to see changes")
	}

	// Setup HTTP API for testing
	http.HandleFunc("/counter", func(w http.ResponseWriter, r *http.Request) {
		handleCounterRequest(w, r, manager, logger)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		handleHealthRequest(w, r, manager)
	})

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		handleConfigRequest(w, r, configPath)
	})

	// Start HTTP server
	server := &http.Server{
		Addr:              ":8080",
		Handler:           nil,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		logger.Info("HTTP server starting", "addr", server.Addr)
		logger.Info("Try these endpoints:")
		logger.Info("  POST /counter - Send counter requests")
		logger.Info("  GET /health - Check plugin health")
		logger.Info("  GET /config - View current config")
		logger.Info("Edit config.json to test hot reload!")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down...")

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	// Disable dynamic configuration
	if manager.IsDynamicConfigurationEnabled() {
		if err := manager.DisableDynamicConfiguration(); err != nil {
			logger.Error("Failed to disable dynamic configuration", "error", err)
		}
	}

	// Shutdown plugin manager
	if err := manager.Shutdown(ctx); err != nil {
		logger.Error("Plugin manager shutdown error", "error", err)
	}

	logger.Info("Shutdown complete")
}

// createInitialConfig creates the initial plugin configuration
func createInitialConfig() plugins.ManagerConfig {
	return plugins.ManagerConfig{
		Plugins: []plugins.PluginConfig{
			{
				Name:      "counter-1",
				Type:      "counter",
				Transport: plugins.TransportHTTP,
				Endpoint:  "http://localhost:9001",
				Enabled:   true,
				Auth: plugins.AuthConfig{
					Method: plugins.AuthNone,
				},
				Connection: plugins.ConnectionConfig{
					MaxConnections:     10,
					MaxIdleConnections: 5,
					IdleTimeout:        30 * time.Second,
					ConnectionTimeout:  10 * time.Second,
					RequestTimeout:     30 * time.Second,
					KeepAlive:          true,
				},
				Options: map[string]interface{}{
					"increment": 1,
				},
			},
		},
	}
}

// writeConfigToFile writes configuration to JSON file
func writeConfigToFile(config plugins.ManagerConfig, filename string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(filename, data, 0600)
}

// handleCounterRequest handles HTTP requests to the counter
func handleCounterRequest(w http.ResponseWriter, r *http.Request, manager *plugins.Manager[CounterRequest, CounterResponse], logger *slog.Logger) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CounterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get the counter plugin
	plugin, err := manager.GetPlugin("counter-1")
	if err != nil {
		logger.Error("Failed to get plugin", "error", err)
		http.Error(w, "Plugin not available", http.StatusServiceUnavailable)
		return
	}

	// Execute request
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Create execution context
	execCtx := plugins.ExecutionContext{
		RequestID:  "req-" + time.Now().Format("20060102-150405"),
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		Headers:    make(map[string]string),
		Metadata:   make(map[string]string),
	}

	resp, err := plugin.Execute(ctx, execCtx, req)
	if err != nil {
		logger.Error("Plugin execution failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// handleHealthRequest handles health check requests
func handleHealthRequest(w http.ResponseWriter, _ *http.Request, manager *plugins.Manager[CounterRequest, CounterResponse]) {
	health := manager.Health()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		http.Error(w, "Failed to encode health response", http.StatusInternalServerError)
	}
}

// handleConfigRequest handles config viewing requests
func handleConfigRequest(w http.ResponseWriter, _ *http.Request, configPath string) {
	// Clean and validate the config path
	cleanPath := filepath.Clean(configPath)
	if !filepath.IsAbs(cleanPath) || strings.Contains(cleanPath, "..") {
		http.Error(w, "Invalid config path", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, "Config file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
	}
}
