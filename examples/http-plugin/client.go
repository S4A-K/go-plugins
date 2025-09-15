// client.go: HTTP client implementation that wraps the text processor service
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	goplugins "github.com/agilira/go-plugins"
)

// TextProcessorPlugin implements the Plugin interface for HTTP text processor service
type TextProcessorPlugin struct {
	client  *http.Client
	baseURL string
	logger  *slog.Logger
	info    goplugins.PluginInfo
}

// NewTextProcessorPlugin creates a new text processor plugin
func NewTextProcessorPlugin(baseURL string, logger *slog.Logger) (*TextProcessorPlugin, error) {
	// Create HTTP client with timeouts
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: false,
		},
	}

	plugin := &TextProcessorPlugin{
		client:  client,
		baseURL: baseURL,
		logger:  logger,
	}

	// Fetch plugin info
	if err := plugin.fetchInfo(); err != nil {
		logger.Warn("Failed to fetch plugin info", "error", err)
		// Set default info
		plugin.info = goplugins.PluginInfo{
			Name:        "Text Processor HTTP Plugin",
			Version:     "1.0.0",
			Description: "HTTP-based text processing service",
		}
	}

	return plugin, nil
}

// fetchInfo fetches plugin information from the server
func (p *TextProcessorPlugin) fetchInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/info", nil)
	if err != nil {
		return fmt.Errorf("failed to create info request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch info: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("info request failed with status %d", resp.StatusCode)
	}

	var infoResp InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&infoResp); err != nil {
		return fmt.Errorf("failed to decode info response: %w", err)
	}

	p.info = goplugins.PluginInfo{
		Name:         infoResp.Name,
		Version:      infoResp.Version,
		Description:  infoResp.Description,
		Capabilities: infoResp.Capabilities,
	}

	return nil
}

// Info returns plugin information
func (p *TextProcessorPlugin) Info() goplugins.PluginInfo {
	return p.info
}

// Execute processes a text processing request
func (p *TextProcessorPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request TextProcessingRequest) (TextProcessingResponse, error) {
	var zero TextProcessingResponse

	// Apply timeout from execution context
	if execCtx.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, execCtx.Timeout)
		defer cancel()
	}

	p.logger.Info("Executing text processing",
		"operation", request.Operation,
		"text_length", len(request.Text),
		"request_id", execCtx.RequestID)

	// Create request payload
	payload := goplugins.HTTPPluginRequest[TextProcessingRequest]{
		Data:      request,
		RequestID: execCtx.RequestID,
		Timeout:   execCtx.Timeout.String(),
		Headers:   execCtx.Headers,
		Metadata:  execCtx.Metadata,
	}

	// Serialize to JSON
	body, err := json.Marshal(payload)
	if err != nil {
		return zero, fmt.Errorf("failed to serialize request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/process", bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "go-plugins-client/1.0")
	httpReq.Header.Set("X-Request-ID", execCtx.RequestID)

	// Add custom headers from execution context
	for key, value := range execCtx.Headers {
		httpReq.Header.Set(key, value)
	}

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return zero, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("Failed to close response body", "error", err)
		}
	}()

	// Parse response
	var pluginResp goplugins.HTTPPluginResponse[TextProcessingResponse]
	if err := json.NewDecoder(resp.Body).Decode(&pluginResp); err != nil {
		return zero, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for errors
	if pluginResp.Error != "" {
		return zero, fmt.Errorf("plugin error: %s", pluginResp.Error)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
	}

	return pluginResp.Data, nil
}

// Health performs a health check
func (p *TextProcessorPlugin) Health(ctx context.Context) goplugins.HealthStatus {
	startTime := time.Now()
	healthStatus := goplugins.HealthStatus{
		LastCheck: startTime,
		Metadata:  make(map[string]string),
	}

	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, p.baseURL+"/health", nil)
	if err != nil {
		healthStatus.Status = goplugins.StatusUnhealthy
		healthStatus.Message = fmt.Sprintf("Failed to create health check request: %v", err)
		healthStatus.ResponseTime = time.Since(startTime)
		return healthStatus
	}

	resp, err := p.client.Do(req)
	healthStatus.ResponseTime = time.Since(startTime)
	healthStatus.Metadata["transport"] = "HTTP"
	healthStatus.Metadata["endpoint"] = p.baseURL + "/health"

	if err != nil {
		p.logger.Error("Health check failed", "error", err)
		healthStatus.Status = goplugins.StatusOffline
		healthStatus.Message = fmt.Sprintf("Health check request failed: %v", err)
		return healthStatus
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		healthStatus.Status = goplugins.StatusUnhealthy
		healthStatus.Message = fmt.Sprintf("Health check failed with status %d", resp.StatusCode)
		return healthStatus
	}

	// Parse health response
	var healthResp HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		healthStatus.Status = goplugins.StatusUnhealthy
		healthStatus.Message = fmt.Sprintf("Failed to parse health response: %v", err)
		return healthStatus
	}

	// Map health response to plugin health status
	switch healthResp.Status {
	case "healthy":
		healthStatus.Status = goplugins.StatusHealthy
	case "degraded":
		healthStatus.Status = goplugins.StatusDegraded
	case "unhealthy":
		healthStatus.Status = goplugins.StatusUnhealthy
	default:
		healthStatus.Status = goplugins.StatusUnknown
	}

	healthStatus.Message = healthResp.Message

	// Add checks to metadata
	for key, value := range healthResp.Checks {
		healthStatus.Metadata[key] = value
	}

	return healthStatus
}

// Close closes the HTTP client connections
func (p *TextProcessorPlugin) Close() error {
	// HTTP client doesn't need explicit closing, but we can close idle connections
	if transport, ok := p.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}

	p.logger.Info("Closed HTTP plugin connections")
	return nil
}
