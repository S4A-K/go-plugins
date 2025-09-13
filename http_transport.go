// http_transport.go: Production-ready HTTP transport implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPPlugin represents a plugin that communicates over HTTP/HTTPS protocols.
//
// This implementation provides a full-featured HTTP client for plugin communication,
// supporting authentication, rate limiting, connection pooling, and comprehensive
// error handling. It's designed for production environments with proper security
// and operational concerns.
//
// Features:
//   - HTTP/HTTPS with configurable TLS settings including mTLS
//   - Multiple authentication methods (API key, Bearer token, Basic auth)
//   - Connection pooling and keep-alive for performance
//   - Rate limiting with token bucket algorithm
//   - Structured request/response handling with JSON serialization
//   - Health checking with configurable endpoints
//   - Proper timeout handling and graceful connection cleanup
//
// Example usage:
//
//	config := PluginConfig{
//	    Name:      "api-service",
//	    Transport: TransportHTTPS,
//	    Endpoint:  "https://api.example.com/v1/plugin",
//	    Auth: AuthConfig{
//	        Method: AuthBearer,
//	        Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//	    },
//	    Connection: ConnectionConfig{
//	        MaxConnections:    10,
//	        RequestTimeout:    30 * time.Second,
//	        ConnectionTimeout: 10 * time.Second,
//	    },
//	    RateLimit: RateLimitConfig{
//	        Enabled:           true,
//	        RequestsPerSecond: 100.0,
//	        BurstSize:         200,
//	    },
//	}
//
//	factory := NewHTTPPluginFactory[MyRequest, MyResponse]()
//	plugin, err := factory.CreatePlugin(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use the plugin
//	response, err := plugin.Execute(ctx, execCtx, request)
type HTTPPlugin[Req, Resp any] struct {
	config      PluginConfig
	client      *http.Client
	transport   *http.Transport
	rateLimiter *RateLimiter
	info        PluginInfo
	mu          sync.RWMutex
}

// HTTPPluginFactory creates HTTP-based plugins with comprehensive configuration support.
//
// This factory handles the creation of HTTPPlugin instances, managing HTTP client
// configuration, TLS setup, authentication, and connection pooling. It validates
// configurations to ensure security and proper operation.
//
// Supported features:
//   - HTTP and HTTPS transports with proper TLS configuration
//   - Multiple authentication methods with security validation
//   - Connection pooling and timeout configuration
//   - Rate limiting setup and validation
//   - Comprehensive configuration validation
//
// Example usage:
//
//	factory := NewHTTPPluginFactory[AuthRequest, AuthResponse]()
//
//	config := PluginConfig{
//	    Transport: TransportHTTPS,
//	    Endpoint:  "https://auth.company.com/api/v1",
//	    Auth: AuthConfig{
//	        Method:   AuthMTLS,
//	        CertFile: "/etc/ssl/client.crt",
//	        KeyFile:  "/etc/ssl/client.key",
//	        CAFile:   "/etc/ssl/ca.crt",
//	    },
//	}
//
//	plugin, err := factory.CreatePlugin(config)
//	if err != nil {
//	    log.Fatalf("Failed to create plugin: %v", err)
//	}
type HTTPPluginFactory[Req, Resp any] struct{}

// NewHTTPPluginFactory creates a new HTTP plugin factory
func NewHTTPPluginFactory[Req, Resp any]() *HTTPPluginFactory[Req, Resp] {
	return &HTTPPluginFactory[Req, Resp]{}
}

// CreatePlugin implements PluginFactory.CreatePlugin for HTTP transport
func (f *HTTPPluginFactory[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	if err := f.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid plugin config: %w", err)
	}

	// Configure HTTP transport
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.Connection.ConnectionTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        config.Connection.MaxConnections,
		MaxIdleConnsPerHost: config.Connection.MaxIdleConnections,
		IdleConnTimeout:     config.Connection.IdleTimeout,
		DisableCompression:  config.Connection.DisableCompression,
	}

	// Configure TLS if needed
	if config.Transport == TransportHTTPS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,            // Always verify in production
			MinVersion:         tls.VersionTLS12, // Use TLS 1.2 or higher for security
		}

		// Load client certificates for mTLS
		if config.Auth.Method == AuthMTLS {
			cert, err := tls.LoadX509KeyPair(config.Auth.CertFile, config.Auth.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		transport.TLSClientConfig = tlsConfig
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Connection.RequestTimeout,
	}

	// Create rate limiter if enabled
	var rateLimiter *RateLimiter
	if config.RateLimit.Enabled {
		rateLimiter = NewRateLimiter(config.RateLimit)
	}

	plugin := &HTTPPlugin[Req, Resp]{
		config:      config,
		client:      client,
		transport:   transport,
		rateLimiter: rateLimiter,
		info: PluginInfo{
			Name:         config.Name,
			Version:      "1.0.0", // TODO: Get from plugin response
			Description:  fmt.Sprintf("HTTP plugin for %s", config.Endpoint),
			Capabilities: []string{"http", "json"},
		},
	}

	return plugin, nil
}

// SupportedTransports implements PluginFactory.SupportedTransports
func (f *HTTPPluginFactory[Req, Resp]) SupportedTransports() []string {
	return []string{string(TransportHTTP), string(TransportHTTPS)}
}

// ValidateConfig implements PluginFactory.ValidateConfig
func (f *HTTPPluginFactory[Req, Resp]) ValidateConfig(config PluginConfig) error {
	if config.Transport != TransportHTTP && config.Transport != TransportHTTPS {
		return fmt.Errorf("unsupported transport for HTTP factory: %s", config.Transport)
	}
	return config.Validate()
}

// Info implements Plugin.Info
func (p *HTTPPlugin[Req, Resp]) Info() PluginInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.info
}

// Execute implements Plugin.Execute
func (p *HTTPPlugin[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp

	// Apply rate limiting
	if err := p.checkRateLimit(); err != nil {
		return zero, err
	}

	// Create and execute HTTP request
	httpResp, err := p.executeHTTPRequest(ctx, execCtx, request)
	if err != nil {
		return zero, err
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil {
			// Log error but don't override the main return value
			_ = closeErr
		}
	}()

	// Parse and validate response
	return p.parseResponse(httpResp)
}

// checkRateLimit checks if the request should be rate limited
func (p *HTTPPlugin[Req, Resp]) checkRateLimit() error {
	if p.rateLimiter != nil {
		if !p.rateLimiter.Allow() {
			return fmt.Errorf("rate limit exceeded for plugin %s", p.config.Name)
		}
	}
	return nil
}

// executeHTTPRequest creates and executes the HTTP request
func (p *HTTPPlugin[Req, Resp]) executeHTTPRequest(ctx context.Context, execCtx ExecutionContext, request Req) (*http.Response, error) {
	// Create HTTP request
	httpReq, err := p.createHTTPRequest(ctx, execCtx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Execute HTTP request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	return httpResp, nil
}

// parseResponse parses and validates the HTTP response
func (p *HTTPPlugin[Req, Resp]) parseResponse(httpResp *http.Response) (Resp, error) {
	var zero Resp

	// Check HTTP status
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return zero, fmt.Errorf("HTTP request failed with status %d", httpResp.StatusCode)
	}

	// Parse response
	var response HTTPPluginResponse[Resp]
	if err := json.NewDecoder(httpResp.Body).Decode(&response); err != nil {
		return zero, fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Error != "" {
		return zero, fmt.Errorf("plugin error: %s", response.Error)
	}

	return response.Data, nil
}

// Health implements Plugin.Health
func (p *HTTPPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	// Use health check endpoint if configured
	endpoint := p.config.HealthCheck.Endpoint
	if endpoint == "" {
		endpoint = p.config.Endpoint + "/health"
	}

	// Create health check request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return HealthStatus{
			Status:       StatusUnhealthy,
			Message:      fmt.Sprintf("Failed to create health check request: %v", err),
			LastCheck:    time.Now(),
			ResponseTime: 0,
		}
	}

	// Add authentication headers
	p.addAuthHeaders(req)

	// Execute request
	start := time.Now()
	resp, err := p.client.Do(req)
	responseTime := time.Since(start)

	if err != nil {
		return HealthStatus{
			Status:       StatusUnhealthy,
			Message:      fmt.Sprintf("Health check request failed: %v", err),
			LastCheck:    time.Now(),
			ResponseTime: responseTime,
		}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log error but don't override the main return value
			_ = closeErr
		}
	}()

	// Check response status
	status := StatusHealthy
	message := "OK"

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status = StatusUnhealthy
		message = fmt.Sprintf("Health check failed with status %d", resp.StatusCode)
	}

	return HealthStatus{
		Status:       status,
		Message:      message,
		LastCheck:    time.Now(),
		ResponseTime: responseTime,
	}
}

// Close implements Plugin.Close
func (p *HTTPPlugin[Req, Resp]) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}

	return nil
}

// createHTTPRequest creates an HTTP request for the plugin call
func (p *HTTPPlugin[Req, Resp]) createHTTPRequest(ctx context.Context, execCtx ExecutionContext, request Req) (*http.Request, error) {
	// Create request payload
	payload := HTTPPluginRequest[Req]{
		Data:      request,
		RequestID: execCtx.RequestID,
		Timeout:   execCtx.Timeout.String(),
		Headers:   execCtx.Headers,
		Metadata:  execCtx.Metadata,
	}

	// Serialize to JSON
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "go-plugins/1.0")
	req.Header.Set("X-Request-ID", execCtx.RequestID)

	// Add custom headers from execution context
	for key, value := range execCtx.Headers {
		req.Header.Set(key, value)
	}

	// Add authentication
	p.addAuthHeaders(req)

	return req, nil
}

// addAuthHeaders adds authentication headers to the request
func (p *HTTPPlugin[Req, Resp]) addAuthHeaders(req *http.Request) {
	switch p.config.Auth.Method {
	case AuthAPIKey:
		req.Header.Set("X-API-Key", p.config.Auth.APIKey)
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+p.config.Auth.Token)
	case AuthBasic:
		req.SetBasicAuth(p.config.Auth.Username, p.config.Auth.Password)
	case AuthCustom:
		// Add custom headers
		for key, value := range p.config.Auth.Headers {
			req.Header.Set(key, value)
		}
	}
}

// HTTPPluginRequest represents the standardized request format for HTTP plugins.
//
// This structure defines the wire format for requests sent to HTTP-based plugins.
// It includes the actual request data along with metadata needed for proper
// request handling, tracing, and timeout management.
//
// The format is designed to be plugin-agnostic while providing all necessary
// context for request processing. Plugins can expect this structure when
// receiving requests via HTTP transport.
//
// Example JSON payload:
//
//	{
//	  "data": {
//	    "user_id": "12345",
//	    "action": "authenticate"
//	  },
//	  "request_id": "req-abc-123",
//	  "timeout": "30s",
//	  "headers": {
//	    "X-Source-Service": "auth-gateway"
//	  },
//	  "metadata": {
//	    "trace_id": "trace-xyz-789"
//	  }
//	}
type HTTPPluginRequest[T any] struct {
	Data      T                 `json:"data"`
	RequestID string            `json:"request_id"`
	Timeout   string            `json:"timeout"`
	Headers   map[string]string `json:"headers,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// HTTPPluginResponse represents the standardized response format for HTTP plugins.
//
// This structure defines the wire format for responses received from HTTP-based
// plugins. It provides a consistent interface for handling both successful
// responses and errors, along with metadata for tracing and debugging.
//
// The response format allows plugins to return either successful data or error
// information, making error handling consistent across all HTTP-based plugins.
// The request ID enables correlation with the original request for tracing.
//
// Example successful response:
//
//	{
//	  "data": {
//	    "token": "jwt-token-here",
//	    "expires_in": 3600
//	  },
//	  "request_id": "req-abc-123",
//	  "metadata": {
//	    "processing_time_ms": "150"
//	  }
//	}
//
// Example error response:
//
//	{
//	  "error": "Invalid credentials provided",
//	  "request_id": "req-abc-123",
//	  "metadata": {
//	    "error_code": "AUTH_FAILED"
//	  }
//	}
type HTTPPluginResponse[T any] struct {
	Data      T                 `json:"data,omitempty"`
	Error     string            `json:"error,omitempty"`
	RequestID string            `json:"request_id"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	config     RateLimitConfig
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		config:     config,
		tokens:     float64(config.BurstSize),
		lastRefill: time.Now(),
	}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow() bool {
	if !rl.config.Enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill tokens based on elapsed time
	tokensToAdd := elapsed.Seconds() * rl.config.RequestsPerSecond
	rl.tokens = min(float64(rl.config.BurstSize), rl.tokens+tokensToAdd)
	rl.lastRefill = now

	// Check if we have tokens available
	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}

	return false
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
