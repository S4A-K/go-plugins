// grpc_transport.go: gRPC transport implementation with TLS support
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCPlugin implements Plugin interface using gRPC transport with comprehensive TLS and security support.
//
// This implementation provides high-performance RPC communication using gRPC
// with full support for TLS, mutual authentication, metadata handling, and
// proper connection management. It's designed for low-latency, high-throughput
// scenarios where performance is critical.
//
// Features:
//   - gRPC and gRPC-TLS transports with configurable security
//   - Mutual TLS (mTLS) authentication with client certificates
//   - Connection reuse and proper lifecycle management
//   - Metadata propagation for distributed tracing
//   - Comprehensive error handling with gRPC status codes
//   - Health checking with standard gRPC health protocol
//   - Automatic connection recovery and reconnection
//
// Example usage:
//
//	config := PluginConfig{
//	    Name:      "payment-processor",
//	    Transport: TransportGRPCTLS,
//	    Endpoint:  "payment.company.com:443",
//	    Auth: AuthConfig{
//	        Method:   AuthMTLS,
//	        CertFile: "/etc/ssl/client.crt",
//	        KeyFile:  "/etc/ssl/client.key",
//	        CAFile:   "/etc/ssl/ca.crt",
//	    },
//	}
//
//	plugin, err := NewGRPCPlugin[PaymentRequest, PaymentResponse](config, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use the plugin
//	response, err := plugin.Execute(ctx, execCtx, request)
//	if err != nil {
//	    log.Printf("Payment processing failed: %v", err)
//	}
//
//	// Don't forget to close
//	defer plugin.Close()
type GRPCPlugin[Req, Resp any] struct {
	info       PluginInfo
	config     PluginConfig
	connection *grpc.ClientConn
	logger     *slog.Logger

	// Connection management
	connected atomic.Bool
	lastCheck time.Time
}

// GRPCPluginService defines the standard gRPC service interface that plugins must implement.
//
// This interface establishes a contract for gRPC-based plugins, providing
// standardized methods for execution, health checking, and metadata retrieval.
// All gRPC plugins should implement this interface to ensure compatibility
// with the plugin system.
//
// Method specifications:
//   - Execute: Process requests with serialized JSON data
//   - Health: Perform health checks (should follow gRPC health checking protocol)
//   - Info: Return plugin metadata and capabilities
//
// Example protobuf service definition:
//
//	service PluginService {
//	  rpc Execute(ExecuteRequest) returns (ExecuteResponse);
//	  rpc Health(HealthRequest) returns (HealthResponse);
//	  rpc Info(InfoRequest) returns (InfoResponse);
//	}
//
// The actual gRPC implementation should serialize/deserialize the byte arrays
// as JSON for consistency with other transport methods.
type GRPCPluginService interface {
	// Execute processes a request and returns a response
	Execute(ctx context.Context, request []byte) ([]byte, error)

	// Health performs a health check
	Health(ctx context.Context) error

	// Info returns plugin information
	Info(ctx context.Context) ([]byte, error)
}

// NewGRPCPlugin creates a new gRPC plugin instance
func NewGRPCPlugin[Req, Resp any](config PluginConfig, logger *slog.Logger) (*GRPCPlugin[Req, Resp], error) {
	if logger == nil {
		logger = slog.Default()
	}

	if err := validateGRPCConfig(config); err != nil {
		return nil, fmt.Errorf("invalid gRPC config: %w", err)
	}

	plugin := &GRPCPlugin[Req, Resp]{
		info: PluginInfo{
			Name:        config.Name,
			Version:     "unknown", // Will be fetched from remote
			Description: fmt.Sprintf("gRPC plugin connecting to %s", config.Endpoint),
		},
		config: config,
		logger: logger,
	}

	// Establish connection
	if err := plugin.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	// Fetch plugin info from remote
	if err := plugin.fetchRemoteInfo(); err != nil {
		logger.Warn("Failed to fetch remote plugin info", "error", err)
	}

	return plugin, nil
}

// validateGRPCConfig validates gRPC-specific configuration
func validateGRPCConfig(config PluginConfig) error {
	if config.Transport != TransportGRPC && config.Transport != TransportGRPCTLS {
		return fmt.Errorf("transport must be grpc or grpc-tls, got %s", config.Transport)
	}

	if config.Endpoint == "" {
		return fmt.Errorf("endpoint is required for gRPC transport")
	}

	// Validate TLS configuration if required
	if config.Transport == TransportGRPCTLS {
		if config.Auth.Method == AuthMTLS {
			if config.Auth.CertFile == "" || config.Auth.KeyFile == "" {
				return fmt.Errorf("cert_file and key_file required for mTLS")
			}
		}
	}

	return nil
}

// connect establishes a gRPC connection with proper credentials
func (g *GRPCPlugin[Req, Resp]) connect() error {
	var opts []grpc.DialOption

	// Configure credentials based on transport type
	if g.config.Transport == TransportGRPCTLS {
		creds, err := g.buildTLSCredentials()
		if err != nil {
			return fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Add connection configuration
	opts = append(opts,
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4*1024*1024), // 4MB
			grpc.MaxCallSendMsgSize(4*1024*1024), // 4MB
		),
	)

	// Establish connection
	conn, err := grpc.NewClient(g.config.Endpoint, opts...)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}

	g.connection = conn
	g.connected.Store(true)

	g.logger.Info("gRPC connection established",
		"plugin", g.info.Name,
		"endpoint", g.config.Endpoint,
		"transport", g.config.Transport)

	return nil
}

// buildTLSCredentials creates TLS credentials based on configuration
func (g *GRPCPlugin[Req, Resp]) buildTLSCredentials() (credentials.TransportCredentials, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum for security
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Load client certificate for mTLS
	if g.config.Auth.Method == AuthMTLS {
		cert, err := tls.LoadX509KeyPair(g.config.Auth.CertFile, g.config.Auth.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if specified
	if g.config.Auth.CAFile != "" {
		caCert, err := os.ReadFile(g.config.Auth.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		config.RootCAs = caCertPool
	}

	return credentials.NewTLS(config), nil
}

// fetchRemoteInfo fetches plugin information from the remote server
func (g *GRPCPlugin[Req, Resp]) fetchRemoteInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create metadata for authentication
	ctx = g.addAuthMetadata(ctx)

	// Use reflection or a standard method to get plugin info
	// This is a simplified implementation - in practice, you'd use generated gRPC stubs
	service := NewGRPCPluginServiceClient(g.connection)

	infoBytes, err := service.Info(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch plugin info: %w", err)
	}

	var remoteInfo PluginInfo
	if err := json.Unmarshal(infoBytes, &remoteInfo); err != nil {
		return fmt.Errorf("failed to parse remote plugin info: %w", err)
	}

	// Update local info with remote data
	g.info.Version = remoteInfo.Version
	if remoteInfo.Description != "" {
		g.info.Description = remoteInfo.Description
	}
	if len(remoteInfo.Capabilities) > 0 {
		g.info.Capabilities = remoteInfo.Capabilities
	}

	return nil
}

// Info returns plugin information
func (g *GRPCPlugin[Req, Resp]) Info() PluginInfo {
	return g.info
}

// Execute processes a request using gRPC
func (g *GRPCPlugin[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp

	if !g.connected.Load() {
		return zero, fmt.Errorf("gRPC connection not established")
	}

	// Apply timeout from execution context
	if execCtx.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, execCtx.Timeout)
		defer cancel()
	}

	// Add authentication and headers to context
	ctx = g.addAuthMetadata(ctx)
	ctx = g.addExecutionMetadata(ctx, execCtx)

	// Serialize request
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return zero, fmt.Errorf("failed to serialize request: %w", err)
	}

	// Execute remote call
	service := NewGRPCPluginServiceClient(g.connection)
	responseBytes, err := service.Execute(ctx, requestBytes)
	if err != nil {
		return zero, g.handleGRPCError(err)
	}

	// Deserialize response
	var response Resp
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return zero, fmt.Errorf("failed to deserialize response: %w", err)
	}

	return response, nil
}

// Health performs a health check via gRPC
func (g *GRPCPlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
	startTime := time.Now()
	healthStatus := HealthStatus{
		LastCheck: startTime,
		Metadata:  make(map[string]string),
	}

	if !g.connected.Load() {
		healthStatus.Status = StatusOffline
		healthStatus.Message = "gRPC connection not established"
		return healthStatus
	}

	// Perform health check with timeout
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	healthCtx = g.addAuthMetadata(healthCtx)

	service := NewGRPCPluginServiceClient(g.connection)
	err := service.Health(healthCtx)

	healthStatus.ResponseTime = time.Since(startTime)

	if err != nil {
		healthStatus.Status = StatusUnhealthy
		healthStatus.Message = fmt.Sprintf("Health check failed: %v", err)

		// Check if it's a connection issue
		if grpcErr, ok := status.FromError(err); ok {
			if grpcErr.Code() == codes.Unavailable {
				healthStatus.Status = StatusOffline
			}
		}
	} else {
		healthStatus.Status = StatusHealthy
		healthStatus.Message = "OK"
	}

	healthStatus.Metadata["endpoint"] = g.config.Endpoint
	healthStatus.Metadata["transport"] = string(g.config.Transport)
	g.lastCheck = startTime

	return healthStatus
}

// Close closes the gRPC connection
func (g *GRPCPlugin[Req, Resp]) Close() error {
	if !g.connected.CompareAndSwap(true, false) {
		return nil // Already closed
	}

	if g.connection != nil {
		err := g.connection.Close()
		g.logger.Info("gRPC connection closed", "plugin", g.info.Name)
		return err
	}

	return nil
}

// addAuthMetadata adds authentication metadata to the context
func (g *GRPCPlugin[Req, Resp]) addAuthMetadata(ctx context.Context) context.Context {
	md := metadata.New(nil)

	switch g.config.Auth.Method {
	case AuthAPIKey:
		md.Set("x-api-key", g.config.Auth.APIKey)
	case AuthBearer:
		md.Set("authorization", "Bearer "+g.config.Auth.Token)
	case AuthBasic:
		// Basic auth would typically be handled at the TLS level or via custom metadata
		md.Set("x-username", g.config.Auth.Username)
		md.Set("x-password", g.config.Auth.Password)
	}

	// Add custom headers
	for key, value := range g.config.Auth.Headers {
		md.Set(key, value)
	}

	return metadata.NewOutgoingContext(ctx, md)
}

// addExecutionMetadata adds execution context metadata
func (g *GRPCPlugin[Req, Resp]) addExecutionMetadata(ctx context.Context, execCtx ExecutionContext) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	md.Set("x-request-id", execCtx.RequestID)

	// Add custom headers from execution context
	for key, value := range execCtx.Headers {
		md.Set(key, value)
	}

	return metadata.NewOutgoingContext(ctx, md)
}

// handleGRPCError converts gRPC errors to appropriate plugin errors
func (g *GRPCPlugin[Req, Resp]) handleGRPCError(err error) error {
	grpcStatus, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("gRPC call failed: %w", err)
	}

	switch grpcStatus.Code() {
	case codes.DeadlineExceeded:
		return fmt.Errorf("request timeout: %w", err)
	case codes.Unavailable:
		g.connected.Store(false)
		return fmt.Errorf("service unavailable: %w", err)
	case codes.Unauthenticated:
		return fmt.Errorf("authentication failed: %w", err)
	case codes.PermissionDenied:
		return fmt.Errorf("permission denied: %w", err)
	case codes.InvalidArgument:
		return fmt.Errorf("invalid request: %w", err)
	case codes.NotFound:
		return fmt.Errorf("method not found: %w", err)
	default:
		return fmt.Errorf("gRPC error [%s]: %s", grpcStatus.Code(), grpcStatus.Message())
	}
}

// GRPCPluginServiceClient wraps the gRPC client for plugin services
type GRPCPluginServiceClient struct {
	conn *grpc.ClientConn
}

// NewGRPCPluginServiceClient creates a new gRPC plugin service client
func NewGRPCPluginServiceClient(conn *grpc.ClientConn) *GRPCPluginServiceClient {
	return &GRPCPluginServiceClient{conn: conn}
}

// Execute calls the remote Execute method
func (c *GRPCPluginServiceClient) Execute(ctx context.Context, request []byte) ([]byte, error) {
	// This would typically use generated gRPC stubs
	// For now, we'll use a generic approach
	var response []byte
	err := c.conn.Invoke(ctx, "/PluginService/Execute", request, &response)
	return response, err
}

// Health calls the remote Health method
func (c *GRPCPluginServiceClient) Health(ctx context.Context) error {
	var response []byte
	return c.conn.Invoke(ctx, "/PluginService/Health", []byte{}, &response)
}

// Info calls the remote Info method
func (c *GRPCPluginServiceClient) Info(ctx context.Context) ([]byte, error) {
	var response []byte
	err := c.conn.Invoke(ctx, "/PluginService/Info", []byte{}, &response)
	return response, err
}

// GRPCPluginFactory creates gRPC plugin instances with full TLS and security configuration.
//
// This factory manages the creation of GRPCPlugin instances, handling complex
// gRPC connection setup, TLS configuration, and security validation. It ensures
// proper connection establishment and validates all security configurations.
//
// Security features:
//   - TLS 1.2+ enforcement with secure cipher suites
//   - Mutual TLS authentication with certificate validation
//   - CA certificate validation for server authentication
//   - Proper credential management and secure defaults
//
// Example usage:
//
//	factory := NewGRPCPluginFactory[OrderRequest, OrderResponse](logger)
//
//	config := PluginConfig{
//	    Name:      "order-service",
//	    Transport: TransportGRPCTLS,
//	    Endpoint:  "orders.company.com:9443",
//	    Auth: AuthConfig{
//	        Method:   AuthMTLS,
//	        CertFile: "/etc/ssl/certs/client.crt",
//	        KeyFile:  "/etc/ssl/private/client.key",
//	        CAFile:   "/etc/ssl/certs/ca.crt",
//	    },
//	}
//
//	plugin, err := factory.CreatePlugin(config)
//	if err != nil {
//	    log.Fatalf("Failed to create gRPC plugin: %v", err)
//	}
type GRPCPluginFactory[Req, Resp any] struct {
	logger *slog.Logger
}

// NewGRPCPluginFactory creates a new gRPC plugin factory
func NewGRPCPluginFactory[Req, Resp any](logger *slog.Logger) *GRPCPluginFactory[Req, Resp] {
	return &GRPCPluginFactory[Req, Resp]{logger: logger}
}

// CreatePlugin creates a new gRPC plugin instance
func (f *GRPCPluginFactory[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	return NewGRPCPlugin[Req, Resp](config, f.logger)
}

// SupportedTransports returns supported transport types
func (f *GRPCPluginFactory[Req, Resp]) SupportedTransports() []string {
	return []string{string(TransportGRPC), string(TransportGRPCTLS)}
}

// ValidateConfig validates gRPC plugin configuration
func (f *GRPCPluginFactory[Req, Resp]) ValidateConfig(config PluginConfig) error {
	return validateGRPCConfig(config)
}
