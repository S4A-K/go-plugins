// grpc_native_transport.go: Native protobuf support for gRPC transport
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"reflect"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// ProtobufMessage represents any protobuf message
type ProtobufMessage interface {
	proto.Message
}

// GRPCNativePlugin represents a plugin that uses native protobuf serialization
// instead of JSON-over-gRPC. This provides better performance and type safety
// for protobuf-based services.
type GRPCNativePlugin[Req, Resp ProtobufMessage] struct {
	config     PluginConfig
	connection *grpc.ClientConn
	logger     Logger
	info       PluginInfo
	connected  atomic.Bool

	// Type information for protobuf messages
	requestType  reflect.Type
	responseType reflect.Type
}

// ProtobufPluginService defines the gRPC service interface for native protobuf plugins
type ProtobufPluginService interface {
	// ExecuteProto processes a protobuf request and returns a protobuf response
	ExecuteProto(ctx context.Context, request proto.Message) (proto.Message, error)

	// Health performs a health check
	Health(ctx context.Context) error

	// Info returns plugin information as protobuf
	InfoProto(ctx context.Context) (proto.Message, error)
}

// NewGRPCNativePlugin creates a new gRPC plugin with native protobuf support
func NewGRPCNativePlugin[Req, Resp ProtobufMessage](config PluginConfig, logger any) (*GRPCNativePlugin[Req, Resp], error) {
	internalLogger := NewLogger(logger)

	if err := validateGRPCConfig(config); err != nil {
		return nil, NewConfigValidationError("invalid gRPC config", err)
	}

	// Get type information for protobuf messages
	var reqZero Req
	var respZero Resp

	reqType := reflect.TypeOf(reqZero)
	respType := reflect.TypeOf(respZero)

	// Validate that types implement proto.Message
	if !reqType.Implements(reflect.TypeOf((*proto.Message)(nil)).Elem()) {
		return nil, NewSerializationError(fmt.Sprintf("request type %T does not implement proto.Message", reqZero), nil)
	}
	if !respType.Implements(reflect.TypeOf((*proto.Message)(nil)).Elem()) {
		return nil, NewSerializationError(fmt.Sprintf("response type %T does not implement proto.Message", respZero), nil)
	}

	plugin := &GRPCNativePlugin[Req, Resp]{
		config:       config,
		logger:       internalLogger,
		requestType:  reqType,
		responseType: respType,
	}

	return plugin, nil
}

// Execute implements the Plugin interface with native protobuf support
func (g *GRPCNativePlugin[Req, Resp]) Execute(ctx context.Context, execCtx ExecutionContext, request Req) (Resp, error) {
	var zero Resp

	if err := g.ensureConnected(); err != nil {
		return zero, err
	}

	ctx = g.prepareContext(ctx, execCtx)

	g.logExecutionStart()

	requestBytes, err := g.serializeRequest(request)
	if err != nil {
		return zero, err
	}

	responseBytes, err := g.executeGRPCCall(ctx, requestBytes)
	if err != nil {
		return zero, err
	}

	response, err := g.deserializeResponse(responseBytes)
	if err != nil {
		return zero, err
	}

	g.logExecutionSuccess()
	return response, nil
}

// ensureConnected ensures the gRPC connection is established
func (g *GRPCNativePlugin[Req, Resp]) ensureConnected() error {
	if g.connection == nil {
		return g.Connect()
	}
	return nil
}

// prepareContext prepares the context with timeout and metadata
func (g *GRPCNativePlugin[Req, Resp]) prepareContext(ctx context.Context, execCtx ExecutionContext) context.Context {
	// Set timeout if specified
	if execCtx.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, execCtx.Timeout)
		defer cancel()
	}

	// Add authentication and execution metadata
	ctx = g.addAuthMetadata(ctx)
	ctx = g.addExecutionMetadata(ctx, execCtx)

	return ctx
}

// logExecutionStart logs the start of request execution
func (g *GRPCNativePlugin[Req, Resp]) logExecutionStart() {
	g.logger.Debug("Executing gRPC native protobuf request",
		"plugin", g.config.Name,
		"requestType", g.requestType.String(),
		"endpoint", g.config.Endpoint)
}

// serializeRequest serializes the request to protobuf bytes
func (g *GRPCNativePlugin[Req, Resp]) serializeRequest(request Req) ([]byte, error) {
	requestMsg, ok := any(request).(proto.Message)
	if !ok {
		return nil, NewSerializationError(fmt.Sprintf("request type %T does not implement proto.Message", request), nil)
	}

	requestBytes, err := proto.Marshal(requestMsg)
	if err != nil {
		return nil, NewSerializationError("failed to marshal protobuf request", err)
	}

	return requestBytes, nil
}

// executeGRPCCall executes the actual gRPC call
func (g *GRPCNativePlugin[Req, Resp]) executeGRPCCall(ctx context.Context, requestBytes []byte) ([]byte, error) {
	service := NewProtobufPluginServiceClient(g.connection)
	responseBytes, executeErr := service.ExecuteNative(ctx, requestBytes)
	// Handle any errors from the gRPC service execution
	if executeErr != nil {
		return nil, g.handleGRPCError(executeErr)
	}
	return responseBytes, nil
}

// deserializeResponse deserializes the response from protobuf bytes
func (g *GRPCNativePlugin[Req, Resp]) deserializeResponse(responseBytes []byte) (Resp, error) {
	var zero Resp

	responseInterface := reflect.New(g.responseType.Elem()).Interface()
	response, ok := responseInterface.(Resp)
	if !ok {
		return zero, NewSerializationError(fmt.Sprintf("failed to convert response to expected type %T", responseInterface), nil)
	}

	responseMsg, ok := any(response).(proto.Message)
	if !ok {
		return zero, NewSerializationError(fmt.Sprintf("response type %T does not implement proto.Message", response), nil)
	}

	if err := proto.Unmarshal(responseBytes, responseMsg); err != nil {
		return zero, NewSerializationError("failed to unmarshal protobuf response", err)
	}

	return response, nil
}

// logExecutionSuccess logs successful execution completion
func (g *GRPCNativePlugin[Req, Resp]) logExecutionSuccess() {
	g.logger.Debug("gRPC native protobuf request completed successfully",
		"plugin", g.config.Name,
		"responseType", g.responseType.String())
}

// Connect establishes a gRPC connection with TLS support
func (g *GRPCNativePlugin[Req, Resp]) Connect() error {
	var opts []grpc.DialOption

	// Configure credentials based on transport type
	if g.config.Transport == TransportGRPCTLS {
		creds, err := g.buildTLSCredentials()
		if err != nil {
			return NewConfigValidationError("failed to build TLS credentials", err)
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
		return NewGRPCTransportError(err)
	}

	g.connection = conn
	g.connected.Store(true)

	g.logger.Info("gRPC native connection established",
		"plugin", g.info.Name,
		"endpoint", g.config.Endpoint,
		"transport", g.config.Transport)

	return nil
}

// Info implements Plugin.Info
func (g *GRPCNativePlugin[Req, Resp]) Info() PluginInfo {
	return PluginInfo{
		Name:        g.config.Name,
		Version:     "1.0.0", // Could be made configurable
		Description: fmt.Sprintf("gRPC native protobuf plugin for %s", g.config.Endpoint),
		Capabilities: []string{
			"grpc",
			"native-protobuf",
			"type-safe",
		},
		Metadata: map[string]string{
			"transport":     string(g.config.Transport),
			"endpoint":      g.config.Endpoint,
			"request_type":  g.requestType.String(),
			"response_type": g.responseType.String(),
		},
	}
}

// Health implements Plugin.Health
func (g *GRPCNativePlugin[Req, Resp]) Health(ctx context.Context) HealthStatus {
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

	// Simple connection test - try to invoke a basic method
	err := g.connection.Invoke(healthCtx, "/health", nil, nil)

	healthStatus.ResponseTime = time.Since(healthStatus.LastCheck)

	if err != nil {
		healthStatus.Status = StatusUnhealthy
		healthStatus.Message = fmt.Sprintf("Health check failed: %v", err)

		// Check if it's a connection issue
		if grpcErr, ok := status.FromError(err); ok {
			if grpcErr.Code() == codes.Unavailable {
				healthStatus.Status = StatusOffline
				healthStatus.Message = "gRPC service unavailable"
			}
		}
	} else {
		healthStatus.Status = StatusHealthy
		healthStatus.Message = "gRPC service healthy"
	}

	return healthStatus
}

// Shutdown implements Plugin.Shutdown
func (g *GRPCNativePlugin[Req, Resp]) Shutdown(ctx context.Context) error {
	g.logger.Info("Shutting down gRPC native plugin", "plugin", g.config.Name)

	if g.connection != nil {
		if err := g.connection.Close(); err != nil {
			g.logger.Error("Failed to close gRPC connection", "error", err)
			return err
		}
		g.connection = nil
	}

	return nil
}

// Close implements Plugin.Close
func (g *GRPCNativePlugin[Req, Resp]) Close() error {
	return g.Shutdown(context.Background())
}

// Helper methods

func (g *GRPCNativePlugin[Req, Resp]) addAuthMetadata(ctx context.Context) context.Context {
	md := metadata.New(nil)

	switch g.config.Auth.Method {
	case AuthAPIKey:
		md.Set("x-api-key", g.config.Auth.APIKey)
	case AuthBearer:
		md.Set("authorization", "Bearer "+g.config.Auth.Token)
	case AuthBasic:
		md.Set("x-username", g.config.Auth.Username)
		md.Set("x-password", g.config.Auth.Password)
	}

	for key, value := range g.config.Auth.Headers {
		md.Set(key, value)
	}

	return metadata.NewOutgoingContext(ctx, md)
}

func (g *GRPCNativePlugin[Req, Resp]) addExecutionMetadata(ctx context.Context, execCtx ExecutionContext) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	md.Set("x-request-id", execCtx.RequestID)

	return metadata.NewOutgoingContext(ctx, md)
}

func (g *GRPCNativePlugin[Req, Resp]) handleGRPCError(err error) error {
	if err == nil {
		return nil
	}

	grpcStatus, ok := status.FromError(err)
	if !ok {
		return NewGRPCTransportError(err)
	}

	switch grpcStatus.Code() {
	case codes.Unavailable, codes.DeadlineExceeded:
		return NewGRPCTransportError(err)
	case codes.Unauthenticated:
		return NewGRPCTransportError(err)
	case codes.PermissionDenied:
		return NewGRPCTransportError(err)
	default:
		return NewGRPCTransportError(err)
	}
}

// ProtobufPluginServiceClient provides the gRPC client for native protobuf operations
type ProtobufPluginServiceClient struct {
	cc grpc.ClientConnInterface
}

// NewProtobufPluginServiceClient creates a new protobuf plugin service client
func NewProtobufPluginServiceClient(cc grpc.ClientConnInterface) ProtobufPluginServiceClient {
	return ProtobufPluginServiceClient{cc: cc}
}

// ExecuteNative executes a native protobuf request
func (c ProtobufPluginServiceClient) ExecuteNative(ctx context.Context, request []byte) ([]byte, error) {
	// Type assert to get the concrete connection
	conn, ok := c.cc.(*grpc.ClientConn)
	if !ok {
		return nil, NewGRPCTransportError(fmt.Errorf("expected *grpc.ClientConn, got %T", c.cc))
	}

	// Check connection state
	if conn.GetState().String() != "READY" {
		return nil, NewGRPCTransportError(fmt.Errorf("gRPC connection not ready: %s", conn.GetState()))
	}

	// For now, we'll implement a basic echo service for testing
	// In production, this would invoke the actual protobuf gRPC service
	// TODO: Replace with actual protobuf service implementation
	if len(request) == 0 {
		return nil, NewSerializationError("empty request not allowed", nil)
	}

	// Simple echo implementation - returns the request as response
	// This allows the error checking to be meaningful
	return request, nil
}

// GRPCPluginFactory creates GRPCNativePlugin instances
type GRPCPluginFactory[Req, Resp ProtobufMessage] struct {
	logger any
}

// NewGRPCPluginFactory creates a new factory for gRPC plugins with protobuf
func NewGRPCPluginFactory[Req, Resp ProtobufMessage](logger any) *GRPCPluginFactory[Req, Resp] {
	return &GRPCPluginFactory[Req, Resp]{
		logger: logger,
	}
}

// CreatePlugin implements PluginFactory interface
func (f *GRPCPluginFactory[Req, Resp]) CreatePlugin(config PluginConfig) (Plugin[Req, Resp], error) {
	plugin, err := NewGRPCNativePlugin[Req, Resp](config, f.logger)
	if err != nil {
		return nil, err
	}
	return plugin, nil
}

// SupportedTransports returns the transport types supported by this factory
func (f *GRPCPluginFactory[Req, Resp]) SupportedTransports() []string {
	return []string{"grpc", "grpc-tls"}
}

// ValidateConfig validates a plugin configuration without creating the plugin
func (f *GRPCPluginFactory[Req, Resp]) ValidateConfig(config PluginConfig) error {
	return validateGRPCConfig(config)
}

// buildTLSCredentials creates TLS credentials based on configuration
func (g *GRPCNativePlugin[Req, Resp]) buildTLSCredentials() (credentials.TransportCredentials, error) {
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
			return nil, NewConfigValidationError("failed to load client certificate", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if specified
	if g.config.Auth.CAFile != "" {
		caCert, err := os.ReadFile(g.config.Auth.CAFile)
		if err != nil {
			return nil, NewConfigValidationError("failed to read CA certificate", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, NewConfigValidationError("failed to parse CA certificate", nil)
		}
		config.RootCAs = caCertPool
	}

	return credentials.NewTLS(config), nil
}

// Utility functions for easier integration

// RegisterGRPCNativePlugin registers a native protobuf gRPC plugin with a manager
func RegisterGRPCNativePlugin[Req, Resp ProtobufMessage](
	manager *Manager[Req, Resp],
	config PluginConfig,
	logger any,
) error {
	plugin, err := NewGRPCNativePlugin[Req, Resp](config, logger)
	if err != nil {
		return NewFactoryError("grpc", "failed to create native gRPC plugin", err)
	}

	return manager.Register(plugin)
}

// RegisterGRPCNativeFactory registers a native protobuf gRPC plugin factory with a manager
func RegisterGRPCNativeFactory[Req, Resp ProtobufMessage](
	manager *Manager[Req, Resp],
	name string,
	logger any,
) error {
	factory := NewGRPCPluginFactory[Req, Resp](logger)
	return manager.RegisterFactory(name, factory)
}

// validateGRPCConfig validates gRPC configuration parameters
func validateGRPCConfig(config PluginConfig) error {
	if config.Endpoint == "" {
		return NewConfigValidationError("gRPC endpoint is required", nil)
	}

	if config.Transport != TransportGRPC && config.Transport != TransportGRPCTLS {
		return NewConfigValidationError(fmt.Sprintf("invalid transport for gRPC plugin: %s", config.Transport), nil)
	}

	return nil
}

// Legacy gRPC service support removed - no longer needed since we're not published yet
