// client.go: gRPC client implementation that wraps the calculator service
package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	goplugins "github.com/agilira/go-plugins"
	pb "github.com/agilira/go-plugins/examples/grpc-plugin/proto"
)

// CalculatorPlugin implements the Plugin interface for gRPC calculator service
type CalculatorPlugin struct {
	client     pb.CalculatorServiceClient
	connection *grpc.ClientConn
	logger     *slog.Logger
	info       goplugins.PluginInfo
}

// NewCalculatorPlugin creates a new calculator plugin
func NewCalculatorPlugin(address string, logger *slog.Logger) (*CalculatorPlugin, error) {
	// Connect to gRPC server
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	client := pb.NewCalculatorServiceClient(conn)

	plugin := &CalculatorPlugin{
		client:     client,
		connection: conn,
		logger:     logger,
	}

	// Fetch plugin info
	if err := plugin.fetchInfo(); err != nil {
		logger.Warn("Failed to fetch plugin info", "error", err)
		// Set default info
		plugin.info = goplugins.PluginInfo{
			Name:        "Calculator gRPC Plugin",
			Version:     "1.0.0",
			Description: "A simple calculator service via gRPC",
		}
	}

	return plugin, nil
}

// fetchInfo fetches plugin information from the server
func (p *CalculatorPlugin) fetchInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := p.client.Info(ctx, &pb.InfoRequest{})
	if err != nil {
		return err
	}

	p.info = goplugins.PluginInfo{
		Name:         resp.Name,
		Version:      resp.Version,
		Description:  resp.Description,
		Capabilities: resp.Capabilities,
	}

	return nil
}

// Info returns plugin information
func (p *CalculatorPlugin) Info() goplugins.PluginInfo {
	return p.info
}

// Execute processes a calculation request
func (p *CalculatorPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request CalculationRequest) (CalculationResponse, error) {
	var zero CalculationResponse

	// Apply timeout from execution context
	if execCtx.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, execCtx.Timeout)
		defer cancel()
	}

	p.logger.Info("Executing calculation",
		"operation", request.Operation,
		"a", request.A,
		"b", request.B,
		"request_id", execCtx.RequestID)

	switch request.Operation {
	case "add":
		return p.executeAdd(ctx, request)
	case "multiply":
		return p.executeMultiply(ctx, request)
	case "divide":
		return p.executeDivide(ctx, request)
	default:
		return zero, fmt.Errorf("unsupported operation: %s", request.Operation)
	}
}

// executeAdd performs addition
func (p *CalculatorPlugin) executeAdd(ctx context.Context, request CalculationRequest) (CalculationResponse, error) {
	resp, err := p.client.Add(ctx, &pb.AddRequest{
		A: request.A,
		B: request.B,
	})
	if err != nil {
		return CalculationResponse{}, p.handleGRPCError(err)
	}

	return CalculationResponse{
		Result: resp.Result,
	}, nil
}

// executeMultiply performs multiplication
func (p *CalculatorPlugin) executeMultiply(ctx context.Context, request CalculationRequest) (CalculationResponse, error) {
	resp, err := p.client.Multiply(ctx, &pb.MultiplyRequest{
		A: request.A,
		B: request.B,
	})
	if err != nil {
		return CalculationResponse{}, p.handleGRPCError(err)
	}

	return CalculationResponse{
		Result: resp.Result,
	}, nil
}

// executeDivide performs division
func (p *CalculatorPlugin) executeDivide(ctx context.Context, request CalculationRequest) (CalculationResponse, error) {
	resp, err := p.client.Divide(ctx, &pb.DivideRequest{
		Dividend: request.A,
		Divisor:  request.B,
	})
	if err != nil {
		return CalculationResponse{}, p.handleGRPCError(err)
	}

	return CalculationResponse{
		Result: resp.Result,
		Error:  resp.Error,
	}, nil
}

// Health performs a health check
func (p *CalculatorPlugin) Health(ctx context.Context) goplugins.HealthStatus {
	startTime := time.Now()
	healthStatus := goplugins.HealthStatus{
		LastCheck: startTime,
		Metadata:  make(map[string]string),
	}

	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := p.client.Health(healthCtx, &pb.HealthRequest{})

	healthStatus.ResponseTime = time.Since(startTime)
	healthStatus.Metadata["transport"] = "gRPC"

	if err != nil {
		p.logger.Error("Health check failed", "error", err)

		if grpcErr, ok := status.FromError(err); ok {
			if grpcErr.Code() == codes.Unavailable {
				healthStatus.Status = goplugins.StatusOffline
				healthStatus.Message = "gRPC service unavailable"
			} else {
				healthStatus.Status = goplugins.StatusUnhealthy
				healthStatus.Message = fmt.Sprintf("Health check failed: %v", grpcErr.Message())
			}
		} else {
			healthStatus.Status = goplugins.StatusUnhealthy
			healthStatus.Message = fmt.Sprintf("Health check failed: %v", err)
		}

		return healthStatus
	}

	if resp.Healthy {
		healthStatus.Status = goplugins.StatusHealthy
		healthStatus.Message = resp.Message
	} else {
		healthStatus.Status = goplugins.StatusUnhealthy
		healthStatus.Message = resp.Message
	}

	return healthStatus
}

// Close closes the gRPC connection
func (p *CalculatorPlugin) Close() error {
	if p.connection != nil {
		p.logger.Info("Closing gRPC connection")
		err := p.connection.Close()
		p.connection = nil // Prevent double close
		return err
	}
	return nil
}

// handleGRPCError converts gRPC errors to appropriate error messages
func (p *CalculatorPlugin) handleGRPCError(err error) error {
	grpcStatus, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("gRPC call failed: %w", err)
	}

	switch grpcStatus.Code() {
	case codes.DeadlineExceeded:
		return fmt.Errorf("request timeout: %w", err)
	case codes.Unavailable:
		return fmt.Errorf("service unavailable: %w", err)
	case codes.InvalidArgument:
		return fmt.Errorf("invalid request: %w", err)
	default:
		return fmt.Errorf("gRPC error [%s]: %s", grpcStatus.Code(), grpcStatus.Message())
	}
}
