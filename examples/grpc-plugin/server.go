// server.go: gRPC server implementation for the calculator plugin
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/agilira/go-plugins/examples/grpc-plugin/proto"
)

// CalculatorServer implements the gRPC CalculatorService
type CalculatorServer struct {
	pb.UnimplementedCalculatorServiceServer
	logger    *slog.Logger
	startTime time.Time
	version   string
}

// NewCalculatorServer creates a new calculator server
func NewCalculatorServer(logger *slog.Logger, version string) *CalculatorServer {
	return &CalculatorServer{
		logger:    logger,
		startTime: time.Now(),
		version:   version,
	}
}

// Add performs addition
func (s *CalculatorServer) Add(ctx context.Context, req *pb.AddRequest) (*pb.AddResponse, error) {
	s.logger.Info("Processing Add request", "a", req.A, "b", req.B)

	result := req.A + req.B

	return &pb.AddResponse{
		Result: result,
	}, nil
}

// Multiply performs multiplication
func (s *CalculatorServer) Multiply(ctx context.Context, req *pb.MultiplyRequest) (*pb.MultiplyResponse, error) {
	s.logger.Info("Processing Multiply request", "a", req.A, "b", req.B)

	result := req.A * req.B

	return &pb.MultiplyResponse{
		Result: result,
	}, nil
}

// Divide performs division
func (s *CalculatorServer) Divide(ctx context.Context, req *pb.DivideRequest) (*pb.DivideResponse, error) {
	s.logger.Info("Processing Divide request", "dividend", req.Dividend, "divisor", req.Divisor)

	if req.Divisor == 0 {
		return &pb.DivideResponse{
			Result: 0,
			Error:  "division by zero",
		}, status.Error(codes.InvalidArgument, "division by zero")
	}

	result := req.Dividend / req.Divisor

	return &pb.DivideResponse{
		Result: result,
		Error:  "",
	}, nil
}

// Health checks the service health
func (s *CalculatorServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	s.logger.Debug("Health check requested")

	return &pb.HealthResponse{
		Healthy:   true,
		Message:   "Calculator service is healthy",
		Timestamp: time.Now().Unix(),
	}, nil
}

// Info returns service information
func (s *CalculatorServer) Info(ctx context.Context, req *pb.InfoRequest) (*pb.InfoResponse, error) {
	s.logger.Debug("Info requested")

	uptime := time.Since(s.startTime)

	return &pb.InfoResponse{
		Name:        "Calculator gRPC Plugin",
		Version:     s.version,
		Description: fmt.Sprintf("A simple calculator service running for %v", uptime.Round(time.Second)),
		Capabilities: []string{
			"add",
			"multiply",
			"divide",
			"health_check",
		},
	}, nil
}

// StartServer starts the gRPC server
func StartServer(ctx context.Context, address string, logger *slog.Logger) (*grpc.Server, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", address, err)
	}

	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(4*1024*1024), // 4MB
		grpc.MaxSendMsgSize(4*1024*1024), // 4MB
	)

	calculatorServer := NewCalculatorServer(logger, "1.0.0")
	pb.RegisterCalculatorServiceServer(server, calculatorServer)

	logger.Info("Starting gRPC server", "address", address)

	go func() {
		if err := server.Serve(listener); err != nil {
			logger.Error("gRPC server failed", "error", err)
		}
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	return server, nil
}
