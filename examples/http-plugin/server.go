// server.go: HTTP server implementation for the text processor plugin
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	goplugins "github.com/agilira/go-plugins"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// TextProcessorServer implements an HTTP server for text processing operations
type TextProcessorServer struct {
	logger    *slog.Logger
	startTime time.Time
	version   string
	server    *http.Server
}

// NewTextProcessorServer creates a new text processor server
func NewTextProcessorServer(logger *slog.Logger, version string) *TextProcessorServer {
	return &TextProcessorServer{
		logger:    logger,
		startTime: time.Now(),
		version:   version,
	}
}

// Start starts the HTTP server on the given address
func (s *TextProcessorServer) Start(ctx context.Context, address string) error {
	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("/process", s.handleProcess)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/info", s.handleInfo)

	// Add middleware
	handler := s.loggingMiddleware(s.corsMiddleware(mux))

	s.server = &http.Server{
		Addr:         address,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info("Starting HTTP server", "address", address)

	// Start server in goroutine
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server failed", "error", err)
		}
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Stop gracefully stops the HTTP server
func (s *TextProcessorServer) Stop() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.logger.Info("Shutting down HTTP server...")
	return s.server.Shutdown(ctx)
}

// handleProcess handles text processing requests
func (s *TextProcessorServer) handleProcess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request
	var pluginReq goplugins.HTTPPluginRequest[TextProcessingRequest]
	if err := json.NewDecoder(r.Body).Decode(&pluginReq); err != nil {
		s.sendErrorResponse(w, pluginReq.RequestID, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	req := pluginReq.Data
	requestID := pluginReq.RequestID

	s.logger.Info("Processing text request",
		"request_id", requestID,
		"operation", req.Operation,
		"text_length", len(req.Text))

	// Process the request
	result, err := s.processText(req)
	if err != nil {
		s.sendErrorResponse(w, requestID, err.Error(), http.StatusBadRequest)
		return
	}

	// Send successful response
	response := goplugins.HTTPPluginResponse[TextProcessingResponse]{
		Data:      result,
		RequestID: requestID,
		Metadata: map[string]string{
			"processing_time": time.Since(time.Now()).String(),
			"operation":       req.Operation,
		},
	}

	s.sendJSONResponse(w, response, http.StatusOK)
}

// processText performs the actual text processing
func (s *TextProcessorServer) processText(req TextProcessingRequest) (TextProcessingResponse, error) {
	var result string
	metadata := make(map[string]string)

	switch req.Operation {
	case "uppercase":
		result = strings.ToUpper(req.Text)
		metadata["original_length"] = strconv.Itoa(len(req.Text))

	case "lowercase":
		result = strings.ToLower(req.Text)
		metadata["original_length"] = strconv.Itoa(len(req.Text))

	case "reverse":
		runes := []rune(req.Text)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		result = string(runes)
		metadata["original_length"] = strconv.Itoa(len(req.Text))

	case "word_count":
		words := strings.Fields(req.Text)
		result = strconv.Itoa(len(words))
		metadata["character_count"] = strconv.Itoa(len(req.Text))
		metadata["line_count"] = strconv.Itoa(strings.Count(req.Text, "\n") + 1)

	case "clean_whitespace":
		// Clean multiple whitespaces and trim
		result = regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(req.Text), " ")
		metadata["original_length"] = strconv.Itoa(len(req.Text))
		metadata["cleaned_length"] = strconv.Itoa(len(result))

	case "extract_emails":
		// Extract email addresses
		emailRegex := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
		emails := emailRegex.FindAllString(req.Text, -1)
		result = strings.Join(emails, ", ")
		metadata["emails_found"] = strconv.Itoa(len(emails))

	case "capitalize":
		// Capitalize first letter of each word
		caser := cases.Title(language.English)
		result = caser.String(strings.ToLower(req.Text))
		metadata["original_length"] = strconv.Itoa(len(req.Text))

	default:
		return TextProcessingResponse{}, fmt.Errorf("unsupported operation: %s", req.Operation)
	}

	return TextProcessingResponse{
		Result:   result,
		Metadata: metadata,
	}, nil
}

// handleHealth handles health check requests
func (s *TextProcessorServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uptime := time.Since(s.startTime)

	health := HealthResponse{
		Status:  "healthy",
		Message: "Text processor is running normally",
		Checks: map[string]string{
			"uptime":    uptime.Round(time.Second).String(),
			"version":   s.version,
			"timestamp": time.Now().Format(time.RFC3339),
		},
	}

	s.sendJSONResponse(w, health, http.StatusOK)
}

// handleInfo handles plugin information requests
func (s *TextProcessorServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := InfoResponse{
		Name:        "Text Processor HTTP Plugin",
		Version:     s.version,
		Description: fmt.Sprintf("HTTP-based text processing service running for %v", time.Since(s.startTime).Round(time.Second)),
		Capabilities: []string{
			"uppercase",
			"lowercase",
			"reverse",
			"word_count",
			"clean_whitespace",
			"extract_emails",
			"capitalize",
		},
	}

	s.sendJSONResponse(w, info, http.StatusOK)
}

// sendErrorResponse sends an error response
func (s *TextProcessorServer) sendErrorResponse(w http.ResponseWriter, requestID, message string, statusCode int) {
	response := goplugins.HTTPPluginResponse[TextProcessingResponse]{
		Error:     message,
		RequestID: requestID,
	}

	s.sendJSONResponse(w, response, statusCode)
}

// sendJSONResponse sends a JSON response
func (s *TextProcessorServer) sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// loggingMiddleware logs HTTP requests
func (s *TextProcessorServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapper.statusCode,
			"duration", duration,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
		)
	})
}

// corsMiddleware adds CORS headers
func (s *TextProcessorServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Request-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWrapper wraps http.ResponseWriter to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
