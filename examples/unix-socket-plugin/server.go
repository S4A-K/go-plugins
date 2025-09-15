package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"log/slog"
)

// FileManagerUnixServer implements the Unix socket server for file management operations
type FileManagerUnixServer struct {
	socketPath string
	listener   net.Listener
	logger     *slog.Logger
	startTime  time.Time
	stats      *ServerStats
}

// ServerStats tracks server performance metrics
type ServerStats struct {
	mu                sync.RWMutex
	RequestCount      int64         `json:"request_count"`
	TotalResponseTime time.Duration `json:"total_response_time"`
	LastRequestTime   time.Time     `json:"last_request_time"`
}

// AddRequest adds a request to the statistics
func (s *ServerStats) AddRequest(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RequestCount++
	s.TotalResponseTime += duration
	s.LastRequestTime = time.Now()
}

// GetStats returns a copy of the statistics
func (s *ServerStats) GetStats() (int64, time.Duration, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RequestCount, s.TotalResponseTime, s.LastRequestTime
}

// validatePath validates a file path to prevent path traversal attacks
func validatePath(path string, baseDir string) error {
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal detected")
	}

	// If baseDir is provided, ensure the path is within it
	if baseDir != "" {
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}

		absBase, err := filepath.Abs(baseDir)
		if err != nil {
			return fmt.Errorf("failed to get absolute base path: %w", err)
		}

		if !strings.HasPrefix(absPath, absBase) {
			return fmt.Errorf("path outside allowed directory")
		}
	}

	return nil
}

// NewFileManagerUnixServer creates a new Unix socket file manager server
func NewFileManagerUnixServer(socketPath string, logger *slog.Logger) *FileManagerUnixServer {
	return &FileManagerUnixServer{
		socketPath: socketPath,
		logger:     logger,
		startTime:  time.Now(),
		stats:      &ServerStats{},
	}
}

// Start starts the Unix socket server
func (s *FileManagerUnixServer) Start(ctx context.Context) error {
	// Remove existing socket file if it exists
	if err := os.RemoveAll(s.socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}

	s.listener = listener
	s.logger.Info("Unix socket server started", "socket_path", s.socketPath)

	// Set socket permissions
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		s.logger.Warn("Failed to set socket permissions", "error", err)
	}

	// Accept connections
	go s.acceptConnections(ctx)

	return nil
}

// Stop stops the Unix socket server
func (s *FileManagerUnixServer) Stop() error {
	if s.listener != nil {
		s.logger.Info("Shutting down Unix socket server...")
		err := s.listener.Close()
		if removeErr := os.RemoveAll(s.socketPath); removeErr != nil {
			s.logger.Warn("Failed to remove socket file", "error", removeErr)
		}
		return err
	}
	return nil
}

// acceptConnections handles incoming connections
func (s *FileManagerUnixServer) acceptConnections(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					s.logger.Error("Failed to accept connection", "error", err)
					continue
				}
			}

			go s.handleConnection(conn)
		}
	}
}

// handleConnection handles a single client connection
func (s *FileManagerUnixServer) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			s.logger.Error("Failed to close connection", "error", err)
		}
	}()

	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)

	for scanner.Scan() {
		requestData := scanner.Bytes()
		s.processRequest(requestData, writer)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		s.logger.Error("Connection error", "error", err)
	}
}

// processRequest processes a single request
func (s *FileManagerUnixServer) processRequest(requestData []byte, writer *bufio.Writer) {
	startTime := time.Now()

	// Parse request
	req, err := RequestFromJSON(requestData)
	if err != nil {
		s.logger.Error("Failed to parse request", "error", err)
		s.sendErrorResponse("unknown", fmt.Errorf("invalid request format"), writer)
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		s.logger.Error("Invalid request", "request_id", req.ID, "error", err)
		s.sendErrorResponse(req.ID, err, writer)
		return
	}

	s.logger.Info("Processing file operation",
		"request_id", req.ID,
		"operation", req.Operation,
	)

	// Execute operation
	var response *Response
	switch req.Operation {
	case "list":
		response = s.handleList(req)
	case "read":
		response = s.handleRead(req)
	case "write":
		response = s.handleWrite(req)
	case "create_dir":
		response = s.handleCreateDir(req)
	case "delete":
		response = s.handleDelete(req)
	case "move":
		response = s.handleMove(req)
	case "copy":
		response = s.handleCopy(req)
	case "stat":
		response = s.handleStat(req)
	case "exists":
		response = s.handleExists(req)
	case "health":
		response = s.handleHealth(req)
	default:
		response = NewErrorResponse(req.ID, fmt.Errorf("unsupported operation: %s", req.Operation))
	}

	// Send response
	responseData, err := response.ToJSON()
	if err != nil {
		s.logger.Error("Failed to marshal response", "request_id", req.ID, "error", err)
		s.sendErrorResponse(req.ID, fmt.Errorf("internal server error"), writer)
		return
	}

	_, err = writer.Write(responseData)
	if err != nil {
		s.logger.Error("Failed to write response", "request_id", req.ID, "error", err)
		return
	}
	_, err = writer.Write([]byte("\n"))
	if err != nil {
		s.logger.Error("Failed to write newline", "request_id", req.ID, "error", err)
		return
	}

	if err := writer.Flush(); err != nil {
		s.logger.Error("Failed to flush response", "request_id", req.ID, "error", err)
		return
	}

	duration := time.Since(startTime)

	// Update stats with thread safety
	s.stats.AddRequest(duration)

	s.logger.Info("File operation completed",
		"request_id", req.ID,
		"operation", req.Operation,
		"duration", duration,
		"success", response.Success,
	)
}

// sendErrorResponse sends an error response
func (s *FileManagerUnixServer) sendErrorResponse(id string, err error, writer *bufio.Writer) {
	response := NewErrorResponse(id, err)
	responseData, _ := response.ToJSON()
	if _, writeErr := writer.Write(responseData); writeErr != nil {
		s.logger.Error("Failed to write error response", "error", writeErr)
	}
	if _, writeErr := writer.Write([]byte("\n")); writeErr != nil {
		s.logger.Error("Failed to write newline", "error", writeErr)
	}
	if flushErr := writer.Flush(); flushErr != nil {
		s.logger.Error("Failed to flush writer", "error", flushErr)
	}
}

// File operation handlers

func (s *FileManagerUnixServer) handleList(req *Request) *Response {
	path, ok := req.GetStringParam("path")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("path parameter is required"))
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to list directory: %w", err))
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fileInfo := FileInfo{
			Name:    entry.Name(),
			Path:    filepath.Join(path, entry.Name()),
			Size:    info.Size(),
			IsDir:   entry.IsDir(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format(time.RFC3339),
		}
		files = append(files, fileInfo)
	}

	result := ListResult{
		Files: files,
		Count: len(files),
		Path:  path,
	}

	metadata := map[string]interface{}{
		"file_count": len(files),
		"path":       path,
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleRead(req *Request) *Response {
	path, ok := req.GetStringParam("path")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("path parameter is required"))
	}

	// Validate path to prevent directory traversal
	if err := validatePath(path, ""); err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("invalid path: %w", err))
	}

	content, err := os.ReadFile(path) // #nosec G304 -- path is validated above
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to read file: %w", err))
	}

	metadata := map[string]interface{}{
		"file_size": len(content),
		"path":      path,
	}

	return NewSuccessResponse(req.ID, string(content), metadata)
}

func (s *FileManagerUnixServer) handleWrite(req *Request) *Response {
	path, ok := req.GetStringParam("path")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("path parameter is required"))
	}

	// Validate path to prevent directory traversal
	if err := validatePath(path, ""); err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("invalid path: %w", err))
	}

	content, ok := req.GetStringParam("content")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("content parameter is required"))
	}

	err := os.WriteFile(path, []byte(content), 0600)
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to write file: %w", err))
	}

	result := WriteResult{
		BytesWritten: int64(len(content)),
		Path:         path,
	}

	metadata := map[string]interface{}{
		"bytes_written": len(content),
		"path":          path,
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleCreateDir(req *Request) *Response {
	path, ok := req.GetStringParam("path")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("path parameter is required"))
	}

	err := os.MkdirAll(path, 0750)
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to create directory: %w", err))
	}

	result := CreateDirResult{
		Path:    path,
		Created: true,
	}

	metadata := map[string]interface{}{
		"path": path,
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleDelete(req *Request) *Response {
	path, ok := req.GetStringParam("path")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("path parameter is required"))
	}

	err := os.RemoveAll(path)
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to delete: %w", err))
	}

	result := DeleteResult{
		Path:    path,
		Deleted: true,
	}

	metadata := map[string]interface{}{
		"path": path,
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleMove(req *Request) *Response {
	source, ok := req.GetStringParam("source")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("source parameter is required"))
	}

	dest, ok := req.GetStringParam("destination")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("destination parameter is required"))
	}

	err := os.Rename(source, dest)
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to move: %w", err))
	}

	result := MoveResult{
		Source:      source,
		Destination: dest,
	}

	metadata := map[string]interface{}{
		"source":      source,
		"destination": dest,
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleCopy(req *Request) *Response {
	source, ok := req.GetStringParam("source")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("source parameter is required"))
	}

	dest, ok := req.GetStringParam("destination")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("destination parameter is required"))
	}

	// Validate paths to prevent directory traversal
	if err := validatePath(source, ""); err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("invalid source path: %w", err))
	}
	if err := validatePath(dest, ""); err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("invalid destination path: %w", err))
	}

	sourceFile, err := os.Open(source) // #nosec G304 -- path is validated above
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to open source file: %w", err))
	}
	defer func() {
		if err := sourceFile.Close(); err != nil {
			s.logger.Error("Failed to close source file", "error", err)
		}
	}()

	destFile, err := os.Create(dest) // #nosec G304 -- path is validated above
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to create destination file: %w", err))
	}
	defer func() {
		if err := destFile.Close(); err != nil {
			s.logger.Error("Failed to close destination file", "error", err)
		}
	}()

	size, err := io.Copy(destFile, sourceFile)
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to copy file: %w", err))
	}

	result := CopyResult{
		Source:      source,
		Destination: dest,
		Size:        size,
	}

	metadata := map[string]interface{}{
		"source":      source,
		"destination": dest,
		"size":        size,
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleStat(req *Request) *Response {
	path, ok := req.GetStringParam("path")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("path parameter is required"))
	}

	info, err := os.Stat(path)
	if err != nil {
		return NewErrorResponse(req.ID, fmt.Errorf("failed to stat file: %w", err))
	}

	fileInfo := FileInfo{
		Name:    info.Name(),
		Path:    path,
		Size:    info.Size(),
		IsDir:   info.IsDir(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().Format(time.RFC3339),
	}

	result := StatResult{
		FileInfo: fileInfo,
	}

	metadata := map[string]interface{}{
		"path": path,
		"size": info.Size(),
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleExists(req *Request) *Response {
	path, ok := req.GetStringParam("path")
	if !ok {
		return NewErrorResponse(req.ID, fmt.Errorf("path parameter is required"))
	}

	_, err := os.Stat(path)
	exists := !os.IsNotExist(err)

	result := ExistsResult{
		Exists: exists,
		Path:   path,
	}

	metadata := map[string]interface{}{
		"path":   path,
		"exists": exists,
	}

	return NewSuccessResponse(req.ID, result, metadata)
}

func (s *FileManagerUnixServer) handleHealth(req *Request) *Response {
	uptime := time.Since(s.startTime)

	// Get stats safely
	requestCount, totalResponseTime, lastRequestTime := s.stats.GetStats()

	avgResponseTime := time.Duration(0)
	if requestCount > 0 {
		avgResponseTime = totalResponseTime / time.Duration(requestCount)
	}

	healthInfo := map[string]interface{}{
		"status":            "healthy",
		"uptime":            uptime.String(),
		"request_count":     requestCount,
		"avg_response_time": avgResponseTime.String(),
		"last_request":      lastRequestTime.Format(time.RFC3339),
		"socket_path":       s.socketPath,
	}

	metadata := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	}

	return NewSuccessResponse(req.ID, healthInfo, metadata)
}
