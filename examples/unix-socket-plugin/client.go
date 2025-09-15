package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"log/slog"

	plugins "github.com/go-plugins"
)

// FileManagerUnixClient implements a Unix socket plugin client for file management
type FileManagerUnixClient struct {
	socketPath   string
	conn         net.Conn
	logger       *slog.Logger
	requestID    int64
	pluginInfo   *plugins.PluginInfo
	healthStatus *plugins.HealthStatus
}

// NewFileManagerUnixClient creates a new Unix socket file manager client
func NewFileManagerUnixClient(socketPath string, logger *slog.Logger) *FileManagerUnixClient {
	return &FileManagerUnixClient{
		socketPath: socketPath,
		logger:     logger,
		pluginInfo: &plugins.PluginInfo{
			Name:         "File Manager Unix Socket Plugin",
			Version:      "1.0.0",
			Description:  "Unix socket-based file management service",
			Capabilities: []string{"list", "read", "write", "create_dir", "delete", "move", "copy", "stat", "exists"},
		},
		healthStatus: &plugins.HealthStatus{
			Status:  plugins.StatusHealthy,
			Message: "File manager is ready",
		},
	}
}

// Connect establishes connection to the Unix socket server
func (c *FileManagerUnixClient) Connect(ctx context.Context) error {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to Unix socket: %w", err)
	}

	c.conn = conn
	c.logger.Info("Connected to Unix socket server", "socket_path", c.socketPath)
	return nil
}

// Disconnect closes the connection to the Unix socket server
func (c *FileManagerUnixClient) Disconnect() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.logger.Info("Disconnected from Unix socket server")
		return err
	}
	return nil
}

// Plugin interface implementation

func (c *FileManagerUnixClient) Info() *plugins.PluginInfo {
	return c.pluginInfo
}

func (c *FileManagerUnixClient) Health() *plugins.HealthStatus {
	// Check connection and get health info from server
	if c.conn == nil {
		c.healthStatus.Status = plugins.StatusUnhealthy
		c.healthStatus.Message = "Not connected to Unix socket server"
		return c.healthStatus
	}

	// Send health request to server
	req := NewRequest(c.generateRequestID(), "health", map[string]interface{}{})
	resp, err := c.sendRequest(req)
	if err != nil {
		c.healthStatus.Status = plugins.StatusUnhealthy
		c.healthStatus.Message = fmt.Sprintf("Health check failed: %v", err)
		return c.healthStatus
	}

	if resp.Success {
		c.healthStatus.Status = plugins.StatusHealthy
		c.healthStatus.Message = "File manager is running normally"

		// Add server health info to metadata
		if _, ok := resp.Result.(map[string]interface{}); ok {
			c.healthStatus.Metadata = map[string]string{
				"socket_path": c.socketPath,
				"timestamp":   time.Now().Format(time.RFC3339),
			}
		}
	} else {
		c.healthStatus.Status = plugins.StatusUnhealthy
		c.healthStatus.Message = fmt.Sprintf("Server health check failed: %s", resp.Error)
	}

	return c.healthStatus
}

// Execute executes a plugin operation
func (c *FileManagerUnixClient) Execute(ctx context.Context, operation string, params map[string]interface{}) (interface{}, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to Unix socket server")
	}

	req := NewRequest(c.generateRequestID(), operation, params)
	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute operation: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("plugin error: %s", resp.Error)
	}

	return resp.Result, nil
}

// File operation methods

func (c *FileManagerUnixClient) ListFiles(path string) (*ListResult, error) {
	params := map[string]interface{}{
		"path": path,
	}

	result, err := c.Execute(context.Background(), "list", params)
	if err != nil {
		return nil, err
	}

	// Convert result to ListResult
	if listData, ok := result.(map[string]interface{}); ok {
		return c.convertToListResult(listData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) ReadFile(path string) (string, error) {
	params := map[string]interface{}{
		"path": path,
	}

	result, err := c.Execute(context.Background(), "read", params)
	if err != nil {
		return "", err
	}

	if content, ok := result.(string); ok {
		return content, nil
	}

	return "", fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) WriteFile(path, content string) (*WriteResult, error) {
	params := map[string]interface{}{
		"path":    path,
		"content": content,
	}

	result, err := c.Execute(context.Background(), "write", params)
	if err != nil {
		return nil, err
	}

	if writeData, ok := result.(map[string]interface{}); ok {
		return c.convertToWriteResult(writeData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) CreateDirectory(path string) (*CreateDirResult, error) {
	params := map[string]interface{}{
		"path": path,
	}

	result, err := c.Execute(context.Background(), "create_dir", params)
	if err != nil {
		return nil, err
	}

	if createData, ok := result.(map[string]interface{}); ok {
		return c.convertToCreateDirResult(createData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) DeletePath(path string) (*DeleteResult, error) {
	params := map[string]interface{}{
		"path": path,
	}

	result, err := c.Execute(context.Background(), "delete", params)
	if err != nil {
		return nil, err
	}

	if deleteData, ok := result.(map[string]interface{}); ok {
		return c.convertToDeleteResult(deleteData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) MovePath(source, destination string) (*MoveResult, error) {
	params := map[string]interface{}{
		"source":      source,
		"destination": destination,
	}

	result, err := c.Execute(context.Background(), "move", params)
	if err != nil {
		return nil, err
	}

	if moveData, ok := result.(map[string]interface{}); ok {
		return c.convertToMoveResult(moveData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) CopyFile(source, destination string) (*CopyResult, error) {
	params := map[string]interface{}{
		"source":      source,
		"destination": destination,
	}

	result, err := c.Execute(context.Background(), "copy", params)
	if err != nil {
		return nil, err
	}

	if copyData, ok := result.(map[string]interface{}); ok {
		return c.convertToCopyResult(copyData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) StatPath(path string) (*StatResult, error) {
	params := map[string]interface{}{
		"path": path,
	}

	result, err := c.Execute(context.Background(), "stat", params)
	if err != nil {
		return nil, err
	}

	if statData, ok := result.(map[string]interface{}); ok {
		return c.convertToStatResult(statData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

func (c *FileManagerUnixClient) PathExists(path string) (*ExistsResult, error) {
	params := map[string]interface{}{
		"path": path,
	}

	result, err := c.Execute(context.Background(), "exists", params)
	if err != nil {
		return nil, err
	}

	if existsData, ok := result.(map[string]interface{}); ok {
		return c.convertToExistsResult(existsData)
	}

	return nil, fmt.Errorf("unexpected result type")
}

// Helper methods

func (c *FileManagerUnixClient) generateRequestID() string {
	c.requestID++
	return fmt.Sprintf("unix-req-%d-%d", time.Now().UnixNano(), c.requestID)
}

func (c *FileManagerUnixClient) sendRequest(req *Request) (*Response, error) {
	// Send request
	requestData, err := req.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	_, err = c.conn.Write(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	_, err = c.conn.Write([]byte("\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to write newline: %w", err)
	}

	// Read response
	scanner := bufio.NewScanner(c.conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		return nil, fmt.Errorf("no response received")
	}

	responseData := scanner.Bytes()
	resp, err := ResponseFromJSON(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// Result conversion methods

func (c *FileManagerUnixClient) convertToListResult(data map[string]interface{}) (*ListResult, error) {
	result := &ListResult{}

	if files, ok := data["files"].([]interface{}); ok {
		for _, fileInterface := range files {
			if fileMap, ok := fileInterface.(map[string]interface{}); ok {
				fileInfo := FileInfo{}
				if name, ok := fileMap["name"].(string); ok {
					fileInfo.Name = name
				}
				if path, ok := fileMap["path"].(string); ok {
					fileInfo.Path = path
				}
				if size, ok := fileMap["size"].(float64); ok {
					fileInfo.Size = int64(size)
				}
				if isDir, ok := fileMap["is_dir"].(bool); ok {
					fileInfo.IsDir = isDir
				}
				if mode, ok := fileMap["mode"].(string); ok {
					fileInfo.Mode = mode
				}
				if modTime, ok := fileMap["mod_time"].(string); ok {
					fileInfo.ModTime = modTime
				}
				result.Files = append(result.Files, fileInfo)
			}
		}
	}

	if count, ok := data["count"].(float64); ok {
		result.Count = int(count)
	}
	if path, ok := data["path"].(string); ok {
		result.Path = path
	}

	return result, nil
}

func (c *FileManagerUnixClient) convertToWriteResult(data map[string]interface{}) (*WriteResult, error) {
	result := &WriteResult{}

	if bytesWritten, ok := data["bytes_written"].(float64); ok {
		result.BytesWritten = int64(bytesWritten)
	}
	if path, ok := data["path"].(string); ok {
		result.Path = path
	}

	return result, nil
}

func (c *FileManagerUnixClient) convertToCreateDirResult(data map[string]interface{}) (*CreateDirResult, error) {
	result := &CreateDirResult{}

	if path, ok := data["path"].(string); ok {
		result.Path = path
	}
	if created, ok := data["created"].(bool); ok {
		result.Created = created
	}

	return result, nil
}

func (c *FileManagerUnixClient) convertToDeleteResult(data map[string]interface{}) (*DeleteResult, error) {
	result := &DeleteResult{}

	if path, ok := data["path"].(string); ok {
		result.Path = path
	}
	if deleted, ok := data["deleted"].(bool); ok {
		result.Deleted = deleted
	}

	return result, nil
}

func (c *FileManagerUnixClient) convertToMoveResult(data map[string]interface{}) (*MoveResult, error) {
	result := &MoveResult{}

	if source, ok := data["source"].(string); ok {
		result.Source = source
	}
	if destination, ok := data["destination"].(string); ok {
		result.Destination = destination
	}

	return result, nil
}

func (c *FileManagerUnixClient) convertToCopyResult(data map[string]interface{}) (*CopyResult, error) {
	result := &CopyResult{}

	if source, ok := data["source"].(string); ok {
		result.Source = source
	}
	if destination, ok := data["destination"].(string); ok {
		result.Destination = destination
	}
	if size, ok := data["size"].(float64); ok {
		result.Size = int64(size)
	}

	return result, nil
}

func (c *FileManagerUnixClient) convertToStatResult(data map[string]interface{}) (*StatResult, error) {
	result := &StatResult{}

	if fileInfoData, ok := data["file_info"].(map[string]interface{}); ok {
		fileInfo := FileInfo{}
		if name, ok := fileInfoData["name"].(string); ok {
			fileInfo.Name = name
		}
		if path, ok := fileInfoData["path"].(string); ok {
			fileInfo.Path = path
		}
		if size, ok := fileInfoData["size"].(float64); ok {
			fileInfo.Size = int64(size)
		}
		if isDir, ok := fileInfoData["is_dir"].(bool); ok {
			fileInfo.IsDir = isDir
		}
		if mode, ok := fileInfoData["mode"].(string); ok {
			fileInfo.Mode = mode
		}
		if modTime, ok := fileInfoData["mod_time"].(string); ok {
			fileInfo.ModTime = modTime
		}
		result.FileInfo = fileInfo
	}

	return result, nil
}

func (c *FileManagerUnixClient) convertToExistsResult(data map[string]interface{}) (*ExistsResult, error) {
	result := &ExistsResult{}

	if exists, ok := data["exists"].(bool); ok {
		result.Exists = exists
	}
	if path, ok := data["path"].(string); ok {
		result.Path = path
	}

	return result, nil
}
