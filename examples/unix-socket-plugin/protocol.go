package main

import (
	"encoding/json"
	"fmt"
)

// Request represents a file operation request sent over the Unix socket
type Request struct {
	ID        string                 `json:"id"`
	Operation string                 `json:"operation"`
	Params    map[string]interface{} `json:"params"`
}

// Response represents a file operation response sent over the Unix socket
type Response struct {
	ID       string                 `json:"id"`
	Success  bool                   `json:"success"`
	Result   interface{}            `json:"result,omitempty"`
	Error    string                 `json:"error,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// FileInfo represents file system information
type FileInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
}

// ListResult represents the result of a list operation
type ListResult struct {
	Files []FileInfo `json:"files"`
	Count int        `json:"count"`
	Path  string     `json:"path"`
}

// WriteResult represents the result of a write operation
type WriteResult struct {
	BytesWritten int64  `json:"bytes_written"`
	Path         string `json:"path"`
}

// CopyResult represents the result of a copy operation
type CopyResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Size        int64  `json:"size"`
}

// MoveResult represents the result of a move operation
type MoveResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// StatResult represents the result of a stat operation
type StatResult struct {
	FileInfo FileInfo `json:"file_info"`
}

// ExistsResult represents the result of an exists operation
type ExistsResult struct {
	Exists bool   `json:"exists"`
	Path   string `json:"path"`
}

// CreateDirResult represents the result of a create directory operation
type CreateDirResult struct {
	Path    string `json:"path"`
	Created bool   `json:"created"`
}

// DeleteResult represents the result of a delete operation
type DeleteResult struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted"`
}

// NewRequest creates a new request with the specified operation and parameters
func NewRequest(id, operation string, params map[string]interface{}) *Request {
	return &Request{
		ID:        id,
		Operation: operation,
		Params:    params,
	}
}

// NewSuccessResponse creates a successful response
func NewSuccessResponse(id string, result interface{}, metadata map[string]interface{}) *Response {
	return &Response{
		ID:       id,
		Success:  true,
		Result:   result,
		Metadata: metadata,
	}
}

// NewErrorResponse creates an error response
func NewErrorResponse(id string, err error) *Response {
	return &Response{
		ID:      id,
		Success: false,
		Error:   err.Error(),
	}
}

// ToJSON converts the request to JSON bytes
func (r *Request) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ToJSON converts the response to JSON bytes
func (r *Response) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON parses a request from JSON bytes
func RequestFromJSON(data []byte) (*Request, error) {
	var req Request
	err := json.Unmarshal(data, &req)
	return &req, err
}

// FromJSON parses a response from JSON bytes
func ResponseFromJSON(data []byte) (*Response, error) {
	var resp Response
	err := json.Unmarshal(data, &resp)
	return &resp, err
}

// GetStringParam gets a string parameter from the request
func (r *Request) GetStringParam(key string) (string, bool) {
	if val, ok := r.Params[key]; ok {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

// GetIntParam gets an integer parameter from the request
func (r *Request) GetIntParam(key string) (int, bool) {
	if val, ok := r.Params[key]; ok {
		switch v := val.(type) {
		case int:
			return v, true
		case float64:
			return int(v), true
		}
	}
	return 0, false
}

// GetBoolParam gets a boolean parameter from the request
func (r *Request) GetBoolParam(key string) (bool, bool) {
	if val, ok := r.Params[key]; ok {
		if b, ok := val.(bool); ok {
			return b, true
		}
	}
	return false, false
}

// Validate validates the request structure
func (r *Request) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("request ID is required")
	}
	if r.Operation == "" {
		return fmt.Errorf("operation is required")
	}
	return nil
}

// Validate validates the response structure
func (r *Response) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("response ID is required")
	}
	return nil
}
