// types.go: Data structures for the HTTP text processor pluginpackage httpplugin

package main

import (
	"encoding/json"
)

// TextProcessingRequest represents a text processing request
type TextProcessingRequest struct {
	Operation string                 `json:"operation"`
	Text      string                 `json:"text"`
	Options   map[string]interface{} `json:"options,omitempty"`
}

// TextProcessingResponse represents the result of text processing
type TextProcessingResponse struct {
	Result   string            `json:"result"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// String returns a JSON representation of the request
func (r TextProcessingRequest) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// String returns a JSON representation of the response
func (r TextProcessingResponse) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status  string            `json:"status"`
	Message string            `json:"message,omitempty"`
	Checks  map[string]string `json:"checks,omitempty"`
}

// InfoResponse represents the plugin info response
type InfoResponse struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Capabilities []string `json:"capabilities"`
}
