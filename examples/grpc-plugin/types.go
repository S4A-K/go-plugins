// types.go: Data structures for the calculator pluginpackage grpcplugin

package main

import (
	"encoding/json"
)

// CalculationRequest represents a generic calculation request
type CalculationRequest struct {
	Operation string  `json:"operation"`
	A         float64 `json:"a"`
	B         float64 `json:"b"`
}

// CalculationResponse represents the result of a calculation
type CalculationResponse struct {
	Result float64 `json:"result"`
	Error  string  `json:"error,omitempty"`
}

// String returns a JSON representation of the request
func (r CalculationRequest) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// String returns a JSON representation of the response
func (r CalculationResponse) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}
