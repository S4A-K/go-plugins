// subprocess_json_communication_test.go: Test for JSON stdin/stdout communication
//
// This file contains tests specifically for JSON-based subprocess communication
// to verify that our refactoring maintains correct stdin/stdout protocol handling.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSubprocessJSONCommunication_SingleRequest tests basic JSON communication
func TestSubprocessJSONCommunication_SingleRequest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping JSON subprocess test on Windows due to script execution limitations")
	}

	ctx := context.Background()

	// Create a JSON-responding plugin
	pluginPath := createJSONPluginExecutable(t)
	defer cleanupFile(t, pluginPath)

	factory := NewSubprocessPluginFactory[IntegrationTestRequest, IntegrationTestResponse](NewTestLogger())

	config := PluginConfig{
		Name:       "json-test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   pluginPath,
		Executable: pluginPath,
		Enabled:    true,
		Auth:       AuthConfig{Method: AuthNone},
	}

	plugin, err := factory.CreatePlugin(config)
	require.NoError(t, err)
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Logf("Warning: plugin close error: %v", err)
		}
	}()

	// Test single request
	request := IntegrationTestRequest{
		Message:   "test message",
		RequestID: "test-001",
		Timestamp: time.Now().Unix(),
	}

	execCtx := ExecutionContext{
		RequestID: "exec-001",
		Timeout:   10 * time.Second,
	}

	response, err := plugin.Execute(ctx, execCtx, request)
	assert.NoError(t, err, "JSON communication should work without errors")
	assert.Equal(t, "test message", response.Message)
	assert.Equal(t, "processed", response.Status)
}

// TestSubprocessJSONCommunication_ConcurrentRequests tests concurrent JSON communication
func TestSubprocessJSONCommunication_ConcurrentRequests(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping JSON subprocess test on Windows due to script execution limitations")
	}

	ctx := context.Background()

	// Create a JSON-responding plugin
	pluginPath := createJSONPluginExecutable(t)
	defer cleanupFile(t, pluginPath)

	factory := NewSubprocessPluginFactory[IntegrationTestRequest, IntegrationTestResponse](NewTestLogger())

	config := PluginConfig{
		Name:       "json-concurrent-plugin",
		Transport:  TransportExecutable,
		Endpoint:   pluginPath,
		Executable: pluginPath,
		Enabled:    true,
		Auth:       AuthConfig{Method: AuthNone},
	}

	plugin, err := factory.CreatePlugin(config)
	require.NoError(t, err)
	defer func() {
		if err := plugin.Close(); err != nil {
			t.Logf("Warning: plugin close error: %v", err)
		}
	}()

	// Test concurrent requests
	const numGoroutines = 5
	const requestsPerGoroutine = 3

	var wg sync.WaitGroup
	errorChan := make(chan error, numGoroutines*requestsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < requestsPerGoroutine; j++ {
				request := IntegrationTestRequest{
					Message:   fmt.Sprintf("concurrent test %d-%d", goroutineID, j),
					RequestID: fmt.Sprintf("concurrent-%d-%d", goroutineID, j),
					Timestamp: time.Now().Unix(),
				}

				execCtx := ExecutionContext{
					RequestID: fmt.Sprintf("exec-%d-%d", goroutineID, j),
					Timeout:   10 * time.Second,
				}

				response, err := plugin.Execute(ctx, execCtx, request)
				if err != nil {
					errorChan <- fmt.Errorf("goroutine %d, request %d: %w", goroutineID, j, err)
				} else {
					// Verify response
					if response.Message != request.Message {
						errorChan <- fmt.Errorf("goroutine %d, request %d: response mismatch", goroutineID, j)
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorChan)

	// Check for errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	assert.Empty(t, errors, "JSON concurrent communication should work without errors")

	// Verify plugin is still healthy
	health := plugin.Health(ctx)
	assert.Equal(t, StatusHealthy, health.Status, "Plugin should remain healthy after concurrent requests")
}

// createJSONPluginExecutable creates a test executable that properly implements JSON stdin/stdout protocol
func createJSONPluginExecutable(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "json_plugin_test")
	require.NoError(t, err)

	// Create a Go program that implements proper JSON stdin/stdout protocol
	goSourcePath := filepath.Join(tmpDir, "json_plugin.go")
	goContent := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type SubprocessRequest struct {
	ID      string      ` + "`json:\"id\"`" + `
	Method  string      ` + "`json:\"method\"`" + `
	Payload interface{} ` + "`json:\"payload\"`" + `
	Context interface{} ` + "`json:\"context\"`" + `
}

type SubprocessResponse struct {
	ID     string      ` + "`json:\"id\"`" + `
	Result interface{} ` + "`json:\"result,omitempty\"`" + `
	Error  *string     ` + "`json:\"error,omitempty\"`" + `
}

type IntegrationTestRequest struct {
	Message   string ` + "`json:\"message\"`" + `
	RequestID string ` + "`json:\"request_id\"`" + `
	Timestamp int64  ` + "`json:\"timestamp\"`" + `
}

type IntegrationTestResponse struct {
	Status    string ` + "`json:\"status\"`" + `
	Message   string ` + "`json:\"message\"`" + `
	RequestID string ` + "`json:\"request_id\"`" + `
	Timestamp int64  ` + "`json:\"timestamp\"`" + `
}

func main() {
	// Write startup message to stderr (not stdout, which is used for JSON)
	fmt.Fprintf(os.Stderr, "Professional subprocess plugin starting (PID: %d)\n", os.Getpid())

	scanner := bufio.NewScanner(os.Stdin)
	
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		
		var req SubprocessRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}
		
		var response SubprocessResponse
		response.ID = req.ID
		
		if req.Method == "health" {
			response.Result = map[string]string{"status": "healthy"}
		} else if req.Method == "info" {
			response.Result = map[string]string{
				"name": "json-test-plugin",
				"version": "1.0.0",
			}
		} else if req.Method == "execute" {
			// Handle execute request
			payloadBytes, _ := json.Marshal(req.Payload)
			var testReq IntegrationTestRequest
			if err := json.Unmarshal(payloadBytes, &testReq); err == nil {
				result := IntegrationTestResponse{
					Status:    "processed",
					Message:   testReq.Message,
					RequestID: testReq.RequestID,
					Timestamp: time.Now().Unix(),
				}
				response.Result = result
			} else {
				errorMsg := "failed to parse request"
				response.Error = &errorMsg
			}
		}
		
		responseBytes, _ := json.Marshal(response)
		fmt.Println(string(responseBytes))
	}
}
`

	err = os.WriteFile(goSourcePath, []byte(goContent), 0644)
	require.NoError(t, err)

	// Compile the Go program to executable
	executablePath := filepath.Join(tmpDir, "json_plugin")
	if runtime.GOOS == "windows" {
		executablePath += ".exe"
	}

	err = compileGoProgram(goSourcePath, executablePath)
	require.NoError(t, err, "Failed to compile JSON plugin executable")

	return executablePath
}
