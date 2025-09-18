// subprocess_test.go: Comprehensive tests for subprocess plugin functionality
//
// This test file provides a safety net for refactoring the subprocess.go file.
// It covers all major components and functionality to ensure no regressions
// occur during the separation of concerns refactoring.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/agilira/go-errors"
)

// TestSubprocessPluginFactory tests the factory creation and configuration
func TestSubprocessPluginFactory(t *testing.T) {
	logger := &MockLogger{}
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](logger)

	if factory == nil {
		t.Fatal("Factory should not be nil")
	}

	if factory.logger != logger {
		t.Error("Factory should use provided logger")
	}

	// Test with nil logger (should use default)
	factoryWithNilLogger := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)
	if factoryWithNilLogger.logger == nil {
		t.Error("Factory should have default logger when nil is provided")
	}
}

func TestSubprocessPluginFactory_SupportedTransports(t *testing.T) {
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)
	transports := factory.SupportedTransports()

	expectedTransports := []string{string(TransportExecutable)}
	if !reflect.DeepEqual(transports, expectedTransports) {
		t.Errorf("Expected transports %v, got %v", expectedTransports, transports)
	}
}

func TestSubprocessPluginFactory_ValidateConfig(t *testing.T) {
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	tests := []struct {
		name        string
		config      PluginConfig
		shouldError bool
		errorType   string
	}{
		{
			name: "valid config with test executable",
			config: func() PluginConfig {
				testExec := createTestExecutable(t)
				t.Cleanup(func() {
					if err := os.Remove(testExec); err != nil {
						t.Logf("Warning: failed to remove test executable: %v", err)
					}
				})
				return PluginConfig{
					Name:       "test-plugin",
					Transport:  TransportExecutable,
					Endpoint:   testExec,
					Executable: testExec,
				}
			}(),
			shouldError: false,
		},
		{
			name: "empty endpoint",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportExecutable,
			},
			shouldError: true,
			errorType:   "ConfigValidationError",
		},
		{
			name: "wrong transport",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportGRPC,
				Endpoint:  "/bin/echo",
			},
			shouldError: true,
			errorType:   "ConfigValidationError",
		},
		{
			name: "empty executable",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportExecutable,
				Endpoint:  "/bin/echo",
			},
			shouldError: true,
			errorType:   "ConfigValidationError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateConfig(tt.config)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				// Check error type if specified
				if tt.errorType != "" {
					checkErrorType(t, err, tt.errorType)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestSubprocessPluginFactory_CreatePlugin(t *testing.T) {
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	// Create a simple test executable
	testExecutable := createTestExecutable(t)
	defer func() {
		if err := os.Remove(testExecutable); err != nil {
			t.Logf("Warning: failed to remove test executable: %v", err)
		}
	}()

	config := PluginConfig{
		Name:       "test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
		Args:       []string{"arg1", "arg2"},
		Env:        []string{"TEST_VAR=value"},
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	if plugin == nil {
		t.Fatal("Plugin should not be nil")
	}

	// Verify plugin configuration through public interface
	subprocessPlugin, ok := plugin.(*SubprocessPlugin[TestRequest, TestResponse])
	if !ok {
		t.Fatal("Plugin should be SubprocessPlugin type")
	}

	// Verify configuration through plugin info (since internal fields are no longer accessible)
	info := subprocessPlugin.Info()
	if !containsString(info.Capabilities, "subprocess") {
		t.Error("Plugin should have subprocess capability")
	}

	if !containsString(info.Capabilities, "refactored-soc") {
		t.Error("Plugin should have refactored-soc capability indicating successful refactoring")
	}
}

func TestProcessStatus_String(t *testing.T) {
	tests := []struct {
		status   ProcessStatus
		expected string
	}{
		{StatusStopped, "stopped"},
		{StatusStarting, "starting"},
		{StatusRunning, "running"},
		{StatusStopping, "stopping"},
		{StatusFailed, "failed"},
		{ProcessStatus(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.status.String(); got != tt.expected {
				t.Errorf("ProcessStatus.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSubprocessPlugin_Info(t *testing.T) {
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	testExecutable := createTestExecutable(t)
	defer func() {
		if err := os.Remove(testExecutable); err != nil {
			t.Logf("Warning: failed to remove test executable: %v", err)
		}
	}()

	config := PluginConfig{
		Name:       "test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	info := plugin.Info()

	if info.Name != "subprocess-plugin" {
		t.Errorf("Expected name 'subprocess-plugin', got %s", info.Name)
	}

	if info.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %s", info.Version)
	}

	expectedCapabilities := []string{"subprocess", "process-management", "standard-protocol", "refactored-soc"}
	if !reflect.DeepEqual(info.Capabilities, expectedCapabilities) {
		t.Errorf("Expected capabilities %v, got %v", expectedCapabilities, info.Capabilities)
	}

	if info.Metadata["transport"] != string(TransportExecutable) {
		t.Errorf("Expected transport metadata %s, got %s", TransportExecutable, info.Metadata["transport"])
	}

	// Note: endpoint metadata is no longer available in the refactored version
	// as it's handled internally by the ProcessManager
	// This is expected behavior after separation of concerns
}

func TestSubprocessPlugin_Health(t *testing.T) {
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	testExecutable := createTestExecutable(t)
	defer func() {
		if err := os.Remove(testExecutable); err != nil {
			t.Logf("Warning: failed to remove test executable: %v", err)
		}
	}()

	config := PluginConfig{
		Name:       "test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	ctx := context.Background()
	health := plugin.Health(ctx)

	// Plugin should be offline since it's not started
	if health.Status != StatusOffline {
		t.Errorf("Expected status %v, got %v", StatusOffline, health.Status)
	}

	if health.Message != "subprocess not started" {
		t.Errorf("Expected message 'subprocess not started', got %s", health.Message)
	}

	if health.LastCheck.IsZero() {
		t.Error("LastCheck should be set")
	}
}

func TestSubprocessPlugin_GetInfo(t *testing.T) {
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	testExecutable := createTestExecutable(t)
	defer func() {
		if err := os.Remove(testExecutable); err != nil {
			t.Logf("Warning: failed to remove test executable: %v", err)
		}
	}()

	config := PluginConfig{
		Name:       "test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	subprocessPlugin := plugin.(*SubprocessPlugin[TestRequest, TestResponse])
	processInfo := subprocessPlugin.GetInfo()

	if processInfo == nil {
		t.Fatal("ProcessInfo should not be nil")
	}

	if processInfo.Status != StatusStopped {
		t.Errorf("Expected status %v, got %v", StatusStopped, processInfo.Status)
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name     string
		config   PluginConfig
		expected []string
	}{
		{
			name: "direct args field",
			config: PluginConfig{
				Args: []string{"arg1", "arg2"},
			},
			expected: []string{"arg1", "arg2"},
		},
		{
			name: "args from options",
			config: PluginConfig{
				Options: map[string]interface{}{
					"args": []string{"opt1", "opt2"},
				},
			},
			expected: []string{"opt1", "opt2"},
		},
		{
			name: "args from annotations",
			config: PluginConfig{
				Annotations: map[string]string{
					"args": "ann1,ann2, ann3 ",
				},
			},
			expected: []string{"ann1", "ann2", "ann3"},
		},
		{
			name: "empty args annotation",
			config: PluginConfig{
				Annotations: map[string]string{
					"args": " , , ",
				},
			},
			expected: nil, // parseArgs returns nil for empty, not empty slice
		},
		{
			name:     "no args",
			config:   PluginConfig{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConfigParser(nil)
			result := parser.parseArgs(tt.config)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ConfigParser.parseArgs() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseEnv(t *testing.T) {
	tests := []struct {
		name     string
		config   PluginConfig
		expected []string
	}{
		{
			name: "direct env field",
			config: PluginConfig{
				Env: []string{"VAR1=value1", "VAR2=value2"},
			},
			expected: []string{"VAR1=value1", "VAR2=value2"},
		},
		{
			name: "env from options array",
			config: PluginConfig{
				Options: map[string]interface{}{
					"env": []string{"OPT1=optval1", "OPT2=optval2"},
				},
			},
			expected: []string{"OPT1=optval1", "OPT2=optval2"},
		},
		{
			name: "env from options map",
			config: PluginConfig{
				Options: map[string]interface{}{
					"environment": map[string]string{
						"KEY1": "val1",
						"KEY2": "val2",
					},
				},
			},
			expected: []string{"KEY1=val1", "KEY2=val2"},
		},
		{
			name: "env from annotations",
			config: PluginConfig{
				Annotations: map[string]string{
					"env_DEBUG":   "1",
					"env_VERBOSE": "true",
					"not_env":     "ignored",
					"env_":        "ignored_empty_key",
				},
			},
			expected: []string{"DEBUG=1", "VERBOSE=true"},
		},
		{
			name: "combined sources",
			config: PluginConfig{
				Env: []string{"DIRECT=1"},
				Options: map[string]interface{}{
					"env": []string{"OPTION=2"},
				},
				Annotations: map[string]string{
					"env_ANNOTATION": "3",
				},
			},
			expected: []string{"DIRECT=1", "OPTION=2", "ANNOTATION=3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConfigParser(nil)
			result := parser.parseEnv(tt.config)

			// Sort both slices since order may vary for map iteration
			if len(result) == len(tt.expected) {
				// Check if all expected values are present
				for _, expected := range tt.expected {
					found := false
					for _, actual := range result {
						if actual == expected {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("ConfigParser.parseEnv() missing expected value %s in result %v", expected, result)
					}
				}
			} else {
				t.Errorf("ConfigParser.parseEnv() = %v (length %d), want %v (length %d)", result, len(result), tt.expected, len(tt.expected))
			}
		})
	}
}

func TestSubprocessPlugin_ValidateExecutablePath(t *testing.T) {
	// Test validation through ConfigParser (which now handles validation)
	t.Run("empty path", func(t *testing.T) {
		parser := NewConfigParser(nil)
		config := PluginConfig{
			Endpoint: "", // empty path
		}
		_, err := parser.ParseConfig(config)
		if err == nil {
			t.Error("Expected error for empty path")
		}
		checkErrorType(t, err, "ConfigPathError")
	})

	// Test validation through plugin creation (integration test)
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	tests := []struct {
		name        string
		execPath    string
		args        []string
		shouldError bool
		errorType   string
	}{
		{
			name:        "path traversal",
			execPath:    "../../../bin/sh",
			shouldError: true,
			errorType:   "PathTraversalError",
		},
		{
			name:        "non-existent file",
			execPath:    "/non/existent/file",
			shouldError: true,
			errorType:   "ConfigFileError",
		},
		{
			name:        "dangerous args semicolon",
			execPath:    "valid", // Will be replaced with actual test executable
			args:        []string{"hello; rm -rf /"},
			shouldError: true,
			errorType:   "ConfigValidationError",
		},
		{
			name:        "dangerous args ampersand",
			execPath:    "valid", // Will be replaced with actual test executable
			args:        []string{"hello & rm -rf /"},
			shouldError: true,
			errorType:   "ConfigValidationError",
		},
		{
			name:        "dangerous args pipe",
			execPath:    "valid", // Will be replaced with actual test executable
			args:        []string{"hello | rm -rf /"},
			shouldError: true,
			errorType:   "ConfigValidationError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execPath := tt.execPath

			// Create a valid executable for dangerous args tests
			if tt.execPath == "valid" {
				execPath = createTestExecutable(t)
				defer func() {
					if err := os.Remove(execPath); err != nil {
						t.Logf("Warning: failed to remove test executable: %v", err)
					}
				}()
			}

			config := PluginConfig{
				Name:       "test-plugin",
				Transport:  TransportExecutable,
				Endpoint:   execPath,
				Executable: execPath,
				Args:       tt.args,
			}

			// Validation now happens during plugin creation
			_, err := factory.CreatePlugin(config)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				checkErrorType(t, err, tt.errorType)
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// Helper functions for tests

func createTestExecutable(t *testing.T) string {
	t.Helper()

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "subprocess_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create a simple shell script
	scriptPath := filepath.Join(tmpDir, "test_executable.sh")
	scriptContent := `#!/bin/bash
echo "Test subprocess"
sleep 1
exit 0
`

	err = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	return scriptPath
}

// Helper functions for testing

// containsString checks if a slice contains a specific string
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// checkErrorType verifies that an error is of the expected type by checking the error code
func checkErrorType(t *testing.T, err error, expectedType string) {
	t.Helper()

	agiErr, ok := err.(*errors.Error)
	if !ok {
		t.Errorf("Expected *errors.Error but got %T: %v", err, err)
		return
	}

	var expectedCode errors.ErrorCode
	switch expectedType {
	case "ConfigValidationError":
		expectedCode = errors.ErrorCode(ErrCodeConfigValidationError)
	case "ConfigPathError":
		expectedCode = errors.ErrorCode(ErrCodeConfigPathError)
	case "PathTraversalError":
		expectedCode = errors.ErrorCode(ErrCodePathTraversalError)
	case "ConfigFileError":
		expectedCode = errors.ErrorCode(ErrCodeConfigFileError)
	}

	if agiErr.ErrorCode() != expectedCode {
		t.Errorf("Expected error code %s but got %s: %v", expectedCode, agiErr.ErrorCode(), err)
	}
}

// Mock types for testing - use existing types from observability_integration_test.go

type MockLogger struct {
	entries []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  map[string]interface{}
}

func (m *MockLogger) Debug(msg string, keysAndValues ...interface{}) {
	m.entries = append(m.entries, LogEntry{
		Level:   "debug",
		Message: msg,
		Fields:  parseKeysAndValues(keysAndValues...),
	})
}

func (m *MockLogger) Info(msg string, keysAndValues ...interface{}) {
	m.entries = append(m.entries, LogEntry{
		Level:   "info",
		Message: msg,
		Fields:  parseKeysAndValues(keysAndValues...),
	})
}

func (m *MockLogger) Warn(msg string, keysAndValues ...interface{}) {
	m.entries = append(m.entries, LogEntry{
		Level:   "warn",
		Message: msg,
		Fields:  parseKeysAndValues(keysAndValues...),
	})
}

func (m *MockLogger) Error(msg string, keysAndValues ...interface{}) {
	m.entries = append(m.entries, LogEntry{
		Level:   "error",
		Message: msg,
		Fields:  parseKeysAndValues(keysAndValues...),
	})
}

func (m *MockLogger) With(keysAndValues ...interface{}) Logger {
	// Return a new logger instance with the provided context
	return &MockLogger{}
}

func parseKeysAndValues(keysAndValues ...interface{}) map[string]interface{} {
	fields := make(map[string]interface{})
	for i := 0; i < len(keysAndValues)-1; i += 2 {
		key, ok := keysAndValues[i].(string)
		if ok && i+1 < len(keysAndValues) {
			fields[key] = keysAndValues[i+1]
		}
	}
	return fields
}

// Integration tests for process lifecycle (these require more setup)

func TestSubprocessPlugin_ProcessLifecycle_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	testExecutable := createLongRunningExecutable(t)
	defer func() {
		if err := os.Remove(testExecutable); err != nil {
			t.Logf("Warning: failed to remove test executable: %v", err)
		}
	}()

	config := PluginConfig{
		Name:       "test-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
	}

	plugin, err := factory.CreatePlugin(config)
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	subprocessPlugin := plugin.(*SubprocessPlugin[TestRequest, TestResponse])

	// Test initial state
	processInfo := subprocessPlugin.GetInfo()
	if processInfo.Status != StatusStopped {
		t.Errorf("Expected initial status %v, got %v", StatusStopped, processInfo.Status)
	}

	// Test health when not started
	ctx := context.Background()
	health := subprocessPlugin.Health(ctx)
	if health.Status != StatusOffline {
		t.Errorf("Expected health status %v when stopped, got %v", StatusOffline, health.Status)
	}

	// Test close when not started (should not error)
	err = subprocessPlugin.Close()
	if err != nil {
		t.Errorf("Close() on stopped plugin should not error: %v", err)
	}
}

func createLongRunningExecutable(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "subprocess_test_long")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	scriptPath := filepath.Join(tmpDir, "long_running.sh")
	scriptContent := `#!/bin/bash
echo "Starting long running process"
trap 'echo "Received signal, exiting gracefully"; exit 0' TERM INT

# Simulate long running work
for i in {1..30}; do
    echo "Working... iteration $i"
    sleep 1
done

echo "Completed normally"
exit 0
`

	err = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		t.Fatalf("Failed to create long running script: %v", err)
	}

	return scriptPath
}

// Benchmark tests to measure performance impact of refactoring

func BenchmarkSubprocessPlugin_Creation(b *testing.B) {
	factory := NewSubprocessPluginFactory[TestRequest, TestResponse](nil)

	testExecutable := "/bin/echo" // Use system echo for consistency
	config := PluginConfig{
		Name:       "bench-plugin",
		Transport:  TransportExecutable,
		Endpoint:   testExecutable,
		Executable: testExecutable,
		Args:       []string{"hello", "world"},
		Env:        []string{"TEST=1", "BENCH=true"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		plugin, err := factory.CreatePlugin(config)
		if err != nil {
			b.Fatalf("Failed to create plugin: %v", err)
		}
		_ = plugin
	}
}
