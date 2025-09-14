// config_loader_unit_test.go: Unit tests for config loader utility functions
//
// This file contains focused unit tests for individual config loader functions
// that don't require the full manager setup or plugin factories.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestConfigLoader_PathValidation_Unit tests path validation functions in isolation.
// PathValidationTestCase represents a test case for path validation
type PathValidationTestCase struct {
	name          string
	path          string
	expectError   bool
	errorContains string
	osSpecific    string // "windows", "unix", or "all"
}

// Helper function to setup path validation test environment
func setupPathValidationTest(t *testing.T) (*TestAssertions, *TestEnvironment, *ConfigWatcher[TestRequest, TestResponse]) {
	assert := NewTestAssertions(t)
	env := NewTestEnvironment(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	manager := NewManager[TestRequest, TestResponse](logger)

	configPath := env.CreateTempFile("dummy-config.json", `{"plugins": []}`)
	watcher, err := NewConfigWatcher(manager, configPath, DefaultDynamicConfigOptions(), logger)
	assert.AssertNoError(err, "create config watcher")

	return assert, env, watcher
}

// Helper function to get base test cases for path validation
func getBasePathValidationTestCases() []PathValidationTestCase {
	return []PathValidationTestCase{
		{
			name:        "ValidRelativePath",
			path:        "config.json",
			expectError: false,
			osSpecific:  "all",
		},
		{
			name:          "PathTraversalAttack_DoubleDot",
			path:          "../../../etc/passwd",
			expectError:   true,
			errorContains: "path traversal detected",
			osSpecific:    "all",
		},
		{
			name:          "PathTraversalAttack_Encoded",
			path:          "config%2e%2e/secret.json",
			expectError:   true,
			errorContains: "encoded path traversal",
			osSpecific:    "all",
		},
		{
			name:          "EmptyPath",
			path:          "",
			expectError:   true,
			errorContains: "empty file path",
			osSpecific:    "all",
		},
		{
			name:          "NullByteInjection",
			path:          "config.json\x00/../../etc",
			expectError:   true,
			errorContains: "null byte detected",
			osSpecific:    "all",
		},
	}
}

// Helper function to get Windows-specific test cases
func getWindowsPathValidationTestCases() []PathValidationTestCase {
	if runtime.GOOS != "windows" {
		return nil
	}

	windowsTests := []struct {
		name          string
		path          string
		expectError   bool
		errorContains string
	}{
		{
			name:          "WindowsReservedName_CON",
			path:          "CON.json",
			expectError:   true,
			errorContains: "reserved Windows filename",
		},
		{
			name:          "WindowsReservedName_PRN",
			path:          "PRN.txt",
			expectError:   true,
			errorContains: "reserved Windows filename",
		},
		{
			name:          "WindowsInvalidChar_Pipe",
			path:          "config|invalid.json",
			expectError:   true,
			errorContains: "invalid Windows path character",
		},
		{
			name:          "WindowsInvalidChar_QuestionMark",
			path:          "config?.json",
			expectError:   true,
			errorContains: "invalid Windows path character",
		},
	}

	var testCases []PathValidationTestCase
	for _, winTest := range windowsTests {
		testCases = append(testCases, PathValidationTestCase{
			name:          winTest.name,
			path:          winTest.path,
			expectError:   winTest.expectError,
			errorContains: winTest.errorContains,
			osSpecific:    "windows",
		})
	}
	return testCases
}

// Helper function to run individual path validation test
func runPathValidationTest(t *testing.T, assert *TestAssertions, watcher *ConfigWatcher[TestRequest, TestResponse], tc PathValidationTestCase) {
	// Skip OS-specific tests if not on the right OS
	if tc.osSpecific == "windows" && runtime.GOOS != "windows" {
		return
	}
	if tc.osSpecific == "unix" && runtime.GOOS == "windows" {
		return
	}

	t.Run(tc.name, func(t *testing.T) {
		// Test path validation without requiring the file to exist
		err := watcher.validatePathTraversal(tc.path, filepath.Clean(tc.path))

		if !tc.expectError {
			// For valid paths, we may get other errors (file not found), but not traversal errors
			if err != nil && (strings.Contains(err.Error(), "traversal") ||
				strings.Contains(err.Error(), "encoded") ||
				strings.Contains(err.Error(), "empty")) {
				t.Errorf("Unexpected path traversal error for %s: %v", tc.name, err)
			}
		} else {
			validatePathValidationError(assert, watcher, tc, err)
		}
	})
}

// Helper function to validate path validation errors
func validatePathValidationError(assert *TestAssertions, watcher *ConfigWatcher[TestRequest, TestResponse], tc PathValidationTestCase, err error) {
	// For invalid paths, test OS-specific validation
	if strings.Contains(tc.errorContains, "Windows") && runtime.GOOS == "windows" {
		osErr := watcher.validateOSSpecificPath(tc.path)
		assert.AssertError(osErr, tc.name+" OS validation")
		assert.AssertTrue(strings.Contains(osErr.Error(), tc.errorContains),
			"error should contain: "+tc.errorContains)
	} else if strings.Contains(tc.errorContains, "traversal") ||
		strings.Contains(tc.errorContains, "encoded") ||
		strings.Contains(tc.errorContains, "empty") {
		// Test traversal validation
		if strings.Contains(tc.errorContains, "empty") {
			// Empty path test
			_, emptyErr := watcher.validateAndSecureFilePath(tc.path)
			assert.AssertError(emptyErr, tc.name)
			assert.AssertTrue(strings.Contains(emptyErr.Error(), tc.errorContains),
				"error should contain: "+tc.errorContains)
		} else {
			assert.AssertError(err, tc.name)
			assert.AssertTrue(strings.Contains(err.Error(), tc.errorContains),
				"error should contain: "+tc.errorContains)
		}
	}
}

func TestConfigLoader_PathValidation_Unit(t *testing.T) {
	assert, env, watcher := setupPathValidationTest(t)
	defer env.Cleanup()

	// Get all test cases
	testCases := getBasePathValidationTestCases()
	testCases = append(testCases, getWindowsPathValidationTestCases()...)

	// Run all test cases
	for _, tc := range testCases {
		runPathValidationTest(t, assert, watcher, tc)
	}
}

// TestConfigLoader_FileOperations_Unit tests file operations with real files.
func TestConfigLoader_FileOperations_Unit(t *testing.T) {
	assert := NewTestAssertions(t)
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create platform-appropriate test directories
	var testDir string
	if runtime.GOOS == "windows" {
		testDir = filepath.Join(os.TempDir(), "go-plugins-test-windows")
	} else {
		testDir = filepath.Join("/tmp", "go-plugins-test-unix")
	}

	err := os.MkdirAll(testDir, 0755)
	assert.AssertNoError(err, "create test directory")
	defer func() {
		if removeErr := os.RemoveAll(testDir); removeErr != nil {
			t.Errorf("Failed to cleanup test directory: %v", removeErr)
		}
	}()

	// Test configuration content
	testConfig := ManagerConfig{
		LogLevel: "info",
		Plugins:  []PluginConfig{}, // Empty plugins to avoid factory issues
	}

	t.Run("CreateSampleConfig_CrossPlatform", func(t *testing.T) {
		configPath := filepath.Join(testDir, "sample-config.json")

		err := CreateSampleConfig(configPath)
		assert.AssertNoError(err, "create sample config")

		// Verify file was created
		info, err := os.Stat(configPath)
		assert.AssertNoError(err, "stat created config file")
		assert.AssertTrue(info.Size() > 0, "config file should not be empty")

		// Verify file is readable
		content, err := os.ReadFile(configPath)
		assert.AssertNoError(err, "read created config file")

		// Verify content is valid JSON
		var config ManagerConfig
		err = json.Unmarshal(content, &config)
		assert.AssertNoError(err, "parse created config JSON")

		// Check OS-specific file permissions
		if runtime.GOOS != "windows" {
			// On Unix systems, check that file has restrictive permissions
			mode := info.Mode()
			assert.AssertEqual(os.FileMode(0600), mode&0777, "Unix file permissions")
		}
	})

	t.Run("WriteConfigFileSecurely_CrossPlatform", func(t *testing.T) {
		configBytes, err := json.MarshalIndent(testConfig, "", "  ")
		assert.AssertNoError(err, "marshal test config")

		configPath := filepath.Join(testDir, "secure-config.json")
		err = writeConfigFileSecurely(configPath, configBytes)
		assert.AssertNoError(err, "write config file securely")

		// Verify file content
		readBytes, err := os.ReadFile(configPath)
		assert.AssertNoError(err, "read secure config file")
		assert.AssertEqual(string(configBytes), string(readBytes), "file content matches")
	})

	t.Run("ReadConfigFileSecurely_CrossPlatform", func(t *testing.T) {
		// Create a test config file
		configBytes, err := json.MarshalIndent(testConfig, "", "  ")
		assert.AssertNoError(err, "marshal test config")

		configPath := filepath.Join(testDir, "read-test-config.json")
		err = os.WriteFile(configPath, configBytes, 0644)
		assert.AssertNoError(err, "write test config file")

		// Test reading with config watcher
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
		manager := NewManager[TestRequest, TestResponse](logger)
		watcher, err := NewConfigWatcher(manager, configPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "create config watcher")

		content, err := watcher.readConfigFileSecurely(configPath)
		assert.AssertNoError(err, "read config file securely")
		assert.AssertEqual(string(configBytes), string(content), "read content matches")
	})

	t.Run("LoadConfigFromFile_Unit", func(t *testing.T) {
		// Create a valid config file with at least one plugin
		validConfig := ManagerConfig{
			LogLevel: "debug",
			Plugins: []PluginConfig{
				{
					Name:      "test-plugin",
					Type:      "test", // Use test type to avoid factory issues
					Transport: TransportHTTP,
					Endpoint:  "http://localhost:8080",
					Auth:      AuthConfig{Method: AuthNone},
				},
			},
		}
		configBytes, err := json.MarshalIndent(validConfig, "", "  ")
		assert.AssertNoError(err, "marshal valid config")

		configPath := filepath.Join(testDir, "load-test-config.json")
		err = os.WriteFile(configPath, configBytes, 0644)
		assert.AssertNoError(err, "write valid config file")

		// Test loading
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
		manager := NewManager[TestRequest, TestResponse](logger)
		watcher, err := NewConfigWatcher(manager, configPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "create config watcher")

		// Test only secure reading and JSON parsing, not full validation
		content, err := watcher.readConfigFileSecurely(configPath)
		assert.AssertNoError(err, "read config file securely")

		// Test JSON parsing
		var parsedConfig ManagerConfig
		err = json.Unmarshal(content, &parsedConfig)
		assert.AssertNoError(err, "parse JSON config")
		assert.AssertEqual("debug", parsedConfig.LogLevel, "config log level parsed")
		assert.AssertEqual(1, len(parsedConfig.Plugins), "plugin count parsed")
	})
}

// TestConfigLoader_ErrorHandling_Unit tests error handling without manager dependencies.
func TestConfigLoader_ErrorHandling_Unit(t *testing.T) {
	assert := NewTestAssertions(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	manager := NewManager[TestRequest, TestResponse](logger)

	// Create temp directory manually to avoid TestEnvironment deadlock
	tempDir, err := os.MkdirTemp("", "go-plugins-unit-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			t.Errorf("Failed to cleanup unit test temp dir: %v", removeErr)
		}
	}()

	t.Run("DirectoryInsteadOfFile", func(t *testing.T) {
		dirPath := filepath.Join(tempDir, "config-directory")
		err := os.MkdirAll(dirPath, 0755)
		assert.AssertNoError(err, "create directory")

		watcher, err := NewConfigWatcher(manager, dirPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher with directory path should succeed")

		// Test file access validation
		err = watcher.validateFileAccess(dirPath)
		assert.AssertError(err, "directory should fail file access validation")
		assert.AssertTrue(strings.Contains(err.Error(), "not a regular file"),
			"error should mention it's not a regular file")
	})

	t.Run("PermissionDeniedFile", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Permission tests are complex on Windows, skipping")
			return
		}

		// Create a file with no read permissions
		restrictedPath := filepath.Join(tempDir, "restricted-config.json")
		err := os.WriteFile(restrictedPath, []byte(`{"plugins": []}`), 0200) // Write-only
		assert.AssertNoError(err, "create restricted file")

		watcher, err := NewConfigWatcher(manager, restrictedPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher should succeed")

		// Test file access validation
		err = watcher.validateFileAccess(restrictedPath)
		assert.AssertError(err, "restricted file should fail access validation")
	})

	t.Run("MalformedJSONFile", func(t *testing.T) {
		malformedPath := filepath.Join(tempDir, "malformed-config.json")
		err := os.WriteFile(malformedPath, []byte(`{"plugins": [{"name": "test", "missing_closing_brace": true`), 0644)
		assert.AssertNoError(err, "create malformed config file")

		watcher, err := NewConfigWatcher(manager, malformedPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher should succeed")

		_, err = watcher.loadConfigFromFile(malformedPath)
		assert.AssertError(err, "loading malformed JSON should fail")
		assert.AssertTrue(strings.Contains(err.Error(), "unmarshal"),
			"error should mention JSON unmarshaling")
	})

	t.Run("EmptyConfigFile", func(t *testing.T) {
		emptyPath := filepath.Join(tempDir, "empty-config.json")
		err := os.WriteFile(emptyPath, []byte(""), 0644)
		assert.AssertNoError(err, "create empty config file")

		watcher, err := NewConfigWatcher(manager, emptyPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher should succeed")

		_, err = watcher.readConfigFileSecurely(emptyPath)
		assert.AssertError(err, "reading empty file should fail")
		assert.AssertTrue(strings.Contains(err.Error(), "empty"),
			"error should mention empty file")
	})
}

// benchmarkConfigLoadOperation benchmarks config loading operations
func benchmarkConfigLoadOperation(t *testing.T, watcher *ConfigWatcher[TestRequest, TestResponse], configPath string) {
	iterations := 100
	start := time.Now()

	for i := 0; i < iterations; i++ {
		// Test only file reading and JSON parsing for performance
		content, err := watcher.readConfigFileSecurely(configPath)
		if err != nil {
			t.Fatal(err)
		}

		var config ManagerConfig
		err = json.Unmarshal(content, &config)
		if err != nil {
			t.Fatal(err)
		}
	}

	duration := time.Since(start)
	avgDuration := duration / time.Duration(iterations)
	t.Logf("Average config load time: %v", avgDuration)

	// Assert reasonable performance (should be under 5ms for empty config)
	if avgDuration > 5*time.Millisecond {
		t.Errorf("Config loading too slow: %v (expected < 5ms)", avgDuration)
	}
}

// benchmarkPathValidationOperation benchmarks path validation operations
func benchmarkPathValidationOperation(t *testing.T, watcher *ConfigWatcher[TestRequest, TestResponse]) {
	testPaths := []string{
		"config.json",
		"./relative/path.json",
		"subdir/config.json",
	}

	iterations := 1000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		for _, path := range testPaths {
			// Test only the OS-specific validation to avoid file system calls
			err := watcher.validateOSSpecificPath(path)
			if err != nil {
				// Log but continue - this is a performance test
				t.Logf("OS path validation failed for %s: %v", path, err)
			}
		}
	}

	duration := time.Since(start)
	totalValidations := iterations * len(testPaths)
	avgDuration := duration / time.Duration(totalValidations)
	t.Logf("Average path validation time: %v", avgDuration)

	// Assert reasonable performance (should be under 10µs per validation)
	if avgDuration > 10*time.Microsecond {
		t.Errorf("Path validation too slow: %v (expected < 10µs)", avgDuration)
	}
}

// TestConfigLoader_Performance_Unit provides performance tests for individual functions.
func TestConfigLoader_Performance_Unit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create a reasonably sized config for benchmarking
	config := ManagerConfig{
		LogLevel: "info",
		Plugins:  []PluginConfig{}, // Empty to avoid factory dependencies
	}

	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	configPath := env.CreateTempFileWithContent("benchmark-config.json", string(configBytes))

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewManager[TestRequest, TestResponse](logger)
	watcher, err := NewConfigWatcher(manager, configPath, DefaultDynamicConfigOptions(), logger)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("BenchmarkConfigLoad", func(t *testing.T) {
		benchmarkConfigLoadOperation(t, watcher, configPath)
	})

	t.Run("BenchmarkPathValidation", func(t *testing.T) {
		benchmarkPathValidationOperation(t, watcher)
	})
}
