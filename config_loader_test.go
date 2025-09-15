// config_loader_test.go: Comprehensive cross-platform tests for dynamic configuration loading
//
// This test suite provides extensive coverage for the configuration loader system,
// including cross-platform compatibility, security validation, file watching,
// and error handling scenarios.
//
// Test categories:
//   - Cross-platform path handling and validation
//   - File system operations (Windows, Linux, macOS)
//   - Security validation (path traversal, permission checks)
//   - Argus file watcher integration
//   - Configuration parsing and validation
//   - Concurrent access and race condition handling
//   - Error scenarios and recovery mechanisms
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConfigLoader_CrossPlatform_PathValidation tests path validation across platforms.
// setupCrossPlatformPathValidationTest sets up the test environment for cross-platform path validation
func setupCrossPlatformPathValidationTest(t *testing.T, assert *TestAssertions) (*ConfigWatcher[TestRequest, TestResponse], func()) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	manager := NewManager[TestRequest, TestResponse](logger)
	watcher, err := NewConfigWatcher(manager, "dummy-path.json", DefaultDynamicConfigOptions(), logger)
	assert.AssertNoError(err, "create config watcher for path validation tests")

	// Create temporary test file for valid path tests
	tempDir, err := os.MkdirTemp("", "go-plugins-path-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Use cross-platform temp file instead of hardcoded /tmp path
	crossPlatformTestFile := filepath.Join(tempDir, "test-config-path-validation.json")
	err = os.WriteFile(crossPlatformTestFile, []byte(`{"plugins":[]}`), 0644)
	assert.AssertNoError(err, "create cross-platform test file")

	relativeTestFile := "config-path-validation.json"
	err = os.WriteFile(relativeTestFile, []byte(`{"plugins":[]}`), 0644)
	assert.AssertNoError(err, "create relative test file")

	cleanup := func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			t.Errorf("Failed to cleanup temp dir: %v", removeErr)
		}
		// crossPlatformTestFile is already inside tempDir, so RemoveAll will handle it
		if removeErr := os.Remove(relativeTestFile); removeErr != nil {
			t.Errorf("Failed to cleanup relative test file: %v", removeErr)
		}
	}

	return watcher, cleanup
}

// CrossPlatformPathValidationTestCase represents a test case for cross-platform path validation
type CrossPlatformPathValidationTestCase struct {
	name          string
	path          string
	expectError   bool
	errorContains string
	osSpecific    string
}

// getCrossPlatformPathValidationTestCases returns the basic test cases for cross-platform path validation
func getCrossPlatformPathValidationTestCases() []CrossPlatformPathValidationTestCase {
	return []CrossPlatformPathValidationTestCase{
		// Note: ValidAbsolutePath test will be generated dynamically in the test function
		{
			name:        "ValidRelativePath",
			path:        "config-path-validation.json",
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

// addWindowsSpecificTestCases adds Windows-specific test cases if running on Windows
func addWindowsSpecificTestCases(testCases []CrossPlatformPathValidationTestCase) []CrossPlatformPathValidationTestCase {
	if runtime.GOOS != "windows" {
		return testCases
	}

	windowsTests := []struct {
		name          string
		path          string
		expectError   bool
		errorContains string
	}{
		// Note: ValidWindowsAbsolutePath test will be added dynamically with a real temp file
		// Note: UNC path tests are skipped as they require specific network environment
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

	for _, winTest := range windowsTests {
		testCases = append(testCases, CrossPlatformPathValidationTestCase{
			name:          winTest.name,
			path:          winTest.path,
			expectError:   winTest.expectError,
			errorContains: winTest.errorContains,
			osSpecific:    "windows",
		})
	}

	return testCases
}

// runPathValidationTests runs the path validation test cases
func runPathValidationTests(t *testing.T, assert *TestAssertions, watcher *ConfigWatcher[TestRequest, TestResponse], testCases []CrossPlatformPathValidationTestCase) {
	for _, tc := range testCases {
		// Skip OS-specific tests if not on the right OS
		if tc.osSpecific == "windows" && runtime.GOOS != "windows" {
			continue
		}
		if tc.osSpecific == "unix" && runtime.GOOS == "windows" {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			_, err := watcher.validateAndSecureFilePath(tc.path)

			if tc.expectError {
				assert.AssertError(err, tc.name)
				if tc.errorContains != "" {
					assert.AssertTrue(strings.Contains(err.Error(), tc.errorContains),
						"error should contain: "+tc.errorContains)
				}
			} else {
				assert.AssertNoError(err, tc.name)
			}
		})
	}
}

func TestConfigLoader_CrossPlatform_PathValidation(t *testing.T) {
	assert := NewTestAssertions(t)
	watcher, cleanup := setupCrossPlatformPathValidationTest(t, assert)
	defer cleanup()

	// Create a cross-platform temp file path for testing
	tempDir, err := os.MkdirTemp("", "go-plugins-path-test-validation")
	if err != nil {
		t.Fatalf("Failed to create temp dir for validation test: %v", err)
	}
	defer os.RemoveAll(tempDir)

	crossPlatformTestFile := filepath.Join(tempDir, "test-config-cross-platform.json")
	err = os.WriteFile(crossPlatformTestFile, []byte(`{"plugins":[]}`), 0644)
	assert.AssertNoError(err, "create cross-platform test file for validation")

	testCases := getCrossPlatformPathValidationTestCases()

	// Add the dynamic cross-platform test case
	testCases = append(testCases, CrossPlatformPathValidationTestCase{
		name:        "ValidAbsolutePath_CrossPlatform",
		path:        crossPlatformTestFile,
		expectError: false,
		osSpecific:  "all",
	})

	// Add Windows-specific test case with a real temp file if running on Windows
	if runtime.GOOS == "windows" {
		windowsTempFile := filepath.Join(tempDir, "windows-test-config.json")
		err := os.WriteFile(windowsTempFile, []byte(`{"plugins":[]}`), 0644)
		if err == nil {
			testCases = append(testCases, CrossPlatformPathValidationTestCase{
				name:        "ValidWindowsAbsolutePath",
				path:        windowsTempFile,
				expectError: false,
				osSpecific:  "windows",
			})
		}
	}

	testCases = addWindowsSpecificTestCases(testCases)
	runPathValidationTests(t, assert, watcher, testCases)
}

// TestConfigLoader_FileOperations_CrossPlatform tests file operations across platforms.
func TestConfigLoader_FileOperations_CrossPlatform(t *testing.T) {
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
		Plugins: []PluginConfig{
			{
				Name:      "test-plugin",
				Type:      "test",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8080",
				Auth:      AuthConfig{Method: AuthNone},
			},
		},
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
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		manager := NewManager[TestRequest, TestResponse](logger)
		watcher, err := NewConfigWatcher(manager, configPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "create config watcher")

		content, err := watcher.readConfigFileSecurely(configPath)
		assert.AssertNoError(err, "read config file securely")
		assert.AssertEqual(string(configBytes), string(content), "read content matches")
	})

	t.Run("HandleLargeConfigFile", func(t *testing.T) {
		// Create a config file that's too large (over 10MB limit)
		largeConfigPath := filepath.Join(testDir, "large-config.json")

		// Create a large but valid JSON file
		largeConfig := ManagerConfig{
			LogLevel: "info",
			Plugins:  make([]PluginConfig, 0),
		}

		// Add many plugins to make it large
		for i := 0; i < 50000; i++ {
			plugin := PluginConfig{
				Name:      fmt.Sprintf("plugin-%d", i),
				Type:      "test",
				Transport: TransportHTTP,
				Endpoint:  fmt.Sprintf("http://localhost:%d", 8080+i),
				Auth:      AuthConfig{Method: AuthNone},
			}
			largeConfig.Plugins = append(largeConfig.Plugins, plugin)
		}

		configBytes, err := json.Marshal(largeConfig)
		assert.AssertNoError(err, "marshal large config")

		err = os.WriteFile(largeConfigPath, configBytes, 0644)
		assert.AssertNoError(err, "write large config file")

		// Test that reading large file fails appropriately
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		manager := NewManager[TestRequest, TestResponse](logger)
		watcher, err := NewConfigWatcher(manager, largeConfigPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "create config watcher")

		_, err = watcher.readConfigFileSecurely(largeConfigPath)
		if len(configBytes) > 10*1024*1024 {
			assert.AssertError(err, "large file should be rejected")
			assert.AssertTrue(strings.Contains(err.Error(), "size exceeds limit"),
				"error should mention size limit")
		}
	})
}

// TestConfigLoader_ArgusIntegration tests integration with Argus file watcher.
func TestConfigLoader_ArgusIntegration(t *testing.T) {
	assert := NewTestAssertions(t)
	env := NewTestEnvironment(t)
	defer env.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create initial config file
	initialConfig := ManagerConfig{
		LogLevel: "info",
		Plugins: []PluginConfig{
			TestData.CreateValidPluginConfig("initial-plugin"),
		},
	}

	configBytes, err := json.MarshalIndent(initialConfig, "", "  ")
	assert.AssertNoError(err, "marshal initial config")

	configPath := env.CreateTempFileWithContent("argus-test-config.json", string(configBytes))

	// Use shorter intervals for testing
	options := DefaultDynamicConfigOptions()
	options.PollInterval = 100 * time.Millisecond
	options.CacheTTL = 50 * time.Millisecond

	t.Run("StartAndStopWatcher", func(t *testing.T) {
		// Create separate manager and watcher instance for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		// Register mock factory for test plugins
		mockFactory := &MockPluginFactory[TestRequest, TestResponse]{
			createFunc: func(config PluginConfig) (Plugin[TestRequest, TestResponse], error) {
				return NewAdvancedMockPlugin[TestRequest, TestResponse](config.Name), nil
			},
		}
		err := manager.RegisterFactory("test", mockFactory)
		assert.AssertNoError(err, "register mock factory")

		watcher, err := NewConfigWatcher(manager, configPath, options, logger)
		assert.AssertNoError(err, "create config watcher")

		ctx := context.Background()

		// Start watcher
		err = watcher.Start(ctx)
		assert.AssertNoError(err, "start watcher")
		assert.AssertTrue(watcher.IsRunning(), "watcher should be running")

		// Verify initial config was loaded
		currentConfig := watcher.GetCurrentConfig()
		assert.AssertNotNil(currentConfig, "current config should not be nil")
		assert.AssertEqual(1, len(currentConfig.Plugins), "should have 1 plugin")
		assert.AssertEqual("initial-plugin", currentConfig.Plugins[0].Name, "plugin name")

		// Stop watcher
		err = watcher.Stop()
		assert.AssertNoError(err, "stop watcher")
		assert.AssertFalse(watcher.IsRunning(), "watcher should not be running")
	})

	t.Run("ConfigFileChange_Detection", func(t *testing.T) {
		// Create separate manager and watcher instance for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		// Register mock factory for test plugins
		mockFactory := &MockPluginFactory[TestRequest, TestResponse]{
			createFunc: func(config PluginConfig) (Plugin[TestRequest, TestResponse], error) {
				return NewAdvancedMockPlugin[TestRequest, TestResponse](config.Name), nil
			},
		}
		err := manager.RegisterFactory("test", mockFactory)
		assert.AssertNoError(err, "register mock factory")

		watcher, err := NewConfigWatcher(manager, configPath, options, logger)
		assert.AssertNoError(err, "create config watcher")

		ctx := context.Background()

		// Start watcher
		err = watcher.Start(ctx)
		assert.AssertNoError(err, "start watcher")
		defer func() {
			if stopErr := watcher.Stop(); stopErr != nil {
				t.Errorf("Failed to stop watcher: %v", stopErr)
			}
		}()

		// Wait for initial load
		time.Sleep(200 * time.Millisecond)

		// Modify config file
		updatedConfig := initialConfig
		updatedConfig.Plugins = append(updatedConfig.Plugins, TestData.CreateValidPluginConfig("new-plugin"))

		updatedBytes, err := json.MarshalIndent(updatedConfig, "", "  ")
		assert.AssertNoError(err, "marshal updated config")

		err = os.WriteFile(configPath, updatedBytes, 0644)
		assert.AssertNoError(err, "write updated config")

		// Wait for change detection and processing
		time.Sleep(500 * time.Millisecond)

		// Verify config was updated
		currentConfig := watcher.GetCurrentConfig()
		assert.AssertNotNil(currentConfig, "current config should not be nil")
		assert.AssertEqual(2, len(currentConfig.Plugins), "should have 2 plugins after update")
	})

	t.Run("InvalidConfigFile_Handling", func(t *testing.T) {
		// Create separate manager and watcher instance for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		// Register mock factory for test plugins
		mockFactory := &MockPluginFactory[TestRequest, TestResponse]{
			createFunc: func(config PluginConfig) (Plugin[TestRequest, TestResponse], error) {
				return NewAdvancedMockPlugin[TestRequest, TestResponse](config.Name), nil
			},
		}
		err := manager.RegisterFactory("test", mockFactory)
		assert.AssertNoError(err, "register mock factory")

		watcher, err := NewConfigWatcher(manager, configPath, options, logger)
		assert.AssertNoError(err, "create config watcher")

		ctx := context.Background()

		// Start watcher
		err = watcher.Start(ctx)
		assert.AssertNoError(err, "start watcher")
		defer func() {
			if stopErr := watcher.Stop(); stopErr != nil {
				t.Errorf("Failed to stop watcher: %v", stopErr)
			}
		}()

		// Get current valid config
		originalConfig := watcher.GetCurrentConfig()

		// Write invalid JSON to config file
		err = os.WriteFile(configPath, []byte(`{"invalid": json}`), 0644)
		assert.AssertNoError(err, "write invalid config")

		// Wait for change detection
		time.Sleep(300 * time.Millisecond)

		// Verify original config is still active (rollback behavior)
		if watcher.options.RollbackOnFailure {
			currentConfig := watcher.GetCurrentConfig()
			assert.AssertNotNil(currentConfig, "config should not be nil after invalid update")
			// Config should remain the same due to rollback
			assert.AssertEqual(len(originalConfig.Plugins), len(currentConfig.Plugins),
				"plugin count should remain same after failed update")
		}
	})
}

// TestConfigLoader_ConcurrentAccess tests concurrent configuration access scenarios.
// Helper function to setup concurrent access test environment
func setupConcurrentAccessTest(t *testing.T) (*TestAssertions, *TestEnvironment, ManagerConfig, string, *slog.Logger, DynamicConfigOptions) {
	assert := NewTestAssertions(t)
	env := NewTestEnvironment(t)

	// Create initial config
	initialConfig := ManagerConfig{
		LogLevel: "info",
		Plugins: []PluginConfig{
			TestData.CreateValidPluginConfig("concurrent-test-plugin"),
		},
	}

	configBytes, err := json.MarshalIndent(initialConfig, "", "  ")
	assert.AssertNoError(err, "marshal initial config")

	configPath := env.CreateTempFileWithContent("concurrent-test-config.json", string(configBytes))
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	options := DefaultDynamicConfigOptions()
	options.PollInterval = 50 * time.Millisecond

	return assert, env, initialConfig, configPath, logger, options
}

// Helper function to create and setup manager with mock factory
func createTestManagerWithMockFactory(assert *TestAssertions, logger *slog.Logger) *Manager[TestRequest, TestResponse] {
	manager := NewManager[TestRequest, TestResponse](logger)

	mockFactory := &MockPluginFactory[TestRequest, TestResponse]{
		createFunc: func(config PluginConfig) (Plugin[TestRequest, TestResponse], error) {
			return NewAdvancedMockPlugin[TestRequest, TestResponse](config.Name), nil
		},
	}
	err := manager.RegisterFactory("test", mockFactory)
	assert.AssertNoError(err, "register mock factory")

	return manager
}

// setupConcurrentWatcher creates and returns a config watcher for concurrent testing
func setupConcurrentWatcher(assert *TestAssertions, configPath string, options DynamicConfigOptions, logger *slog.Logger) *ConfigWatcher[TestRequest, TestResponse] {
	manager := createTestManagerWithMockFactory(assert, logger)
	watcher, err := NewConfigWatcher(manager, configPath, options, logger)
	assert.AssertNoError(err, "create config watcher")
	return watcher
}

// runConcurrentStartOperations runs multiple start operations concurrently
func runConcurrentStartOperations(watcher *ConfigWatcher[TestRequest, TestResponse], numGoroutines int, errors chan error) {
	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			time.Sleep(time.Duration(id*10) * time.Millisecond) // Stagger operations
			if err := watcher.Start(ctx); err != nil && !strings.Contains(err.Error(), "already running") {
				errors <- fmt.Errorf("start error: %w", err)
			}
		}(i)
	}

	wg.Wait()
}

// runConcurrentStopOperations runs multiple stop operations concurrently
func runConcurrentStopOperations(watcher *ConfigWatcher[TestRequest, TestResponse], numGoroutines int, errors chan error) {
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			time.Sleep(time.Duration(id*10) * time.Millisecond) // Stagger operations
			if err := watcher.Stop(); err != nil &&
				!strings.Contains(err.Error(), "not running") &&
				!strings.Contains(err.Error(), "already stopped") {
				errors <- fmt.Errorf("stop error: %w", err)
			}
		}(i)
	}

	wg.Wait()
}

// validateConcurrentErrors checks for unexpected errors in concurrent operations
func validateConcurrentErrors(t *testing.T, errors chan error, numGoroutines int) {
	var errorCount int
	for err := range errors {
		if err != nil {
			t.Logf("Concurrent operation error: %v", err)
			errorCount++
		}
	}

	// Some errors are expected due to race conditions, but not too many
	if errorCount > numGoroutines {
		t.Errorf("Too many errors in concurrent operations: %d", errorCount)
	}
}

// Helper function to run concurrent start/stop test
func runConcurrentStartStopTest(t *testing.T, assert *TestAssertions, configPath string, options DynamicConfigOptions, logger *slog.Logger) {
	watcher := setupConcurrentWatcher(assert, configPath, options, logger)

	defer func() {
		if stopErr := watcher.Stop(); stopErr != nil &&
			!strings.Contains(stopErr.Error(), "already stopped") &&
			!strings.Contains(stopErr.Error(), "not running") {
			t.Errorf("Failed to stop watcher during cleanup: %v", stopErr)
		}
	}() // Ensure cleanup

	const numGoroutines = 5 // Reduced to avoid excessive contention
	errors := make(chan error, numGoroutines*2)

	// Test concurrent start operations - only one should succeed
	runConcurrentStartOperations(watcher, numGoroutines, errors)

	// Wait a bit then test concurrent stop operations
	time.Sleep(100 * time.Millisecond)
	runConcurrentStopOperations(watcher, numGoroutines, errors)

	close(errors)
	validateConcurrentErrors(t, errors, numGoroutines)

	// Ensure watcher is in a consistent state
	if err := watcher.Stop(); err != nil {
		t.Logf("Warning: failed to stop watcher: %v", err)
	}
}

// Helper function to run concurrent config reads test
func runConcurrentConfigReadsTest(t *testing.T, assert *TestAssertions, configPath string, options DynamicConfigOptions, logger *slog.Logger) {
	manager := createTestManagerWithMockFactory(assert, logger)

	watcher, err := NewConfigWatcher(manager, configPath, options, logger)
	assert.AssertNoError(err, "create config watcher")

	ctx := context.Background()
	err = watcher.Start(ctx)
	assert.AssertNoError(err, "start watcher for concurrent reads")
	defer func() {
		if stopErr := watcher.Stop(); stopErr != nil {
			t.Errorf("Failed to stop watcher for concurrent reads: %v", stopErr)
		}
	}()

	const numReaders = 20
	var wg sync.WaitGroup
	configChan := make(chan *ManagerConfig, numReaders)

	// Start multiple goroutines reading config concurrently
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			config := watcher.GetCurrentConfig()
			configChan <- config
		}()
	}

	wg.Wait()
	close(configChan)

	// Verify all reads were successful and consistent
	var configs []*ManagerConfig
	for config := range configChan {
		assert.AssertNotNil(config, "config should not be nil in concurrent read")
		configs = append(configs, config)
	}

	assert.AssertEqual(numReaders, len(configs), "should have all config reads")

	// All configs should be identical (same pointer or same content)
	firstConfig := configs[0]
	for i, config := range configs {
		assert.AssertEqual(len(firstConfig.Plugins), len(config.Plugins),
			fmt.Sprintf("config %d should have same plugin count", i))
	}
}

// Helper function to run concurrent file modification test
func runConcurrentFileModificationTest(t *testing.T, assert *TestAssertions, initialConfig ManagerConfig, configPath string, options DynamicConfigOptions, logger *slog.Logger) {
	manager := createTestManagerWithMockFactory(assert, logger)

	watcher, err := NewConfigWatcher(manager, configPath, options, logger)
	assert.AssertNoError(err, "create config watcher")

	ctx := context.Background()
	err = watcher.Start(ctx)
	assert.AssertNoError(err, "start watcher for concurrent file modification")
	defer func() {
		if stopErr := watcher.Stop(); stopErr != nil {
			t.Errorf("Failed to stop watcher for concurrent file modification: %v", stopErr)
		}
	}()

	const numWriters = 5
	var wg sync.WaitGroup

	// Start multiple goroutines modifying the config file concurrently
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()

			// Create a deep copy of the config for this writer to avoid race conditions
			config := initialConfig
			config.Plugins = make([]PluginConfig, len(initialConfig.Plugins))
			copy(config.Plugins, initialConfig.Plugins)
			config.Plugins[0].Name = fmt.Sprintf("writer-%d-plugin", writerID)

			configBytes, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				t.Logf("Writer %d: marshal error: %v", writerID, err)
				return
			}

			// Write to file multiple times
			for j := 0; j < 3; j++ {
				time.Sleep(time.Duration(writerID*10) * time.Millisecond) // Stagger writes
				if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
					t.Logf("Writer %d: write error: %v", writerID, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Wait for all changes to be processed
	time.Sleep(500 * time.Millisecond)

	// Verify the watcher is still functional
	assert.AssertTrue(watcher.IsRunning(), "watcher should still be running after concurrent modifications")

	finalConfig := watcher.GetCurrentConfig()
	assert.AssertNotNil(finalConfig, "final config should not be nil")
	assert.AssertEqual(1, len(finalConfig.Plugins), "should have 1 plugin after concurrent modifications")
}

func TestConfigLoader_ConcurrentAccess(t *testing.T) {
	assert, env, initialConfig, configPath, logger, options := setupConcurrentAccessTest(t)
	defer env.Cleanup()

	t.Run("ConcurrentStartStop", func(t *testing.T) {
		runConcurrentStartStopTest(t, assert, configPath, options, logger)
	})

	t.Run("ConcurrentConfigReads", func(t *testing.T) {
		runConcurrentConfigReadsTest(t, assert, configPath, options, logger)
	})

	t.Run("ConcurrentFileModification", func(t *testing.T) {
		runConcurrentFileModificationTest(t, assert, initialConfig, configPath, options, logger)
	})
}

// TestConfigLoader_ErrorHandling tests various error scenarios and recovery.
func TestConfigLoader_ErrorHandling(t *testing.T) {
	assert := NewTestAssertions(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Create temp directory manually to avoid TestEnvironment deadlock
	tempDir, err := os.MkdirTemp("", "go-plugins-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			t.Errorf("Failed to cleanup temp dir: %v", removeErr)
		}
	}()

	// Pre-create all files
	malformedPath := filepath.Join(tempDir, "malformed-config.json")
	err = os.WriteFile(malformedPath, []byte(`{"plugins": [{"name": "test", "missing_closing_brace": true`), 0644)
	if err != nil {
		t.Fatalf("Failed to create malformed config: %v", err)
	}

	emptyPath := filepath.Join(tempDir, "empty-config.json")
	err = os.WriteFile(emptyPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create empty config: %v", err)
	}

	invalidPath := filepath.Join(tempDir, "invalid-config.json")
	err = os.WriteFile(invalidPath, []byte(`{"plugins": [{"name": "", "transport": ""}]}`), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid config: %v", err)
	}

	t.Run("NonExistentConfigFile", func(t *testing.T) {
		// Create separate manager for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		nonExistentPath := filepath.Join(tempDir, "non-existent-config.json")

		_, err := NewConfigWatcher(manager, nonExistentPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher with non-existent file should succeed")

		// However, starting it should fail
		watcher, err := NewConfigWatcher(manager, nonExistentPath, DefaultDynamicConfigOptions(), logger)
		if err != nil {
			t.Fatalf("Failed to create watcher: %v", err)
		}
		err = watcher.Start(context.Background())
		assert.AssertError(err, "starting watcher with non-existent file should fail")
		assert.AssertTrue(strings.Contains(err.Error(), "does not exist"),
			"error should mention file doesn't exist")
	})

	t.Run("DirectoryInsteadOfFile", func(t *testing.T) {
		// Create separate manager for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		dirPath := filepath.Join(tempDir, "config-directory")
		err := os.MkdirAll(dirPath, 0755)
		assert.AssertNoError(err, "create directory")

		watcher, err := NewConfigWatcher(manager, dirPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher with directory path should succeed")

		err = watcher.Start(context.Background())
		assert.AssertError(err, "starting watcher with directory should fail")
		assert.AssertTrue(strings.Contains(err.Error(), "not a regular file"),
			"error should mention it's not a regular file")
	})

	t.Run("PermissionDeniedFile", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Permission tests are complex on Windows, skipping")
			return
		}

		// Create separate manager for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		// Create a file with no read permissions
		restrictedPath := filepath.Join(tempDir, "restricted-config.json")
		err := os.WriteFile(restrictedPath, []byte(`{"plugins": []}`), 0200) // Write-only
		assert.AssertNoError(err, "create restricted file")

		watcher, err := NewConfigWatcher(manager, restrictedPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher should succeed")

		err = watcher.Start(context.Background())
		assert.AssertError(err, "starting watcher with unreadable file should fail")
	})

	t.Run("MalformedJSONFile", func(t *testing.T) {
		// Create separate manager for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		watcher, err := NewConfigWatcher(manager, malformedPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher should succeed")

		err = watcher.Start(context.Background())
		assert.AssertError(err, "starting watcher with malformed JSON should fail")
		assert.AssertTrue(strings.Contains(err.Error(), "unmarshal"),
			"error should mention JSON unmarshaling")
	})

	t.Run("EmptyConfigFile", func(t *testing.T) {
		// Create separate manager for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		watcher, err := NewConfigWatcher(manager, emptyPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher should succeed")

		err = watcher.Start(context.Background())
		assert.AssertError(err, "starting watcher with empty file should fail")
		assert.AssertTrue(strings.Contains(err.Error(), "empty"),
			"error should mention empty file")
	})

	t.Run("InvalidConfigContent", func(t *testing.T) {
		// Create separate manager for this subtest
		manager := NewManager[TestRequest, TestResponse](logger)

		watcher, err := NewConfigWatcher(manager, invalidPath, DefaultDynamicConfigOptions(), logger)
		assert.AssertNoError(err, "creating watcher should succeed")

		err = watcher.Start(context.Background())
		assert.AssertError(err, "starting watcher with invalid config should fail")
		assert.AssertTrue(strings.Contains(err.Error(), "invalid configuration"),
			"error should mention invalid configuration")
	})
}

// benchmarkConfigLoadFromFile benchmarks config loading from file
func benchmarkConfigLoadFromFile(t *testing.T, watcher *ConfigWatcher[TestRequest, TestResponse], configPath string) {
	start := time.Now()
	for i := 0; i < 100; i++ {
		_, err := watcher.loadConfigFromFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
	}
	duration := time.Since(start)

	avgDuration := duration / 100
	t.Logf("Average config load time: %v", avgDuration)

	// Assert reasonable performance (should be under 5ms for 10 plugins)
	if avgDuration > 5*time.Millisecond {
		t.Errorf("Config loading too slow: %v (expected < 5ms)", avgDuration)
	}
}

// benchmarkSecurePathValidation benchmarks secure path validation
func benchmarkSecurePathValidation(t *testing.T, watcher *ConfigWatcher[TestRequest, TestResponse], configPath string) {
	// Create a cross-platform temp path for benchmarking
	tempPath := filepath.Join(os.TempDir(), "benchmark-test.json")

	testPaths := []string{
		configPath,
		"config.json",
		tempPath, // Use cross-platform temp path instead of /tmp/test.json
		"./relative/path.json",
	}

	start := time.Now()
	for i := 0; i < 1000; i++ {
		for _, path := range testPaths {
			_, err := watcher.validateAndSecureFilePath(path)
			if err != nil {
				// Log but continue - this is a performance test
				t.Logf("Path validation failed for %s: %v", path, err)
			}
		}
	}
	duration := time.Since(start)

	totalValidations := 1000 * len(testPaths)
	avgDuration := duration / time.Duration(totalValidations)
	t.Logf("Average path validation time: %v", avgDuration)

	// Assert reasonable performance (should be under 100µs per validation)
	if avgDuration > 100*time.Microsecond {
		t.Errorf("Path validation too slow: %v (expected < 100µs)", avgDuration)
	}
}

// TestConfigLoader_PerformanceBenchmarks provides performance benchmarks for config operations.
func TestConfigLoader_PerformanceBenchmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance benchmarks in short mode")
	}

	env := NewTestEnvironment(t)
	defer env.Cleanup()

	// Create a reasonably sized config for benchmarking
	config := ManagerConfig{
		LogLevel: "info",
		Plugins:  make([]PluginConfig, 10), // 10 plugins for performance test
	}

	for i := 0; i < 10; i++ {
		config.Plugins[i] = PluginConfig{
			Name:      fmt.Sprintf("plugin-%d", i),
			Type:      "test",
			Transport: TransportHTTPS,
			Endpoint:  fmt.Sprintf("https://api-%d.example.com", i),
			Auth:      AuthConfig{Method: AuthAPIKey, APIKey: fmt.Sprintf("key-%d", i)},
		}
	}

	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	configPath := env.CreateTempFileWithContent("benchmark-config.json", string(configBytes))

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	manager := NewManager[TestRequest, TestResponse](logger)
	watcher, err := NewConfigWatcher(manager, configPath, DefaultDynamicConfigOptions(), logger)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("BenchmarkConfigLoad", func(t *testing.T) {
		benchmarkConfigLoadFromFile(t, watcher, configPath)
	})

	t.Run("BenchmarkPathValidation", func(t *testing.T) {
		benchmarkSecurePathValidation(t, watcher, configPath)
	})
}

// TestConfigLoader_RealWorldScenarios tests real-world usage scenarios.
// Helper function to setup common test environment
func setupRealWorldScenarioTest(t *testing.T) (assert *TestAssertions, logger *slog.Logger, tempDir string) {
	assert = NewTestAssertions(t)
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create temp directory manually to avoid TestEnvironment deadlock
	var err error
	tempDir, err = os.MkdirTemp("", "go-plugins-scenario-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			t.Errorf("Failed to cleanup scenario test temp dir: %v", removeErr)
		}
	})

	return assert, logger, tempDir
}

// Helper function to setup manager with mock factory
func setupManagerWithMockFactory(t *testing.T, logger *slog.Logger) *Manager[TestRequest, TestResponse] {
	manager := NewManager[TestRequest, TestResponse](logger)

	mockFactory := &MockPluginFactory[TestRequest, TestResponse]{
		createFunc: func(config PluginConfig) (Plugin[TestRequest, TestResponse], error) {
			return NewAdvancedMockPlugin[TestRequest, TestResponse](config.Name), nil
		},
	}

	err := manager.RegisterFactory("test", mockFactory)
	if err != nil {
		t.Fatalf("Failed to register mock factory: %v", err)
	}

	return manager
}

// Helper function for development workflow test
func testDevelopmentWorkflow(t *testing.T, assert *TestAssertions, logger *slog.Logger, tempDir string) {
	manager := setupManagerWithMockFactory(t, logger)

	// Simulate a development workflow where config is frequently changed
	config := createInitialDevConfig()
	configPath := filepath.Join(tempDir, "dev-config.json")

	watcher := setupConfigWatcher(assert, manager, config, configPath, logger, 100*time.Millisecond)
	defer stopWatcher(t, watcher)

	// Test configuration updates
	testAuthConfigUpdate(t, watcher, config, configPath)
	testPluginAddition(t, assert, watcher, config, configPath)
	testLogLevelUpdate(t, assert, watcher, config, configPath)
}

// Helper function to create initial development config
func createInitialDevConfig() ManagerConfig {
	return ManagerConfig{
		LogLevel: "debug",
		Plugins: []PluginConfig{
			{
				Name:      "dev-plugin",
				Type:      "test",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:3000",
				Enabled:   true,
				Auth:      AuthConfig{Method: AuthNone},
			},
		},
	}
}

// Helper function to setup config watcher
func setupConfigWatcher(assert *TestAssertions, manager *Manager[TestRequest, TestResponse],
	config ManagerConfig, configPath string, logger *slog.Logger, pollInterval time.Duration) *ConfigWatcher[TestRequest, TestResponse] {

	configBytes, err := json.MarshalIndent(config, "", "  ")
	assert.AssertNoError(err, "marshal config")

	err = os.WriteFile(configPath, configBytes, 0644)
	assert.AssertNoError(err, "write config file")

	options := DefaultDynamicConfigOptions()
	options.PollInterval = pollInterval

	watcher, err := NewConfigWatcher(manager, configPath, options, logger)
	assert.AssertNoError(err, "create watcher")

	ctx := context.Background()
	err = watcher.Start(ctx)
	assert.AssertNoError(err, "start watcher")

	return watcher
}

// Helper function to stop watcher safely
func stopWatcher(t *testing.T, watcher *ConfigWatcher[TestRequest, TestResponse]) {
	if stopErr := watcher.Stop(); stopErr != nil {
		t.Errorf("Failed to stop watcher: %v", stopErr)
	}
}

// Helper function to test auth config update
func testAuthConfigUpdate(t *testing.T, watcher *ConfigWatcher[TestRequest, TestResponse],
	config ManagerConfig, configPath string) {

	// Add authentication
	config.Plugins[0].Auth = AuthConfig{Method: AuthAPIKey, APIKey: "dev-key-123"}
	updateConfigFile(t, config, configPath)

	// Wait and verify auth method update
	waitForConfigUpdate(t, watcher, func(currentConfig *ManagerConfig) bool {
		return currentConfig != nil && len(currentConfig.Plugins) > 0 &&
			currentConfig.Plugins[0].Auth.Method == AuthAPIKey
	}, "auth method updated")
}

// Helper function to test plugin addition
func testPluginAddition(t *testing.T, assert *TestAssertions, watcher *ConfigWatcher[TestRequest, TestResponse],
	config ManagerConfig, configPath string) {

	// Add more plugins
	config.Plugins = append(config.Plugins, PluginConfig{
		Name:      "analytics-plugin",
		Type:      "test",
		Transport: TransportHTTPS,
		Endpoint:  "https://analytics.dev.example.com",
		Enabled:   true,
		Auth:      AuthConfig{Method: AuthBearer, Token: "analytics-token"},
	})

	updateConfigFile(t, config, configPath)
	time.Sleep(200 * time.Millisecond)

	currentConfig := watcher.GetCurrentConfig()
	assert.AssertEqual(2, len(currentConfig.Plugins), "second plugin added")
}

// Helper function to test log level update
func testLogLevelUpdate(t *testing.T, assert *TestAssertions, watcher *ConfigWatcher[TestRequest, TestResponse],
	config ManagerConfig, configPath string) {

	// Change log level for debugging
	config.LogLevel = "trace"
	updateConfigFile(t, config, configPath)

	// Wait for config update with retry
	waitForConfigUpdate(t, watcher, func(cfg *ManagerConfig) bool {
		return cfg.LogLevel == "trace"
	}, "log level update to trace")

	currentConfig := watcher.GetCurrentConfig()
	assert.AssertEqual("trace", currentConfig.LogLevel, "log level updated")
}

// Helper function to update config file
func updateConfigFile(t *testing.T, config ManagerConfig, configPath string) {
	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	if writeErr := os.WriteFile(configPath, configBytes, 0644); writeErr != nil {
		t.Fatalf("Failed to write config: %v", writeErr)
	}
}

// Helper function to wait for config update with retry logic
func waitForConfigUpdate(t *testing.T, watcher *ConfigWatcher[TestRequest, TestResponse],
	condition func(*ManagerConfig) bool, message string) {

	var currentConfig *ManagerConfig
	for i := 0; i < 10; i++ {
		time.Sleep(200 * time.Millisecond)
		currentConfig = watcher.GetCurrentConfig()
		if condition(currentConfig) {
			break
		}
		t.Logf("Attempt %d: Waiting for condition: %s", i+1, message)
	}

	if currentConfig == nil || len(currentConfig.Plugins) == 0 {
		t.Fatalf("No configuration or plugins found")
	}

	if !condition(currentConfig) {
		t.Fatalf("Condition not met after retries: %s", message)
	}
}

// Helper function for production deployment test
func testProductionDeployment(t *testing.T, assert *TestAssertions, logger *slog.Logger, tempDir string) {
	manager := setupManagerWithMockFactory(t, logger)

	// Create production configuration
	prodConfig := createProductionConfig()
	configPath := filepath.Join(tempDir, "prod-config.json")

	// Setup production watcher with conservative options
	watcher := setupProductionWatcher(assert, manager, prodConfig, configPath, logger)
	defer stopWatcher(t, watcher)

	// Verify production configuration
	verifyProductionConfigLoaded(assert, watcher)

	// Test production update (monitoring service)
	testProductionMonitoringUpdate(t, assert, watcher, prodConfig, configPath)
}

// Helper function to create production configuration
func createProductionConfig() ManagerConfig {
	return ManagerConfig{
		LogLevel:    "info",
		MetricsPort: 9090,
		DefaultRetry: RetryConfig{
			MaxRetries:      5,
			InitialInterval: 200 * time.Millisecond,
			MaxInterval:     30 * time.Second,
			Multiplier:      2.0,
			RandomJitter:    true,
		},
		DefaultCircuitBreaker: CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 10,
			RecoveryTimeout:  60 * time.Second,
		},
		Plugins: []PluginConfig{
			{
				Name:      "auth-service",
				Type:      "test",
				Transport: TransportHTTPS,
				Endpoint:  "https://auth.prod.example.com/api/v1",
				Enabled:   true,
				Auth:      AuthConfig{Method: AuthAPIKey, APIKey: "prod-auth-key-123"},
				Priority:  1,
			},
			{
				Name:      "payment-service",
				Type:      "test",
				Transport: TransportGRPCTLS,
				Endpoint:  "payments.prod.example.com:443",
				Enabled:   true,
				Auth:      AuthConfig{Method: AuthAPIKey, APIKey: "prod-payment-key-456"},
				Priority:  2,
			},
			{
				Name:      "notification-service",
				Type:      "test",
				Transport: TransportHTTPS,
				Endpoint:  "https://notifications.prod.example.com/api/v2",
				Enabled:   true,
				Auth:      AuthConfig{Method: AuthBearer, Token: "prod-notification-token"},
				Priority:  3,
			},
		},
	}
}

// Helper function to setup production watcher
func setupProductionWatcher(assert *TestAssertions, manager *Manager[TestRequest, TestResponse],
	prodConfig ManagerConfig, configPath string, logger *slog.Logger) *ConfigWatcher[TestRequest, TestResponse] {

	configBytes, err := json.MarshalIndent(prodConfig, "", "  ")
	assert.AssertNoError(err, "marshal prod config")

	err = os.WriteFile(configPath, configBytes, 0644)
	assert.AssertNoError(err, "write prod config file")

	// Production options: more conservative
	options := DefaultDynamicConfigOptions()
	options.PollInterval = 200 * time.Millisecond // Faster for tests
	options.ReloadStrategy = ReloadStrategyGraceful
	options.RollbackOnFailure = true
	options.DrainTimeout = 60 * time.Second

	watcher, err := NewConfigWatcher(manager, configPath, options, logger)
	assert.AssertNoError(err, "create prod watcher")

	ctx := context.Background()
	err = watcher.Start(ctx)
	assert.AssertNoError(err, "start prod watcher")

	return watcher
}

// Helper function to verify production config loaded
func verifyProductionConfigLoaded(assert *TestAssertions, watcher *ConfigWatcher[TestRequest, TestResponse]) {
	currentConfig := watcher.GetCurrentConfig()
	assert.AssertEqual(3, len(currentConfig.Plugins), "all production plugins loaded")
	assert.AssertEqual("auth-service", currentConfig.Plugins[0].Name, "auth service loaded")
	assert.AssertEqual(AuthAPIKey, currentConfig.Plugins[0].Auth.Method, "API key auth configured")
}

// Helper function to test production monitoring update
func testProductionMonitoringUpdate(t *testing.T, assert *TestAssertions, watcher *ConfigWatcher[TestRequest, TestResponse],
	prodConfig ManagerConfig, configPath string) {

	// Add monitoring service
	prodConfig.Plugins = append(prodConfig.Plugins, PluginConfig{
		Name:      "monitoring-service",
		Type:      "test",
		Transport: TransportHTTPS,
		Endpoint:  "https://monitoring.prod.example.com/api/v1",
		Enabled:   true,
		Auth:      AuthConfig{Method: AuthAPIKey, APIKey: "monitoring-api-key"},
		Priority:  4,
	})

	updateConfigFile(t, prodConfig, configPath)

	// In production, we'd wait longer for the change, but for testing we'll use a shorter time
	time.Sleep(400 * time.Millisecond)

	currentConfig := watcher.GetCurrentConfig()
	assert.AssertEqual(4, len(currentConfig.Plugins), "monitoring service added in production")
}

func TestConfigLoader_RealWorldScenarios(t *testing.T) {
	assert, logger, tempDir := setupRealWorldScenarioTest(t)

	t.Run("DevelopmentWorkflow", func(t *testing.T) {
		testDevelopmentWorkflow(t, assert, logger, tempDir)
	})

	t.Run("ProductionDeployment", func(t *testing.T) {
		testProductionDeployment(t, assert, logger, tempDir)
	})
}
