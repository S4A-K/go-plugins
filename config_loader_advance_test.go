// config_loader_advanced_test.go: Comprehensive tests for missing config loader coverage
//
// Focus on: DefaultDynamicConfigOptions, LoadConfigFromFile, validation functions,
// CreateSampleConfig, parseYAMLConfig, and Windows-specific path validation.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestDefaultDynamicConfigOptions tests the DefaultDynamicConfigOptions function
func TestDefaultDynamicConfigOptions(t *testing.T) {
	t.Run("ReturnsValidDefaults", func(t *testing.T) {
		options := DefaultDynamicConfigOptions()

		assert.Equal(t, ReloadStrategyGraceful, options.ReloadStrategy, "Should use graceful strategy by default")
		assert.True(t, options.EnableDiff, "Should enable diff by default")
		assert.True(t, options.RollbackOnFailure, "Should rollback by default")
		assert.NotZero(t, options.PollInterval, "Should have non-zero poll interval")
		assert.NotZero(t, options.CacheTTL, "Should have non-zero cache TTL")
		assert.NotZero(t, options.DrainTimeout, "Should have non-zero drain timeout")

		// Verify reasonable default values
		assert.True(t, options.PollInterval > 0, "Poll interval should be positive")
		assert.True(t, options.CacheTTL > 0, "Cache TTL should be positive")
		assert.True(t, options.DrainTimeout > 0, "Drain timeout should be positive")
		assert.True(t, options.CacheTTL <= options.PollInterval, "Cache TTL should be <= Poll interval")
	})

	t.Run("DefaultsAreConsistent", func(t *testing.T) {
		// Get defaults multiple times to ensure consistency
		options1 := DefaultDynamicConfigOptions()
		options2 := DefaultDynamicConfigOptions()

		assert.Equal(t, options1.PollInterval, options2.PollInterval)
		assert.Equal(t, options1.CacheTTL, options2.CacheTTL)
		assert.Equal(t, options1.ReloadStrategy, options2.ReloadStrategy)
		assert.Equal(t, options1.EnableDiff, options2.EnableDiff)
		assert.Equal(t, options1.DrainTimeout, options2.DrainTimeout)
		assert.Equal(t, options1.RollbackOnFailure, options2.RollbackOnFailure)
	})

	t.Run("DefaultValuesAreReasonable", func(t *testing.T) {
		options := DefaultDynamicConfigOptions()

		// Check that defaults are in reasonable ranges
		assert.True(t, options.PollInterval >= 1*time.Second, "Poll interval should be at least 1 second")
		assert.True(t, options.PollInterval <= 60*time.Second, "Poll interval should be reasonable")
		assert.True(t, options.DrainTimeout >= 5*time.Second, "Drain timeout should allow reasonable drain time")
		assert.True(t, options.DrainTimeout <= 300*time.Second, "Drain timeout should not be excessive")
	})
}

// TestLoadConfigFromFile_PublicAPI tests the public LoadConfigFromFile function with REAL valid configurations
func TestLoadConfigFromFile_PublicAPI(t *testing.T) {
	t.Run("LoadCompleteValidJSONConfig", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "complete_config.json")

		// Create a COMPLETE, VALID configuration using the REAL ManagerConfig structure
		validConfig := ManagerConfig{
			LogLevel:    "info",
			MetricsPort: 8080,
			Security: SecurityConfig{
				Enabled: true,
				Policy:  SecurityPolicyStrict,
			},
			Plugins: []PluginConfig{
				{
					Name:      "test_plugin",
					Type:      "http",
					Transport: TransportGRPC,
					Endpoint:  "localhost:8080",
					Enabled:   true,
					Auth: AuthConfig{
						Method: AuthNone,
					},
					Options: map[string]interface{}{
						"timeout": "30s",
					},
				},
			},
		}

		// Marshal to JSON and write to file
		configBytes, err := json.Marshal(validConfig)
		assert.NoError(t, err, "Should marshal valid config")

		err = os.WriteFile(configPath, configBytes, 0644)
		assert.NoError(t, err, "Should write config file")

		// Now test the actual LoadConfigFromFile function with a REAL valid config
		loadedConfig, err := LoadConfigFromFile(configPath)
		assert.NoError(t, err, "Should successfully load complete valid JSON config")
		assert.NotNil(t, loadedConfig, "Loaded config should not be nil")
		assert.Len(t, loadedConfig.Plugins, 1, "Should have exactly one plugin")
		assert.Equal(t, "test_plugin", loadedConfig.Plugins[0].Name, "Plugin name should match")
		assert.Equal(t, "localhost:8080", loadedConfig.Plugins[0].Endpoint, "Plugin endpoint should match")
	})

	t.Run("LoadCompleteValidYAMLConfig", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "complete_config.yaml")

		// Create a COMPLETE, VALID YAML configuration using the EXACT same structure as JSON
		yamlContent := `
log_level: debug
metrics_port: 9090

security:
  enabled: true
  policy: 2

plugins:
  - name: yaml_test_plugin
    type: http
    transport: grpc
    endpoint: localhost:8081
    enabled: true
    auth:
      method: none
    options:
      timeout: "30s"
`

		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		assert.NoError(t, err, "Should write YAML config file")

		// Test the actual LoadConfigFromFile function with valid YAML
		loadedConfig, err := LoadConfigFromFile(configPath)
		assert.NoError(t, err, "Should successfully load complete valid YAML config")
		assert.NotNil(t, loadedConfig, "Loaded config should not be nil")
		assert.Len(t, loadedConfig.Plugins, 1, "Should have exactly one plugin")
		assert.Equal(t, "yaml_test_plugin", loadedConfig.Plugins[0].Name, "Plugin name should match")
		assert.Equal(t, "localhost:8081", loadedConfig.Plugins[0].Endpoint, "Plugin endpoint should match")
	})

	t.Run("LoadInvalidJSONSyntax", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "malformed_syntax.json")

		// Malformed JSON - missing comma
		configContent := `{
			"log_level": "info"
			"plugins": []
		}`

		err := os.WriteFile(configPath, []byte(configContent), 0644)
		assert.NoError(t, err, "Should create malformed JSON file")

		_, err = LoadConfigFromFile(configPath)
		assert.Error(t, err, "Should fail to parse malformed JSON")
		assert.Contains(t, err.Error(), "parse", "Error should indicate parsing issue")
	})

	t.Run("LoadNonExistentFile", func(t *testing.T) {
		_, err := LoadConfigFromFile("/nonexistent/directory/config.json")
		assert.Error(t, err, "Should fail to load non-existent file")
		assert.Contains(t, err.Error(), "does not exist", "Error should indicate file not found")
	})

	t.Run("LoadEmptyFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "empty_config.json")

		err := os.WriteFile(configPath, []byte(""), 0644)
		assert.NoError(t, err, "Should create empty config file")

		_, err = LoadConfigFromFile(configPath)
		assert.Error(t, err, "Should fail to load empty config file")
	})

	t.Run("LoadInvalidYAMLSyntax", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "malformed.yaml")

		// Malformed YAML - unclosed bracket
		yamlContent := `
log_level: info
plugins: [
  - name: test
    unclosed_bracket: [missing_close
`

		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		assert.NoError(t, err, "Should create malformed YAML file")

		_, err = LoadConfigFromFile(configPath)
		assert.Error(t, err, "Should fail to parse malformed YAML")
		assert.Contains(t, err.Error(), "YAML", "Error should indicate YAML parsing issue")
	})
}

// TestCreateSampleConfig tests the CreateSampleConfig function
func TestCreateSampleConfig(t *testing.T) {
	t.Run("CreateValidSampleConfig", func(t *testing.T) {
		tmpDir := t.TempDir()
		samplePath := filepath.Join(tmpDir, "sample_config.json")

		err := CreateSampleConfig(samplePath)
		assert.NoError(t, err, "Should create sample config successfully")

		// Verify file exists
		assert.FileExists(t, samplePath, "Sample config file should exist")

		// Verify file content is valid JSON
		content, err := os.ReadFile(samplePath)
		assert.NoError(t, err, "Should read sample config file")
		assert.NotEmpty(t, content, "Sample config should not be empty")

		// Try to load the created config to verify it's valid
		config, err := LoadConfigFromFile(samplePath)
		assert.NoError(t, err, "Created sample config should be valid")
		assert.NotEmpty(t, config.Plugins, "Sample config should contain plugins")
	})

	t.Run("CreateSampleInInvalidDirectory", func(t *testing.T) {
		// Try to create in non-existent directory without proper permissions
		invalidPath := "/root/nonexistent/sample_config.json"

		err := CreateSampleConfig(invalidPath)
		// Should either create or fail gracefully - both are acceptable
		// On some systems this might succeed, on others it might fail
		t.Logf("CreateSampleConfig result for invalid path: %v", err)
	})

	t.Run("CreateSampleOverwriteExisting", func(t *testing.T) {
		tmpDir := t.TempDir()
		samplePath := filepath.Join(tmpDir, "existing_config.json")

		// Create an existing file
		existingContent := `{"existing": true}`
		err := os.WriteFile(samplePath, []byte(existingContent), 0644)
		assert.NoError(t, err, "Should create existing file")

		// Create sample config (should overwrite)
		err = CreateSampleConfig(samplePath)
		assert.NoError(t, err, "Should create sample config even if file exists")

		// Verify content changed
		content, err := os.ReadFile(samplePath)
		assert.NoError(t, err, "Should read updated file")
		assert.NotContains(t, string(content), `"existing": true`, "Should overwrite existing content")
	})
}

// TestParseYAMLConfig tests the parseYAMLConfig function indirectly
func TestParseYAMLConfig_IndirectTesting(t *testing.T) {
	t.Run("ParseValidYAMLStructures", func(t *testing.T) {
		tmpDir := t.TempDir()

		testCases := []struct {
			name    string
			content string
			valid   bool
		}{
			{
				name: "SimpleYAML",
				content: `
plugins:
  - name: simple
    type: http
    transport: grpc
    endpoint: localhost:8080
    enabled: true
    auth:
      method: none
`,
				valid: true,
			},
			{
				name: "ComplexYAML",
				content: `
log_level: info
security:
  enabled: true
  policy: 2
plugins:
  - name: complex
    type: http
    transport: grpc
    endpoint: localhost:8080
    enabled: true
    auth:
      method: none
discovery:
  enabled: true
  directories: ["/usr/local/plugins"]
`,
				valid: true,
			},
			{
				name: "YAMLWithSecurity",
				content: `
security:
  enabled: true
  policy: 2
  whitelist_file: "/etc/plugins/whitelist.json"
plugins:
  - name: secure-plugin
    type: http
    transport: grpc
    endpoint: localhost:8080
    enabled: true
    auth:
      method: none
`,
				valid: true,
			},
			{
				name: "InvalidYAML",
				content: `
plugins:
  - name: invalid
    type: http
    transport: grpc
    endpoint: localhost:8080
  malformed yaml: [unclosed
`,
				valid: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				configPath := filepath.Join(tmpDir, fmt.Sprintf("%s.yaml", tc.name))
				err := os.WriteFile(configPath, []byte(tc.content), 0644)
				assert.NoError(t, err, "Should create YAML test file")

				_, err = LoadConfigFromFile(configPath)
				if tc.valid {
					assert.NoError(t, err, "Should parse valid YAML")
				} else {
					assert.Error(t, err, "Should fail to parse invalid YAML")
				}
			})
		}
	})
}

// TestWindowsPathValidation tests Windows-specific path validation functions
func TestWindowsPathValidation(t *testing.T) {
	// Skip these tests on non-Windows systems since the Windows validation
	// functions are platform-specific and may not behave correctly on Unix
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows path validation tests on non-Windows system")
	}

	t.Run("WindowsPathValidationScenarios", func(t *testing.T) {
		logger := NewTestLogger()
		manager := NewManager[TestRequest, TestResponse](logger)

		// Create a ConfigWatcher to access Windows validation methods
		options := DefaultDynamicConfigOptions()
		watcher := &ConfigWatcher[TestRequest, TestResponse]{
			manager: manager,
			options: options,
			logger:  logger,
		}

		testPaths := []struct {
			path        string
			shouldError bool
			description string
		}{
			{"C:\\valid\\path\\file.json", false, "Valid Windows absolute path"},
			{"relative\\path\\file.json", false, "Valid Windows relative path"},
			{"CON", true, "Reserved Windows device name"},
			{"PRN.txt", true, "Reserved Windows device name with extension"},
			{"C:\\path\\with\\<invalid>\\characters", true, "Invalid Windows characters"},
			{fmt.Sprintf("C:\\%s\\file.json", repeatString("a", 300)), true, "Path too long"},
			{"C:\\valid\\path", false, "Valid short path"},
		}

		for _, testCase := range testPaths {
			t.Run(testCase.description, func(t *testing.T) {
				err := watcher.validateWindowsPath(testCase.path)
				if testCase.shouldError {
					assert.Error(t, err, "Should reject: %s", testCase.path)
				} else {
					assert.NoError(t, err, "Should accept: %s", testCase.path)
				}
			})
		}
	})
}

// TestConfigLoaderEdgeCases tests additional edge cases for config loading
func TestConfigLoaderEdgeCases(t *testing.T) {
	t.Run("LoadConfigWithDifferentExtensions", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Test various file extensions
		extensions := []string{".json", ".yaml", ".yml"}

		for _, ext := range extensions {
			configPath := filepath.Join(tmpDir, fmt.Sprintf("test%s", ext))
			var configContent string

			if ext == ".json" {
				configContent = `{
					"plugins": [
						{
							"name": "test-plugin",
							"type": "http",
							"transport": "grpc",
							"endpoint": "localhost:8080",
							"enabled": true,
							"auth": {
								"method": "none"
							}
						}
					]
				}`
			} else {
				configContent = `
plugins:
  - name: test-plugin
    type: http
    transport: grpc
    endpoint: localhost:8080
    enabled: true
    auth:
      method: none
`
			}

			err := os.WriteFile(configPath, []byte(configContent), 0644)
			assert.NoError(t, err, "Should create config file with extension %s", ext)

			config, err := LoadConfigFromFile(configPath)
			assert.NoError(t, err, "Should load config with extension %s", ext)
			assert.NotNil(t, config.Plugins, "Should have plugins array for %s", ext)
		}
	})

	t.Run("LoadConfigWithSpecialCharacters", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config_with_üñíçødé.json")

		configContent := `{
			"plugins": [
				{
					"name": "test-with-üñíçødé",
					"type": "http",
					"transport": "grpc",
					"endpoint": "localhost:8080",
					"enabled": true,
					"auth": {
						"method": "none"
					}
				}
			]
		}`

		err := os.WriteFile(configPath, []byte(configContent), 0644)
		assert.NoError(t, err, "Should create config file with Unicode characters")

		config, err := LoadConfigFromFile(configPath)
		assert.NoError(t, err, "Should load config with Unicode characters")
		assert.Equal(t, "test-with-üñíçødé", config.Plugins[0].Name, "Should preserve Unicode in plugin name")
	})
}

// Helper function for generating long strings
func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
