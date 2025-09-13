// config_comprehensive_test.go: Comprehensive tests for configuration system
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestPluginConfig_Validate_ComprehensiveValidation tests all validation scenarios
func TestPluginConfig_Validate_ComprehensiveValidation(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	testCases := []struct {
		name          string
		config        PluginConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "ValidHTTPPluginConfiguration",
			config: PluginConfig{
				Name:      "test-http-plugin",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8080/api",
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError: false,
		},
		{
			name: "ValidHTTPSPluginConfiguration",
			config: PluginConfig{
				Name:      "test-https-plugin",
				Transport: TransportHTTPS,
				Endpoint:  "https://api.example.com/v1",
				Auth:      AuthConfig{Method: AuthAPIKey, APIKey: "secret-key"},
			},
			expectError: false,
		},
		{
			name: "ValidUnixSocketConfiguration",
			config: PluginConfig{
				Name:      "test-unix-plugin",
				Transport: TransportUnix,
				Endpoint:  "/tmp/test.sock",
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError: false,
		},
		{
			name: "ValidExecutableConfiguration",
			config: PluginConfig{
				Name:       "test-exec-plugin",
				Transport:  TransportExecutable,
				Executable: "/usr/bin/test-plugin",
				Args:       []string{"--config", "test.conf"},
				Auth:       AuthConfig{Method: AuthNone},
			},
			expectError: false,
		},
		{
			name: "MissingNameShouldFail",
			config: PluginConfig{
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8080",
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError:   true,
			errorContains: "Invalid plugin name",
		},
		{
			name: "MissingTransportShouldFail",
			config: PluginConfig{
				Name:     "test-plugin",
				Endpoint: "http://localhost:8080",
				Auth:     AuthConfig{Method: AuthNone},
			},
			expectError:   true,
			errorContains: "Invalid transport",
		},
		{
			name: "InvalidURLShouldFail",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportHTTP,
				Endpoint:  "://invalid-url-missing-scheme",
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError:   true,
			errorContains: "Invalid endpoint URL",
		},
		{
			name: "HTTPWithoutEndpointShouldFail",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportHTTP,
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError:   true,
			errorContains: "Missing endpoint",
		},
		{
			name: "UnixWithoutSocketPathShouldFail",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportUnix,
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError:   true,
			errorContains: "Missing socket path",
		},
		{
			name: "ExecutableWithoutPathShouldFail",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportExecutable,
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError:   true,
			errorContains: "Missing executable",
		},
		{
			name: "UnsupportedTransportShouldFail",
			config: PluginConfig{
				Name:      "test-plugin",
				Transport: TransportType("unknown"),
				Endpoint:  "http://localhost:8080",
				Auth:      AuthConfig{Method: AuthNone},
			},
			expectError:   true,
			errorContains: "Unsupported transport",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()

			if tc.expectError {
				assert.AssertError(err, tc.name)
				if tc.errorContains != "" {
					assert.AssertTrue(strings.Contains(err.Error(), tc.errorContains),
						"error message should contain: "+tc.errorContains)
				}
			} else {
				assert.AssertNoError(err, tc.name)
			}
		})
	}

	_ = env // Silence unused variable
}

// TestAuthConfig_Validate_AllAuthMethods tests all authentication method validations
func TestAuthConfig_Validate_AllAuthMethods(t *testing.T) {
	assert := NewTestAssertions(t)

	testCases := []struct {
		name          string
		config        AuthConfig
		expectError   bool
		errorContains string
	}{
		{
			name:        "AuthNoneShouldPass",
			config:      AuthConfig{Method: AuthNone},
			expectError: false,
		},
		{
			name:        "ValidAPIKeyShouldPass",
			config:      AuthConfig{Method: AuthAPIKey, APIKey: "valid-api-key"},
			expectError: false,
		},
		{
			name:          "EmptyAPIKeyShouldFail",
			config:        AuthConfig{Method: AuthAPIKey},
			expectError:   true,
			errorContains: "Missing API key",
		},
		{
			name:        "ValidBearerTokenShouldPass",
			config:      AuthConfig{Method: AuthBearer, Token: "valid.jwt.token"},
			expectError: false,
		},
		{
			name:          "EmptyBearerTokenShouldFail",
			config:        AuthConfig{Method: AuthBearer},
			expectError:   true,
			errorContains: "Missing bearer token",
		},
		{
			name:        "ValidBasicAuthShouldPass",
			config:      AuthConfig{Method: AuthBasic, Username: "user", Password: "pass"},
			expectError: false,
		},
		{
			name:          "BasicAuthMissingUsernameShouldFail",
			config:        AuthConfig{Method: AuthBasic, Password: "pass"},
			expectError:   true,
			errorContains: "Missing basic credentials",
		},
		{
			name:          "BasicAuthMissingPasswordShouldFail",
			config:        AuthConfig{Method: AuthBasic, Username: "user"},
			expectError:   true,
			errorContains: "Missing basic credentials",
		},
		{
			name: "ValidMTLSAuthShouldPass",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			expectError: false,
		},
		{
			name:          "MTLSMissingCertFileShouldFail",
			config:        AuthConfig{Method: AuthMTLS, KeyFile: "/path/to/key.pem"},
			expectError:   true,
			errorContains: "Missing mTLS certificates",
		},
		{
			name:          "MTLSMissingKeyFileShouldFail",
			config:        AuthConfig{Method: AuthMTLS, CertFile: "/path/to/cert.pem"},
			expectError:   true,
			errorContains: "Missing mTLS certificates",
		},
		{
			name: "CustomAuthShouldAlwaysPass",
			config: AuthConfig{
				Method:  AuthCustom,
				Headers: map[string]string{"X-Custom-Auth": "custom-value"},
			},
			expectError: false,
		},
		{
			name:          "UnsupportedAuthMethodShouldFail",
			config:        AuthConfig{Method: AuthMethod("unknown")},
			expectError:   true,
			errorContains: "Unsupported authentication method",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()

			if tc.expectError {
				assert.AssertError(err, tc.name)
				if tc.errorContains != "" {
					assert.AssertTrue(strings.Contains(err.Error(), tc.errorContains),
						"error message should contain: "+tc.errorContains)
				}
			} else {
				assert.AssertNoError(err, tc.name)
			}
		})
	}
}

// TestManagerConfig_Validate_DuplicatePluginNames tests duplicate name detection
func TestManagerConfig_Validate_DuplicatePluginNames(t *testing.T) {
	assert := NewTestAssertions(t)

	// Create two plugins with the same name
	plugin1 := TestData.CreateValidPluginConfig("duplicate-name")
	plugin2 := TestData.CreateValidPluginConfig("duplicate-name")

	config := ManagerConfig{
		Plugins: []PluginConfig{plugin1, plugin2},
	}

	err := config.Validate()
	assert.AssertError(err, "duplicate plugin names should be rejected")
	assert.AssertTrue(strings.Contains(err.Error(), "Duplicate plugin name"),
		"error should mention duplicate plugin name")
}

// TestManagerConfig_Validate_EmptyPluginsList tests empty plugins validation
func TestManagerConfig_Validate_EmptyPluginsList(t *testing.T) {
	assert := NewTestAssertions(t)

	config := ManagerConfig{
		Plugins: []PluginConfig{},
	}

	err := config.Validate()
	assert.AssertError(err, "empty plugins list should be rejected")
	assert.AssertTrue(strings.Contains(err.Error(), "No plugins configured"),
		"error should mention plugin requirement")
}

// TestManagerConfig_ApplyDefaults_ComprehensiveDefaults tests all default applications
func TestManagerConfig_ApplyDefaults_ComprehensiveDefaults(t *testing.T) {
	assert := NewTestAssertions(t)

	// Create a plugin with minimal configuration
	plugin := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportHTTP,
		Endpoint:  "http://localhost:8080",
		// Leave all other fields empty to test defaults
	}

	// Create manager config with defaults
	config := ManagerConfig{
		DefaultRetry: RetryConfig{
			MaxRetries:      5,
			InitialInterval: 200 * time.Millisecond,
			MaxInterval:     10 * time.Second,
			Multiplier:      2.5,
		},
		DefaultCircuitBreaker: CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 10,
		},
		DefaultHealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 60 * time.Second,
		},
		DefaultConnection: ConnectionConfig{
			MaxConnections: 20,
			RequestTimeout: 45 * time.Second,
		},
		DefaultRateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 15.0,
			BurstSize:         30,
		},
		Plugins: []PluginConfig{plugin},
	}

	// Apply defaults
	config.ApplyDefaults()

	// Verify that defaults were applied
	appliedPlugin := config.Plugins[0]

	// Check auth default
	assert.AssertEqual(AuthNone, appliedPlugin.Auth.Method, "auth method default")

	// Check retry defaults
	assert.AssertEqual(5, appliedPlugin.Retry.MaxRetries, "retry max retries default")
	assert.AssertEqual(200*time.Millisecond, appliedPlugin.Retry.InitialInterval, "retry initial interval default")

	// Check circuit breaker defaults
	assert.AssertTrue(appliedPlugin.CircuitBreaker.Enabled, "circuit breaker enabled default")
	assert.AssertEqual(10, appliedPlugin.CircuitBreaker.FailureThreshold, "circuit breaker failure threshold default")

	// Check health check defaults
	assert.AssertTrue(appliedPlugin.HealthCheck.Enabled, "health check enabled default")
	assert.AssertEqual(60*time.Second, appliedPlugin.HealthCheck.Interval, "health check interval default")

	// Check connection defaults
	assert.AssertEqual(20, appliedPlugin.Connection.MaxConnections, "connection max connections default")
	assert.AssertEqual(45*time.Second, appliedPlugin.Connection.RequestTimeout, "connection request timeout default")

	// Check rate limit defaults
	assert.AssertTrue(appliedPlugin.RateLimit.Enabled, "rate limit enabled default")
	assert.AssertEqual(15.0, appliedPlugin.RateLimit.RequestsPerSecond, "rate limit requests per second default")
}

// TestManagerConfig_ApplyDefaults_PreserveExistingValues tests that existing values are preserved
func TestManagerConfig_ApplyDefaults_PreserveExistingValues(t *testing.T) {
	assert := NewTestAssertions(t)

	// Create a plugin with existing configuration
	plugin := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportHTTP,
		Endpoint:  "http://localhost:8080",
		Auth:      AuthConfig{Method: AuthAPIKey, APIKey: "existing-key"},
		Retry:     RetryConfig{MaxRetries: 7}, // Existing non-zero value
		CircuitBreaker: CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 15, // Existing value
		},
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 90 * time.Second, // Existing value
		},
		Connection: ConnectionConfig{
			MaxConnections: 25, // Existing non-zero value
		},
		RateLimit: RateLimitConfig{
			Enabled: true, // Already enabled
		},
	}

	// Create manager config with different defaults
	config := ManagerConfig{
		DefaultRetry: RetryConfig{
			MaxRetries: 3, // Different from plugin value
		},
		DefaultCircuitBreaker: CircuitBreakerConfig{
			Enabled:          false, // Different from plugin value
			FailureThreshold: 5,     // Different from plugin value
		},
		DefaultHealthCheck: HealthCheckConfig{
			Enabled:  false,            // Different from plugin value
			Interval: 30 * time.Second, // Different from plugin value
		},
		DefaultConnection: ConnectionConfig{
			MaxConnections: 10, // Different from plugin value
		},
		DefaultRateLimit: RateLimitConfig{
			Enabled: false, // Different from plugin value
		},
		Plugins: []PluginConfig{plugin},
	}

	// Apply defaults
	config.ApplyDefaults()

	// Verify that existing values were preserved
	appliedPlugin := config.Plugins[0]

	assert.AssertEqual(AuthAPIKey, appliedPlugin.Auth.Method, "existing auth method preserved")
	assert.AssertEqual("existing-key", appliedPlugin.Auth.APIKey, "existing API key preserved")

	// Retry should NOT be overridden because MaxRetries is non-zero
	assert.AssertEqual(7, appliedPlugin.Retry.MaxRetries, "existing retry config preserved")

	// Circuit breaker should NOT be overridden because it's already enabled
	assert.AssertTrue(appliedPlugin.CircuitBreaker.Enabled, "existing circuit breaker enabled preserved")
	assert.AssertEqual(15, appliedPlugin.CircuitBreaker.FailureThreshold, "existing failure threshold preserved")

	// Health check should NOT be overridden because it's already enabled
	assert.AssertTrue(appliedPlugin.HealthCheck.Enabled, "existing health check enabled preserved")
	assert.AssertEqual(90*time.Second, appliedPlugin.HealthCheck.Interval, "existing health check interval preserved")

	// Connection should NOT be overridden because MaxConnections is non-zero
	assert.AssertEqual(25, appliedPlugin.Connection.MaxConnections, "existing max connections preserved")

	// Rate limit should NOT be overridden because it's already enabled
	assert.AssertTrue(appliedPlugin.RateLimit.Enabled, "existing rate limit enabled preserved")
}

// TestManagerConfig_JSON_SerializationRoundTrip tests JSON serialization and deserialization
func TestManagerConfig_JSON_SerializationRoundTrip(t *testing.T) {
	assert := NewTestAssertions(t)

	// Create a complex configuration
	originalConfig := ManagerConfig{
		LogLevel:    "debug",
		MetricsPort: 9091,
		DefaultRetry: RetryConfig{
			MaxRetries:      5,
			InitialInterval: 250 * time.Millisecond,
			MaxInterval:     15 * time.Second,
			Multiplier:      2.2,
			RandomJitter:    true,
		},
		Plugins: []PluginConfig{
			{
				Name:      "plugin1",
				Transport: TransportHTTPS,
				Endpoint:  "https://api1.example.com",
				Auth: AuthConfig{
					Method: AuthBearer,
					Token:  "jwt-token-123",
				},
				Options: map[string]interface{}{
					"custom_option": "value",
					"number":        42,
				},
				Labels: map[string]string{
					"env":     "production",
					"version": "1.0",
				},
			},
			{
				Name:       "plugin2",
				Transport:  TransportExecutable,
				Executable: "/usr/local/bin/plugin2",
				Args:       []string{"--verbose", "--config=/etc/plugin2.conf"},
				Env:        []string{"ENV=test", "DEBUG=true"},
				WorkDir:    "/tmp",
				Auth:       AuthConfig{Method: AuthNone}, // Add required auth field
			},
		},
	}

	// Serialize to JSON
	jsonData, err := originalConfig.ToJSON()
	assert.AssertNoError(err, "JSON serialization")

	// Verify that JSON is valid by unmarshaling to generic interface
	var jsonObj interface{}
	err = json.Unmarshal(jsonData, &jsonObj)
	assert.AssertNoError(err, "JSON validity check")

	// Deserialize back to ManagerConfig
	var deserializedConfig ManagerConfig
	err = deserializedConfig.FromJSON(jsonData)
	assert.AssertNoError(err, "JSON deserialization")

	// Verify critical fields were preserved
	assert.AssertEqual(originalConfig.LogLevel, deserializedConfig.LogLevel, "log level preservation")
	assert.AssertEqual(originalConfig.MetricsPort, deserializedConfig.MetricsPort, "metrics port preservation")
	assert.AssertEqual(len(originalConfig.Plugins), len(deserializedConfig.Plugins), "plugins count preservation")

	// Verify first plugin details
	orig1 := originalConfig.Plugins[0]
	deser1 := deserializedConfig.Plugins[0]
	assert.AssertEqual(orig1.Name, deser1.Name, "plugin1 name preservation")
	assert.AssertEqual(orig1.Transport, deser1.Transport, "plugin1 transport preservation")
	assert.AssertEqual(orig1.Endpoint, deser1.Endpoint, "plugin1 endpoint preservation")
	assert.AssertEqual(orig1.Auth.Method, deser1.Auth.Method, "plugin1 auth method preservation")
	assert.AssertEqual(orig1.Auth.Token, deser1.Auth.Token, "plugin1 auth token preservation")

	// Verify second plugin details
	orig2 := originalConfig.Plugins[1]
	deser2 := deserializedConfig.Plugins[1]
	assert.AssertEqual(orig2.Name, deser2.Name, "plugin2 name preservation")
	assert.AssertEqual(orig2.Executable, deser2.Executable, "plugin2 executable preservation")
	assert.AssertEqual(len(orig2.Args), len(deser2.Args), "plugin2 args count preservation")
	if len(orig2.Args) > 0 && len(deser2.Args) > 0 {
		assert.AssertEqual(orig2.Args[0], deser2.Args[0], "plugin2 first arg preservation")
	}
}

// TestManagerConfig_JSON_InvalidJSONHandling tests error handling for invalid JSON
func TestManagerConfig_JSON_InvalidJSONHandling(t *testing.T) {
	assert := NewTestAssertions(t)

	testCases := []struct {
		name        string
		jsonData    string
		shouldError bool
	}{
		{
			name:        "InvalidJSONSyntax",
			jsonData:    `{"invalid": json}`,
			shouldError: true,
		},
		{
			name:        "MissingRequiredFields",
			jsonData:    `{"log_level": "info"}`, // Missing plugins
			shouldError: true,
		},
		{
			name:        "InvalidPluginConfiguration",
			jsonData:    `{"plugins": [{"name": "test"}]}`, // Missing transport
			shouldError: true,
		},
		{
			name:        "EmptyJSON",
			jsonData:    `{}`,
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var config ManagerConfig
			err := config.FromJSON([]byte(tc.jsonData))

			if tc.shouldError {
				assert.AssertError(err, tc.name)
			} else {
				assert.AssertNoError(err, tc.name)
			}
		})
	}
}

// TestGetDefaultManagerConfig_DefaultValues tests that default configuration has reasonable values
func TestGetDefaultManagerConfig_DefaultValues(t *testing.T) {
	assert := NewTestAssertions(t)

	config := GetDefaultManagerConfig()

	// Verify basic settings
	assert.AssertEqual("info", config.LogLevel, "default log level")
	assert.AssertEqual(9090, config.MetricsPort, "default metrics port")

	// Verify default retry settings are reasonable
	assert.AssertTrue(config.DefaultRetry.MaxRetries > 0, "default retry max retries > 0")
	assert.AssertTrue(config.DefaultRetry.InitialInterval > 0, "default retry initial interval > 0")
	assert.AssertTrue(config.DefaultRetry.MaxInterval > config.DefaultRetry.InitialInterval,
		"default retry max interval > initial interval")
	assert.AssertTrue(config.DefaultRetry.Multiplier >= 1.0, "default retry multiplier >= 1.0")

	// Verify default circuit breaker settings
	assert.AssertTrue(config.DefaultCircuitBreaker.Enabled, "default circuit breaker enabled")
	assert.AssertTrue(config.DefaultCircuitBreaker.FailureThreshold > 0, "default circuit breaker failure threshold > 0")
	assert.AssertTrue(config.DefaultCircuitBreaker.RecoveryTimeout > 0, "default circuit breaker recovery timeout > 0")

	// Verify default health check settings
	assert.AssertTrue(config.DefaultHealthCheck.Enabled, "default health check enabled")
	assert.AssertTrue(config.DefaultHealthCheck.Interval > 0, "default health check interval > 0")
	assert.AssertTrue(config.DefaultHealthCheck.Timeout > 0, "default health check timeout > 0")
	assert.AssertTrue(config.DefaultHealthCheck.FailureLimit > 0, "default health check failure limit > 0")

	// Verify default connection settings
	assert.AssertTrue(config.DefaultConnection.MaxConnections > 0, "default connection max connections > 0")
	assert.AssertTrue(config.DefaultConnection.RequestTimeout > 0, "default connection request timeout > 0")
	assert.AssertTrue(config.DefaultConnection.KeepAlive, "default connection keep alive enabled")

	// Verify plugins list is initialized (empty but not nil)
	assert.AssertEqual(0, len(config.Plugins), "default plugins list should be empty")
}

// BenchmarkConfigValidation_Performance benchmarks configuration validation performance
func BenchmarkConfigValidation_Performance(b *testing.B) {
	// Create a complex but valid configuration
	config := PluginConfig{
		Name:      "benchmark-plugin",
		Transport: TransportHTTPS,
		Endpoint:  "https://api.example.com/v1/benchmark",
		Auth: AuthConfig{
			Method:   AuthMTLS,
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
			CAFile:   "/path/to/ca.pem",
		},
		Retry: RetryConfig{
			MaxRetries:      5,
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     30 * time.Second,
			Multiplier:      2.0,
			RandomJitter:    true,
		},
		CircuitBreaker: CircuitBreakerConfig{
			Enabled:             true,
			FailureThreshold:    10,
			RecoveryTimeout:     60 * time.Second,
			MinRequestThreshold: 5,
			SuccessThreshold:    3,
		},
		Options: map[string]interface{}{
			"timeout":     30000,
			"retries":     3,
			"compression": true,
		},
		Labels: map[string]string{
			"env":        "production",
			"datacenter": "us-west-2",
			"version":    "1.2.3",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := config.Validate()
		if err != nil {
			b.Fatal(err)
		}
	}
}
