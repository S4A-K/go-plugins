// http_transport_comprehensive_test.go: Comprehensive tests for HTTP transport implementation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestHTTPPluginFactory_CreatePlugin_ValidConfiguration tests plugin creation with valid configs
func TestHTTPPluginFactory_CreatePlugin_ValidConfiguration(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	factory := NewHTTPPluginFactory[string, string]()

	testCases := []struct {
		name   string
		config PluginConfig
	}{
		{
			name: "BasicHTTPPlugin",
			config: PluginConfig{
				Name:      "basic-http",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8080/api",
				Auth:      AuthConfig{Method: AuthNone},
				Connection: ConnectionConfig{
					MaxConnections:     10,
					MaxIdleConnections: 5,
					IdleTimeout:        30 * time.Second,
					ConnectionTimeout:  10 * time.Second,
					RequestTimeout:     30 * time.Second,
					KeepAlive:          true,
				},
			},
		},
		{
			name: "HTTPSPluginWithAPIKey",
			config: PluginConfig{
				Name:      "https-api-key",
				Transport: TransportHTTPS,
				Endpoint:  "https://api.example.com/v1",
				Auth: AuthConfig{
					Method: AuthAPIKey,
					APIKey: "secret-api-key-123",
				},
			},
		},
		{
			name: "HTTPPluginWithRateLimit",
			config: PluginConfig{
				Name:      "http-rate-limited",
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8080/api",
				Auth:      AuthConfig{Method: AuthNone},
				RateLimit: RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 10.0,
					BurstSize:         20,
					TimeWindow:        time.Second,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plugin, err := factory.CreatePlugin(tc.config)
			assert.AssertNoError(err, "plugin creation")

			// Verify plugin info
			info := plugin.Info()
			assert.AssertEqual(tc.config.Name, info.Name, "plugin name")
			assert.AssertTrue(len(info.Capabilities) > 0, "plugin capabilities")

			// Test that plugin can be closed
			err = plugin.Close()
			assert.AssertNoError(err, "plugin close")
		})
	}

	_ = env // Silence unused variable
}

// TestHTTPPluginFactory_CreatePlugin_InvalidConfiguration tests plugin creation with invalid configs
func TestHTTPPluginFactory_CreatePlugin_InvalidConfiguration(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	factory := NewHTTPPluginFactory[string, string]()

	testCases := []struct {
		name          string
		config        PluginConfig
		errorContains string
	}{
		{
			name: "InvalidTransport",
			config: PluginConfig{
				Name:       "invalid-transport",
				Transport:  TransportExecutable, // Not supported by HTTP factory
				Executable: "/bin/test",         // Make it valid for general validation
				Auth:       AuthConfig{Method: AuthNone},
			},
			errorContains: "unsupported transport",
		},
		{
			name: "MissingName",
			config: PluginConfig{
				Transport: TransportHTTP,
				Endpoint:  "http://localhost:8080",
				Auth:      AuthConfig{Method: AuthNone},
			},
			errorContains: "Invalid plugin name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plugin, err := factory.CreatePlugin(tc.config)

			assert.AssertError(err, "invalid config should fail")
			assert.AssertTrue(plugin == nil, "plugin should be nil on error")

			if tc.errorContains != "" {
				t.Logf("Error received: %v", err.Error()) // Debug log
				assert.AssertTrue(strings.Contains(err.Error(), tc.errorContains),
					"error should contain: "+tc.errorContains)
			}
		})
	}

	_ = env // Silence unused variable
}

// TestHTTPPluginFactory_SupportedTransports tests supported transport listing
func TestHTTPPluginFactory_SupportedTransports(t *testing.T) {
	assert := NewTestAssertions(t)

	factory := NewHTTPPluginFactory[string, string]()
	transports := factory.SupportedTransports()

	assert.AssertEqual(2, len(transports), "number of supported transports")
	assert.AssertTrue(contains(transports, string(TransportHTTP)), "HTTP transport supported")
	assert.AssertTrue(contains(transports, string(TransportHTTPS)), "HTTPS transport supported")
}

// TestHTTPPluginFactory_ValidateConfig tests configuration validation
func TestHTTPPluginFactory_ValidateConfig(t *testing.T) {
	assert := NewTestAssertions(t)

	factory := NewHTTPPluginFactory[string, string]()

	// Valid HTTP config
	validConfig := PluginConfig{
		Name:      "test",
		Transport: TransportHTTP,
		Endpoint:  "http://localhost:8080",
		Auth:      AuthConfig{Method: AuthNone},
	}

	err := factory.ValidateConfig(validConfig)
	assert.AssertNoError(err, "valid HTTP config")

	// Valid HTTPS config
	validConfig.Transport = TransportHTTPS
	validConfig.Endpoint = "https://localhost:8443"
	err = factory.ValidateConfig(validConfig)
	assert.AssertNoError(err, "valid HTTPS config")

	// Invalid transport
	invalidConfig := validConfig
	invalidConfig.Transport = TransportGRPC
	err = factory.ValidateConfig(invalidConfig)
	assert.AssertError(err, "invalid transport should fail")
}

// TestHTTPPlugin_Execute_SuccessfulRequest tests successful HTTP plugin execution
func TestHTTPPlugin_Execute_SuccessfulRequest(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	// Create mock HTTP server
	mockServer := env.CreateMockHTTPServer(nil) // Use default handler
	defer mockServer.Close()

	// Create plugin with string types to match default response
	factory := NewHTTPPluginFactory[string, string]()
	config := PluginConfig{
		Name:      "test-plugin",
		Transport: TransportHTTP,
		Endpoint:  mockServer.URL,
		Auth:      AuthConfig{Method: AuthNone},
	}

	plugin, err := factory.CreatePlugin(config)
	assert.AssertNoError(err, "plugin creation")

	// Execute request
	ctx := context.Background()
	execCtx := TestData.CreateExecutionContext()
	request := "test-data"

	response, err := plugin.Execute(ctx, execCtx, request)
	assert.AssertNoError(err, "plugin execution")

	// Verify response
	assert.AssertEqual("ok", response, "response data")

	// Verify server received the request
	requests := mockServer.GetRequests()
	assert.AssertEqual(1, len(requests), "server should receive one request")

	req := requests[0]
	assert.AssertEqual("POST", req.Method, "request method")
	assert.AssertEqual("application/json", req.Header.Get("Content-Type"), "content type header")
	assert.AssertEqual(execCtx.RequestID, req.Header.Get("X-Request-ID"), "request ID header")
}

// TestHTTPPlugin_Execute_WithAuthentication tests all authentication methods
func TestHTTPPlugin_Execute_WithAuthentication(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	testCases := []struct {
		name           string
		auth           AuthConfig
		expectedHeader string
		expectedValue  string
	}{
		{
			name:           "APIKeyAuthentication",
			auth:           AuthConfig{Method: AuthAPIKey, APIKey: "test-api-key"},
			expectedHeader: "X-API-Key",
			expectedValue:  "test-api-key",
		},
		{
			name:           "BearerAuthentication",
			auth:           AuthConfig{Method: AuthBearer, Token: "jwt-token-123"},
			expectedHeader: "Authorization",
			expectedValue:  "Bearer jwt-token-123",
		},
		{
			name:           "BasicAuthentication",
			auth:           AuthConfig{Method: AuthBasic, Username: "testuser", Password: "testpass"},
			expectedHeader: "Authorization",
			expectedValue:  "Basic dGVzdHVzZXI6dGVzdHBhc3M=", // base64(testuser:testpass)
		},
		{
			name: "CustomAuthentication",
			auth: AuthConfig{
				Method: AuthCustom,
				Headers: map[string]string{
					"X-Custom-Auth": "custom-value",
				},
			},
			expectedHeader: "X-Custom-Auth",
			expectedValue:  "custom-value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			mockServer := env.CreateMockHTTPServer(nil)
			defer mockServer.Close()

			// Create plugin with authentication
			factory := NewHTTPPluginFactory[string, string]()
			config := PluginConfig{
				Name:      "auth-test-plugin",
				Transport: TransportHTTP,
				Endpoint:  mockServer.URL,
				Auth:      tc.auth,
			}

			plugin, err := factory.CreatePlugin(config)
			assert.AssertNoError(err, "plugin creation")

			// Execute request
			ctx := context.Background()
			execCtx := TestData.CreateExecutionContext()

			_, err = plugin.Execute(ctx, execCtx, "test-data")
			assert.AssertNoError(err, "plugin execution")

			// Verify authentication header was sent
			requests := mockServer.GetRequests()
			assert.AssertEqual(1, len(requests), "server should receive one request")

			req := requests[0]
			actualValue := req.Header.Get(tc.expectedHeader)
			assert.AssertEqual(tc.expectedValue, actualValue, "authentication header value")
		})
	}
}

// TestHTTPPlugin_Execute_HTTPSWithTLS tests HTTPS plugin execution
func TestHTTPPlugin_Execute_HTTPSWithTLS(t *testing.T) {
	// Skip HTTPS test for now since it requires proper certificate setup
	t.Skip("HTTPS test requires proper certificate setup - covered in integration tests")
}

// TestHTTPPlugin_Execute_ErrorHandling tests various error scenarios
func TestHTTPPlugin_Execute_ErrorHandling(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	testCases := []struct {
		name          string
		setupServer   func() *MockHTTPServer
		expectError   bool
		errorContains string
	}{
		{
			name: "ServerReturns4xxError",
			setupServer: func() *MockHTTPServer {
				server := env.CreateMockHTTPServer(nil)
				server.SetResponse("POST", "/", MockResponse{
					StatusCode: http.StatusBadRequest,
					Body:       "Bad Request",
				})
				return server
			},
			expectError:   true,
			errorContains: "HTTP request failed with status 400",
		},
		{
			name: "ServerReturns5xxError",
			setupServer: func() *MockHTTPServer {
				server := env.CreateMockHTTPServer(nil)
				server.SetResponse("POST", "/", MockResponse{
					StatusCode: http.StatusInternalServerError,
					Body:       "Internal Server Error",
				})
				return server
			},
			expectError:   true,
			errorContains: "HTTP request failed with status 500",
		},
		{
			name: "ServerReturnsPluginError",
			setupServer: func() *MockHTTPServer {
				server := env.CreateMockHTTPServer(nil)
				server.SetResponse("POST", "/", MockResponse{
					StatusCode: http.StatusOK,
					Body: HTTPPluginResponse[string]{
						Error:     "Plugin execution failed",
						RequestID: "test-request",
					},
				})
				return server
			},
			expectError:   true,
			errorContains: "plugin error: Plugin execution failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := tc.setupServer()
			defer mockServer.Close()

			// Create plugin
			factory := NewHTTPPluginFactory[string, string]()
			config := PluginConfig{
				Name:      "error-test-plugin",
				Transport: TransportHTTP,
				Endpoint:  mockServer.URL,
				Auth:      AuthConfig{Method: AuthNone},
			}

			plugin, err := factory.CreatePlugin(config)
			assert.AssertNoError(err, "plugin creation")

			// Execute request
			ctx := context.Background()
			execCtx := TestData.CreateExecutionContext()

			_, err = plugin.Execute(ctx, execCtx, "test-data")

			if tc.expectError {
				assert.AssertError(err, "should return error")
				if tc.errorContains != "" {
					assert.AssertTrue(strings.Contains(err.Error(), tc.errorContains),
						"error should contain: "+tc.errorContains)
				}
			} else {
				assert.AssertNoError(err, "should not return error")
			}
		})
	}
}

// TestHTTPPlugin_Execute_WithTimeout tests request timeout handling
func TestHTTPPlugin_Execute_WithTimeout(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	// Create mock server with delay
	mockServer := env.CreateMockHTTPServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Delay longer than timeout
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(HTTPPluginResponse[string]{
			Data:      "delayed response",
			RequestID: r.Header.Get("X-Request-ID"),
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})
	defer mockServer.Close()

	// Create plugin with short timeout
	factory := NewHTTPPluginFactory[string, string]()
	config := PluginConfig{
		Name:      "timeout-test-plugin",
		Transport: TransportHTTP,
		Endpoint:  mockServer.URL,
		Auth:      AuthConfig{Method: AuthNone},
		Connection: ConnectionConfig{
			RequestTimeout: 50 * time.Millisecond, // Shorter than server delay
		},
	}

	plugin, err := factory.CreatePlugin(config)
	assert.AssertNoError(err, "plugin creation")

	// Execute request - should timeout
	ctx := context.Background()
	execCtx := TestData.CreateExecutionContext()
	execCtx.Timeout = 50 * time.Millisecond

	_, err = plugin.Execute(ctx, execCtx, "test-data")
	assert.AssertError(err, "should timeout")
}

// TestRateLimiter_BasicFunctionality tests rate limiter functionality
func TestRateLimiter_BasicFunctionality(t *testing.T) {
	assert := NewTestAssertions(t)

	// Create rate limiter with 2 requests per second, burst size 3
	config := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 2.0,
		BurstSize:         3,
		TimeWindow:        time.Second,
	}

	limiter := NewRateLimiter(config)

	// First 3 requests should be allowed immediately (burst)
	assert.AssertTrue(limiter.Allow(), "first request should be allowed")
	assert.AssertTrue(limiter.Allow(), "second request should be allowed")
	assert.AssertTrue(limiter.Allow(), "third request should be allowed")

	// Fourth request should be denied (burst exhausted)
	assert.AssertFalse(limiter.Allow(), "fourth request should be denied")

	// Wait for token refill (500ms = 1 token at 2 req/sec)
	time.Sleep(550 * time.Millisecond)

	// Now one more request should be allowed
	assert.AssertTrue(limiter.Allow(), "request after refill should be allowed")
}

// TestRateLimiter_DisabledRateLimiter tests disabled rate limiter
func TestRateLimiter_DisabledRateLimiter(t *testing.T) {
	assert := NewTestAssertions(t)

	config := RateLimitConfig{
		Enabled: false, // Disabled
	}

	limiter := NewRateLimiter(config)

	// All requests should be allowed when disabled
	for i := 0; i < 100; i++ {
		assert.AssertTrue(limiter.Allow(), "all requests should be allowed when disabled")
	}
}

// TestHTTPPlugin_Execute_WithRateLimit tests plugin execution with rate limiting
func TestHTTPPlugin_Execute_WithRateLimit(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	// Create mock server
	mockServer := env.CreateMockHTTPServer(nil)
	defer mockServer.Close()

	// Create plugin with rate limiting
	factory := NewHTTPPluginFactory[string, string]()
	config := PluginConfig{
		Name:      "rate-limited-plugin",
		Transport: TransportHTTP,
		Endpoint:  mockServer.URL,
		Auth:      AuthConfig{Method: AuthNone},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1.0, // 1 request per second
			BurstSize:         1,   // Only 1 request allowed initially
		},
	}

	plugin, err := factory.CreatePlugin(config)
	assert.AssertNoError(err, "plugin creation")

	ctx := context.Background()
	execCtx := TestData.CreateExecutionContext()

	// First request should succeed
	_, err = plugin.Execute(ctx, execCtx, "test-data-1")
	assert.AssertNoError(err, "first request should succeed")

	// Second request should be rate limited
	_, err = plugin.Execute(ctx, execCtx, "test-data-2")
	assert.AssertError(err, "second request should be rate limited")
	assert.AssertTrue(strings.Contains(err.Error(), "rate limit exceeded"), "error should mention rate limit")
}

// TestHTTPPlugin_Health_HealthCheckEndpoint tests health check functionality
func TestHTTPPlugin_Health_HealthCheckEndpoint(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	testCases := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		expectedStatus PluginStatus
	}{
		{
			name: "HealthyEndpoint",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte("OK")); err != nil {
					// Log error but don't fail in closure - let test handle it
					t.Logf("Warning: Failed to write response: %v", err)
				}
			},
			expectedStatus: StatusHealthy,
		},
		{
			name: "UnhealthyEndpoint",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				if _, err := w.Write([]byte("Service Unavailable")); err != nil {
					// Log error but don't fail in closure - let test handle it
					t.Logf("Warning: Failed to write response: %v", err)
				}
			},
			expectedStatus: StatusUnhealthy,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server with custom health endpoint
			mockServer := env.CreateMockHTTPServer(tc.serverResponse)
			defer mockServer.Close()

			// Create plugin
			factory := NewHTTPPluginFactory[string, string]()
			config := PluginConfig{
				Name:      "health-test-plugin",
				Transport: TransportHTTP,
				Endpoint:  mockServer.URL,
				Auth:      AuthConfig{Method: AuthNone},
				HealthCheck: HealthCheckConfig{
					Endpoint: mockServer.URL + "/health",
				},
			}

			plugin, err := factory.CreatePlugin(config)
			assert.AssertNoError(err, "plugin creation")

			// Check health
			ctx := context.Background()
			status := plugin.Health(ctx)

			assert.AssertEqual(tc.expectedStatus, status.Status, "health status")
			assert.AssertTrue(status.LastCheck.After(time.Now().Add(-time.Second)), "last check time")
			assert.AssertTrue(status.ResponseTime >= 0, "response time should be non-negative")
		})
	}
}

// TestHTTPPlugin_ConcurrentExecution tests concurrent plugin execution
func TestHTTPPlugin_ConcurrentExecution(t *testing.T) {
	env := NewTestEnvironment(t)
	assert := NewTestAssertions(t)

	// Create mock server
	mockServer := env.CreateMockHTTPServer(nil)
	defer mockServer.Close()

	// Create plugin
	factory := NewHTTPPluginFactory[string, string]()
	config := PluginConfig{
		Name:      "concurrent-test-plugin",
		Transport: TransportHTTP,
		Endpoint:  mockServer.URL,
		Auth:      AuthConfig{Method: AuthNone},
	}

	plugin, err := factory.CreatePlugin(config)
	assert.AssertNoError(err, "plugin creation")

	// Execute multiple concurrent requests
	const numRequests = 10
	var wg sync.WaitGroup
	errors := make([]error, numRequests)

	ctx := context.Background()

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			execCtx := TestData.CreateExecutionContext()
			execCtx.RequestID = execCtx.RequestID + "-" + string(rune('A'+index))

			_, err := plugin.Execute(ctx, execCtx, "concurrent-request")
			errors[index] = err
		}(i)
	}

	wg.Wait()

	// Verify all requests succeeded
	for i, err := range errors {
		if err != nil {
			t.Logf("Concurrent request %c failed: %v", rune('A'+i), err)
		}
		assert.AssertNoError(err, "concurrent request "+string(rune('A'+i)))
	}

	// Verify server received all requests
	requests := mockServer.GetRequests()
	assert.AssertEqual(numRequests, len(requests), "server should receive all concurrent requests")
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
