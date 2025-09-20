// config_auth_validation_test.go: Comprehensive test suite for authentication validation
//
// These tests ensure that authentication configuration validation works correctly
// for all supported auth methods with proper error handling and edge cases.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"testing"

	"github.com/agilira/go-errors"
)

// TestAuthConfig_ValidateAPIKeyAuth tests API key authentication validation
func TestAuthConfig_ValidateAPIKeyAuth(t *testing.T) {
	tests := []struct {
		name      string
		config    AuthConfig
		expectErr bool
		errType   string
	}{
		{
			name: "valid_api_key_auth",
			config: AuthConfig{
				Method: AuthAPIKey,
				APIKey: "valid-api-key-123",
			},
			expectErr: false,
		},
		{
			name: "empty_api_key",
			config: AuthConfig{
				Method: AuthAPIKey,
				APIKey: "",
			},
			expectErr: true,
			errType:   "MissingAPIKey",
		},
		{
			name: "whitespace_only_api_key",
			config: AuthConfig{
				Method: AuthAPIKey,
				APIKey: "   ",
			},
			expectErr: false, // Current implementation doesn't trim whitespace
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateAPIKeyAuth()

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for %s, but got nil", tt.name)
					return
				}

				// Verify error type if specified
				if tt.errType != "" {
					if tt.errType == "MissingAPIKey" {
						if _, ok := err.(*errors.Error); !ok {
							t.Errorf("Expected MissingAPIKeyError, got %T: %v", err, err)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}

// TestAuthConfig_ValidateBearerAuth tests Bearer token authentication validation
func TestAuthConfig_ValidateBearerAuth(t *testing.T) {
	tests := []struct {
		name      string
		config    AuthConfig
		expectErr bool
		errType   string
	}{
		{
			name: "valid_bearer_token",
			config: AuthConfig{
				Method: AuthBearer,
				Token:  "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
			expectErr: false,
		},
		{
			name: "valid_simple_token",
			config: AuthConfig{
				Method: AuthBearer,
				Token:  "simple-token-123",
			},
			expectErr: false,
		},
		{
			name: "empty_bearer_token",
			config: AuthConfig{
				Method: AuthBearer,
				Token:  "",
			},
			expectErr: true,
			errType:   "MissingBearerToken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateBearerAuth()

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for %s, but got nil", tt.name)
					return
				}

				if tt.errType == "MissingBearerToken" {
					if _, ok := err.(*errors.Error); !ok {
						t.Errorf("Expected MissingBearerTokenError, got %T: %v", err, err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}

// TestAuthConfig_ValidateBasicAuth tests Basic authentication validation
func TestAuthConfig_ValidateBasicAuth(t *testing.T) {
	tests := []struct {
		name      string
		config    AuthConfig
		expectErr bool
		errType   string
	}{
		{
			name: "valid_basic_auth",
			config: AuthConfig{
				Method:   AuthBasic,
				Username: "admin",
				Password: "secure-password-123",
			},
			expectErr: false,
		},
		{
			name: "missing_username",
			config: AuthConfig{
				Method:   AuthBasic,
				Username: "",
				Password: "password",
			},
			expectErr: true,
			errType:   "MissingBasicCredentials",
		},
		{
			name: "missing_password",
			config: AuthConfig{
				Method:   AuthBasic,
				Username: "user",
				Password: "",
			},
			expectErr: true,
			errType:   "MissingBasicCredentials",
		},
		{
			name: "both_missing",
			config: AuthConfig{
				Method:   AuthBasic,
				Username: "",
				Password: "",
			},
			expectErr: true,
			errType:   "MissingBasicCredentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateBasicAuth()

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for %s, but got nil", tt.name)
					return
				}

				if tt.errType == "MissingBasicCredentials" {
					if _, ok := err.(*errors.Error); !ok {
						t.Errorf("Expected MissingBasicCredentialsError, got %T: %v", err, err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}

// TestAuthConfig_ValidateMTLSAuth tests mTLS authentication validation
func TestAuthConfig_ValidateMTLSAuth(t *testing.T) {
	tests := []struct {
		name      string
		config    AuthConfig
		expectErr bool
		errType   string
	}{
		{
			name: "valid_mtls_auth",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "/path/to/client.crt",
				KeyFile:  "/path/to/client.key",
				CAFile:   "/path/to/ca.crt", // Optional
			},
			expectErr: false,
		},
		{
			name: "valid_mtls_without_ca",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "/path/to/client.crt",
				KeyFile:  "/path/to/client.key",
				// CAFile is optional
			},
			expectErr: false,
		},
		{
			name: "missing_cert_file",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "",
				KeyFile:  "/path/to/client.key",
			},
			expectErr: true,
			errType:   "MissingMTLSCerts",
		},
		{
			name: "missing_key_file",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "/path/to/client.crt",
				KeyFile:  "",
			},
			expectErr: true,
			errType:   "MissingMTLSCerts",
		},
		{
			name: "both_files_missing",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "",
				KeyFile:  "",
			},
			expectErr: true,
			errType:   "MissingMTLSCerts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateMTLSAuth()

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for %s, but got nil", tt.name)
					return
				}

				if tt.errType == "MissingMTLSCerts" {
					if _, ok := err.(*errors.Error); !ok {
						t.Errorf("Expected MissingMTLSCertsError, got %T: %v", err, err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}

// TestAuthConfig_Validate tests the main Validate method that orchestrates all auth validations
func TestAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    AuthConfig
		expectErr bool
		errType   string
	}{
		{
			name: "auth_none_valid",
			config: AuthConfig{
				Method: AuthNone,
			},
			expectErr: false,
		},
		{
			name: "auth_custom_valid",
			config: AuthConfig{
				Method: AuthCustom,
				Headers: map[string]string{
					"Custom-Auth": "custom-value",
				},
			},
			expectErr: false,
		},
		{
			name: "valid_api_key_method",
			config: AuthConfig{
				Method: AuthAPIKey,
				APIKey: "valid-key",
			},
			expectErr: false,
		},
		{
			name: "invalid_api_key_method",
			config: AuthConfig{
				Method: AuthAPIKey,
				APIKey: "",
			},
			expectErr: true,
			errType:   "MissingAPIKey",
		},
		{
			name: "valid_bearer_method",
			config: AuthConfig{
				Method: AuthBearer,
				Token:  "valid-token",
			},
			expectErr: false,
		},
		{
			name: "invalid_bearer_method",
			config: AuthConfig{
				Method: AuthBearer,
				Token:  "",
			},
			expectErr: true,
			errType:   "MissingBearerToken",
		},
		{
			name: "valid_basic_method",
			config: AuthConfig{
				Method:   AuthBasic,
				Username: "user",
				Password: "pass",
			},
			expectErr: false,
		},
		{
			name: "invalid_basic_method",
			config: AuthConfig{
				Method:   AuthBasic,
				Username: "user",
				Password: "",
			},
			expectErr: true,
			errType:   "MissingBasicCredentials",
		},
		{
			name: "valid_mtls_method",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "/path/to/cert",
				KeyFile:  "/path/to/key",
			},
			expectErr: false,
		},
		{
			name: "invalid_mtls_method",
			config: AuthConfig{
				Method:   AuthMTLS,
				CertFile: "/path/to/cert",
				KeyFile:  "",
			},
			expectErr: true,
			errType:   "MissingMTLSCerts",
		},
		{
			name: "unsupported_auth_method",
			config: AuthConfig{
				Method: "unsupported-method",
			},
			expectErr: true,
			errType:   "UnsupportedAuthMethod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for %s, but got nil", tt.name)
					return
				}

				// Verify error type if specified
				if tt.errType != "" {
					if _, ok := err.(*errors.Error); !ok {
						t.Errorf("Expected %s error, got %T: %v", tt.errType, err, err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}
