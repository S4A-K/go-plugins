package goplugins

import (
	"os"
	"runtime"
	"testing"
)

func TestLoadSecurityConfigFromEnv(t *testing.T) {
	// Set test environment variables
	if err := os.Setenv("GOPLUGINS_SECURITY_ENABLED", "true"); err != nil {
		t.Fatalf("Failed to set GOPLUGINS_SECURITY_ENABLED: %v", err)
	}
	if err := os.Setenv("GOPLUGINS_SECURITY_POLICY", "strict"); err != nil {
		t.Fatalf("Failed to set GOPLUGINS_SECURITY_POLICY: %v", err)
	}

	// Use platform-appropriate path
	whitelistPath := "/tmp/test.json"
	if runtime.GOOS == "windows" {
		whitelistPath = "C:\\temp\\test.json"
	}
	if err := os.Setenv("GOPLUGINS_WHITELIST_FILE", whitelistPath); err != nil {
		t.Fatalf("Failed to set GOPLUGINS_WHITELIST_FILE: %v", err)
	}

	defer func() {
		if err := os.Unsetenv("GOPLUGINS_SECURITY_ENABLED"); err != nil {
			t.Logf("Warning: Failed to unset GOPLUGINS_SECURITY_ENABLED: %v", err)
		}
		if err := os.Unsetenv("GOPLUGINS_SECURITY_POLICY"); err != nil {
			t.Logf("Warning: Failed to unset GOPLUGINS_SECURITY_POLICY: %v", err)
		}
		if err := os.Unsetenv("GOPLUGINS_WHITELIST_FILE"); err != nil {
			t.Logf("Warning: Failed to unset GOPLUGINS_WHITELIST_FILE: %v", err)
		}
	}()

	// Test loading from environment
	config, err := LoadSecurityConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadSecurityConfigFromEnv failed: %v", err)
	}

	// Verify configuration loaded correctly
	if !config.Enabled {
		t.Error("Expected Enabled=true from GOPLUGINS_SECURITY_ENABLED=true")
	}

	if config.Policy != SecurityPolicyStrict {
		t.Errorf("Expected Policy=SecurityPolicyStrict, got %v", config.Policy)
	}

	if config.WhitelistFile != whitelistPath {
		t.Errorf("Expected WhitelistFile='%s', got %s", whitelistPath, config.WhitelistFile)
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"true", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"enabled", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"off", false},
		{"disabled", false},
		{"invalid", false},
		{"", false},
	}

	for _, test := range tests {
		result := parseBool(test.input)
		if result != test.expected {
			t.Errorf("parseBool(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}
