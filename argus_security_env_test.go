package goplugins

import (
	"os"
	"testing"
)

func TestLoadSecurityConfigFromEnv(t *testing.T) {
	// Set test environment variables
	os.Setenv("GOPLUGINS_SECURITY_ENABLED", "true")
	os.Setenv("GOPLUGINS_SECURITY_POLICY", "strict")
	os.Setenv("GOPLUGINS_WHITELIST_FILE", "/tmp/test.json")

	defer func() {
		os.Unsetenv("GOPLUGINS_SECURITY_ENABLED")
		os.Unsetenv("GOPLUGINS_SECURITY_POLICY")
		os.Unsetenv("GOPLUGINS_WHITELIST_FILE")
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

	if config.WhitelistFile != "/tmp/test.json" {
		t.Errorf("Expected WhitelistFile='/tmp/test.json', got %s", config.WhitelistFile)
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
