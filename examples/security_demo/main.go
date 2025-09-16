// examples/security_demo/main.go: Complete security system demonstration
//
// This example demonstrates comprehensive usage of the plugin security system
// with whitelist, Argus hot-reload and audit trail.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	goplugins "github.com/agilira/go-plugins"
)

// DemoRequest represents a request structure for the security demo
type DemoRequest struct {
	Action string                 `json:"action"`
	Data   map[string]interface{} `json:"data"`
}

// DemoResponse represents a response structure for the security demo
type DemoResponse struct {
	Success bool                   `json:"success"`
	Result  map[string]interface{} `json:"result"`
	Error   string                 `json:"error,omitempty"`
}

func main() {
	fmt.Println("Plugin Security System Demo")
	fmt.Println("===========================")

	// Create temporary directory for example
	tempDir, err := os.MkdirTemp("", "goplugins_security_demo")
	if err != nil {
		log.Fatal("Failed to create temp directory:", err)
	}
	defer func() {
		fmt.Printf("Cleaning up temporary directory: %s\n", tempDir)
		_ = os.RemoveAll(tempDir) // Ignore cleanup errors
	}()

	fmt.Printf("Using temporary directory: %s\n", tempDir)

	// Create example whitelist
	whitelistFile := filepath.Join(tempDir, "security-whitelist.json")
	auditFile := filepath.Join(tempDir, "security-audit.jsonl")

	fmt.Println("\nCreating sample whitelist...")
	if err := goplugins.CreateSampleWhitelist(whitelistFile); err != nil {
		log.Fatal("Failed to create sample whitelist:", err)
	}
	fmt.Printf("Whitelist created: %s\n", whitelistFile)

	// Setup manager with security
	fmt.Println("\nSetting up plugin manager with security...")
	manager := setupSecureManager(whitelistFile, auditFile)

	// Show basic security information
	fmt.Println("\nSecurity system information:")
	config, err := manager.GetPluginSecurityConfig()
	if err != nil {
		fmt.Printf("ERROR: Failed to get security config: %v\n", err)
		return
	}

	fmt.Printf("Policy: %s\n", config.Policy.String())
	fmt.Printf("Hash Algorithm: %v\n", config.HashAlgorithm)
	fmt.Printf("Whitelist File: %s\n", whitelistFile)
	fmt.Printf("Audit File: %s\n", auditFile)

	fmt.Println("\nDemo completed successfully!")
}

func setupSecureManager(whitelistFile, auditFile string) *goplugins.Manager[DemoRequest, DemoResponse] {
	fmt.Println("Creating plugin manager...")

	// Create manager with nil logger to avoid logger type issues
	manager := goplugins.NewManager[DemoRequest, DemoResponse](nil)
	fmt.Println("Plugin manager created")

	// Complete security configuration
	securityConfig := goplugins.SecurityConfig{
		Enabled:       true,
		Policy:        goplugins.SecurityPolicyStrict,
		WhitelistFile: whitelistFile,
		WatchConfig:   false, // Disable Argus hot-reload for demo
		HashAlgorithm: goplugins.HashAlgorithmSHA256,
		MaxFileSize:   100 * 1024 * 1024, // 100MB
		AllowedTypes:  []string{"http", "grpc", "https"},
		AuditConfig: goplugins.SecurityAuditConfig{
			Enabled:   true,
			AuditFile: auditFile,
		},
	}

	// Enable security
	fmt.Println("Enabling plugin security...")
	if err := manager.EnablePluginSecurity(securityConfig); err != nil {
		log.Fatal("Failed to enable plugin security:", err)
	}
	fmt.Println("Plugin security enabled")

	return manager
}
