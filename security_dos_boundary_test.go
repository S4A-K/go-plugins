// security_dos_boundary_test.go: tests for DoS boundary conditions in security validation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestValidateWhitelistIntegrity_DoS_FileSizeBoundary verifies exact boundary condition
func TestValidateWhitelistIntegrity_DoS_FileSizeBoundary(t *testing.T) {
	// Setup: crea SecurityArgusIntegration con file whitelist temporaneo
	tmpFile, err := os.CreateTemp("", "whitelist_boundary_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("Warning: Failed to remove temp file: %v", err)
		}
	}()
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	integration := &SecurityArgusIntegration{
		whitelistFile: tmpFile.Name(),
		logger:        &testLogger{t: t},
	}

	// Test Case 1: Exact limit (10MB)
	t.Run("ExactlyAtLimit_10MB", func(t *testing.T) {
		maxSize := int64(10 * 1024 * 1024) // 10MB esatto

		// build a file of 10MB
		if err := createFileWithSize(tmpFile.Name(), maxSize); err != nil {
			t.Fatalf("Failed to create 10MB file: %v", err)
		}
		defer func() {
			if err := os.Remove(tmpFile.Name()); err != nil {
				t.Logf("Warning: Failed to remove temp file: %v", err)
			}
		}()

		// Should pass - file at maximum allowed size
		err := integration.ValidateWhitelistIntegrity()
		if err != nil {
			t.Errorf("ValidateWhitelistIntegrity failed for file at exact size limit: %v", err)
		}
	})

	// Test Case 2: 10MB File + 1 byte (boundary violation)
	t.Run("OneBytePastLimit_DoSAttempt", func(t *testing.T) {
		maxSize := int64(10*1024*1024) + 1 // 10MB + 1 byte

		// Create a file of 10MB + 1 byte to test boundary condition
		if err := createFileWithSize(tmpFile.Name(), maxSize); err != nil {
			t.Fatalf("Failed to create oversized file: %v", err)
		}
		defer func() {
			if err := os.Remove(tmpFile.Name()); err != nil {
				t.Logf("Warning: Failed to remove temp file: %v", err)
			}
		}()

		// Should fail - exceeds limit by 1 byte
		err := integration.ValidateWhitelistIntegrity()
		if err == nil {
			t.Error("ValidateWhitelistIntegrity should fail for file exceeding size limit by 1 byte")
		}

		// Verify that the error contains size information
		if err != nil && !strings.Contains(err.Error(), "too large") {
			t.Errorf("Error message should indicate file is too large, got: %v", err)
		}
	})

	// Test Case 3: Large file (potential DoS - 100MB)
	t.Run("LargeFile_DoSDetection", func(t *testing.T) {
		largeSize := int64(100 * 1024 * 1024) // 100MB

		// This test verifies that the function does not attempt to read the entire file
		// but only does stat() to check the size
		if err := createFileWithSize(tmpFile.Name(), largeSize); err != nil {
			t.Fatalf("Failed to create large file: %v", err)
		}
		defer func() {
			if err := os.Remove(tmpFile.Name()); err != nil {
				t.Logf("Warning: Failed to remove temp file: %v", err)
			}
		}()

		// Execution time should be fast (< 100ms) even with large file
		start := time.Now()
		err := integration.ValidateWhitelistIntegrity()
		duration := time.Since(start)

		if err == nil {
			t.Error("ValidateWhitelistIntegrity should reject large file")
		}

		// Performance check: should not take more than 100ms for large files
		if duration > 100*time.Millisecond {
			t.Errorf("ValidateWhitelistIntegrity too slow for large file: %v", duration)
		}
	})
}

// TestValidateWhitelistIntegrity_MemorySafety_NilPath verifies handling of nil/empty path
func TestValidateWhitelistIntegrity_MemorySafety_NilPath(t *testing.T) {
	// Test Case: SecurityArgusIntegration with empty whitelistFile (nil equivalent)
	integration := &SecurityArgusIntegration{
		whitelistFile: "", // Unconfigured path
		logger:        &testLogger{t: t},
	}

	err := integration.ValidateWhitelistIntegrity()

	// Should fail with specific error for missing configuration
	if err == nil {
		t.Error("ValidateWhitelistIntegrity should fail for unconfigured whitelist file")
	}

	// Verify that the error indicates missing configuration
	if err != nil && !strings.Contains(err.Error(), "not configured") {
		t.Errorf("Error should indicate missing configuration, got: %v", err)
	}
}

// TestValidateWhitelistIntegrity_SecurityBypass_SymlinkAttack verifies protection against symlink
func TestValidateWhitelistIntegrity_SecurityBypass_SymlinkAttack(t *testing.T) {
	// Setup: create large target file
	largeFile, err := os.CreateTemp("", "large_target_*.bin")
	if err != nil {
		t.Fatalf("Failed to create large target file: %v", err)
	}
	defer func() {
		if err := os.Remove(largeFile.Name()); err != nil {
			t.Logf("Warning: Failed to remove large file: %v", err)
		}
	}()

	// Create 50MB file (exceeds limit)
	if err := createFileWithSize(largeFile.Name(), 50*1024*1024); err != nil {
		t.Fatalf("Failed to create large target: %v", err)
	}

	// Setup: create symlink to large file
	symlinkFile, err := os.CreateTemp("", "whitelist_symlink_*.json")
	if err != nil {
		t.Fatalf("Failed to create symlink file: %v", err)
	}
	if err := os.Remove(symlinkFile.Name()); err != nil {
		t.Logf("Warning: Failed to remove temp file for symlink: %v", err)
	}

	// Create symlink (if supported by OS)
	if err := os.Symlink(largeFile.Name(), symlinkFile.Name()); err != nil {
		t.Skipf("Symlinks not supported on this system: %v", err)
	}
	defer func() {
		if err := os.Remove(symlinkFile.Name()); err != nil {
			t.Logf("Warning: Failed to remove symlink file: %v", err)
		}
	}()

	integration := &SecurityArgusIntegration{
		whitelistFile: symlinkFile.Name(),
		logger:        &testLogger{t: t},
	}

	// Should detect that the file (via symlink) exceeds the limit
	err = integration.ValidateWhitelistIntegrity()
	if err == nil {
		t.Error("ValidateWhitelistIntegrity should detect large file via symlink")
	}
}

// Helper functions
func createFileWithSize(filename string, size int64) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log error but don't return it since we might have another error to return
		}
	}()

	// Use Truncate to create file of specific size without writing data
	return file.Truncate(size)
}
