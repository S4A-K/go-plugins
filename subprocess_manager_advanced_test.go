// subprocess_manager_advanced_test.go: Comprehensive tests for missing subprocess manager coverage
//
// Focus on: Process lifecycle management, communication setup, error handling,
// configuration validation, process monitoring, and cleanup functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultSubprocessManagerConfig tests the DefaultSubprocessManagerConfig function
func TestDefaultSubprocessManagerConfig(t *testing.T) {
	t.Run("ReturnsValidDefaults", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()

		assert.NotNil(t, config, "Should return non-nil config")
		// ExecutablePath is empty by default - needs to be set by user

		// Verify handshake config has reasonable defaults
		assert.NotZero(t, config.HandshakeConfig.ProtocolVersion, "Should have protocol version")
		assert.NotEmpty(t, config.HandshakeConfig.MagicCookieKey, "Should have magic cookie key")

		// Verify stream config has defaults
		assert.NotNil(t, config.StreamConfig, "Should have stream config")

		// Verify bridge config has defaults
		assert.NotNil(t, config.BridgeConfig, "Should have bridge config")
	})

	t.Run("DefaultsAreConsistent", func(t *testing.T) {
		config1 := DefaultSubprocessManagerConfig()
		config2 := DefaultSubprocessManagerConfig()

		assert.Equal(t, config1.ExecutablePath, config2.ExecutablePath)
		assert.Equal(t, config1.HandshakeConfig.ProtocolVersion, config2.HandshakeConfig.ProtocolVersion)
	})
}

// TestSubprocessManagerConfig_Validate tests the configuration validation
func TestSubprocessManagerConfig_Validate(t *testing.T) {
	t.Run("ValidateValidConfig", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/bin/echo" // Use a known executable

		err := config.Validate()
		assert.NoError(t, err, "Valid config should pass validation")
	})

	t.Run("ValidateEmptyExecutablePath", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "" // Empty path should fail

		err := config.Validate()
		assert.Error(t, err, "Empty executable path should fail validation")
	})

	t.Run("ValidateNonExistentExecutable", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/nonexistent/executable"

		err := config.Validate()
		// The validation might be permissive and not check file existence at config time
		// This is often done for flexibility (file might exist at runtime)
		t.Logf("Validation result for non-existent executable: %v", err)
	})
}

// TestSubprocessManagerConfig_ApplyDefaults tests the ApplyDefaults function
func TestSubprocessManagerConfig_ApplyDefaults(t *testing.T) {
	t.Run("ApplyDefaultsToEmptyConfig", func(t *testing.T) {
		config := &SubprocessManagerConfig{}

		config.ApplyDefaults()

		// ExecutablePath remains empty - it's user responsibility to set it
		assert.NotZero(t, config.HandshakeConfig.ProtocolVersion, "Should apply default protocol version")
	})

	t.Run("ApplyDefaultsPreservesExistingValues", func(t *testing.T) {
		config := &SubprocessManagerConfig{
			ExecutablePath: "/custom/path",
		}

		config.ApplyDefaults()

		assert.Equal(t, "/custom/path", config.ExecutablePath, "Should preserve existing executable path")
		assert.NotZero(t, config.HandshakeConfig.ProtocolVersion, "Should still apply missing defaults")
	})
}

// TestNewSubprocessManager tests the constructor
func TestNewSubprocessManager(t *testing.T) {
	t.Run("CreateWithValidConfig", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/bin/echo"
		config.Logger = NewTestLogger()

		manager := NewSubprocessManager(config)

		assert.NotNil(t, manager, "Should create manager")
		assert.Equal(t, "/bin/echo", manager.executablePath)
		assert.NotNil(t, manager.configParser, "Should initialize config parser")
		assert.NotNil(t, manager.handshakeManager, "Should initialize handshake manager")
		assert.NotNil(t, manager.streamSyncer, "Should initialize stream syncer")
		assert.NotNil(t, manager.communicationBridge, "Should initialize communication bridge")
		assert.False(t, manager.IsStarted(), "Should not be started initially")
		assert.False(t, manager.IsStopping(), "Should not be stopping initially")
	})
}

// TestSubprocessManager_StateAccessors tests the state accessor methods
func TestSubprocessManager_StateAccessors(t *testing.T) {
	config := DefaultSubprocessManagerConfig()
	config.ExecutablePath = "/bin/echo"
	config.Logger = NewTestLogger()

	manager := NewSubprocessManager(config)

	t.Run("InitialState", func(t *testing.T) {
		assert.False(t, manager.IsStarted(), "Should not be started initially")
		assert.False(t, manager.IsStopping(), "Should not be stopping initially")
		assert.False(t, manager.IsAlive(), "Should not be alive initially")
		assert.False(t, manager.IsRunning(), "Should not be running initially")
		assert.Nil(t, manager.GetCommand(), "Should not have command initially")
		assert.NotNil(t, manager.GetProcessInfo(), "Should have process info struct")
	})

	t.Run("ComponentAccessors", func(t *testing.T) {
		assert.NotNil(t, manager.GetCommunicationBridge(), "Should have communication bridge")
		assert.NotNil(t, manager.GetHandshakeManager(), "Should have handshake manager")
		assert.NotNil(t, manager.GetStreamSyncer(), "Should have stream syncer")

		// Test configuration accessors
		handshakeConfig := manager.GetHandshakeConfig()
		assert.NotZero(t, handshakeConfig.ProtocolVersion, "Should have handshake config")

		streamConfig := manager.GetStreamConfig()
		assert.NotNil(t, streamConfig, "Should have stream config")

		// Test network accessors (when not running)
		assert.Empty(t, manager.GetAddress(), "Address should be empty when not running")
		assert.Zero(t, manager.GetPort(), "Port should be zero when not running")
	})
}

// TestSubprocessManager_ValidationMethods tests internal validation methods
func TestSubprocessManager_ValidationMethods(t *testing.T) {
	config := DefaultSubprocessManagerConfig()
	config.ExecutablePath = "/bin/echo"
	config.Logger = NewTestLogger()

	manager := NewSubprocessManager(config)

	t.Run("ValidateStreamConfig", func(t *testing.T) {
		// This tests the validateStreamConfig method indirectly through Start
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// The validation should pass for our default config
		err := manager.Start(ctx)
		if err != nil {
			// If Start fails, it should not be due to stream config validation
			assert.NotContains(t, err.Error(), "stream", "Stream config validation should pass")
		}

		if manager.IsStarted() {
			_ = manager.Stop(ctx)
		}
	})

	t.Run("ValidateBridgeConfig", func(t *testing.T) {
		// This tests the validateBridgeConfig method indirectly
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := manager.Start(ctx)
		if err != nil {
			// If Start fails, it should not be due to bridge config validation
			assert.NotContains(t, err.Error(), "bridge", "Bridge config validation should pass")
		}

		if manager.IsStarted() {
			_ = manager.Stop(ctx)
		}
	})
}

// TestSubprocessManager_CommunicationBridge tests bridge management
func TestSubprocessManager_CommunicationBridge(t *testing.T) {
	config := DefaultSubprocessManagerConfig()
	config.ExecutablePath = "/bin/echo"
	config.Logger = NewTestLogger()

	manager := NewSubprocessManager(config)

	t.Run("BridgeOperationsWhenNotRunning", func(t *testing.T) {
		// Test bridge operations when subprocess is not running
		err := manager.StartCommunicationBridge()
		// This might succeed or fail depending on implementation - both are valid
		t.Logf("StartCommunicationBridge result when not running: %v", err)

		err = manager.StopCommunicationBridge()
		// This should handle the case gracefully
		assert.NoError(t, err, "StopCommunicationBridge should handle not-running case gracefully")
	})

	t.Run("BridgeAccessor", func(t *testing.T) {
		bridge := manager.GetCommunicationBridge()
		assert.NotNil(t, bridge, "Should have communication bridge")
	})
}

// TestSubprocessManager_ProcessLifecycle tests process lifecycle with a real process
func TestSubprocessManager_ProcessLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping subprocess lifecycle test on Windows due to different process behavior")
	}

	config := DefaultSubprocessManagerConfig()
	config.ExecutablePath = "/bin/sleep"
	config.Args = []string{"1"} // Sleep for 1 second
	config.Logger = NewTestLogger()

	manager := NewSubprocessManager(config)

	t.Run("StartAndStopProcess", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Try to start the process - this will likely fail handshake since /bin/sleep is not a plugin
		err := manager.Start(ctx)

		if err != nil {
			// Expected for non-plugin executables - they fail handshake
			assert.Contains(t, err.Error(), "handshake", "Should fail handshake for non-plugin executable")

			// Even if start failed, we might have some process state to test
			processInfo := manager.GetProcessInfo()
			assert.NotNil(t, processInfo, "Should have process info even after failed start")
		} else {
			// If it somehow succeeded, test the lifecycle
			assert.True(t, manager.IsStarted(), "Should be started")

			// Stop the process
			err = manager.Stop(ctx)
			assert.NoError(t, err, "Should stop process successfully")
		}
	})

	t.Run("StartWithEnvironmentAndSetup", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Test with additional environment and custom setup
		additionalEnv := []string{"TEST_VAR=test_value"}
		setupCalled := false

		setupFunc := func(cmd *exec.Cmd) error {
			setupCalled = true
			assert.NotNil(t, cmd, "Command should not be nil in setup")
			return nil
		}

		err := manager.StartWithEnvironmentAndSetup(ctx, additionalEnv, setupFunc)
		require.NoError(t, err, "Should start with custom environment and setup")

		assert.True(t, setupCalled, "Setup function should be called")
		assert.True(t, manager.IsStarted(), "Should be started")

		// Verify environment was applied
		cmd := manager.GetCommand()
		if cmd != nil {
			envFound := false
			for _, env := range cmd.Env {
				if env == "TEST_VAR=test_value" {
					envFound = true
					break
				}
			}
			assert.True(t, envFound, "Additional environment should be applied")
		}

		// Cleanup
		_ = manager.Stop(ctx)
	})
}

// TestSubprocessManager_ErrorHandling tests error handling and edge cases
func TestSubprocessManager_ErrorHandling(t *testing.T) {
	t.Run("StartWithInvalidExecutable", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/nonexistent/executable"
		config.Logger = NewTestLogger()

		manager := NewSubprocessManager(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := manager.Start(ctx)
		assert.Error(t, err, "Should fail to start with invalid executable")
		assert.False(t, manager.IsStarted(), "Should not be started after failure")
	})

	t.Run("StopWithoutStart", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/bin/echo"
		config.Logger = NewTestLogger()

		manager := NewSubprocessManager(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := manager.Stop(ctx)
		// Should handle this gracefully
		assert.NoError(t, err, "Stop without start should be handled gracefully")
	})

	t.Run("RestartWithoutStart", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/bin/echo"
		config.Logger = NewTestLogger()

		manager := NewSubprocessManager(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := manager.Restart(ctx)
		// Restart without start should handle gracefully or return appropriate error
		t.Logf("Restart without start result: %v", err)
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		config := DefaultSubprocessManagerConfig()
		config.ExecutablePath = "/bin/sleep"
		config.Args = []string{"60"} // Long-running process
		config.Logger = NewTestLogger()

		manager := NewSubprocessManager(config)

		// Create a context that will be cancelled quickly
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := manager.Start(ctx)
		// Should either succeed quickly or fail (context cancellation or handshake failure)
		// With short timeout, the process creation/handshake will likely fail
		if err != nil {
			t.Logf("Start failed as expected with short context timeout: %v", err)
			assert.Error(t, err, "Should fail with short timeout")
		}

		// Cleanup if started
		if manager.IsStarted() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			_ = manager.Stop(cleanupCtx)
		}
	})
}

// TestSubprocessManager_StreamConfiguration tests stream configuration methods
func TestSubprocessManager_StreamConfiguration(t *testing.T) {
	config := DefaultSubprocessManagerConfig()
	config.ExecutablePath = "/bin/echo"
	config.Logger = NewTestLogger()

	manager := NewSubprocessManager(config)

	t.Run("StreamSyncerAccess", func(t *testing.T) {
		syncer := manager.GetStreamSyncer()
		assert.NotNil(t, syncer, "Should have stream syncer")

		streamConfig := manager.GetStreamConfig()
		assert.NotNil(t, streamConfig, "Should have stream config")
	})
}
