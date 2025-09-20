package goplugins

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestBlock4PluginLoadingOperations - Tests for Plugin Loading/Unloading Operations
//
// Block 4 Functions Under Test:
// - LoadDiscoveredPlugin: Dynamic plugin loading with dependency resolution
// - UnloadPlugin: Safe plugin unloading with cleanup and dependency checking
// - loadPlugin: Core plugin loading implementation
// - Register: Plugin registration in manager
// - Unregister: Plugin deregistration and cleanup
// - Hot-swapping and reload scenarios
//
// Focus Areas:
// - Plugin lifecycle state management and transitions
// - Resource cleanup and memory leak prevention
// - Concurrent loading scenarios and race conditions
// - Dependency resolution edge cases
// - Error handling and rollback mechanisms
// - State consistency under failure conditions

// ==============================================
// CATEGORY 1: Core Plugin Loading Operations
// ==============================================

func TestLoadDiscoveredPlugin_BasicFunctionality(t *testing.T) {
	manager := createTestManagerForLoading(t)
	loader := manager.dynamicLoader

	// Set up discovery engine with mock plugin
	mockPlugin := createMockDiscoveredPlugin("test-plugin", "1.0.0")
	loader.discoveryEngine.AddMockPlugin(mockPlugin)

	testCases := []struct {
		pluginName    string
		shouldSucceed bool
		name          string
	}{
		{"test-plugin", true, "load valid discovered plugin"},
		{"nonexistent-plugin", false, "load non-existent plugin should fail"},
		{"test-plugin", false, "load already loaded plugin should fail"},
	}

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := loader.LoadDiscoveredPlugin(ctx, tc.pluginName)

			if tc.shouldSucceed && err != nil {
				t.Errorf("Expected plugin %s to load successfully, got error: %v", tc.pluginName, err)
			}

			if !tc.shouldSucceed && err == nil {
				t.Errorf("Expected plugin %s to fail loading, but succeeded", tc.pluginName)
			}

			// Verify loading state
			if tc.shouldSucceed {
				states := loader.GetLoadingStatus()
				if state, exists := states[tc.pluginName]; !exists || state != LoadingStateLoaded {
					t.Errorf("Expected plugin %s to be in loaded state, got %v", tc.pluginName, state)
				}
			}
		})
	}
}

func TestLoadDiscoveredPlugin_EdgeCasesAndBugs(t *testing.T) {
	testCases := []struct {
		scenario    string
		setupFunc   func(*DynamicLoader[TestRequest, TestResponse])
		pluginName  string
		shouldFail  bool
		expectedBug string
	}{
		{
			"load plugin with invalid version",
			func(loader *DynamicLoader[TestRequest, TestResponse]) {
				mockPlugin := createMockDiscoveredPlugin("invalid-version-plugin", "not.a.version")
				loader.discoveryEngine.AddMockPlugin(mockPlugin)
			},
			"invalid-version-plugin",
			true,
			"Invalid versions should be rejected during loading",
		},
		{
			"load plugin while shutting down",
			func(loader *DynamicLoader[TestRequest, TestResponse]) {
				mockPlugin := createMockDiscoveredPlugin("shutdown-plugin", "1.0.0")
				loader.discoveryEngine.AddMockPlugin(mockPlugin)
				// Simulate shutdown state
				loader.manager.shutdown.Store(true)
			},
			"shutdown-plugin",
			true,
			"Loading during shutdown should be prevented",
		},
		// REMOVED CIRCULAR DEPENDENCY TEST - causes stack overflow (Bug #1)
		// This test is moved to dedicated bug test file
		{
			"concurrent load same plugin",
			func(loader *DynamicLoader[TestRequest, TestResponse]) {
				mockPlugin := createMockDiscoveredPlugin("concurrent-plugin", "1.0.0")
				loader.discoveryEngine.AddMockPlugin(mockPlugin)
			},
			"concurrent-plugin",
			false, // One should succeed, others should fail gracefully
			"Concurrent loading of same plugin should handle race conditions",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			manager := createTestManagerForLoading(t)
			loader := manager.dynamicLoader

			tc.setupFunc(loader)

			ctx := context.Background()

			if tc.scenario == "concurrent load same plugin" {
				// Test concurrent loading
				const numGoroutines = 10
				var wg sync.WaitGroup
				errors := make(chan error, numGoroutines)

				for i := 0; i < numGoroutines; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						err := loader.LoadDiscoveredPlugin(ctx, tc.pluginName)
						errors <- err
					}()
				}

				wg.Wait()
				close(errors)

				successCount := 0
				errorCount := 0
				for err := range errors {
					if err == nil {
						successCount++
					} else {
						errorCount++
					}
				}

				// Exactly one should succeed
				if successCount != 1 {
					t.Errorf("BUG (%s): Expected exactly 1 success in concurrent loading, got %d successes, %d errors",
						tc.expectedBug, successCount, errorCount)
				}
			} else {
				err := loader.LoadDiscoveredPlugin(ctx, tc.pluginName)

				if tc.shouldFail && err == nil {
					t.Errorf("BUG (%s): Expected loading to fail for %s, but succeeded", tc.expectedBug, tc.pluginName)
				}

				if !tc.shouldFail && err != nil {
					t.Errorf("BUG (%s): Expected loading to succeed for %s, got error: %v", tc.expectedBug, tc.pluginName, err)
				}
			}
		})
	}
}

// ==============================================
// CATEGORY 2: Plugin Unloading and Cleanup
// ==============================================

func TestUnloadPlugin_BasicFunctionality(t *testing.T) {
	manager := createTestManagerForLoading(t)
	loader := manager.dynamicLoader

	// Load some plugins first
	plugin1 := createMockDiscoveredPlugin("plugin-1", "1.0.0")
	plugin2 := createMockDiscoveredPluginWithDeps("plugin-2", "1.0.0", []string{"plugin-1"})
	loader.discoveryEngine.AddMockPlugin(plugin1)
	loader.discoveryEngine.AddMockPlugin(plugin2)

	ctx := context.Background()

	// Load plugins
	if err := loader.LoadDiscoveredPlugin(ctx, "plugin-1"); err != nil {
		t.Fatalf("Failed to load plugin-1: %v", err)
	}
	if err := loader.LoadDiscoveredPlugin(ctx, "plugin-2"); err != nil {
		t.Fatalf("Failed to load plugin-2: %v", err)
	}

	testCases := []struct {
		pluginName    string
		force         bool
		shouldSucceed bool
		name          string
	}{
		{"plugin-1", false, false, "unload plugin with dependents should fail"},
		{"plugin-1", true, true, "force unload plugin with dependents should succeed"},
		{"plugin-2", false, true, "unload plugin without dependents should succeed"},
		{"nonexistent", false, false, "unload non-existent plugin should fail"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := loader.UnloadPlugin(ctx, tc.pluginName, tc.force)

			if tc.shouldSucceed && err != nil {
				t.Errorf("Expected unloading %s to succeed, got error: %v", tc.pluginName, err)
			}

			if !tc.shouldSucceed && err == nil {
				t.Errorf("Expected unloading %s to fail, but succeeded", tc.pluginName)
			}

			// Verify state after unloading
			if tc.shouldSucceed {
				states := loader.GetLoadingStatus()
				if _, exists := states[tc.pluginName]; exists {
					t.Errorf("Expected plugin %s to be removed from loading states after unload", tc.pluginName)
				}
			}
		})
	}
}

func TestUnloadPlugin_ResourceCleanup(t *testing.T) {
	manager := createTestManagerForLoading(t)
	loader := manager.dynamicLoader

	// Load plugin with resource tracking
	mockPlugin := createMockDiscoveredPlugin("resource-plugin", "1.0.0")
	loader.discoveryEngine.AddMockPlugin(mockPlugin)

	ctx := context.Background()

	if err := loader.LoadDiscoveredPlugin(ctx, "resource-plugin"); err != nil {
		t.Fatalf("Failed to load resource-plugin: %v", err)
	}

	// Verify plugin is loaded and consuming resources
	states := loader.GetLoadingStatus()
	if state := states["resource-plugin"]; state != LoadingStateLoaded {
		t.Fatalf("Expected plugin to be loaded, got state: %v", state)
	}

	// Verify plugin is registered in manager
	plugin, err := manager.GetPlugin("resource-plugin")
	if err != nil {
		t.Fatalf("Expected plugin to be registered in manager, got error: %v", err)
	}

	// Check plugin info before unload
	info := plugin.Info()
	if info.Name != "resource-plugin" {
		t.Errorf("Expected plugin name to be 'resource-plugin', got %s", info.Name)
	}

	// Unload plugin
	if err := loader.UnloadPlugin(ctx, "resource-plugin", false); err != nil {
		t.Fatalf("Failed to unload plugin: %v", err)
	}

	// Verify complete cleanup
	// 1. Plugin removed from loading states
	states = loader.GetLoadingStatus()
	if _, exists := states["resource-plugin"]; exists {
		t.Error("BUG: Plugin still exists in loading states after unload")
	}

	// 2. Plugin removed from manager
	_, err = manager.GetPlugin("resource-plugin")
	if err == nil {
		t.Error("BUG: Plugin still registered in manager after unload")
	}

	// 3. Plugin removed from dependency graph
	graph := loader.GetDependencyGraph()
	if deps := graph.GetDependencies("resource-plugin"); len(deps) > 0 {
		t.Error("BUG: Plugin dependencies still exist in graph after unload")
	}
}

// ==============================================
// CATEGORY 3: Dependency Resolution Testing
// ==============================================

func TestLoadDiscoveredPlugin_DependencyResolution(t *testing.T) {
	manager := createTestManagerForLoading(t)
	loader := manager.dynamicLoader

	// Create dependency chain: app -> auth -> crypto -> base
	plugins := []*DiscoveryResult{
		createMockDiscoveredPlugin("base", "1.0.0"),
		createMockDiscoveredPluginWithDeps("crypto", "1.0.0", []string{"base"}),
		createMockDiscoveredPluginWithDeps("auth", "1.0.0", []string{"crypto"}),
		createMockDiscoveredPluginWithDeps("app", "1.0.0", []string{"auth"}),
	}

	for _, plugin := range plugins {
		loader.discoveryEngine.AddMockPlugin(plugin)
	}

	ctx := context.Background()

	// Load top-level plugin, should auto-resolve dependencies
	err := loader.LoadDiscoveredPlugin(ctx, "app")
	if err != nil {
		t.Fatalf("Failed to load app plugin: %v", err)
	}

	// Verify all dependencies are loaded in correct order
	states := loader.GetLoadingStatus()
	expectedPlugins := []string{"base", "crypto", "auth", "app"}

	for _, pluginName := range expectedPlugins {
		if state, exists := states[pluginName]; !exists || state != LoadingStateLoaded {
			t.Errorf("Expected plugin %s to be loaded, got state: %v", pluginName, state)
		}
	}

	// Verify dependency graph is correct
	graph := loader.GetDependencyGraph()
	if deps := graph.GetDependencies("app"); len(deps) == 0 {
		t.Error("Expected app plugin to have dependencies in graph")
	}
}

func TestLoadDiscoveredPlugin_BrokenDependencies(t *testing.T) {
	testCases := []struct {
		scenario    string
		setupFunc   func(*DynamicLoader[TestRequest, TestResponse])
		pluginName  string
		expectedBug string
	}{
		{
			"missing dependency",
			func(loader *DynamicLoader[TestRequest, TestResponse]) {
				// Plugin depends on non-existent dependency
				plugin := createMockDiscoveredPluginWithDeps("broken-app", "1.0.0", []string{"missing-dep"})
				loader.discoveryEngine.AddMockPlugin(plugin)
			},
			"broken-app",
			"Missing dependencies should prevent loading",
		},
		{
			"incompatible dependency version",
			func(loader *DynamicLoader[TestRequest, TestResponse]) {
				// Set strict version constraint that dependency doesn't satisfy
				dep := createMockDiscoveredPlugin("strict-dep", "2.0.0")
				app := createMockDiscoveredPluginWithDeps("strict-app", "1.0.0", []string{"strict-dep"})
				loader.discoveryEngine.AddMockPlugin(dep)
				loader.discoveryEngine.AddMockPlugin(app)
				loader.SetCompatibilityRule("strict-dep", "^1.0.0") // Incompatible with 2.0.0
			},
			"strict-app",
			"Version incompatible dependencies should prevent loading",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			manager := createTestManagerForLoading(t)
			loader := manager.dynamicLoader

			tc.setupFunc(loader)

			ctx := context.Background()
			err := loader.LoadDiscoveredPlugin(ctx, tc.pluginName)

			if err == nil {
				t.Errorf("BUG (%s): Expected loading to fail for %s, but succeeded", tc.expectedBug, tc.pluginName)
			}

			// Verify no partial state left behind
			states := loader.GetLoadingStatus()
			for pluginName, state := range states {
				if state == LoadingStateLoading {
					t.Errorf("BUG: Plugin %s left in loading state after failure", pluginName)
				}
			}
		})
	}
}

// ==============================================
// CATEGORY 4: Concurrent Operations and Race Conditions
// ==============================================

func TestPluginLoading_ConcurrentOperations(t *testing.T) {
	manager := createTestManagerForLoading(t)
	loader := manager.dynamicLoader

	// Set up multiple plugins
	plugins := make([]*DiscoveryResult, 20)
	for i := 0; i < 20; i++ {
		pluginName := "concurrent-plugin-" + string(rune('a'+i))
		plugins[i] = createMockDiscoveredPlugin(pluginName, "1.0.0")
		loader.discoveryEngine.AddMockPlugin(plugins[i])
	}

	ctx := context.Background()

	// Test concurrent loading
	t.Run("concurrent_loading", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, len(plugins))

		// Load all plugins concurrently
		for i, plugin := range plugins {
			wg.Add(1)
			go func(pluginName string, index int) {
				defer wg.Done()

				// Add some randomization to increase chance of race conditions
				time.Sleep(time.Duration(index%5) * time.Millisecond)

				err := loader.LoadDiscoveredPlugin(ctx, pluginName)
				errors <- err
			}(plugin.Manifest.Name, i)
		}

		wg.Wait()
		close(errors)

		// Count successes and failures
		successCount := 0
		for err := range errors {
			if err == nil {
				successCount++
			} else {
				t.Logf("Loading error (expected for concurrent test): %v", err)
			}
		}

		if successCount != len(plugins) {
			t.Errorf("Expected all %d plugins to load successfully, got %d successes", len(plugins), successCount)
		}
	})

	// Test concurrent load/unload operations
	t.Run("concurrent_load_unload", func(t *testing.T) {
		var wg sync.WaitGroup
		operations := 100

		wg.Add(operations)
		for i := 0; i < operations; i++ {
			go func(index int) {
				defer wg.Done()

				pluginName := "concurrent-plugin-a" // Use same plugin for race conditions

				if index%2 == 0 {
					// Load operation
					loader.LoadDiscoveredPlugin(ctx, pluginName)
				} else {
					// Unload operation
					loader.UnloadPlugin(ctx, pluginName, false)
				}
			}(i)
		}

		wg.Wait()

		// Verify system is in consistent state
		states := loader.GetLoadingStatus()
		for pluginName, state := range states {
			if state == LoadingStateLoading || state == LoadingStateUnloading {
				t.Errorf("BUG: Plugin %s left in intermediate state: %v", pluginName, state)
			}
		}
	})
}

func TestPluginLoading_StateConsistency(t *testing.T) {
	manager := createTestManagerForLoading(t)
	loader := manager.dynamicLoader

	mockPlugin := createMockDiscoveredPlugin("state-plugin", "1.0.0")
	loader.discoveryEngine.AddMockPlugin(mockPlugin)

	ctx := context.Background()

	// Test state transitions
	states := []struct {
		operation     string
		expectedState LoadingState
	}{
		{"initial", LoadingState("")}, // Not in states initially
		{"load", LoadingStateLoaded},
		{"unload", LoadingState("")}, // Removed from states
	}

	for _, state := range states {
		switch state.operation {
		case "load":
			err := loader.LoadDiscoveredPlugin(ctx, "state-plugin")
			if err != nil {
				t.Fatalf("Failed to load plugin: %v", err)
			}
		case "unload":
			err := loader.UnloadPlugin(ctx, "state-plugin", false)
			if err != nil {
				t.Fatalf("Failed to unload plugin: %v", err)
			}
		}

		// Verify state
		currentStates := loader.GetLoadingStatus()
		actualState, exists := currentStates["state-plugin"]

		if state.expectedState == "" {
			if exists {
				t.Errorf("Expected plugin to not exist in states after %s, but found state: %v",
					state.operation, actualState)
			}
		} else {
			if !exists || actualState != state.expectedState {
				t.Errorf("After %s operation, expected state %v, got %v (exists: %v)",
					state.operation, state.expectedState, actualState, exists)
			}
		}
	}
}

// ==============================================
// CATEGORY 5: Error Handling and Recovery
// ==============================================

func TestPluginLoading_ErrorHandling(t *testing.T) {
	testCases := []struct {
		scenario    string
		setupFunc   func(*DynamicLoader[TestRequest, TestResponse])
		pluginName  string
		operation   string
		expectError bool
		errorType   string
	}{
		{
			"load with factory error",
			func(loader *DynamicLoader[TestRequest, TestResponse]) {
				// Plugin with unsupported transport
				plugin := &DiscoveryResult{
					Source: "test",
					Manifest: &PluginManifest{
						Name:      "factory-error-plugin",
						Version:   "1.0.0",
						Transport: TransportType("unsupported-transport"),
						Endpoint:  "test://localhost",
					},
				}
				loader.discoveryEngine.AddMockPlugin(plugin)
			},
			"factory-error-plugin",
			"load",
			true,
			"UnsupportedTransportError",
		},
		{
			"unload non-existent plugin",
			func(loader *DynamicLoader[TestRequest, TestResponse]) {
				// No setup needed
			},
			"non-existent-plugin",
			"unload",
			true,
			"PluginNotFoundError",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			manager := createTestManagerForLoading(t)
			loader := manager.dynamicLoader

			tc.setupFunc(loader)

			ctx := context.Background()
			var err error

			switch tc.operation {
			case "load":
				err = loader.LoadDiscoveredPlugin(ctx, tc.pluginName)
			case "unload":
				err = loader.UnloadPlugin(ctx, tc.pluginName, false)
			}

			if tc.expectError && err == nil {
				t.Errorf("Expected error of type %s for %s, but operation succeeded", tc.errorType, tc.scenario)
			}

			if !tc.expectError && err != nil {
				t.Errorf("Expected %s to succeed, got error: %v", tc.scenario, err)
			}

			// Verify system remains in clean state after errors
			if tc.expectError {
				states := loader.GetLoadingStatus()
				if state, exists := states[tc.pluginName]; exists && state != LoadingStateFailed {
					t.Errorf("Expected failed plugin to be in failed state or removed, got: %v", state)
				}
			}
		})
	}
}

func TestPluginLoading_PerformanceBenchmark(t *testing.T) {
	manager := createTestManagerForLoading(t)
	loader := manager.dynamicLoader

	// Set up many plugins for performance testing
	const numPlugins = 100
	for i := 0; i < numPlugins; i++ {
		pluginName := fmt.Sprintf("perf-plugin-%d", i) // Use safe numeric suffix
		plugin := createMockDiscoveredPlugin(pluginName, "1.0.0")
		loader.discoveryEngine.AddMockPlugin(plugin)
	}

	ctx := context.Background()

	// Measure loading performance
	start := time.Now()

	for i := 0; i < numPlugins; i++ {
		pluginName := fmt.Sprintf("perf-plugin-%d", i) // Use safe numeric suffix
		if err := loader.LoadDiscoveredPlugin(ctx, pluginName); err != nil {
			t.Errorf("Failed to load plugin %s: %v", pluginName, err)
		}
	}

	loadTime := time.Since(start)

	// Measure unloading performance
	start = time.Now()

	for i := 0; i < numPlugins; i++ {
		pluginName := fmt.Sprintf("perf-plugin-%d", i) // Use safe numeric suffix
		if err := loader.UnloadPlugin(ctx, pluginName, false); err != nil {
			t.Errorf("Failed to unload plugin %s: %v", pluginName, err)
		}
	}

	unloadTime := time.Since(start)

	t.Logf("Performance: Loaded %d plugins in %v (%.2f μs/plugin)",
		numPlugins, loadTime, float64(loadTime.Nanoseconds())/float64(numPlugins)/1000.0)
	t.Logf("Performance: Unloaded %d plugins in %v (%.2f μs/plugin)",
		numPlugins, unloadTime, float64(unloadTime.Nanoseconds())/float64(numPlugins)/1000.0)

	// Performance threshold check (adjust based on system capabilities)
	maxTimePerPlugin := 1 * time.Millisecond
	avgLoadTime := loadTime / time.Duration(numPlugins)
	avgUnloadTime := unloadTime / time.Duration(numPlugins)

	if avgLoadTime > maxTimePerPlugin {
		t.Errorf("Plugin loading too slow: %v per plugin (max: %v)", avgLoadTime, maxTimePerPlugin)
	}

	if avgUnloadTime > maxTimePerPlugin {
		t.Errorf("Plugin unloading too slow: %v per plugin (max: %v)", avgUnloadTime, maxTimePerPlugin)
	}
}

// ==============================================
// Helper Functions
// ==============================================

func createTestManagerForLoading(_ *testing.T) *Manager[TestRequest, TestResponse] {
	logger := NewTestLogger()
	manager := NewManager[TestRequest, TestResponse](logger)

	// Initialize discovery engine if not present
	if manager.discoveryEngine == nil {
		manager.discoveryEngine = &DiscoveryEngine{
			discoveredPlugins: make(map[string]*DiscoveryResult),
		}
	}

	return manager
}

func createMockDiscoveredPlugin(name, version string) *DiscoveryResult {
	return &DiscoveryResult{
		Source: "test",
		Manifest: &PluginManifest{
			Name:      name,
			Version:   version,
			Transport: TransportExecutable, // Use executable instead of GRPC
			Endpoint:  "/usr/bin/true",     // Use /usr/bin/true which should exist on most Linux systems
		},
	}
}

func createMockDiscoveredPluginWithDeps(name, version string, dependencies []string) *DiscoveryResult {
	result := createMockDiscoveredPlugin(name, version)
	if len(dependencies) > 0 {
		result.Manifest.Requirements = &PluginRequirements{
			RequiredPlugins: dependencies,
		}
	}
	return result
}

// Mock discovery engine extension for testing
func (de *DiscoveryEngine) AddMockPlugin(result *DiscoveryResult) {
	if de.discoveredPlugins == nil {
		de.discoveredPlugins = make(map[string]*DiscoveryResult)
	}
	de.discoveredPlugins[result.Manifest.Name] = result
}
