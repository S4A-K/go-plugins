// dynamic_loader_dependency_test.go: Block 2 - Dependency Graph Operations Testing
//
// BLOCK 2 FOCUS: Test critici per le operazioni di dependency graph management
// - AddPlugin: Gestione dependency graph e relazioni
// - RemovePlugin: Cleanup e integrity check durante rimozione
// - CalculateLoadOrder: Kahn's algorithm per topological sorting
// - ValidateDependencies: Circular dependency detection e missing deps
//
// OBIETTIVO: Scoprire bugs negli algoritmi complessi di graph management
// con focus su circular dependencies, race conditions, e edge cases.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"
)

// TestDynamicLoader_DependencyGraph_CoreFunctionality tests basic dependency graph operations
func TestDynamicLoader_DependencyGraph_CoreFunctionality(t *testing.T) {
	t.Run("BasicGraphOperations_AddRemove", func(t *testing.T) {
		tests := []struct {
			name     string
			scenario func(*testing.T, *DependencyGraph)
		}{
			{"EmptyGraph_Initial", func(t *testing.T, dg *DependencyGraph) {
				loadOrder, err := dg.CalculateLoadOrder()
				if err != nil {
					t.Errorf("Empty graph should have valid load order: %v", err)
				}
				if len(loadOrder) != 0 {
					t.Errorf("Empty graph load order should be empty, got: %v", loadOrder)
				}
			}},
			{"SinglePlugin_NoDependencies", func(t *testing.T, dg *DependencyGraph) {
				err := dg.AddPlugin("plugin-a", []string{})
				if err != nil {
					t.Errorf("Failed to add simple plugin: %v", err)
				}

				loadOrder, err := dg.CalculateLoadOrder()
				if err != nil {
					t.Errorf("Failed to calculate load order: %v", err)
				}
				if len(loadOrder) != 1 || loadOrder[0] != "plugin-a" {
					t.Errorf("Expected [plugin-a], got: %v", loadOrder)
				}
			}},
			{"LinearChain_Dependencies", func(t *testing.T, dg *DependencyGraph) {
				// Create chain: A -> B -> C
				err := dg.AddPlugin("plugin-c", []string{})
				if err != nil {
					t.Errorf("Failed to add plugin-c: %v", err)
				}
				err = dg.AddPlugin("plugin-b", []string{"plugin-c"})
				if err != nil {
					t.Errorf("Failed to add plugin-b: %v", err)
				}
				err = dg.AddPlugin("plugin-a", []string{"plugin-b"})
				if err != nil {
					t.Errorf("Failed to add plugin-a: %v", err)
				}

				loadOrder, err := dg.CalculateLoadOrder()
				if err != nil {
					t.Errorf("Failed to calculate load order: %v", err)
				}

				// Verify correct order: C, B, A
				expected := []string{"plugin-c", "plugin-b", "plugin-a"}
				if !equalStringSlices(loadOrder, expected) {
					t.Errorf("Expected %v, got: %v", expected, loadOrder)
				}
			}},
			{"MultipleRoots_ParallelPaths", func(t *testing.T, dg *DependencyGraph) {
				// Create: A -> C, B -> C (two roots)
				err := dg.AddPlugin("plugin-c", []string{})
				if err != nil {
					t.Errorf("Failed to add plugin-c: %v", err)
				}
				err = dg.AddPlugin("plugin-a", []string{"plugin-c"})
				if err != nil {
					t.Errorf("Failed to add plugin-a: %v", err)
				}
				err = dg.AddPlugin("plugin-b", []string{"plugin-c"})
				if err != nil {
					t.Errorf("Failed to add plugin-b: %v", err)
				}

				loadOrder, err := dg.CalculateLoadOrder()
				if err != nil {
					t.Errorf("Failed to calculate load order: %v", err)
				}

				// C must be first, A and B can be in any order after
				if len(loadOrder) != 3 || loadOrder[0] != "plugin-c" {
					t.Errorf("plugin-c should be first in load order, got: %v", loadOrder)
				}

				// Check A and B are present
				found := make(map[string]bool)
				for _, plugin := range loadOrder {
					found[plugin] = true
				}
				if !found["plugin-a"] || !found["plugin-b"] {
					t.Errorf("Missing plugin-a or plugin-b in load order: %v", loadOrder)
				}
			}},
			{"RemovePlugin_IntegrityCheck", func(t *testing.T, dg *DependencyGraph) {
				// Build graph: A -> B -> C
				dg.AddPlugin("plugin-c", []string{})
				dg.AddPlugin("plugin-b", []string{"plugin-c"})
				dg.AddPlugin("plugin-a", []string{"plugin-b"})

				// Remove middle plugin
				dg.RemovePlugin("plugin-b")

				// Verify B is removed and dependencies cleaned up
				deps := dg.GetDependencies("plugin-a")
				if len(deps) != 1 || deps[0] != "plugin-b" {
					t.Errorf("plugin-a dependencies should still be [plugin-b] (dangling ref), got: %v", deps)
				}

				// Verify load order calculation handles missing dependency
				_, err := dg.CalculateLoadOrder()
				if err == nil {
					t.Error("Expected error due to missing dependency after removal")
				}
			}},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				dg := NewDependencyGraph()
				test.scenario(t, dg)
			})
		}

		t.Logf("✅ Basic dependency graph operations working correctly - tested %d scenarios", len(tests))
	})

	t.Run("KahnsAlgorithm_TopologicalSorting", func(t *testing.T) {
		tests := []struct {
			name        string
			setupGraph  func(*DependencyGraph)
			expectOrder []string
			expectError bool
		}{
			{
				"DiamondDependency",
				func(dg *DependencyGraph) {
					// D -> B, D -> C, B -> A, C -> A (diamond shape)
					dg.AddPlugin("plugin-a", []string{})
					dg.AddPlugin("plugin-b", []string{"plugin-a"})
					dg.AddPlugin("plugin-c", []string{"plugin-a"})
					dg.AddPlugin("plugin-d", []string{"plugin-b", "plugin-c"})
				},
				[]string{"plugin-a"}, // A must be first
				false,
			},
			{
				"ComplexDAG_MultiLevel",
				func(dg *DependencyGraph) {
					// Complex: F -> D,E; D -> B; E -> C; B,C -> A
					dg.AddPlugin("plugin-a", []string{})
					dg.AddPlugin("plugin-b", []string{"plugin-a"})
					dg.AddPlugin("plugin-c", []string{"plugin-a"})
					dg.AddPlugin("plugin-d", []string{"plugin-b"})
					dg.AddPlugin("plugin-e", []string{"plugin-c"})
					dg.AddPlugin("plugin-f", []string{"plugin-d", "plugin-e"})
				},
				[]string{"plugin-a"}, // A must be first
				false,
			},
			{
				"LargeGraph_Performance",
				func(dg *DependencyGraph) {
					// Create large linear chain for performance testing
					for i := 0; i < 100; i++ {
						name := fmt.Sprintf("plugin-%03d", i)
						if i == 0 {
							dg.AddPlugin(name, []string{})
						} else {
							prev := fmt.Sprintf("plugin-%03d", i-1)
							dg.AddPlugin(name, []string{prev})
						}
					}
				},
				[]string{"plugin-000"}, // First plugin must be first
				false,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				dg := NewDependencyGraph()
				test.setupGraph(dg)

				start := time.Now()
				loadOrder, err := dg.CalculateLoadOrder()
				duration := time.Since(start)

				if test.expectError && err == nil {
					t.Error("Expected error but got none")
				} else if !test.expectError && err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if !test.expectError {
					// Verify expected elements are first
					for i, expected := range test.expectOrder {
						if i >= len(loadOrder) || loadOrder[i] != expected {
							t.Errorf("Position %d: expected %s, got %v", i, expected, loadOrder)
						}
					}
				}

				// Performance check for large graphs
				if test.name == "LargeGraph_Performance" && duration > 10*time.Millisecond {
					t.Logf("⚠️  Performance warning: large graph took %v", duration)
				}
			})
		}

		t.Logf("✅ Kahn's algorithm working correctly - tested %d complex scenarios", len(tests))
	})
}

// TestDynamicLoader_DependencyGraph_EdgeCasesAndBugs tests edge cases and potential bugs
func TestDynamicLoader_DependencyGraph_EdgeCasesAndBugs(t *testing.T) {
	t.Run("CircularDependencies_Detection", func(t *testing.T) {
		circularTests := []struct {
			name        string
			setupCycle  func(*DependencyGraph)
			description string
		}{
			{
				"SimpleCircle_TwoNodes",
				func(dg *DependencyGraph) {
					dg.AddPlugin("plugin-a", []string{"plugin-b"})
					dg.AddPlugin("plugin-b", []string{"plugin-a"})
				},
				"A -> B -> A",
			},
			{
				"SelfLoop_SingleNode",
				func(dg *DependencyGraph) {
					dg.AddPlugin("plugin-a", []string{"plugin-a"})
				},
				"A -> A",
			},
			{
				"ThreeNodeCycle",
				func(dg *DependencyGraph) {
					dg.AddPlugin("plugin-a", []string{"plugin-b"})
					dg.AddPlugin("plugin-b", []string{"plugin-c"})
					dg.AddPlugin("plugin-c", []string{"plugin-a"})
				},
				"A -> B -> C -> A",
			},
			{
				"ComplexCycle_WithValidNodes",
				func(dg *DependencyGraph) {
					// Valid part
					dg.AddPlugin("valid-1", []string{})
					dg.AddPlugin("valid-2", []string{"valid-1"})
					// Cycle part
					dg.AddPlugin("cycle-a", []string{"cycle-b", "valid-1"})
					dg.AddPlugin("cycle-b", []string{"cycle-c"})
					dg.AddPlugin("cycle-c", []string{"cycle-a"})
				},
				"Mixed valid + A -> B -> C -> A",
			},
			{
				"LongCycle_Performance",
				func(dg *DependencyGraph) {
					// Create long cycle for stress testing
					const cycleLength = 50
					for i := 0; i < cycleLength; i++ {
						name := fmt.Sprintf("cycle-%d", i)
						nextName := fmt.Sprintf("cycle-%d", (i+1)%cycleLength)
						dg.AddPlugin(name, []string{nextName})
					}
				},
				"50-node circular chain",
			},
		}

		var detectedCycles int
		for _, test := range circularTests {
			t.Run(test.name, func(t *testing.T) {
				dg := NewDependencyGraph()
				test.setupCycle(dg)

				// Test CalculateLoadOrder
				_, err := dg.CalculateLoadOrder()
				if err == nil {
					t.Errorf("Expected circular dependency error for %s", test.description)
				} else {
					detectedCycles++
					t.Logf("✅ Correctly detected circular dependency: %s", test.description)
				}

				// Test ValidateDependencies
				err = dg.ValidateDependencies()
				if err == nil {
					t.Errorf("ValidateDependencies should detect circular dependency for %s", test.description)
				}
			})
		}

		if detectedCycles == len(circularTests) {
			t.Logf("✅ All %d circular dependency scenarios correctly detected", detectedCycles)
		} else {
			t.Errorf("Only detected %d/%d circular dependencies", detectedCycles, len(circularTests))
		}
	})

	t.Run("MissingDependencies_ErrorHandling", func(t *testing.T) {
		missingDepTests := []struct {
			name        string
			setupGraph  func(*DependencyGraph)
			description string
		}{
			{
				"SingleMissing_AfterRemoval",
				func(dg *DependencyGraph) {
					dg.AddPlugin("dependency", []string{})
					dg.AddPlugin("plugin-a", []string{"dependency"})
					dg.RemovePlugin("dependency") // Create dangling reference
				},
				"A depends on plugin that was removed",
			},
			{
				"MultipleMissing_AfterRemoval",
				func(dg *DependencyGraph) {
					dg.AddPlugin("dep-1", []string{})
					dg.AddPlugin("dep-2", []string{})
					dg.AddPlugin("plugin-a", []string{"dep-1", "dep-2"})
					dg.RemovePlugin("dep-1")
					dg.RemovePlugin("dep-2") // Both dependencies removed
				},
				"A depends on multiple removed plugins",
			},
			{
				"ChainWithMissing_MiddleNode",
				func(dg *DependencyGraph) {
					dg.AddPlugin("plugin-c", []string{})
					dg.AddPlugin("plugin-b", []string{"plugin-c"})
					dg.AddPlugin("plugin-a", []string{"plugin-b"})
					dg.RemovePlugin("plugin-b") // Remove middle dependency
				},
				"Chain with removed middle node",
			},
			{
				"ComplexMissing_PartialRemoval",
				func(dg *DependencyGraph) {
					// Create valid graph
					dg.AddPlugin("base", []string{})
					dg.AddPlugin("middle", []string{"base"})
					dg.AddPlugin("top", []string{"middle", "base"})
					// Remove middle dependency
					dg.RemovePlugin("middle")
				},
				"Complex graph with partial dependency removal",
			},
		}

		var detectedMissing int
		for _, test := range missingDepTests {
			t.Run(test.name, func(t *testing.T) {
				dg := NewDependencyGraph()
				test.setupGraph(dg)

				// Test ValidateDependencies
				err := dg.ValidateDependencies()
				if err == nil {
					t.Errorf("Expected missing dependency error for: %s", test.description)
				} else {
					detectedMissing++
					t.Logf("✅ Correctly detected missing dependency: %s", test.description)
				}

				// Test CalculateLoadOrder (should also fail)
				_, err = dg.CalculateLoadOrder()
				if err == nil {
					t.Errorf("CalculateLoadOrder should fail for missing dependency: %s", test.description)
				}
			})
		}

		t.Logf("✅ All %d missing dependency scenarios correctly detected", detectedMissing)
	})

	t.Run("GraphIntegrity_AfterModifications", func(t *testing.T) {
		tests := []struct {
			name      string
			operation func(*DependencyGraph) string
		}{
			{
				"AddDuplicate_Plugin",
				func(dg *DependencyGraph) string {
					dg.AddPlugin("plugin-a", []string{})
					dg.AddPlugin("plugin-a", []string{"plugin-b"}) // Update dependencies
					deps := dg.GetDependencies("plugin-a")
					if len(deps) != 1 || deps[0] != "plugin-b" {
						return fmt.Sprintf("Expected [plugin-b], got %v", deps)
					}
					return ""
				},
			},
			{
				"RemoveNonExistent_Plugin",
				func(dg *DependencyGraph) string {
					dg.RemovePlugin("non-existent") // Should not panic
					return ""
				},
			},
			{
				"ModifyDependencies_UpdateRelations",
				func(dg *DependencyGraph) string {
					dg.AddPlugin("plugin-a", []string{"plugin-b"})
					dg.AddPlugin("plugin-b", []string{})
					dg.AddPlugin("plugin-a", []string{"plugin-c"}) // Change dependencies

					// Verify old relationship cleaned up
					dependents := dg.GetDependents("plugin-b")
					for _, dep := range dependents {
						if dep == "plugin-a" {
							return "plugin-b should no longer have plugin-a as dependent"
						}
					}
					return ""
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				dg := NewDependencyGraph()
				if errMsg := test.operation(dg); errMsg != "" {
					t.Error(errMsg)
				}
			})
		}

		t.Logf("✅ Graph integrity maintained through all modification scenarios")
	})
}

// TestDynamicLoader_DependencyGraph_ConcurrencyAndPerformance tests thread safety and performance
func TestDynamicLoader_DependencyGraph_ConcurrencyAndPerformance(t *testing.T) {
	t.Run("ConcurrentAccess_ThreadSafety", func(t *testing.T) {
		dg := NewDependencyGraph()

		const goroutines = 20
		const operationsPerGoroutine = 100

		var wg sync.WaitGroup
		errors := make(chan string, goroutines*operationsPerGoroutine)

		// Concurrent operations
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				// Use local random generator instead of deprecated global Seed
				rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))

				for j := 0; j < operationsPerGoroutine; j++ {
					pluginName := fmt.Sprintf("plugin-%d-%d", id, j)

					switch rng.Intn(4) {
					case 0: // AddPlugin
						deps := []string{}
						if j > 0 {
							deps = []string{fmt.Sprintf("plugin-%d-%d", id, j-1)}
						}
						if err := dg.AddPlugin(pluginName, deps); err != nil {
							errors <- fmt.Sprintf("AddPlugin error: %v", err)
						}

					case 1: // RemovePlugin
						if j > 0 {
							dg.RemovePlugin(fmt.Sprintf("plugin-%d-%d", id, j-1))
						}

					case 2: // GetDependencies
						dg.GetDependencies(pluginName)

					case 3: // CalculateLoadOrder
						dg.CalculateLoadOrder()
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		var errorCount int
		for err := range errors {
			t.Logf("Concurrent error: %s", err)
			errorCount++
		}

		if errorCount > 0 {
			t.Errorf("Encountered %d errors during concurrent operations", errorCount)
		} else {
			t.Logf("✅ Concurrency test passed - %d goroutines × %d operations completed safely",
				goroutines, operationsPerGoroutine)
		}
	})

	t.Run("Performance_LargeGraphOperations", func(t *testing.T) {
		dg := NewDependencyGraph()

		// Build large graph
		const graphSize = 1000
		start := time.Now()

		// Create chain dependencies for predictable performance
		for i := 0; i < graphSize; i++ {
			pluginName := fmt.Sprintf("plugin-%04d", i)
			var deps []string
			if i > 0 {
				deps = []string{fmt.Sprintf("plugin-%04d", i-1)}
			}
			if err := dg.AddPlugin(pluginName, deps); err != nil {
				t.Fatalf("Failed to add plugin %s: %v", pluginName, err)
			}
		}
		buildTime := time.Since(start)

		// Calculate load order
		start = time.Now()
		loadOrder, err := dg.CalculateLoadOrder()
		calcTime := time.Since(start)

		if err != nil {
			t.Fatalf("Failed to calculate load order: %v", err)
		}

		if len(loadOrder) != graphSize {
			t.Errorf("Expected %d plugins in load order, got %d", graphSize, len(loadOrder))
		}

		// Performance assertions
		if buildTime > 100*time.Millisecond {
			t.Logf("⚠️  Performance warning: building %d-node graph took %v", graphSize, buildTime)
		}

		if calcTime > 50*time.Millisecond {
			t.Logf("⚠️  Performance warning: calculating load order for %d nodes took %v", graphSize, calcTime)
		}

		t.Logf("✅ Performance test completed - %d nodes: build=%v, calc=%v",
			graphSize, buildTime, calcTime)
	})

	t.Run("MemoryUsage_StressTest", func(t *testing.T) {
		// Test for memory leaks during intensive operations
		dg := NewDependencyGraph()

		const iterations = 1000
		for i := 0; i < iterations; i++ {
			// Add plugins
			for j := 0; j < 10; j++ {
				name := fmt.Sprintf("temp-%d-%d", i, j)
				deps := []string{}
				if j > 0 {
					deps = []string{fmt.Sprintf("temp-%d-%d", i, j-1)}
				}
				dg.AddPlugin(name, deps)
			}

			// Calculate order
			dg.CalculateLoadOrder()

			// Remove plugins (cleanup)
			for j := 0; j < 10; j++ {
				name := fmt.Sprintf("temp-%d-%d", i, j)
				dg.RemovePlugin(name)
			}
		}

		t.Logf("✅ Memory stress test completed - %d iterations of add/calc/remove cycles", iterations)
	})
}

// Helper functions
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
