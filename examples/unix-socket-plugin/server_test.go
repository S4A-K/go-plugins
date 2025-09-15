package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	plugins "github.com/go-plugins"
)

func TestFileManagerUnixServer(t *testing.T) {
	// Setup
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise in tests
	}))

	socketPath := filepath.Join(t.TempDir(), "test.sock")
	server := NewFileManagerUnixServer(socketPath, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			// Ignore "use of closed network connection" error as it's expected during shutdown
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("Failed to stop server: %v", err)
			}
		}
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	t.Run("ServerStartStop", func(t *testing.T) {
		// Server should be running at this point
		if server.listener == nil {
			t.Error("Server listener is nil")
		}

		// Check socket file exists
		if _, err := os.Stat(socketPath); os.IsNotExist(err) {
			t.Error("Socket file does not exist")
		}
	})

	t.Run("ServerStats", func(t *testing.T) {
		if server.stats == nil {
			t.Error("Server stats is nil")
		}

		// Stats should be initialized
		if server.stats.RequestCount < 0 {
			t.Error("Request count should be non-negative")
		}
	})

	t.Run("ServerShutdown", func(t *testing.T) {
		// Test graceful shutdown
		err := server.Stop()
		if err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}

		// Socket file should be removed
		if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
			t.Error("Socket file should be removed after shutdown")
		}
	})
}

func TestFileManagerUnixClient(t *testing.T) {
	// Setup
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Start server
	server := NewFileManagerUnixServer(socketPath, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Create client
	client := NewFileManagerUnixClient(socketPath, logger)

	t.Run("ClientConnection", func(t *testing.T) {
		err := client.Connect(ctx)
		if err != nil {
			t.Fatalf("Failed to connect client: %v", err)
		}
		defer func() {
			if err := client.Disconnect(); err != nil {
				t.Errorf("Failed to disconnect client: %v", err)
			}
		}()

		if client.conn == nil {
			t.Error("Client connection is nil")
		}
	})

	t.Run("PluginInfo", func(t *testing.T) {
		err := client.Connect(ctx)
		if err != nil {
			t.Fatalf("Failed to connect client: %v", err)
		}
		defer func() {
			if err := client.Disconnect(); err != nil {
				t.Errorf("Failed to disconnect client: %v", err)
			}
		}()

		info := client.Info()
		if info == nil {
			t.Error("Plugin info is nil")
			return
		}

		if info.Name == "" {
			t.Error("Plugin name is empty")
		}

		if info.Version == "" {
			t.Error("Plugin version is empty")
		}

		if len(info.Capabilities) == 0 {
			t.Error("Plugin capabilities are empty")
		}
	})

	t.Run("HealthCheck", func(t *testing.T) {
		err := client.Connect(ctx)
		if err != nil {
			t.Fatalf("Failed to connect client: %v", err)
		}
		defer func() {
			if err := client.Disconnect(); err != nil {
				t.Errorf("Failed to disconnect client: %v", err)
			}
		}()

		health := client.Health()
		if health == nil {
			t.Error("Health status is nil")
			return
		}

		if health.Status != plugins.StatusHealthy {
			t.Errorf("Expected healthy status, got %s", health.Status)
		}
	})
}

func TestFileOperations(t *testing.T) {
	// Setup server and client
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	socketPath := filepath.Join(t.TempDir(), "test.sock")
	server := NewFileManagerUnixServer(socketPath, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	client := NewFileManagerUnixClient(socketPath, logger)
	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect client: %v", err)
	}
	defer func() {
		if err := client.Disconnect(); err != nil {
			t.Errorf("Failed to disconnect client: %v", err)
		}
	}()

	// Create temp directory for tests
	tempDir := t.TempDir()

	t.Run("WriteAndReadFile", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "test.txt")
		testContent := "Hello, Unix Socket Plugin Test!"

		// Write file
		writeResult, err := client.WriteFile(testFile, testContent)
		if err != nil {
			t.Fatalf("Failed to write file: %v", err)
		}

		if writeResult.BytesWritten != int64(len(testContent)) {
			t.Errorf("Expected %d bytes written, got %d", len(testContent), writeResult.BytesWritten)
		}

		if writeResult.Path != testFile {
			t.Errorf("Expected path %s, got %s", testFile, writeResult.Path)
		}

		// Read file
		content, err := client.ReadFile(testFile)
		if err != nil {
			t.Fatalf("Failed to read file: %v", err)
		}

		if content != testContent {
			t.Errorf("Expected content %q, got %q", testContent, content)
		}
	})

	t.Run("CreateDirectory", func(t *testing.T) {
		testDir := filepath.Join(tempDir, "testdir")

		result, err := client.CreateDirectory(testDir)
		if err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}

		if !result.Created {
			t.Error("Directory should be created")
		}

		if result.Path != testDir {
			t.Errorf("Expected path %s, got %s", testDir, result.Path)
		}

		// Verify directory exists
		existsResult, err := client.PathExists(testDir)
		if err != nil {
			t.Fatalf("Failed to check directory existence: %v", err)
		}

		if !existsResult.Exists {
			t.Error("Directory should exist")
		}
	})

	t.Run("ListFiles", func(t *testing.T) {
		// Create some test files
		for i := 0; i < 3; i++ {
			testFile := filepath.Join(tempDir, "listtest_"+string(rune('0'+i))+".txt")
			_, err := client.WriteFile(testFile, "test content")
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
		}

		result, err := client.ListFiles(tempDir)
		if err != nil {
			t.Fatalf("Failed to list files: %v", err)
		}

		if result.Count < 3 {
			t.Errorf("Expected at least 3 files, got %d", result.Count)
		}

		if result.Path != tempDir {
			t.Errorf("Expected path %s, got %s", tempDir, result.Path)
		}

		if len(result.Files) != result.Count {
			t.Errorf("Files array length %d doesn't match count %d", len(result.Files), result.Count)
		}
	})

	t.Run("CopyFile", func(t *testing.T) {
		sourceFile := filepath.Join(tempDir, "source.txt")
		destFile := filepath.Join(tempDir, "dest.txt")
		testContent := "Content to copy"

		// Create source file
		_, err := client.WriteFile(sourceFile, testContent)
		if err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		// Copy file
		copyResult, err := client.CopyFile(sourceFile, destFile)
		if err != nil {
			t.Fatalf("Failed to copy file: %v", err)
		}

		if copyResult.Source != sourceFile {
			t.Errorf("Expected source %s, got %s", sourceFile, copyResult.Source)
		}

		if copyResult.Destination != destFile {
			t.Errorf("Expected destination %s, got %s", destFile, copyResult.Destination)
		}

		// Verify copied content
		content, err := client.ReadFile(destFile)
		if err != nil {
			t.Fatalf("Failed to read copied file: %v", err)
		}

		if content != testContent {
			t.Errorf("Expected content %q, got %q", testContent, content)
		}
	})

	t.Run("MoveFile", func(t *testing.T) {
		sourceFile := filepath.Join(tempDir, "movesource.txt")
		destFile := filepath.Join(tempDir, "movedest.txt")
		testContent := "Content to move"

		// Create source file
		_, err := client.WriteFile(sourceFile, testContent)
		if err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		// Move file
		moveResult, err := client.MovePath(sourceFile, destFile)
		if err != nil {
			t.Fatalf("Failed to move file: %v", err)
		}

		if moveResult.Source != sourceFile {
			t.Errorf("Expected source %s, got %s", sourceFile, moveResult.Source)
		}

		if moveResult.Destination != destFile {
			t.Errorf("Expected destination %s, got %s", destFile, moveResult.Destination)
		}

		// Verify source doesn't exist
		existsResult, err := client.PathExists(sourceFile)
		if err != nil {
			t.Fatalf("Failed to check source existence: %v", err)
		}

		if existsResult.Exists {
			t.Error("Source file should not exist after move")
		}

		// Verify destination exists with correct content
		content, err := client.ReadFile(destFile)
		if err != nil {
			t.Fatalf("Failed to read moved file: %v", err)
		}

		if content != testContent {
			t.Errorf("Expected content %q, got %q", testContent, content)
		}
	})

	t.Run("StatFile", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "stat.txt")
		testContent := "Content for stat test"

		// Create test file
		_, err := client.WriteFile(testFile, testContent)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Get file stats
		statResult, err := client.StatPath(testFile)
		if err != nil {
			t.Fatalf("Failed to stat file: %v", err)
		}

		fileInfo := statResult.FileInfo

		if fileInfo.Size != int64(len(testContent)) {
			t.Errorf("Expected size %d, got %d", len(testContent), fileInfo.Size)
		}

		if fileInfo.IsDir {
			t.Error("File should not be a directory")
		}

		if fileInfo.Name != "stat.txt" {
			t.Errorf("Expected name 'stat.txt', got %s", fileInfo.Name)
		}
	})

	t.Run("DeleteFile", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "delete.txt")

		// Create test file
		_, err := client.WriteFile(testFile, "content to delete")
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Delete file
		deleteResult, err := client.DeletePath(testFile)
		if err != nil {
			t.Fatalf("Failed to delete file: %v", err)
		}

		if !deleteResult.Deleted {
			t.Error("File should be deleted")
		}

		if deleteResult.Path != testFile {
			t.Errorf("Expected path %s, got %s", testFile, deleteResult.Path)
		}

		// Verify file doesn't exist
		existsResult, err := client.PathExists(testFile)
		if err != nil {
			t.Fatalf("Failed to check file existence: %v", err)
		}

		if existsResult.Exists {
			t.Error("File should not exist after deletion")
		}
	})

	t.Run("PathExists", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "exists.txt")

		// Check non-existent file
		existsResult, err := client.PathExists(testFile)
		if err != nil {
			t.Fatalf("Failed to check non-existent file: %v", err)
		}

		if existsResult.Exists {
			t.Error("Non-existent file should not exist")
		}

		// Create file
		_, err = client.WriteFile(testFile, "test content")
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Check existing file
		existsResult, err = client.PathExists(testFile)
		if err != nil {
			t.Fatalf("Failed to check existing file: %v", err)
		}

		if !existsResult.Exists {
			t.Error("Existing file should exist")
		}
	})
}

func TestErrorHandling(t *testing.T) {
	// Setup server and client
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	socketPath := filepath.Join(t.TempDir(), "test.sock")
	server := NewFileManagerUnixServer(socketPath, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	client := NewFileManagerUnixClient(socketPath, logger)
	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect client: %v", err)
	}
	defer func() {
		if err := client.Disconnect(); err != nil {
			t.Errorf("Failed to disconnect client: %v", err)
		}
	}()

	t.Run("ReadNonExistentFile", func(t *testing.T) {
		_, err := client.ReadFile("/path/that/does/not/exist.txt")
		if err == nil {
			t.Error("Expected error when reading non-existent file")
		}
	})

	t.Run("WriteInvalidPath", func(t *testing.T) {
		_, err := client.WriteFile("/root/cannot_write_here.txt", "test")
		if err == nil {
			t.Error("Expected error when writing to invalid path")
		}
	})

	t.Run("InvalidOperation", func(t *testing.T) {
		_, err := client.Execute(context.Background(), "invalid_operation", map[string]interface{}{})
		if err == nil {
			t.Error("Expected error for invalid operation")
		}
	})

	t.Run("MissingParameters", func(t *testing.T) {
		_, err := client.Execute(context.Background(), "read", map[string]interface{}{})
		if err == nil {
			t.Error("Expected error for missing parameters")
		}
	})
}

func TestConcurrentOperations(t *testing.T) {
	// Setup server and client
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	socketPath := filepath.Join(t.TempDir(), "test.sock")
	server := NewFileManagerUnixServer(socketPath, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	tempDir := t.TempDir()
	const numOperations = 10

	t.Run("ConcurrentFileOperations", func(t *testing.T) {
		results := make(chan error, numOperations)

		for i := 0; i < numOperations; i++ {
			go func(index int) {
				// Each goroutine needs its own client connection for Unix sockets
				client := NewFileManagerUnixClient(socketPath, logger)
				err := client.Connect(ctx)
				if err != nil {
					results <- err
					return
				}
				defer func() {
					if err := client.Disconnect(); err != nil {
						logger.Error("Failed to disconnect client", "error", err)
					}
				}()

				testFile := filepath.Join(tempDir, "concurrent_"+string(rune('0'+index))+".txt")
				testContent := "Concurrent operation content"

				// Write file
				_, err = client.WriteFile(testFile, testContent)
				if err != nil {
					results <- err
					return
				}

				// Read file back
				content, err := client.ReadFile(testFile)
				if err != nil {
					results <- err
					return
				}

				if content != testContent {
					results <- err
					return
				}

				results <- nil
			}(i)
		}

		// Collect results
		var errors []error
		for i := 0; i < numOperations; i++ {
			if err := <-results; err != nil {
				errors = append(errors, err)
			}
		}

		if len(errors) > 0 {
			t.Errorf("Concurrent operations failed: %d errors out of %d operations", len(errors), numOperations)
			for _, err := range errors {
				t.Logf("Error: %v", err)
			}
		}
	})
}

// Benchmark tests
func BenchmarkFileOperations(b *testing.B) {
	// Setup
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	socketPath := filepath.Join(b.TempDir(), "bench.sock")
	server := NewFileManagerUnixServer(socketPath, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		b.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			b.Errorf("Failed to stop server: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	client := NewFileManagerUnixClient(socketPath, logger)
	err = client.Connect(ctx)
	if err != nil {
		b.Fatalf("Failed to connect client: %v", err)
	}
	defer func() {
		if err := client.Disconnect(); err != nil {
			b.Errorf("Failed to disconnect client: %v", err)
		}
	}()

	tempDir := b.TempDir()
	testContent := "Benchmark test content"

	b.Run("WriteFile", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			testFile := filepath.Join(tempDir, "bench_write_"+string(rune('0'+i%10))+".txt")
			_, err := client.WriteFile(testFile, testContent)
			if err != nil {
				b.Fatalf("Failed to write file: %v", err)
			}
		}
	})

	b.Run("ReadFile", func(b *testing.B) {
		// Create test file
		testFile := filepath.Join(tempDir, "bench_read.txt")
		_, err := client.WriteFile(testFile, testContent)
		if err != nil {
			b.Fatalf("Failed to create test file: %v", err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.ReadFile(testFile)
			if err != nil {
				b.Fatalf("Failed to read file: %v", err)
			}
		}
	})

	b.Run("Health", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			health := client.Health()
			if health.Status != plugins.StatusHealthy {
				b.Fatalf("Health check failed")
			}
		}
	})
}
