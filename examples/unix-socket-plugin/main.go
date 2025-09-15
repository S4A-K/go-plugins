package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const (
	defaultSocketPath = "/tmp/filemanager.sock"
)

func main() {
	// Setup structured logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Parse command line arguments
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "server":
			runServer(logger)
			return
		case "client":
			runClient(logger)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	// Default: run both server and client
	logger.Info("Starting Unix Socket File Manager Plugin Example")
	logger.Info("This example demonstrates file management over Unix domain sockets")

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server
	server := NewFileManagerUnixServer(defaultSocketPath, logger)
	if err := server.Start(ctx); err != nil {
		logger.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			logger.Error("Failed to stop server", "error", err)
		}
	}()

	// Wait a moment for server to start
	time.Sleep(100 * time.Millisecond)

	// Create and connect client
	client := NewFileManagerUnixClient(defaultSocketPath, logger)
	if err := client.Connect(ctx); err != nil {
		logger.Error("Failed to connect client", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := client.Disconnect(); err != nil {
			logger.Error("Failed to disconnect client", "error", err)
		}
	}()

	// Run examples in a goroutine
	go runExamples(client, logger)

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutting down...")
}

func runServer(logger *slog.Logger) {
	logger.Info("Starting Unix Socket File Manager Server")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server
	server := NewFileManagerUnixServer(defaultSocketPath, logger)
	if err := server.Start(ctx); err != nil {
		logger.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			logger.Error("Failed to stop server", "error", err)
		}
	}()

	logger.Info("Server is running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutting down server...")
}

func runClient(logger *slog.Logger) {
	logger.Info("Starting Unix Socket File Manager Client")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and connect client
	client := NewFileManagerUnixClient(defaultSocketPath, logger)
	if err := client.Connect(ctx); err != nil {
		logger.Error("Failed to connect to server", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := client.Disconnect(); err != nil {
			logger.Error("Failed to disconnect client", "error", err)
		}
	}()

	// Run examples
	runExamples(client, logger)
}

func runExamples(client *FileManagerUnixClient, logger *slog.Logger) {
	logger.Info("Starting file management demonstrations...")

	// Get plugin information
	info := client.Info()
	logger.Info("Plugin Information",
		"name", info.Name,
		"version", info.Version,
		"description", info.Description,
		"capabilities", info.Capabilities,
	)

	// Check plugin health
	health := client.Health()
	logger.Info("Plugin Health Check",
		"status", health.Status,
		"message", health.Message,
		"metadata", health.Metadata,
	)

	// Create a temporary directory for examples
	tempDir := filepath.Join(os.TempDir(), "filemanager-plugin-example")
	if err := os.MkdirAll(tempDir, 0750); err != nil {
		logger.Error("Failed to create temp directory", "error", err)
		return
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Error("Failed to remove temp directory", "error", err)
		}
	}()

	logger.Info("Using temporary directory", "path", tempDir)

	// Demonstrate file operations
	demonstrateFileOperations(client, logger, tempDir)

	// Demonstrate directory operations
	demonstrateDirectoryOperations(client, logger, tempDir)

	// Demonstrate file information operations
	demonstrateFileInfoOperations(client, logger, tempDir)

	// Demonstrate error handling
	demonstrateErrorHandling(client, logger)

	// Demonstrate concurrent operations
	demonstrateConcurrentOperations(client, logger, tempDir)

	logger.Info("Example completed successfully")
}

func demonstrateFileOperations(client *FileManagerUnixClient, logger *slog.Logger, tempDir string) {
	logger.Info("=== File Operations Demo ===")

	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Hello, Unix Socket Plugin!\nThis is a test file.\nDemonstrating file operations."

	// Write file
	logger.Info("Writing file", "path", testFile, "content_length", len(testContent))
	writeResult, err := client.WriteFile(testFile, testContent)
	if err != nil {
		logger.Error("Failed to write file", "error", err)
		return
	}
	logger.Info("File written successfully",
		"bytes_written", writeResult.BytesWritten,
		"path", writeResult.Path,
	)

	// Read file
	logger.Info("Reading file", "path", testFile)
	content, err := client.ReadFile(testFile)
	if err != nil {
		logger.Error("Failed to read file", "error", err)
		return
	}
	logger.Info("File read successfully",
		"content_length", len(content),
		"content_preview", content[:min(50, len(content))],
	)

	// Copy file
	copyPath := filepath.Join(tempDir, "test_copy.txt")
	logger.Info("Copying file", "source", testFile, "destination", copyPath)
	copyResult, err := client.CopyFile(testFile, copyPath)
	if err != nil {
		logger.Error("Failed to copy file", "error", err)
		return
	}
	logger.Info("File copied successfully",
		"source", copyResult.Source,
		"destination", copyResult.Destination,
		"size", copyResult.Size,
	)

	// Move file
	movePath := filepath.Join(tempDir, "test_moved.txt")
	logger.Info("Moving file", "source", copyPath, "destination", movePath)
	moveResult, err := client.MovePath(copyPath, movePath)
	if err != nil {
		logger.Error("Failed to move file", "error", err)
		return
	}
	logger.Info("File moved successfully",
		"source", moveResult.Source,
		"destination", moveResult.Destination,
	)
}

func demonstrateDirectoryOperations(client *FileManagerUnixClient, logger *slog.Logger, tempDir string) {
	logger.Info("=== Directory Operations Demo ===")

	subDir := filepath.Join(tempDir, "subdir")

	// Create directory
	logger.Info("Creating directory", "path", subDir)
	createResult, err := client.CreateDirectory(subDir)
	if err != nil {
		logger.Error("Failed to create directory", "error", err)
		return
	}
	logger.Info("Directory created successfully",
		"path", createResult.Path,
		"created", createResult.Created,
	)

	// Create some files in the directory
	for i := 0; i < 3; i++ {
		fileName := fmt.Sprintf("file%d.txt", i+1)
		filePath := filepath.Join(subDir, fileName)
		content := fmt.Sprintf("This is file %d\nCreated for directory listing demo.", i+1)

		_, err := client.WriteFile(filePath, content)
		if err != nil {
			logger.Error("Failed to create demo file", "file", fileName, "error", err)
			continue
		}
	}

	// List directory contents
	logger.Info("Listing directory contents", "path", tempDir)
	listResult, err := client.ListFiles(tempDir)
	if err != nil {
		logger.Error("Failed to list directory", "error", err)
		return
	}

	logger.Info("Directory listing completed",
		"path", listResult.Path,
		"file_count", listResult.Count,
	)

	for _, file := range listResult.Files {
		logger.Info("File entry",
			"name", file.Name,
			"size", file.Size,
			"is_dir", file.IsDir,
			"mode", file.Mode,
			"mod_time", file.ModTime,
		)
	}

	// Delete directory and contents
	logger.Info("Deleting directory", "path", subDir)
	deleteResult, err := client.DeletePath(subDir)
	if err != nil {
		logger.Error("Failed to delete directory", "error", err)
		return
	}
	logger.Info("Directory deleted successfully",
		"path", deleteResult.Path,
		"deleted", deleteResult.Deleted,
	)
}

func demonstrateFileInfoOperations(client *FileManagerUnixClient, logger *slog.Logger, tempDir string) {
	logger.Info("=== File Information Operations Demo ===")

	// Create a test file
	testFile := filepath.Join(tempDir, "info_test.txt")
	testContent := "File for information testing"
	if _, err := client.WriteFile(testFile, testContent); err != nil {
		logger.Error("Failed to create test file", "error", err)
		return
	}

	// Get file statistics
	logger.Info("Getting file statistics", "path", testFile)
	statResult, err := client.StatPath(testFile)
	if err != nil {
		logger.Error("Failed to get file stats", "error", err)
		return
	}

	fileInfo := statResult.FileInfo
	logger.Info("File statistics",
		"name", fileInfo.Name,
		"path", fileInfo.Path,
		"size", fileInfo.Size,
		"is_dir", fileInfo.IsDir,
		"mode", fileInfo.Mode,
		"mod_time", fileInfo.ModTime,
	)

	// Check file existence
	logger.Info("Checking file existence", "path", testFile)
	existsResult, err := client.PathExists(testFile)
	if err != nil {
		logger.Error("Failed to check file existence", "error", err)
		return
	}
	logger.Info("File existence check",
		"path", existsResult.Path,
		"exists", existsResult.Exists,
	)

	// Check non-existent file
	nonExistentPath := filepath.Join(tempDir, "does_not_exist.txt")
	logger.Info("Checking non-existent file", "path", nonExistentPath)
	existsResult, err = client.PathExists(nonExistentPath)
	if err != nil {
		logger.Error("Failed to check non-existent file", "error", err)
		return
	}
	logger.Info("Non-existent file check",
		"path", existsResult.Path,
		"exists", existsResult.Exists,
	)
}

func demonstrateErrorHandling(client *FileManagerUnixClient, logger *slog.Logger) {
	logger.Info("=== Error Handling Demo ===")

	// Try to read non-existent file
	logger.Info("Testing error handling - reading non-existent file")
	_, err := client.ReadFile("/path/that/does/not/exist.txt")
	if err != nil {
		logger.Info("Error handling test successful", "expected_error", err.Error())
	} else {
		logger.Warn("Expected error but got success")
	}

	// Try to write to invalid path
	logger.Info("Testing error handling - writing to invalid path")
	_, err = client.WriteFile("/root/cannot_write_here.txt", "test")
	if err != nil {
		logger.Info("Error handling test successful", "expected_error", err.Error())
	} else {
		logger.Warn("Expected error but got success")
	}

	// Try invalid operation
	logger.Info("Testing error handling - invalid operation")
	_, err = client.Execute(context.Background(), "invalid_operation", map[string]interface{}{})
	if err != nil {
		logger.Info("Error handling test successful", "expected_error", err.Error())
	} else {
		logger.Warn("Expected error but got success")
	}
}

func demonstrateConcurrentOperations(client *FileManagerUnixClient, logger *slog.Logger, tempDir string) {
	logger.Info("=== Concurrent Operations Demo ===")

	// Create multiple files concurrently
	const numOperations = 5
	results := make(chan error, numOperations)

	logger.Info("Starting concurrent file operations", "count", numOperations)

	for i := 0; i < numOperations; i++ {
		go func(index int) {
			fileName := filepath.Join(tempDir, fmt.Sprintf("concurrent_%d.txt", index))
			content := fmt.Sprintf("Concurrent operation %d\nTesting parallel file operations", index)

			_, err := client.WriteFile(fileName, content)
			if err != nil {
				results <- fmt.Errorf("operation %d failed: %w", index, err)
				return
			}

			// Also read it back
			_, err = client.ReadFile(fileName)
			if err != nil {
				results <- fmt.Errorf("read operation %d failed: %w", index, err)
				return
			}

			logger.Info("Concurrent operation completed", "index", index, "file", fileName)
			results <- nil
		}(i)
	}

	// Wait for all operations to complete
	var errors []error
	for i := 0; i < numOperations; i++ {
		if err := <-results; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		logger.Error("Some concurrent operations failed", "error_count", len(errors))
		for _, err := range errors {
			logger.Error("Concurrent operation error", "error", err)
		}
	} else {
		logger.Info("All concurrent operations completed successfully")
	}
}

func printUsage() {
	fmt.Println("Unix Socket Plugin Example")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  go run .           # Run both server and client with examples")
	fmt.Println("  go run . server    # Run server only")
	fmt.Println("  go run . client    # Run client only (requires running server)")
	fmt.Println("  go run . help      # Show this help")
	fmt.Println("")
	fmt.Println("The plugin provides file management operations over Unix domain sockets:")
	fmt.Println("  • File operations: read, write, copy, move, delete")
	fmt.Println("  • Directory operations: create, list, delete")
	fmt.Println("  • Information operations: stat, exists")
	fmt.Println("  • Health monitoring and error handling")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
