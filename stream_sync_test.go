// stream_sync_test.go: Tests for subprocess stream synchronization
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestDefaultStreamSyncConfig(t *testing.T) {
	config := DefaultStreamSyncConfig

	if !config.SyncStdout {
		t.Error("Expected stdout sync to be enabled by default")
	}

	if !config.SyncStderr {
		t.Error("Expected stderr sync to be enabled by default")
	}

	if config.BufferSize != 4096 {
		t.Errorf("Expected buffer size 4096, got %d", config.BufferSize)
	}

	if !config.LineBuffered {
		t.Error("Expected line buffered to be true by default")
	}

	if !config.PrefixOutput {
		t.Error("Expected prefix output to be true by default")
	}

	if config.OutputPrefix != "[plugin]" {
		t.Errorf("Expected output prefix '[plugin]', got %s", config.OutputPrefix)
	}
}

func TestStreamTypeString(t *testing.T) {
	tests := []struct {
		streamType StreamType
		expected   string
	}{
		{StreamStdout, "stdout"},
		{StreamStderr, "stderr"},
		{StreamType(999), "unknown"},
	}

	for _, test := range tests {
		if got := test.streamType.String(); got != test.expected {
			t.Errorf("StreamType(%d).String() = %s, expected %s", test.streamType, got, test.expected)
		}
	}
}

func TestNewStreamSyncer(t *testing.T) {
	config := DefaultStreamSyncConfig
	logger := NewTestLogger()

	syncer := NewStreamSyncer(config, logger)

	if syncer == nil {
		t.Fatal("NewStreamSyncer returned nil")
	}

	if syncer.config.SyncStdout != config.SyncStdout {
		t.Error("Config not set correctly")
	}

	if len(syncer.streams) != 0 {
		t.Errorf("Expected 0 streams initially, got %d", len(syncer.streams))
	}
}

func TestStreamSyncerSetOutputWriters(t *testing.T) {
	config := DefaultStreamSyncConfig
	logger := NewTestLogger()
	syncer := NewStreamSyncer(config, logger)

	var stdoutBuf, stderrBuf bytes.Buffer
	syncer.SetOutputWriters(&stdoutBuf, &stderrBuf)

	// Verify writers were set (we can't directly check private fields,
	// but we can test through Start() which will use them)
}

func TestStreamSyncerAddStream(t *testing.T) {
	config := DefaultStreamSyncConfig
	logger := NewTestLogger()
	syncer := NewStreamSyncer(config, logger)

	// Create a test reader
	reader := io.NopCloser(strings.NewReader("test data"))

	// Add stdout stream
	err := syncer.AddStream(StreamStdout, reader)
	if err != nil {
		t.Fatalf("AddStream failed: %v", err)
	}

	// Verify stream was added
	if len(syncer.streams) != 1 {
		t.Errorf("Expected 1 stream, got %d", len(syncer.streams))
	}

	// Try to add stream after starting (should fail)
	syncer.started = true
	reader2 := io.NopCloser(strings.NewReader("test data 2"))
	err = syncer.AddStream(StreamStderr, reader2)
	if err == nil {
		t.Error("Expected error when adding stream to started syncer")
	}
}

func TestStreamSyncerAddStream_DisabledSync(t *testing.T) {
	config := StreamSyncConfig{
		SyncStdout: false,
		SyncStderr: true,
	}
	logger := NewTestLogger()
	syncer := NewStreamSyncer(config, logger)

	// Try to add stdout stream (should be skipped)
	reader := io.NopCloser(strings.NewReader("test data"))
	err := syncer.AddStream(StreamStdout, reader)
	if err != nil {
		t.Fatalf("AddStream should not fail for disabled stream: %v", err)
	}

	// Should not have added any streams
	if len(syncer.streams) != 0 {
		t.Errorf("Expected 0 streams (stdout disabled), got %d", len(syncer.streams))
	}

	// Try stderr (should work)
	reader2 := io.NopCloser(strings.NewReader("test data 2"))
	err = syncer.AddStream(StreamStderr, reader2)
	if err != nil {
		t.Fatalf("AddStream failed for enabled stream: %v", err)
	}

	if len(syncer.streams) != 1 {
		t.Errorf("Expected 1 stream (stderr enabled), got %d", len(syncer.streams))
	}
}

func TestStreamSyncerStartStop(t *testing.T) {
	config := DefaultStreamSyncConfig
	logger := NewTestLogger()
	syncer := NewStreamSyncer(config, logger)

	var stdoutBuf, stderrBuf bytes.Buffer
	syncer.SetOutputWriters(&stdoutBuf, &stderrBuf)

	// Add test streams
	stdoutReader := io.NopCloser(strings.NewReader("stdout line 1\nstdout line 2\n"))
	stderrReader := io.NopCloser(strings.NewReader("stderr line 1\nstderr line 2\n"))

	err := syncer.AddStream(StreamStdout, stdoutReader)
	if err != nil {
		t.Fatalf("AddStream stdout failed: %v", err)
	}

	err = syncer.AddStream(StreamStderr, stderrReader)
	if err != nil {
		t.Fatalf("AddStream stderr failed: %v", err)
	}

	// Start synchronization
	err = syncer.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Give some time for synchronization to process
	time.Sleep(100 * time.Millisecond)

	// Stop synchronization
	err = syncer.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Check that output was written
	stdoutOutput := stdoutBuf.String()
	stderrOutput := stderrBuf.String()

	if !strings.Contains(stdoutOutput, "stdout line 1") {
		t.Errorf("Expected stdout output to contain 'stdout line 1', got: %s", stdoutOutput)
	}

	if !strings.Contains(stderrOutput, "stderr line 1") {
		t.Errorf("Expected stderr output to contain 'stderr line 1', got: %s", stderrOutput)
	}
}

func TestStreamSyncerFormatLine(t *testing.T) {
	tests := []struct {
		name           string
		config         StreamSyncConfig
		line           string
		streamType     StreamType
		expectContains []string
	}{
		{
			name: "basic formatting with prefix",
			config: StreamSyncConfig{
				PrefixOutput:    true,
				OutputPrefix:    "[test]",
				TimestampOutput: false,
			},
			line:           "test message",
			streamType:     StreamStdout,
			expectContains: []string{"[test]:stdout", "test message"},
		},
		{
			name: "formatting with timestamp",
			config: StreamSyncConfig{
				PrefixOutput:    false,
				TimestampOutput: true,
			},
			line:           "test message",
			streamType:     StreamStderr,
			expectContains: []string{"test message", fmt.Sprintf("%d", time.Now().Year())}, // Dynamic year
		},
		{
			name: "formatting with both prefix and timestamp",
			config: StreamSyncConfig{
				PrefixOutput:    true,
				OutputPrefix:    "[combined]",
				TimestampOutput: true,
			},
			line:           "test message",
			streamType:     StreamStdout,
			expectContains: []string{"[combined]:stdout", "test message", fmt.Sprintf("%d", time.Now().Year())},
		},
		{
			name: "no formatting",
			config: StreamSyncConfig{
				PrefixOutput:    false,
				TimestampOutput: false,
			},
			line:           "plain message",
			streamType:     StreamStdout,
			expectContains: []string{"plain message"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := NewTestLogger()
			syncer := NewStreamSyncer(test.config, logger)

			formatted := syncer.formatLine(test.line, test.streamType)

			for _, expected := range test.expectContains {
				if !strings.Contains(formatted, expected) {
					t.Errorf("Expected formatted line to contain '%s', got: %s", expected, formatted)
				}
			}
		})
	}
}

func TestStreamStats(t *testing.T) {
	stats := &StreamStats{
		StreamType: StreamStdout,
		LinesRead:  10,
		BytesRead:  100,
		Duration:   time.Second,
	}

	str := stats.String()
	expected := []string{"stdout", "10 lines", "100 bytes", "1s"}

	for _, exp := range expected {
		if !strings.Contains(str, exp) {
			t.Errorf("Expected stats string to contain '%s', got: %s", exp, str)
		}
	}
}

func TestDefaultWriters(t *testing.T) {
	// Test DefaultStdoutWriter
	stdoutWriter := &DefaultStdoutWriter{}
	testData := []byte("test stdout data")
	n, err := stdoutWriter.Write(testData)
	if err != nil {
		t.Errorf("DefaultStdoutWriter.Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, got %d", len(testData), n)
	}

	// Test DefaultStderrWriter
	stderrWriter := &DefaultStderrWriter{}
	testData = []byte("test stderr data")
	n, err = stderrWriter.Write(testData)
	if err != nil {
		t.Errorf("DefaultStderrWriter.Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, got %d", len(testData), n)
	}
}

// TestPipeReader creates a pipe reader for testing.
type TestPipeReader struct {
	*io.PipeReader
}

// Close implements io.ReadCloser.
func (tpr *TestPipeReader) Close() error {
	return tpr.PipeReader.Close()
}

func TestStreamSyncerWithPipe(t *testing.T) {
	config := DefaultStreamSyncConfig
	logger := NewTestLogger()
	syncer := NewStreamSyncer(config, logger)

	var stdoutBuf bytes.Buffer
	syncer.SetOutputWriters(&stdoutBuf, &stdoutBuf)

	// Create pipe for streaming data
	pipeReader, pipeWriter := io.Pipe()
	testReader := &TestPipeReader{PipeReader: pipeReader}

	err := syncer.AddStream(StreamStdout, testReader)
	if err != nil {
		t.Fatalf("AddStream failed: %v", err)
	}

	// Start syncer
	err = syncer.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Write some test data
	go func() {
		defer func() {
			if err := pipeWriter.Close(); err != nil {
				t.Logf("Warning: failed to close pipe writer: %v", err)
			}
		}()
		if _, err := pipeWriter.Write([]byte("line 1\nline 2\nline 3\n")); err != nil {
			t.Logf("Warning: failed to write to pipe: %v", err)
		}
	}()

	// Give time for processing
	time.Sleep(200 * time.Millisecond)

	// Stop syncer
	err = syncer.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	output := stdoutBuf.String()
	if !strings.Contains(output, "line 1") || !strings.Contains(output, "line 2") {
		t.Errorf("Expected output to contain test lines, got: %s", output)
	}
}
