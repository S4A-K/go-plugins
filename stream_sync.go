// stream_sync.go: Stdout/Stderr synchronization for subprocess plugins
//
// This file implements synchronization of subprocess stdout and stderr streams
// to the host process, enabling transparent logging and debugging of plugin output.
// This is essential for operational monitoring.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package goplugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// StreamSyncConfig configures how subprocess streams are synchronized.
type StreamSyncConfig struct {
	// SyncStdout enables stdout synchronization
	SyncStdout bool `json:"sync_stdout" yaml:"sync_stdout"`

	// SyncStderr enables stderr synchronization
	SyncStderr bool `json:"sync_stderr" yaml:"sync_stderr"`

	// BufferSize sets the buffer size for stream readers
	BufferSize int `json:"buffer_size" yaml:"buffer_size"`

	// LineBuffered enables line-by-line output (vs streaming)
	LineBuffered bool `json:"line_buffered" yaml:"line_buffered"`

	// PrefixOutput adds prefix to each line (e.g., "[plugin-name]")
	PrefixOutput bool `json:"prefix_output" yaml:"prefix_output"`

	// OutputPrefix is the prefix string to use
	OutputPrefix string `json:"output_prefix" yaml:"output_prefix"`

	// TimestampOutput adds timestamp to each line
	TimestampOutput bool `json:"timestamp_output" yaml:"timestamp_output"`
}

// DefaultStreamSyncConfig provides sensible defaults for stream synchronization.
var DefaultStreamSyncConfig = StreamSyncConfig{
	SyncStdout:      true,
	SyncStderr:      true,
	BufferSize:      4096,
	LineBuffered:    true,
	PrefixOutput:    true,
	OutputPrefix:    "[plugin]",
	TimestampOutput: false,
}

// StreamType identifies the type of stream being synchronized.
type StreamType int

const (
	StreamStdout StreamType = iota
	StreamStderr
)

// String implements fmt.Stringer for StreamType.
func (st StreamType) String() string {
	switch st {
	case StreamStdout:
		return "stdout"
	case StreamStderr:
		return "stderr"
	default:
		return "unknown"
	}
}

// StreamSyncer manages synchronization of subprocess streams to host output.
type StreamSyncer struct {
	config StreamSyncConfig
	logger Logger

	// Stream management
	streams map[StreamType]*StreamReader
	mutex   sync.RWMutex

	// Output destinations
	stdoutWriter io.Writer
	stderrWriter io.Writer

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	started bool
}

// StreamReader handles reading from a single stream.
type StreamReader struct {
	streamType StreamType
	reader     io.ReadCloser
	scanner    *bufio.Scanner
	syncer     *StreamSyncer

	// Statistics
	linesRead int64
	bytesRead int64
	startTime time.Time

	// Control
	done chan struct{}
}

// NewStreamSyncer creates a new stream synchronizer.
func NewStreamSyncer(config StreamSyncConfig, logger Logger) *StreamSyncer {
	if logger == nil {
		logger = DefaultLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &StreamSyncer{
		config:       config,
		logger:       logger,
		streams:      make(map[StreamType]*StreamReader),
		stdoutWriter: nil, // Will be set to os.Stdout by default
		stderrWriter: nil, // Will be set to os.Stderr by default
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetOutputWriters sets custom writers for stdout and stderr.
// If not called, defaults to os.Stdout and os.Stderr.
func (ss *StreamSyncer) SetOutputWriters(stdout, stderr io.Writer) {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	ss.stdoutWriter = stdout
	ss.stderrWriter = stderr
}

// AddStream adds a stream to be synchronized.
func (ss *StreamSyncer) AddStream(streamType StreamType, reader io.ReadCloser) error {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	if ss.started {
		return NewCommunicationError("cannot add stream: syncer already started", nil)
	}

	// Check if this stream type should be synchronized
	if streamType == StreamStdout && !ss.config.SyncStdout {
		ss.logger.Debug("Stdout sync disabled, skipping stream")
		return nil
	}
	if streamType == StreamStderr && !ss.config.SyncStderr {
		ss.logger.Debug("Stderr sync disabled, skipping stream")
		return nil
	}

	streamReader := &StreamReader{
		streamType: streamType,
		reader:     reader,
		syncer:     ss,
		startTime:  time.Now(),
		done:       make(chan struct{}),
	}

	// Create scanner with appropriate buffer size
	streamReader.scanner = bufio.NewScanner(reader)
	if ss.config.BufferSize > 0 {
		buf := make([]byte, ss.config.BufferSize)
		streamReader.scanner.Buffer(buf, ss.config.BufferSize)
	}

	ss.streams[streamType] = streamReader

	ss.logger.Debug("Added stream for synchronization",
		"stream_type", streamType.String(),
		"buffer_size", ss.config.BufferSize,
		"line_buffered", ss.config.LineBuffered)

	return nil
}

// Start begins stream synchronization.
func (ss *StreamSyncer) Start() error {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	if ss.started {
		return NewCommunicationError("stream syncer already started", nil)
	}

	// Set default output writers if not configured
	if ss.stdoutWriter == nil {
		ss.stdoutWriter = &DefaultStdoutWriter{}
	}
	if ss.stderrWriter == nil {
		ss.stderrWriter = &DefaultStderrWriter{}
	}

	// Start synchronization goroutines for each stream
	for streamType, streamReader := range ss.streams {
		ss.wg.Add(1)
		go ss.syncStream(streamReader)

		ss.logger.Debug("Started stream synchronization goroutine",
			"stream_type", streamType.String())
	}

	ss.started = true
	ss.logger.Info("Stream synchronization started",
		"stream_count", len(ss.streams),
		"stdout_sync", ss.config.SyncStdout,
		"stderr_sync", ss.config.SyncStderr)

	return nil
}

// Stop stops stream synchronization and closes all streams.
func (ss *StreamSyncer) Stop() error {
	ss.mutex.Lock()

	if !ss.started {
		ss.mutex.Unlock()
		return nil
	}

	// Cancel context to signal goroutines to stop
	ss.cancel()

	// Close all stream readers
	for streamType, streamReader := range ss.streams {
		if streamReader.reader != nil {
			if err := streamReader.reader.Close(); err != nil {
				ss.logger.Warn("Failed to close stream reader", "stream_type", streamType.String(), "error", err)
			}
			ss.logger.Debug("Closed stream reader", "stream_type", streamType.String())
		}
	}

	ss.mutex.Unlock()

	// Wait for all goroutines to finish
	ss.wg.Wait()

	ss.mutex.Lock()
	ss.started = false
	ss.mutex.Unlock()

	ss.logger.Info("Stream synchronization stopped")
	return nil
}

// syncStream runs the synchronization loop for a single stream.
func (ss *StreamSyncer) syncStream(streamReader *StreamReader) {
	defer ss.wg.Done()
	defer close(streamReader.done)

	ss.logger.Debug("Starting stream sync loop", "stream_type", streamReader.streamType.String())

	// Get appropriate output writer
	var writer io.Writer
	switch streamReader.streamType {
	case StreamStdout:
		writer = ss.stdoutWriter
	case StreamStderr:
		writer = ss.stderrWriter
	default:
		ss.logger.Error("Unknown stream type", "stream_type", streamReader.streamType)
		return
	}

	// Sync loop
	for {
		select {
		case <-ss.ctx.Done():
			ss.logger.Debug("Stream sync stopped by context", "stream_type", streamReader.streamType.String())
			return
		default:
			// Continue reading
		}

		if ss.config.LineBuffered {
			// Line-buffered reading
			if !streamReader.scanner.Scan() {
				// Check for error or EOF
				if err := streamReader.scanner.Err(); err != nil {
					ss.logger.Error("Stream scan error",
						"stream_type", streamReader.streamType.String(),
						"error", err)
				}
				ss.logger.Debug("Stream ended", "stream_type", streamReader.streamType.String())
				return
			}

			line := streamReader.scanner.Text()
			streamReader.linesRead++
			streamReader.bytesRead += int64(len(line))

			// Format and write line
			formattedLine := ss.formatLine(line, streamReader.streamType)
			if _, err := fmt.Fprintln(writer, formattedLine); err != nil {
				ss.logger.Error("Failed to write to output stream",
					"stream_type", streamReader.streamType.String(),
					"error", err)
			}
		} else {
			// Streaming mode - read in chunks and forward immediately
			buffer := make([]byte, ss.config.BufferSize)
			n, err := streamReader.reader.Read(buffer)

			if err != nil {
				if err != io.EOF {
					ss.logger.Error("Stream read error",
						"stream_type", streamReader.streamType.String(),
						"error", err)
				}
				ss.logger.Debug("Stream ended", "stream_type", streamReader.streamType.String())
				return
			}

			if n > 0 {
				streamReader.bytesRead += int64(n)

				// In streaming mode, optionally add timestamp/prefix per chunk
				data := buffer[:n]
				if ss.config.TimestampOutput || ss.config.PrefixOutput {
					// Convert to string for formatting, then back to bytes
					dataStr := string(data)
					formattedStr := ss.formatStreamChunk(dataStr, streamReader.streamType)
					data = []byte(formattedStr)
				}

				// Write directly to output without additional newlines
				if _, err := writer.Write(data); err != nil {
					ss.logger.Error("Failed to write to output stream",
						"stream_type", streamReader.streamType.String(),
						"error", err)
				}
			}
		}
	}
}

// formatLine formats a line according to configuration.
func (ss *StreamSyncer) formatLine(line string, streamType StreamType) string {
	result := line

	// Add timestamp if requested
	if ss.config.TimestampOutput {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		result = fmt.Sprintf("[%s] %s", timestamp, result)
	}

	// Add prefix if requested
	if ss.config.PrefixOutput && ss.config.OutputPrefix != "" {
		// Include stream type in prefix
		prefix := fmt.Sprintf("%s:%s", ss.config.OutputPrefix, streamType.String())
		result = fmt.Sprintf("%s %s", prefix, result)
	}

	return result
}

// formatStreamChunk formats a data chunk for streaming mode output.
// Unlike formatLine, this is designed for binary/chunk data that may not be line-oriented.
func (ss *StreamSyncer) formatStreamChunk(chunk string, streamType StreamType) string {
	result := chunk

	// For streaming mode, we only add prefix/timestamp at the beginning of chunks
	// to avoid breaking binary data or inserting formatting in the middle of output
	if ss.config.PrefixOutput && ss.config.OutputPrefix != "" {
		// Only add prefix if this chunk starts what looks like a new line or is the first chunk
		if len(chunk) > 0 && (chunk[0] != ' ' && chunk[0] != '\t') {
			prefix := fmt.Sprintf("%s:%s ", ss.config.OutputPrefix, streamType.String())
			result = prefix + result
		}
	}

	if ss.config.TimestampOutput {
		// Only add timestamp at the beginning of chunks that look like new content
		if len(chunk) > 0 && (chunk[0] != ' ' && chunk[0] != '\t') {
			timestamp := time.Now().Format("2006-01-02 15:04:05.000")
			result = fmt.Sprintf("[%s] %s", timestamp, result)
		}
	}

	return result
}

// GetStats returns synchronization statistics for all streams.
func (ss *StreamSyncer) GetStats() map[StreamType]*StreamStats {
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()

	stats := make(map[StreamType]*StreamStats)
	for streamType, streamReader := range ss.streams {
		stats[streamType] = &StreamStats{
			StreamType: streamType,
			LinesRead:  streamReader.linesRead,
			BytesRead:  streamReader.bytesRead,
			Duration:   time.Since(streamReader.startTime),
		}
	}

	return stats
}

// StreamStats contains statistics about stream synchronization.
type StreamStats struct {
	StreamType StreamType    `json:"stream_type"`
	LinesRead  int64         `json:"lines_read"`
	BytesRead  int64         `json:"bytes_read"`
	Duration   time.Duration `json:"duration"`
}

// String implements fmt.Stringer for StreamStats.
func (ss *StreamStats) String() string {
	return fmt.Sprintf("%s: %d lines, %d bytes, %v duration",
		ss.StreamType.String(), ss.LinesRead, ss.BytesRead, ss.Duration)
}

// DefaultStdoutWriter wraps os.Stdout for use as default stdout writer.
type DefaultStdoutWriter struct{}

// Write implements io.Writer interface.
func (dsw *DefaultStdoutWriter) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}

// DefaultStderrWriter wraps os.Stderr for use as default stderr writer.
type DefaultStderrWriter struct{}

// Write implements io.Writer interface.
func (dsw *DefaultStderrWriter) Write(p []byte) (n int, err error) {
	return os.Stderr.Write(p)
}
