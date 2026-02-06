package logstreamer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// NginxLogBatch represents a batch of nginx log entries to send to backend
type NginxLogBatch struct {
	AgentID string          `json:"agent_id"`
	Entries []NginxLogEntry `json:"entries"`
}

// NginxCollector collects nginx access logs and sends them to the backend
type NginxCollector struct {
	logPath       string
	backendURL    string
	agentID       string
	httpClient    *http.Client
	logger        *zap.Logger
	parser        *NginxLogParser

	// Buffering
	buffer        []NginxLogEntry
	bufferMu      sync.Mutex
	bufferSize    int
	flushInterval time.Duration

	// File tracking
	file          *os.File
	fileOffset    int64

	// Configuration
	skipHealthChecks bool
	normalizePaths   bool
}

// NginxCollectorConfig holds configuration for the nginx collector
type NginxCollectorConfig struct {
	LogPath          string
	BackendURL       string
	AgentID          string
	BufferSize       int
	FlushInterval    time.Duration
	SkipHealthChecks bool
	NormalizePaths   bool
}

// DefaultNginxCollectorConfig returns default configuration
func DefaultNginxCollectorConfig() NginxCollectorConfig {
	return NginxCollectorConfig{
		LogPath:          "/var/log/nginx/access.log",
		BufferSize:       500,
		FlushInterval:    5 * time.Second,
		SkipHealthChecks: true,
		NormalizePaths:   false,
	}
}

// NewNginxCollector creates a new nginx log collector
func NewNginxCollector(config NginxCollectorConfig, logger *zap.Logger) *NginxCollector {
	if config.BufferSize == 0 {
		config.BufferSize = 500
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.LogPath == "" {
		config.LogPath = "/var/log/nginx/access.log"
	}

	return &NginxCollector{
		logPath:          config.LogPath,
		backendURL:       config.BackendURL,
		agentID:          config.AgentID,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		logger:           logger,
		parser:           NewNginxLogParser(),
		buffer:           make([]NginxLogEntry, 0, config.BufferSize),
		bufferSize:       config.BufferSize,
		flushInterval:    config.FlushInterval,
		skipHealthChecks: config.SkipHealthChecks,
		normalizePaths:   config.NormalizePaths,
	}
}

// Start begins collecting nginx access logs
func (c *NginxCollector) Start(ctx context.Context) error {
	c.logger.Info("Starting nginx log collector",
		zap.String("log_path", c.logPath),
		zap.String("backend", c.backendURL),
		zap.String("agent_id", c.agentID),
		zap.Int("buffer_size", c.bufferSize),
		zap.Duration("flush_interval", c.flushInterval),
	)

	// Start flush loop
	go c.flushLoop(ctx)

	// Start file watcher
	return c.watchFile(ctx)
}

// flushLoop periodically flushes buffered logs to the backend
func (c *NginxCollector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush
			c.flush()
			c.logger.Info("Nginx log collector stopped")
			return
		case <-ticker.C:
			c.flush()
		}
	}
}

// watchFile watches the nginx access log file for new entries
func (c *NginxCollector) watchFile(ctx context.Context) error {
	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Open the log file
	if err := c.openLogFile(); err != nil {
		c.logger.Warn("Failed to open nginx log file, will retry",
			zap.String("path", c.logPath),
			zap.Error(err),
		)
	}

	// Watch the log file
	if err := watcher.Add(c.logPath); err != nil {
		// File doesn't exist yet, watch parent directory
		c.logger.Debug("Log file doesn't exist yet, watching for creation",
			zap.String("path", c.logPath),
		)
	}

	// Also watch /var/log/nginx for file recreation (log rotation)
	watcher.Add("/var/log/nginx")

	// Read any existing content
	if c.file != nil {
		c.readNewLines()
	}

	// Periodic check for file changes (backup for missed events)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if c.file != nil {
				c.file.Close()
			}
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			if event.Name == c.logPath {
				switch {
				case event.Op&fsnotify.Write == fsnotify.Write:
					// File was written to
					c.readNewLines()

				case event.Op&fsnotify.Create == fsnotify.Create:
					// File was created (after rotation)
					c.logger.Info("Log file recreated, reopening")
					c.reopenLogFile()

				case event.Op&fsnotify.Remove == fsnotify.Remove:
					// File was removed (log rotation)
					c.logger.Info("Log file removed, waiting for recreation")
					if c.file != nil {
						c.file.Close()
						c.file = nil
					}
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			c.logger.Error("File watcher error", zap.Error(err))

		case <-ticker.C:
			// Periodic check for file changes
			if c.file == nil {
				if err := c.openLogFile(); err == nil {
					c.logger.Info("Log file now available")
					watcher.Add(c.logPath)
				}
			}
			c.readNewLines()
		}
	}
}

// openLogFile opens the nginx access log file
func (c *NginxCollector) openLogFile() error {
	file, err := os.Open(c.logPath)
	if err != nil {
		return err
	}

	// Seek to end to only read new entries
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		file.Close()
		return err
	}

	c.file = file
	c.fileOffset = offset
	c.logger.Info("Opened nginx log file",
		zap.String("path", c.logPath),
		zap.Int64("offset", offset),
	)
	return nil
}

// reopenLogFile closes and reopens the log file (after rotation)
func (c *NginxCollector) reopenLogFile() {
	if c.file != nil {
		c.file.Close()
		c.file = nil
	}

	if err := c.openLogFile(); err != nil {
		c.logger.Warn("Failed to reopen log file", zap.Error(err))
	}

	// Reset offset to read from beginning of new file
	if c.file != nil {
		c.file.Seek(0, io.SeekStart)
		c.fileOffset = 0
	}
}

// readNewLines reads new lines from the log file
func (c *NginxCollector) readNewLines() {
	if c.file == nil {
		c.logger.Debug("readNewLines: file is nil")
		return
	}

	// Get current file size
	info, err := c.file.Stat()
	if err != nil {
		c.logger.Warn("Failed to stat file", zap.Error(err))
		return
	}

	currentSize := info.Size()

	// Check if file was truncated (log rotation)
	if currentSize < c.fileOffset {
		c.logger.Info("Log file was truncated, reading from beginning")
		c.file.Seek(0, io.SeekStart)
		c.fileOffset = 0
	}

	// Check if there's new content
	if currentSize <= c.fileOffset {
		return
	}

	c.logger.Info("Reading new log entries",
		zap.Int64("current_size", currentSize),
		zap.Int64("last_offset", c.fileOffset),
	)

	// Seek to last position
	c.file.Seek(c.fileOffset, io.SeekStart)

	// Read new lines
	reader := bufio.NewReader(c.file)
	linesRead := 0
	linesSkipped := 0
	linesParsed := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				c.logger.Warn("Error reading line", zap.Error(err))
			}
			break
		}
		linesRead++

		// Parse the line
		entry, err := c.parser.Parse(line)
		if err != nil {
			c.logger.Warn("Failed to parse nginx log line",
				zap.String("line", line),
				zap.Error(err),
			)
			continue
		}

		if entry == nil {
			linesSkipped++
			c.logger.Info("Failed to parse log line (nil result)",
				zap.String("line", line[:min(len(line), 200)]),
			)
			continue
		}
		linesParsed++

		// Skip health checks if configured
		if c.skipHealthChecks && IsHealthCheck(entry.Path, entry.UserAgent) {
			linesSkipped++
			continue
		}

		// Normalize paths if configured
		if c.normalizePaths {
			entry.Path = NormalizePath(entry.Path)
		}

		c.addEntry(*entry)
	}

	if linesRead > 0 {
		c.logger.Info("Processed nginx log lines",
			zap.Int("read", linesRead),
			zap.Int("parsed", linesParsed),
			zap.Int("skipped", linesSkipped),
		)
	}

	// Update offset
	newOffset, _ := c.file.Seek(0, io.SeekCurrent)
	c.fileOffset = newOffset
}

// addEntry adds a log entry to the buffer
func (c *NginxCollector) addEntry(entry NginxLogEntry) {
	c.bufferMu.Lock()
	defer c.bufferMu.Unlock()

	c.buffer = append(c.buffer, entry)
	c.logger.Debug("Added entry to buffer",
		zap.Int("buffer_count", len(c.buffer)),
		zap.String("path", entry.Path),
	)

	// Flush if buffer is full
	if len(c.buffer) >= c.bufferSize {
		go c.flush()
	}
}

// flush sends buffered logs to the backend
func (c *NginxCollector) flush() {
	c.bufferMu.Lock()
	if len(c.buffer) == 0 {
		c.bufferMu.Unlock()
		return
	}

	// Copy and clear buffer
	entries := make([]NginxLogEntry, len(c.buffer))
	copy(entries, c.buffer)
	c.buffer = c.buffer[:0]
	c.bufferMu.Unlock()

	// Send to backend
	batch := NginxLogBatch{
		AgentID: c.agentID,
		Entries: entries,
	}

	data, err := json.Marshal(batch)
	if err != nil {
		c.logger.Error("Failed to marshal nginx log batch", zap.Error(err))
		return
	}

	url := c.backendURL + "/api/v1/logs/nginx/ingest"
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		c.logger.Error("Failed to send nginx logs to backend",
			zap.Error(err),
			zap.Int("entries", len(entries)),
		)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Error("Backend rejected nginx logs",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)),
		)
		return
	}

	c.logger.Info("Flushed nginx logs to backend", zap.Int("count", len(entries)))
}

// Stop stops the nginx log collector
func (c *NginxCollector) Stop() {
	if c.file != nil {
		c.file.Close()
		c.file = nil
	}

	// Final flush
	c.flush()
}
