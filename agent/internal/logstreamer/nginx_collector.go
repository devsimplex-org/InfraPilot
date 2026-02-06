package logstreamer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// trackedFile represents a log file being watched
type trackedFile struct {
	path   string
	file   *os.File
	offset int64
}

// NginxCollector collects nginx access logs and sends them to the backend
type NginxCollector struct {
	logPath       string // Primary log path (for config)
	logDirs       []string // Directories to watch for log files
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

	// Multi-file tracking
	files    map[string]*trackedFile
	filesMu  sync.RWMutex

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
		logDirs:          []string{"/var/log/nginx", "/var/log/nginx/domains"},
		backendURL:       config.BackendURL,
		agentID:          config.AgentID,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		logger:           logger,
		parser:           NewNginxLogParser(),
		buffer:           make([]NginxLogEntry, 0, config.BufferSize),
		bufferSize:       config.BufferSize,
		flushInterval:    config.FlushInterval,
		files:            make(map[string]*trackedFile),
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
	return c.watchFiles(ctx)
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

// watchFiles watches all nginx log files for new entries
func (c *NginxCollector) watchFiles(ctx context.Context) error {
	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Watch log directories
	for _, dir := range c.logDirs {
		if err := watcher.Add(dir); err != nil {
			c.logger.Debug("Could not watch directory, may not exist yet",
				zap.String("dir", dir),
				zap.Error(err),
			)
		} else {
			c.logger.Info("Watching directory for log files", zap.String("dir", dir))
		}
	}

	// Scan for existing log files
	c.scanExistingLogFiles()

	// Periodic scan for new files and changes (backup for missed events)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.closeAllFiles()
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			c.handleFileEvent(event, watcher)

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			c.logger.Error("File watcher error", zap.Error(err))

		case <-ticker.C:
			// Periodic scan for changes
			c.readAllFiles()
			// Also try to watch directories that may now exist
			for _, dir := range c.logDirs {
				watcher.Add(dir)
			}
		}
	}
}

// scanExistingLogFiles scans for existing nginx log files
func (c *NginxCollector) scanExistingLogFiles() {
	for _, dir := range c.logDirs {
		// Look for access log files
		patterns := []string{
			filepath.Join(dir, "access.log"),
			filepath.Join(dir, "*.access.log"),
		}

		for _, pattern := range patterns {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}

			for _, path := range matches {
				c.trackFile(path)
			}
		}
	}
}

// trackFile starts tracking a log file
func (c *NginxCollector) trackFile(path string) {
	c.filesMu.Lock()
	defer c.filesMu.Unlock()

	// Skip if already tracking
	if _, exists := c.files[path]; exists {
		return
	}

	file, err := os.Open(path)
	if err != nil {
		c.logger.Debug("Could not open log file",
			zap.String("path", path),
			zap.Error(err),
		)
		return
	}

	// Seek to end to only read new entries
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		file.Close()
		c.logger.Debug("Could not seek in log file",
			zap.String("path", path),
			zap.Error(err),
		)
		return
	}

	c.files[path] = &trackedFile{
		path:   path,
		file:   file,
		offset: offset,
	}

	c.logger.Info("Now tracking log file", zap.String("path", path), zap.Int64("offset", offset))
}

// untrackFile stops tracking a log file
func (c *NginxCollector) untrackFile(path string) {
	c.filesMu.Lock()
	defer c.filesMu.Unlock()

	if tf, exists := c.files[path]; exists {
		if tf.file != nil {
			tf.file.Close()
		}
		delete(c.files, path)
		c.logger.Info("Stopped tracking log file", zap.String("path", path))
	}
}

// handleFileEvent handles fsnotify events
func (c *NginxCollector) handleFileEvent(event fsnotify.Event, watcher *fsnotify.Watcher) {
	path := event.Name

	// Only process access log files
	if !strings.HasSuffix(path, "access.log") && !strings.HasSuffix(path, ".access.log") {
		return
	}

	switch {
	case event.Op&fsnotify.Write == fsnotify.Write:
		// File was written to - read new lines
		c.readFile(path)

	case event.Op&fsnotify.Create == fsnotify.Create:
		// New file created
		c.logger.Info("Log file created", zap.String("path", path))
		c.trackFile(path)
		// Also watch the file directly
		watcher.Add(path)

	case event.Op&fsnotify.Remove == fsnotify.Remove:
		// File was removed (log rotation)
		c.logger.Info("Log file removed", zap.String("path", path))
		c.untrackFile(path)
	}
}

// readAllFiles reads new lines from all tracked files
func (c *NginxCollector) readAllFiles() {
	c.filesMu.RLock()
	paths := make([]string, 0, len(c.files))
	for path := range c.files {
		paths = append(paths, path)
	}
	c.filesMu.RUnlock()

	for _, path := range paths {
		c.readFile(path)
	}
}

// readFile reads new lines from a specific log file
func (c *NginxCollector) readFile(path string) {
	c.filesMu.Lock()
	tf, exists := c.files[path]
	if !exists || tf.file == nil {
		c.filesMu.Unlock()
		// Try to track the file if it exists
		c.trackFile(path)
		return
	}

	// Get current file size
	info, err := tf.file.Stat()
	if err != nil {
		c.filesMu.Unlock()
		c.logger.Debug("Failed to stat file", zap.String("path", path), zap.Error(err))
		return
	}

	currentSize := info.Size()

	// Check if file was truncated (log rotation)
	if currentSize < tf.offset {
		c.logger.Info("Log file was truncated, reading from beginning", zap.String("path", path))
		tf.file.Seek(0, io.SeekStart)
		tf.offset = 0
	}

	// Check if there's new content
	if currentSize <= tf.offset {
		c.filesMu.Unlock()
		return
	}

	// Seek to last position
	tf.file.Seek(tf.offset, io.SeekStart)

	// Read new lines
	reader := bufio.NewReader(tf.file)
	c.filesMu.Unlock()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				c.logger.Debug("Error reading line", zap.String("path", path), zap.Error(err))
			}
			break
		}

		// Parse the line
		entry, err := c.parser.Parse(line)
		if err != nil {
			c.logger.Debug("Failed to parse nginx log line",
				zap.String("path", path),
				zap.String("line", line),
				zap.Error(err),
			)
			continue
		}

		if entry == nil {
			continue
		}

		// Skip health checks if configured
		if c.skipHealthChecks && IsHealthCheck(entry.Path, entry.UserAgent) {
			continue
		}

		// Normalize paths if configured
		if c.normalizePaths {
			entry.Path = NormalizePath(entry.Path)
		}

		c.addEntry(*entry)
	}

	// Update offset
	c.filesMu.Lock()
	if tf, exists := c.files[path]; exists && tf.file != nil {
		newOffset, _ := tf.file.Seek(0, io.SeekCurrent)
		tf.offset = newOffset
	}
	c.filesMu.Unlock()
}

// closeAllFiles closes all tracked files
func (c *NginxCollector) closeAllFiles() {
	c.filesMu.Lock()
	defer c.filesMu.Unlock()

	for path, tf := range c.files {
		if tf.file != nil {
			tf.file.Close()
		}
		delete(c.files, path)
	}
}

// addEntry adds a log entry to the buffer
func (c *NginxCollector) addEntry(entry NginxLogEntry) {
	c.bufferMu.Lock()
	defer c.bufferMu.Unlock()

	c.buffer = append(c.buffer, entry)

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

	c.logger.Debug("Flushed nginx logs to backend", zap.Int("count", len(entries)))
}

// Stop stops the nginx log collector
func (c *NginxCollector) Stop() {
	c.closeAllFiles()

	// Final flush
	c.flush()
}
