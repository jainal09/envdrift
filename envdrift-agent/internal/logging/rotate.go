// Package logging provides a size-rotating log writer for the agent.
//
// The macOS launchd plist redirects the agent's stdout to a fixed file via
// StandardOutPath, which launchd never rotates — the log grew unbounded while
// the guardian logged on every 30s tick (#494). launchd cannot rotate (it
// holds the fd open and offers no rotation directive), so the agent rotates
// its own log: the installed service runs `start --log-file <path>` and the
// stdlib logger writes through a RotatingWriter.
package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	// DefaultMaxBytes caps the active log file at 5 MiB before rotation.
	DefaultMaxBytes int64 = 5 * 1024 * 1024
	// DefaultBackups keeps three rotated files (<path>.1 .. <path>.3).
	DefaultBackups = 3
)

// RotatingWriter is an io.WriteCloser that appends to a file and rotates it
// by size: when a write would push the file past maxBytes, the current file
// becomes <path>.1 (existing backups shift to .2, .3, ...; the oldest beyond
// the backup count is dropped) and a fresh file is started. It is safe for
// concurrent use.
type RotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	backups  int
	file     *os.File
	size     int64
	// closed distinguishes a Close()d writer (writes must stay refused) from a
	// writer whose file is momentarily nil because a rotation's reopen failed
	// (writes must retry the open — see Write). Without it a single transient
	// reopen failure would permanently, silently disable all agent logging.
	closed bool
}

// NewRotatingWriter opens (creating parent directories as needed) a rotating
// writer for path. A non-positive maxBytes falls back to DefaultMaxBytes; a
// negative backups is treated as zero (rotation truncates without keeping
// old files).
func NewRotatingWriter(path string, maxBytes int64, backups int) (*RotatingWriter, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if backups < 0 {
		backups = 0
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	size := int64(0)
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}

	return &RotatingWriter{
		path:     path,
		maxBytes: maxBytes,
		backups:  backups,
		file:     f,
		size:     size,
	}, nil
}

// Write appends p, rotating first when the write would exceed the size cap.
// A single write larger than maxBytes is still written in full after a
// rotation (the cap is a rotation trigger, not a hard write limit).
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, os.ErrClosed
	}

	// A previous rotation failed to reopen the file (w.file left nil). Retry the
	// open here so a transient failure (e.g. momentary disk pressure) does not
	// permanently disable logging for the life of the process (#494). The write
	// that hit the failure is lost; logging resumes from this one.
	if w.file == nil {
		if err := w.reopenLocked(); err != nil {
			return 0, err
		}
	}

	if w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// reopenLocked opens the active log file in append mode and refreshes the size
// accounting from its current length. It recovers a writer whose file was left
// nil by a failed rotation reopen. Callers must hold w.mu.
func (w *RotatingWriter) reopenLocked() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("reopen log file: %w", err)
	}
	w.file = f
	w.size = 0
	if info, statErr := f.Stat(); statErr == nil {
		w.size = info.Size()
	}
	return nil
}

// Close closes the underlying file. Subsequent writes return os.ErrClosed.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.closed = true
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// rotateLocked shifts backups (<path>.1 -> <path>.2, ...), moves the active
// file to <path>.1, and starts a fresh file. Callers must hold w.mu. The
// fresh file is opened with O_TRUNC so the log stays bounded even if a rename
// failed (e.g. the file is held open by another process on Windows) — bounded
// beats complete for a background agent's log.
func (w *RotatingWriter) rotateLocked() error {
	// Close before renaming: Windows cannot rename an open file.
	_ = w.file.Close()
	w.file = nil
	w.size = 0

	if w.backups > 0 {
		for i := w.backups - 1; i >= 1; i-- {
			_ = os.Rename(w.backupPath(i), w.backupPath(i+1))
		}
		_ = os.Rename(w.path, w.backupPath(1))
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("reopen log file after rotation: %w", err)
	}
	w.file = f
	return nil
}

// backupPath returns the path of the i-th rotated backup (<path>.<i>).
func (w *RotatingWriter) backupPath(i int) string {
	return fmt.Sprintf("%s.%d", w.path, i)
}
