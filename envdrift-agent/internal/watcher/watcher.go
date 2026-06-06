// Package watcher provides file system watching for .env files.
package watcher

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileEvent represents a file change event
type FileEvent struct {
	Path      string
	ModTime   time.Time
	Operation string
}

// Watcher watches directories for .env file changes
type Watcher struct {
	fsWatcher       *fsnotify.Watcher
	patterns        []string
	exclude         []string
	recursive       bool
	events          chan FileEvent
	done            chan struct{}
	stopOnce        sync.Once
	closeEventsOnce sync.Once
	mu              sync.RWMutex
	lastMod         map[string]time.Time
}

// New creates and returns a Watcher configured with the provided filename include patterns, exclude patterns, and recursion setting.
// It returns an error if the underlying fsnotify watcher cannot be created.
func New(patterns, exclude []string, recursive bool) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		fsWatcher: fsw,
		patterns:  patterns,
		exclude:   exclude,
		recursive: recursive,
		events:    make(chan FileEvent, 100),
		done:      make(chan struct{}),
		lastMod:   make(map[string]time.Time),
	}, nil
}

// Events returns the channel of file events
func (w *Watcher) Events() <-chan FileEvent {
	return w.events
}

// AddDirectory adds a directory to watch
func (w *Watcher) AddDirectory(dir string) error {
	dir = expandPath(dir)

	if w.recursive {
		return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip inaccessible directories
			}
			if info.IsDir() {
				if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
					return filepath.SkipDir // Skip hidden directories
				}
				return w.fsWatcher.Add(path)
			}
			return nil
		})
	}

	return w.fsWatcher.Add(dir)
}

// Start begins watching for file changes
func (w *Watcher) Start() {
	go w.run()
}

// Stop stops the watcher. It signals shutdown via w.done and closes the
// fsnotify watcher; w.events is closed by run() (the sole sender) so there is
// no send-on-closed-channel panic. Stop is safe to call multiple times (#362).
func (w *Watcher) Stop() {
	// Both close(w.done) and fsWatcher.Close() run inside stopOnce so a second or
	// concurrent Stop() can't double-close the fsnotify watcher (which logs a
	// spurious "already closed" and isn't safe for concurrent calls).
	w.stopOnce.Do(func() {
		close(w.done)
		if err := w.fsWatcher.Close(); err != nil {
			log.Printf("Watcher close error: %v", err)
		}
	})
}

func (w *Watcher) run() {
	// The sole sender closes w.events on exit so consumers observe ok==false
	// and don't leak goroutines waiting on a never-closed channel (#362).
	defer w.closeEvents()
	for {
		select {
		case <-w.done:
			return
		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

// closeEvents closes the events channel exactly once. Only run() (the sole
// sender) may call this, on its way out, to avoid a send-on-closed panic.
func (w *Watcher) closeEvents() {
	w.closeEventsOnce.Do(func() { close(w.events) })
}

func (w *Watcher) handleEvent(event fsnotify.Event) {
	// Only care about writes and creates
	if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
		return
	}

	path := event.Name

	// If a new directory was created, start watching it (recursively) so that
	// .env files created beneath it later are not missed (#348 G2). Do this
	// before the pattern filter, since a directory name won't match .env*.
	if w.recursive && event.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			if err := w.AddDirectory(path); err != nil {
				log.Printf("Watcher add subdir error: %v", err)
			}
		}
	}

	// Check if it matches our patterns
	if !w.matchesPattern(path) {
		return
	}

	// Check if it's excluded
	if w.isExcluded(path) {
		return
	}

	// Get file info for mod time
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	w.mu.Lock()
	w.lastMod[path] = info.ModTime()
	w.mu.Unlock()

	// Send event, but bail out if we're shutting down so a full buffer can't
	// wedge run() and leak the goroutine (#362).
	select {
	case w.events <- FileEvent{
		Path:      path,
		ModTime:   info.ModTime(),
		Operation: event.Op.String(),
	}:
	case <-w.done:
	}
}

func (w *Watcher) matchesPattern(path string) bool {
	base := filepath.Base(path)
	for _, pattern := range w.patterns {
		matched, _ := filepath.Match(pattern, base)
		if matched {
			return true
		}
	}
	return false
}

func (w *Watcher) isExcluded(path string) bool {
	base := filepath.Base(path)
	for _, pattern := range w.exclude {
		matched, _ := filepath.Match(pattern, base)
		if matched {
			return true
		}
	}
	return false
}

// LastModified returns the last modification time for a file
func (w *Watcher) LastModified(path string) time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastMod[path]
}

// expandPath expands a leading "~/" in path to the current user's home directory.
// If path does not start with "~/", it is returned unchanged.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}
