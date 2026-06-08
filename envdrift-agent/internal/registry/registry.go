// Package registry handles loading the project registry from ~/.envdrift/projects.json.
package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ProjectEntry represents a single registered project.
type ProjectEntry struct {
	Path  string `json:"path"`
	Added string `json:"added"`
}

// Registry holds the list of registered projects.
type Registry struct {
	Projects []ProjectEntry `json:"projects"`
}

// RegistryPath returns the path to the projects registry file: ~/.envdrift/projects.json
func RegistryPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".envdrift", "projects.json")
}

// Load reads the projects registry from ~/.envdrift/projects.json.
// Returns an empty registry if the file doesn't exist.
func Load() (*Registry, error) {
	registryPath := RegistryPath()

	data, err := os.ReadFile(registryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Registry{Projects: []ProjectEntry{}}, nil
		}
		return nil, err
	}

	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}

	return &reg, nil
}

// GetProjectPaths returns a slice of all registered project paths.
func (r *Registry) GetProjectPaths() []string {
	paths := make([]string, len(r.Projects))
	for i, p := range r.Projects {
		paths[i] = p.Path
	}
	return paths
}

// HasProject checks if a path is registered.
func (r *Registry) HasProject(path string) bool {
	for _, p := range r.Projects {
		if p.Path == path {
			return true
		}
	}
	return false
}

// RegistryWatcher watches the projects.json file for changes.
type RegistryWatcher struct {
	fsWatcher *fsnotify.Watcher
	registry  *Registry
	onChange  func(*Registry)
	done      chan struct{}
	stopOnce  sync.Once
	mu        sync.RWMutex
	// debounceTimer coalesces rapid registry writes; guarded by timerMu so Stop()
	// can cancel a pending reload that would otherwise fire after shutdown.
	timerMu       sync.Mutex
	debounceTimer *time.Timer
	stopped       bool
}

// NewRegistryWatcher creates a watcher for the projects.json file.
// The onChange callback is called whenever the registry changes.
func NewRegistryWatcher(onChange func(*Registry)) (*RegistryWatcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	reg, err := Load()
	if err != nil {
		_ = fsw.Close()
		return nil, err
	}

	rw := &RegistryWatcher{
		fsWatcher: fsw,
		registry:  reg,
		onChange:  onChange,
		done:      make(chan struct{}),
	}

	return rw, nil
}

// Start begins watching the registry file for changes.
func (rw *RegistryWatcher) Start() error {
	registryPath := RegistryPath()

	// Ensure the directory exists
	dir := filepath.Dir(registryPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Watch the directory (to catch file creation)
	if err := rw.fsWatcher.Add(dir); err != nil {
		return err
	}

	go rw.run()
	return nil
}

// Stop stops watching the registry file. It is idempotent and concurrency-safe:
// the body runs at most once (sync.Once), mirroring Watcher.Stop (#362), so a
// second or concurrent call can't panic on a double close(rw.done). It also
// cancels any pending debounce timer and marks the watcher stopped so a reload
// that the timer already fired can't run onChange after shutdown and re-add
// project watchers the guardian believes it tore down.
func (rw *RegistryWatcher) Stop() {
	rw.stopOnce.Do(func() {
		rw.timerMu.Lock()
		rw.stopped = true
		if rw.debounceTimer != nil {
			rw.debounceTimer.Stop()
			rw.debounceTimer = nil
		}
		rw.timerMu.Unlock()

		close(rw.done)
		_ = rw.fsWatcher.Close()
	})
}

// GetRegistry returns the current registry.
func (rw *RegistryWatcher) GetRegistry() *Registry {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	return rw.registry
}

func (rw *RegistryWatcher) run() {
	for {
		select {
		case <-rw.done:
			// Stop() already cancelled the debounce timer under timerMu.
			return

		case event, ok := <-rw.fsWatcher.Events:
			if !ok {
				return
			}

			// Check if it's the projects.json file
			if filepath.Base(event.Name) != "projects.json" {
				continue
			}

			rw.scheduleReload()

		case _, ok := <-rw.fsWatcher.Errors:
			if !ok {
				return
			}
		}
	}
}

// scheduleReload (re)arms the debounce timer on the struct under timerMu so that
// Stop() can cancel a pending reload. If the watcher is already stopped, no new
// timer is armed.
func (rw *RegistryWatcher) scheduleReload() {
	rw.timerMu.Lock()
	defer rw.timerMu.Unlock()

	if rw.stopped {
		return
	}
	if rw.debounceTimer != nil {
		rw.debounceTimer.Stop()
	}
	rw.debounceTimer = time.AfterFunc(100*time.Millisecond, rw.reload)
}

func (rw *RegistryWatcher) reload() {
	// A timer can fire concurrently with Stop(): if Stop() already ran, skip the
	// onChange callback so we don't re-add watchers the guardian has torn down
	// (leaking fsnotify watchers/FDs and goroutines past shutdown).
	rw.timerMu.Lock()
	stopped := rw.stopped
	rw.timerMu.Unlock()
	if stopped {
		return
	}

	reg, err := Load()
	if err != nil {
		return
	}

	rw.mu.Lock()
	rw.registry = reg
	rw.mu.Unlock()

	if rw.onChange != nil {
		rw.onChange(reg)
	}
}
