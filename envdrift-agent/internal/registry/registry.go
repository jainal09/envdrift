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
	mu        sync.RWMutex
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

// Stop stops watching the registry file.
func (rw *RegistryWatcher) Stop() {
	close(rw.done)
	_ = rw.fsWatcher.Close()
}

// GetRegistry returns the current registry.
func (rw *RegistryWatcher) GetRegistry() *Registry {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	return rw.registry
}

func (rw *RegistryWatcher) run() {
	var debounceTimer *time.Timer

	for {
		select {
		case <-rw.done:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case event, ok := <-rw.fsWatcher.Events:
			if !ok {
				return
			}

			// Check if it's the projects.json file
			if filepath.Base(event.Name) != "projects.json" {
				continue
			}

			// Debounce rapid changes
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(100*time.Millisecond, func() {
				rw.reload()
			})

		case _, ok := <-rw.fsWatcher.Errors:
			if !ok {
				return
			}
		}
	}
}

func (rw *RegistryWatcher) reload() {
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
