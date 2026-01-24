// Package guardian is the core orchestrator for the envdrift-agent.
package guardian

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/jainal09/envdrift-agent/internal/config"
	"github.com/jainal09/envdrift-agent/internal/encrypt"
	"github.com/jainal09/envdrift-agent/internal/lockcheck"
	"github.com/jainal09/envdrift-agent/internal/notify"
	"github.com/jainal09/envdrift-agent/internal/project"
	"github.com/jainal09/envdrift-agent/internal/registry"
	"github.com/jainal09/envdrift-agent/internal/watcher"
)

var errNoEnvdrift = fmt.Errorf("envdrift not found. Install it: pip install envdrift")

// ProjectWatcher manages watching a single project with its own config.
type ProjectWatcher struct {
	projectPath string
	config      *project.GuardianConfig
	watcher     *watcher.Watcher
	lastMod     map[string]time.Time
	mu          sync.RWMutex
}

// NewProjectWatcher creates a watcher for a single project.
func NewProjectWatcher(projectPath string, cfg *project.GuardianConfig) (*ProjectWatcher, error) {
	w, err := watcher.New(cfg.Patterns, cfg.Exclude, true)
	if err != nil {
		return nil, err
	}

	return &ProjectWatcher{
		projectPath: projectPath,
		config:      cfg,
		watcher:     w,
		lastMod:     make(map[string]time.Time),
	}, nil
}

// Start begins watching the project directory.
func (pw *ProjectWatcher) Start() error {
	if err := pw.watcher.AddDirectory(pw.projectPath); err != nil {
		return err
	}
	pw.watcher.Start()
	return nil
}

// Stop stops the project watcher.
func (pw *ProjectWatcher) Stop() {
	pw.watcher.Stop()
}

// Events returns the file events channel.
func (pw *ProjectWatcher) Events() <-chan watcher.FileEvent {
	return pw.watcher.Events()
}

// TrackFile records a file modification.
func (pw *ProjectWatcher) TrackFile(path string, modTime time.Time) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.lastMod[path] = modTime
}

// GetIdleFiles returns files that have been idle longer than the configured timeout.
func (pw *ProjectWatcher) GetIdleFiles() []string {
	pw.mu.RLock()
	defer pw.mu.RUnlock()

	now := time.Now()
	var idle []string

	for path, modTime := range pw.lastMod {
		if now.Sub(modTime) >= pw.config.IdleTimeout {
			idle = append(idle, path)
		}
	}

	return idle
}

// RemoveFile stops tracking a file.
func (pw *ProjectWatcher) RemoveFile(path string) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	delete(pw.lastMod, path)
}

// Guardian orchestrates file watching and auto-encryption for multiple projects.
type Guardian struct {
	globalConfig    *config.Config
	projects        map[string]*ProjectWatcher // path -> watcher
	registryWatcher *registry.RegistryWatcher
	checkTick       time.Duration
	mu              sync.RWMutex
	// These are set during Start() for use by onRegistryChange
	ctx    context.Context
	events chan projectEvent
}

// New creates a Guardian configured with cfg.
func New(cfg *config.Config) (*Guardian, error) {
	g := &Guardian{
		globalConfig: cfg,
		projects:     make(map[string]*ProjectWatcher),
		checkTick:    30 * time.Second,
	}

	return g, nil
}

// Start begins the guardian loop.
func (g *Guardian) Start(ctx context.Context) error {
	// Check envdrift availability
	if !encrypt.IsEnvdriftAvailable() {
		return errNoEnvdrift
	}

	log.Println("EnvDrift Guardian starting...")

	// Set up registry watcher
	rw, err := registry.NewRegistryWatcher(g.onRegistryChange)
	if err != nil {
		return fmt.Errorf("failed to create registry watcher: %w", err)
	}
	g.registryWatcher = rw

	// Start watching the registry file
	if err := rw.Start(); err != nil {
		return fmt.Errorf("failed to start registry watcher: %w", err)
	}

	// Load initial projects
	g.loadProjects(rw.GetRegistry())

	// Start the check loop
	ticker := time.NewTicker(g.checkTick)
	defer ticker.Stop()

	// Create an aggregated events channel and store for use by onRegistryChange
	events := make(chan projectEvent, 100)
	g.ctx = ctx
	g.events = events

	// Start event forwarding for existing projects
	g.mu.RLock()
	for path, pw := range g.projects {
		go g.forwardEvents(ctx, path, pw, events)
	}
	g.mu.RUnlock()

	for {
		select {
		case <-ctx.Done():
			log.Println("Guardian shutting down...")
			g.stopAllProjects()
			g.registryWatcher.Stop()
			return nil

		case event := <-events:
			// File was modified in a project
			g.mu.RLock()
			pw, ok := g.projects[event.projectPath]
			g.mu.RUnlock()
			if ok {
				pw.TrackFile(event.filePath, event.modTime)
				log.Printf("[%s] File modified: %s", event.projectPath, event.filePath)
			}

		case <-ticker.C:
			// Check for idle files in all projects
			g.checkIdleFiles()
		}
	}
}

// projectEvent represents a file event from a specific project.
type projectEvent struct {
	projectPath string
	filePath    string
	modTime     time.Time
}

// forwardEvents forwards events from a project watcher to the aggregated channel.
func (g *Guardian) forwardEvents(ctx context.Context, projectPath string, pw *ProjectWatcher, out chan<- projectEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-pw.Events():
			if !ok {
				return
			}
			out <- projectEvent{
				projectPath: projectPath,
				filePath:    event.Path,
				modTime:     event.ModTime,
			}
		}
	}
}

// loadProjects initializes watchers for all registered projects.
func (g *Guardian) loadProjects(reg *registry.Registry) {
	if reg == nil {
		return
	}

	projectPaths := reg.GetProjectPaths()
	log.Printf("Loading %d registered projects", len(projectPaths))

	// Load project configs
	configs, err := project.LoadAllProjectConfigs(projectPaths)
	if err != nil {
		log.Printf("Error loading project configs: %v", err)
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, pc := range configs {
		if _, exists := g.projects[pc.Path]; exists {
			continue // Already watching
		}

		pw, err := NewProjectWatcher(pc.Path, pc.Guardian)
		if err != nil {
			log.Printf("Error creating watcher for %s: %v", pc.Path, err)
			continue
		}

		if err := pw.Start(); err != nil {
			log.Printf("Error starting watcher for %s: %v", pc.Path, err)
			continue
		}

		g.projects[pc.Path] = pw
		log.Printf("Watching project: %s (idle_timeout: %v, patterns: %v)",
			pc.Path, pc.Guardian.IdleTimeout, pc.Guardian.Patterns)
	}
}

// onRegistryChange handles changes to the projects registry.
func (g *Guardian) onRegistryChange(reg *registry.Registry) {
	log.Println("Registry changed, reloading projects...")

	// Get new project list
	newPaths := make(map[string]bool)
	for _, p := range reg.GetProjectPaths() {
		newPaths[p] = true
	}

	// Load configs for new projects
	configs, _ := project.LoadAllProjectConfigs(reg.GetProjectPaths())
	enabledPaths := make(map[string]*project.GuardianConfig)
	for _, pc := range configs {
		enabledPaths[pc.Path] = pc.Guardian
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Stop watchers for removed projects
	for path, pw := range g.projects {
		if _, exists := enabledPaths[path]; !exists {
			log.Printf("Stopping watcher for removed project: %s", path)
			pw.Stop()
			delete(g.projects, path)
		}
	}

	// Add watchers for new projects
	for path, cfg := range enabledPaths {
		if _, exists := g.projects[path]; exists {
			continue
		}

		pw, err := NewProjectWatcher(path, cfg)
		if err != nil {
			log.Printf("Error creating watcher for %s: %v", path, err)
			continue
		}

		if err := pw.Start(); err != nil {
			log.Printf("Error starting watcher for %s: %v", path, err)
			continue
		}

		g.projects[path] = pw
		log.Printf("Added project: %s (idle_timeout: %v)", path, cfg.IdleTimeout)

		// Start event forwarding for the new project
		if g.events != nil && g.ctx != nil {
			go g.forwardEvents(g.ctx, path, pw, g.events)
		}
	}
}

// stopAllProjects stops all project watchers.
func (g *Guardian) stopAllProjects() {
	g.mu.Lock()
	defer g.mu.Unlock()

	for path, pw := range g.projects {
		log.Printf("Stopping watcher for: %s", path)
		pw.Stop()
	}
	g.projects = make(map[string]*ProjectWatcher)
}

// checkIdleFiles looks for files that haven't been modified in a while.
func (g *Guardian) checkIdleFiles() {
	g.mu.RLock()
	projects := make(map[string]*ProjectWatcher)
	for k, v := range g.projects {
		projects[k] = v
	}
	g.mu.RUnlock()

	for projectPath, pw := range projects {
		idleFiles := pw.GetIdleFiles()

		for _, path := range idleFiles {
			// Check if file exists
			if _, err := os.Stat(path); os.IsNotExist(err) {
				pw.RemoveFile(path)
				continue
			}

			// Check if already encrypted
			encrypted, err := encrypt.IsEncrypted(path)
			if err != nil {
				log.Printf("Error checking encryption status: %v", err)
				continue
			}
			if encrypted {
				pw.RemoveFile(path)
				continue
			}

			// Check if file is open by another process
			if lockcheck.IsFileOpen(path) {
				log.Printf("[%s] File still open, skipping: %s", projectPath, path)
				continue
			}

			log.Printf("[%s] Encrypting idle file: %s", projectPath, path)
			if err := encrypt.EncryptSilent(path); err != nil {
				log.Printf("[%s] Error encrypting %s: %v", projectPath, path, err)
				if pw.config.Notify {
					_ = notify.Error("Failed to encrypt: " + path)
				}
				continue
			}

			log.Printf("[%s] Successfully encrypted: %s", projectPath, path)
			if pw.config.Notify {
				_ = notify.Encrypted(path)
			}

			// Remove from tracking
			pw.RemoveFile(path)
		}
	}
}
