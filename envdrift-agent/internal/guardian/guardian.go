// Package guardian is the core orchestrator for the envdrift-agent.
package guardian

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
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

// defaultEncryptTimeout bounds a single `envdrift encrypt` subprocess. A child
// that hangs past it is killed and retried on a later idle check, so one stuck
// encryption can never stall the other projects indefinitely (#494).
const defaultEncryptTimeout = 2 * time.Minute

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
	encryptTimeout  time.Duration
	mu              sync.RWMutex
	// checking marks an idle-check worker in flight so ticks never pile up
	// overlapping workers; checkWG lets shutdown wait for that worker (#494).
	checking atomic.Bool
	checkWG  sync.WaitGroup
	// These are set during Start() for use by onRegistryChange
	ctx    context.Context
	events chan projectEvent
}

// New creates a Guardian configured with cfg.
func New(cfg *config.Config) (*Guardian, error) {
	g := &Guardian{
		globalConfig:   cfg,
		projects:       make(map[string]*ProjectWatcher),
		checkTick:      30 * time.Second,
		encryptTimeout: defaultEncryptTimeout,
	}

	return g, nil
}

// projectDefaults derives the per-project default GuardianConfig from the
// global ~/.envdrift/guardian.toml settings (#494): idle_timeout, patterns,
// exclude and notify act as the documented defaults for every registered
// project and are overridden by the project's own [guardian] section.
// Enabled is deliberately NOT inherited — watching stays per-project opt-in;
// the global guardian.enabled is the agent's master switch, checked in Start().
func (g *Guardian) projectDefaults() *project.GuardianConfig {
	d := project.DefaultGuardianConfig()
	if g.globalConfig == nil {
		return d
	}

	gc := g.globalConfig.Guardian
	if gc.IdleTimeout > 0 {
		d.IdleTimeout = gc.IdleTimeout
	}
	if len(gc.Patterns) > 0 {
		d.Patterns = append([]string(nil), gc.Patterns...)
	}
	if len(gc.Exclude) > 0 {
		d.Exclude = append([]string(nil), gc.Exclude...)
	}
	d.Notify = gc.Notify
	return d
}

// Start begins the guardian loop.
func (g *Guardian) Start(ctx context.Context) error {
	// Honor the global guardian switch (#348 G3): when disabled, no-op cleanly
	// before standing up any watcher or goroutine.
	if g.globalConfig == nil || !g.globalConfig.Guardian.Enabled {
		log.Println("Guardian disabled in config; not starting.")
		return nil
	}

	// Check envdrift availability
	if !encrypt.IsEnvdriftAvailable() {
		return errNoEnvdrift
	}

	log.Println("EnvDrift Guardian starting...")

	// Create an aggregated events channel and publish ctx/events under g.mu
	// before the registry watcher can fire onRegistryChange (which reads them
	// under the same lock), so the write here never races the read (#361).
	events := g.publishContext(ctx)

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
			// Wait for an in-flight idle check: its encrypt subprocess is
			// killed via the cancelled context, so this returns promptly and
			// Start's return means the guardian is fully stopped (#494).
			g.checkWG.Wait()
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
			g.startIdleCheck(ctx)
		}
	}
}

// startIdleCheck runs checkIdleFiles on a worker goroutine so a slow or hung
// `envdrift encrypt` subprocess can never wedge the Start() select loop:
// ctx.Done() (the SIGINT/SIGTERM path) and file-event processing stay
// responsive while encryption is in flight (#494). At most one check runs at
// a time; a tick that fires while the previous check is still running is
// skipped rather than queued.
func (g *Guardian) startIdleCheck(ctx context.Context) {
	if !g.checking.CompareAndSwap(false, true) {
		return
	}
	g.checkWG.Add(1)
	go func() {
		defer g.checkWG.Done()
		defer g.checking.Store(false)
		g.checkIdleFiles(ctx)
	}()
}

// publishContext stores ctx and a fresh aggregated events channel on the
// Guardian under g.mu, and returns the channel. onRegistryChange reads g.ctx /
// g.events under the same lock from the registry-watcher goroutine, so this
// mutex-guarded write keeps the two from racing (#361).
func (g *Guardian) publishContext(ctx context.Context) chan projectEvent {
	events := make(chan projectEvent, 100)
	g.mu.Lock()
	g.ctx = ctx
	g.events = events
	g.mu.Unlock()
	return events
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
				// The watcher closed its events channel (project removed /
				// stopped); the forwarder is done (#362).
				return
			}
			// Guard the send on ctx.Done() too, so a slow/absent consumer can't
			// wedge this goroutine after the guardian shuts down (#362).
			select {
			case out <- projectEvent{
				projectPath: projectPath,
				filePath:    event.Path,
				modTime:     event.ModTime,
			}:
			case <-ctx.Done():
				return
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

	// Load project configs, with the global guardian.toml values as the
	// per-project defaults (#494).
	configs, err := project.LoadAllProjectConfigsWithDefaults(projectPaths, g.projectDefaults())
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
	// If the guardian is already shutting down, do nothing: a late registry
	// reload (e.g. a debounce timer that fired during Stop) must not re-create
	// and start project watchers after stopAllProjects() cleared g.projects, or
	// those fsnotify watchers/goroutines leak past shutdown (#413).
	if g.isShuttingDown() {
		return
	}

	log.Println("Registry changed, reloading projects...")

	enabledPaths := g.loadEnabledConfigs(reg.GetProjectPaths())

	g.mu.Lock()
	defer g.mu.Unlock()

	// Re-check shutdown *inside* g.mu, the same lock stopAllProjects() holds.
	// The early isShuttingDown() check above is only a fast path; without this
	// guarded re-check a Stop()/stopAllProjects() that lands between the two
	// could be immediately followed by us re-adding watchers (TOCTOU, #413).
	if g.ctxDone() {
		return
	}

	g.stopRemovedProjects(enabledPaths)
	g.startNewProjects(enabledPaths)
}

// isShuttingDown reports whether the guardian's context has been cancelled.
// It takes g.mu.RLock; callers must not already hold g.mu.
func (g *Guardian) isShuttingDown() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.ctxDone()
}

// ctxDone reports whether g.ctx is cancelled. Callers must hold g.mu (RLock or
// Lock); a nil ctx (Start not yet reached) is treated as "not shutting down".
func (g *Guardian) ctxDone() bool {
	if g.ctx == nil {
		return false
	}
	select {
	case <-g.ctx.Done():
		return true
	default:
		return false
	}
}

// loadEnabledConfigs loads the guardian config for each registered path —
// applying the global guardian.toml values as per-project defaults (#494) —
// and returns the enabled ones keyed by project path.
func (g *Guardian) loadEnabledConfigs(paths []string) map[string]*project.GuardianConfig {
	configs, _ := project.LoadAllProjectConfigsWithDefaults(paths, g.projectDefaults())
	enabledPaths := make(map[string]*project.GuardianConfig, len(configs))
	for _, pc := range configs {
		enabledPaths[pc.Path] = pc.Guardian
	}
	return enabledPaths
}

// stopRemovedProjects stops and removes watchers for projects no longer present
// in enabledPaths. Callers must hold g.mu.Lock.
func (g *Guardian) stopRemovedProjects(enabledPaths map[string]*project.GuardianConfig) {
	for path, pw := range g.projects {
		if _, exists := enabledPaths[path]; !exists {
			log.Printf("Stopping watcher for removed project: %s", path)
			pw.Stop()
			delete(g.projects, path)
		}
	}
}

// startNewProjects creates and starts watchers for newly-enabled projects.
// Callers must hold g.mu.Lock.
func (g *Guardian) startNewProjects(enabledPaths map[string]*project.GuardianConfig) {
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

// checkIdleFiles looks for files that haven't been modified in a while and
// encrypts them. It runs on a worker goroutine (see startIdleCheck) and bails
// out as soon as ctx is cancelled; each encrypt subprocess is bounded by both
// ctx and g.encryptTimeout so a hung child can never wedge the agent (#494).
func (g *Guardian) checkIdleFiles(ctx context.Context) {
	g.mu.RLock()
	projects := make(map[string]*ProjectWatcher)
	for k, v := range g.projects {
		projects[k] = v
	}
	g.mu.RUnlock()

	for projectPath, pw := range projects {
		idleFiles := pw.GetIdleFiles()

		for _, path := range idleFiles {
			// Shutting down: leave the remaining files for the next run.
			if ctx.Err() != nil {
				return
			}

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

			if !g.encryptIdleFile(ctx, projectPath, pw, path) {
				return
			}
		}
	}
}

// encryptIdleFile runs one context-bounded `envdrift encrypt` for path and
// handles logging/notification. It returns false when the guardian is
// shutting down (the caller must stop), true otherwise.
func (g *Guardian) encryptIdleFile(ctx context.Context, projectPath string, pw *ProjectWatcher, path string) bool {
	log.Printf("[%s] Encrypting idle file: %s", projectPath, path)

	encCtx, cancel := context.WithTimeout(ctx, g.encryptTimeout)
	err := encrypt.EncryptSilentContext(encCtx, path)
	timedOut := errors.Is(encCtx.Err(), context.DeadlineExceeded)
	cancel()

	if err != nil {
		// Our own shutdown killed the subprocess; not an error worth noise.
		if ctx.Err() != nil {
			return false
		}
		if timedOut {
			log.Printf("[%s] Encrypting %s timed out after %v (subprocess killed); will retry on a later check",
				projectPath, path, g.encryptTimeout)
		} else {
			log.Printf("[%s] Error encrypting %s: %v", projectPath, path, err)
		}
		if pw.config.Notify {
			_ = notify.Error("Failed to encrypt: " + path)
		}
		return true
	}

	log.Printf("[%s] Successfully encrypted: %s", projectPath, path)
	if pw.config.Notify {
		_ = notify.Encrypted(path)
	}

	// Remove from tracking
	pw.RemoveFile(path)
	return true
}
