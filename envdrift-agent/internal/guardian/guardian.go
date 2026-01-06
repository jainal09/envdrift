// Package guardian is the core orchestrator for the envdrift-agent.
package guardian

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jainal09/envdrift-agent/internal/config"
	"github.com/jainal09/envdrift-agent/internal/encrypt"
	"github.com/jainal09/envdrift-agent/internal/lockcheck"
	"github.com/jainal09/envdrift-agent/internal/notify"
	"github.com/jainal09/envdrift-agent/internal/watcher"
)

var errNoEnvdrift = fmt.Errorf("envdrift not found. Install it: pip install envdrift")

// Guardian orchestrates file watching and auto-encryption
type Guardian struct {
	config    *config.Config
	watcher   *watcher.Watcher
	lastMod   map[string]time.Time
	checkTick time.Duration
}

// New creates a Guardian configured with cfg, initializing its file watcher, last-mod tracking, and a 30-second idle-check interval.
// It returns an error if the underlying watcher cannot be created.
func New(cfg *config.Config) (*Guardian, error) {
	w, err := watcher.New(
		cfg.Guardian.Patterns,
		cfg.Guardian.Exclude,
		cfg.Directories.Recursive,
	)
	if err != nil {
		return nil, err
	}

	return &Guardian{
		config:    cfg,
		watcher:   w,
		lastMod:   make(map[string]time.Time),
		checkTick: 30 * time.Second, // Check for idle files every 30s
	}, nil
}

// Start begins the guardian loop
func (g *Guardian) Start(ctx context.Context) error {
	// Check envdrift availability
	if !encrypt.IsEnvdriftAvailable() {
		return errNoEnvdrift
	}

	log.Println("EnvDrift Guardian starting...")
	log.Printf("Idle timeout: %v", g.config.Guardian.IdleTimeout)
	log.Printf("Watch patterns: %v", g.config.Guardian.Patterns)
	log.Printf("Exclude patterns: %v", g.config.Guardian.Exclude)

	// Add watch directories
	for _, dir := range g.config.Directories.Watch {
		log.Printf("Adding watch directory: %s", dir)
		if err := g.watcher.AddDirectory(dir); err != nil {
			log.Printf("Warning: could not watch %s: %v", dir, err)
		}
	}

	// Also watch current directory
	if cwd, err := os.Getwd(); err == nil {
		_ = g.watcher.AddDirectory(cwd)
	}

	g.watcher.Start()

	// Start the check loop
	ticker := time.NewTicker(g.checkTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Guardian shutting down...")
			g.watcher.Stop()
			return nil

		case event := <-g.watcher.Events():
			// File was modified, update last mod time
			g.lastMod[event.Path] = event.ModTime
			log.Printf("File modified: %s", event.Path)

		case <-ticker.C:
			// Check for files that are idle
			g.checkIdleFiles()
		}
	}
}

// checkIdleFiles looks for files that haven't been modified in a while
func (g *Guardian) checkIdleFiles() {
	now := time.Now()
	idleTimeout := g.config.Guardian.IdleTimeout

	for path, modTime := range g.lastMod {
		// Check if file has been idle long enough
		if now.Sub(modTime) < idleTimeout {
			continue
		}

		// Check if file exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			delete(g.lastMod, path)
			continue
		}

		// Check if already encrypted
		encrypted, err := encrypt.IsEncrypted(path)
		if err != nil {
			log.Printf("Error checking encryption status: %v", err)
			continue
		}
		if encrypted {
			delete(g.lastMod, path)
			continue
		}

		// Check if file is open by another process
		if lockcheck.IsFileOpen(path) {
			log.Printf("File still open, skipping: %s", path)
			continue
		}

		log.Printf("Encrypting idle file: %s", path)
		if err := encrypt.EncryptSilent(path); err != nil {
			log.Printf("Error encrypting %s: %v", path, err)
			if g.config.Guardian.Notify {
				_ = notify.Error("Failed to encrypt: " + path)
			}
			continue
		}

		log.Printf("Successfully encrypted: %s", path)
		if g.config.Guardian.Notify {
			_ = notify.Encrypted(path)
		}

		// Remove from tracking
		delete(g.lastMod, path)
	}
}
