// Package guardian race regression for #361.
package guardian

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"

	"github.com/jainal09/envdrift-agent/internal/config"
	"github.com/jainal09/envdrift-agent/internal/registry"
)

// TestGuardian_PublishContextConcurrentRegistryChange_Race exercises the field
// publish that Start performs (g.ctx / g.events, via publishContext) concurrently
// with onRegistryChange, which reads those same fields under g.mu when adding a
// new project. On the pre-fix code the publish was an unsynchronized write, so
// `go test -race` reports a data race against the mutex-guarded read. After the
// fix, publishContext writes under g.mu and the race detector is clean.
//
// This deliberately drives the field access directly (not via Start) so the
// write/read windows overlap deterministically and so it does not depend on the
// envdrift binary being installed in CI.
//
// Run with: go test -race ./internal/guardian/ -run PublishContextConcurrentRegistryChange_Race
func TestGuardian_PublishContextConcurrentRegistryChange_Race(t *testing.T) {
	// Silence the guardian's verbose add/remove logging during the hammer loop.
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(io.Discard)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	p1 := makeProject(t)
	p2 := makeProject(t)
	writeRegistry(t, home, p1)

	cfg := config.DefaultConfig()
	cfg.Guardian.Enabled = true

	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const iterations = 300
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: repeatedly publish ctx/events (the access Start performs).
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			g.publishContext(ctx)
		}
	}()

	// Reader: repeatedly drive onRegistryChange, whose add path reads
	// g.ctx / g.events to start a forwarder.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			g.onRegistryChange(&registry.Registry{Projects: []registry.ProjectEntry{
				{Path: p1, Added: "now"}, {Path: p2, Added: "now"},
			}})
			g.onRegistryChange(&registry.Registry{Projects: []registry.ProjectEntry{
				{Path: p1, Added: "now"},
			}})
		}
	}()

	wg.Wait()

	// Cancel any forwarder goroutines spawned by onRegistryChange and stop
	// watchers so the test leaves nothing running.
	cancel()
	g.stopAllProjects()
}
