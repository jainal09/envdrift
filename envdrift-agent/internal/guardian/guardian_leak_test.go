// Package guardian goroutine-leak regression for #362.
package guardian

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jainal09/envdrift-agent/internal/project"
)

// waitGoroutines polls until runtime.NumGoroutine() <= target or the deadline.
func waitGoroutines(target int, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for {
		runtime.GC()
		if runtime.NumGoroutine() <= target {
			return true
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGuardian_RemoveProject_NoGoroutineLeak adds a project (spawning the
// watcher run() goroutine and a forwardEvents goroutine), then stops the
// watcher and cancels the forwarder, and asserts both goroutines exit.
//
// On the pre-fix code, Watcher.Stop() never closed w.events, so forwardEvents'
// `case event, ok := <-pw.Events()` never observed ok==false. Combined with a
// blocked send it leaked. After the fix, run() closes w.events on exit so the
// forwarder receives ok==false and returns.
func TestGuardian_RemoveProject_NoGoroutineLeak(t *testing.T) {
	// Settle any goroutines left over from earlier tests.
	waitGoroutines(0, 200*time.Millisecond)
	base := runtime.NumGoroutine()

	dir := t.TempDir()
	cfg := project.DefaultGuardianConfig()
	cfg.Enabled = true
	pw, err := NewProjectWatcher(dir, cfg)
	if err != nil {
		t.Fatalf("NewProjectWatcher: %v", err)
	}
	if err := pw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// IMPORTANT: ctx stays alive for the whole test. We rely solely on the
	// watcher closing w.events (run()'s defer closeEvents) to make the
	// forwarder exit. This isolates the #362 watcher-side leak: if Stop() never
	// closes w.events, forwardEvents blocks forever on <-pw.Events() even though
	// its context is still live, and the goroutine count never returns to base.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan projectEvent, 100) // buffered: forwarder won't block on send
	go (&Guardian{}).forwardEvents(ctx, dir, pw, events)

	time.Sleep(100 * time.Millisecond) // let goroutines come up

	// Remove the project: stop the watcher ONLY (do not cancel the forwarder).
	pw.Stop()

	// Both run() and forwardEvents must exit, returning to the baseline count.
	// On the pre-fix code the forwarder stays blocked on <-pw.Events() (events
	// never closed), so the count never returns to base.
	if !waitGoroutines(base, 3*time.Second) {
		t.Fatalf("goroutines did not exit: base=%d now=%d (forwardEvents/run leaked, #362)",
			base, runtime.NumGoroutine())
	}
}

// TestGuardian_ForwardEvents_BlockedSendUnblocks is the deadlock variant of
// #362: forwardEvents blocked on `out <-` (no reader) must still terminate when
// the context is cancelled, rather than wedging the goroutine forever.
func TestGuardian_ForwardEvents_BlockedSendUnblocks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fs event test in short mode")
	}

	dir := t.TempDir()
	cfg := project.DefaultGuardianConfig()
	cfg.Enabled = true
	pw, err := NewProjectWatcher(dir, cfg)
	if err != nil {
		t.Fatalf("NewProjectWatcher: %v", err)
	}
	if err := pw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pw.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	// Unbuffered channel with NO reader -> forwardEvents will block on `out <-`
	// once an event arrives.
	out := make(chan projectEvent)
	exited := make(chan struct{})
	go func() {
		(&Guardian{}).forwardEvents(ctx, dir, pw, out)
		close(exited)
	}()

	// Trigger at least one event so forwardEvents reaches the blocking send.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	cancel() // must unblock forwardEvents via its ctx.Done() select case

	select {
	case <-exited:
		// forwardEvents returned: no deadlock.
	case <-time.After(3 * time.Second):
		t.Fatal("forwardEvents wedged on blocked send after cancel (#362)")
	}
}
