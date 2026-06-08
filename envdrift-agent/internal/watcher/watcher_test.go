// Package watcher tests
package watcher

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	w, err := New([]string{".env*"}, []string{".env.example"}, true)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	if w == nil {
		t.Fatal("Watcher should not be nil")
	}
}

func TestMatchesPattern(t *testing.T) {
	w, _ := New([]string{".env*", "*.env"}, []string{}, false)
	defer w.Stop()

	tests := []struct {
		path     string
		expected bool
	}{
		{".env", true},
		{".env.local", true},
		{".env.production", true},
		{"config.env", true},
		{"README.md", false},
		{"package.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := w.matchesPattern(tt.path)
			if result != tt.expected {
				t.Errorf("matchesPattern(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsExcluded(t *testing.T) {
	w, _ := New([]string{".env*"}, []string{".env.example", ".env.sample"}, false)
	defer w.Stop()

	tests := []struct {
		path     string
		expected bool
	}{
		{".env.example", true},
		{".env.sample", true},
		{".env.production", false},
		{".env", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := w.isExcluded(tt.path)
			if result != tt.expected {
				t.Errorf("isExcluded(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~/projects", filepath.Join(home, "projects")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := expandPath(tt.input)
			if result != tt.expected {
				t.Errorf("expandPath(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAddDirectory(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New([]string{".env*"}, []string{}, false)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	err = w.AddDirectory(tempDir)
	if err != nil {
		t.Fatalf("Failed to add directory: %v", err)
	}
}

func TestEventsChannel(t *testing.T) {
	w, _ := New([]string{".env*"}, []string{}, false)
	defer w.Stop()

	events := w.Events()
	if events == nil {
		t.Error("Events channel should not be nil")
	}
}

func TestLastModified(t *testing.T) {
	w, _ := New([]string{".env*"}, []string{}, false)
	defer w.Stop()

	// Initially should be zero time
	modTime := w.LastModified("/some/path")
	if !modTime.IsZero() {
		t.Error("LastModified should return zero time for unknown path")
	}
}

func TestFileEventChange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file event test in short mode")
	}

	tempDir := t.TempDir()

	w, err := New([]string{".env*"}, []string{}, false)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	err = w.AddDirectory(tempDir)
	if err != nil {
		t.Fatalf("Failed to add directory: %v", err)
	}

	w.Start()

	// Create a .env file
	envPath := filepath.Join(tempDir, ".env.test")
	if err := os.WriteFile(envPath, []byte("TEST=value\n"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wait for event (with timeout)
	select {
	case event := <-w.Events():
		if event.Path != envPath {
			t.Errorf("Expected path %s, got %s", envPath, event.Path)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for file event")
	}
}

// TestNewSubdirectoryIsWatched is the #348 G2 regression: a directory created
// AFTER AddDirectory must be watched recursively, so a .env file written
// beneath it later still fires an event.
func TestNewSubdirectoryIsWatched(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fs event test in short mode")
	}

	root := t.TempDir()

	w, err := New([]string{".env*"}, []string{}, true) // recursive
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	if err := w.AddDirectory(root); err != nil {
		t.Fatalf("Failed to add directory: %v", err)
	}
	w.Start()

	// Create a subdir AFTER AddDirectory, then write a .env inside it.
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}
	// Give the watcher a chance to pick up (and Add) the new directory.
	time.Sleep(200 * time.Millisecond)

	envPath := filepath.Join(sub, ".env.local")
	if err := os.WriteFile(envPath, []byte("X=1\n"), 0o644); err != nil {
		t.Fatalf("Failed to write nested .env: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case event := <-w.Events():
			if event.Path == envPath {
				return // success
			}
			// Ignore unrelated events (e.g. the directory create itself if
			// it ever matched); keep waiting for our file.
		case <-deadline:
			t.Fatalf("no event for .env in subdir created after AddDirectory (G2)")
		}
	}
}

// waitForEvent drains w.Events until an event for wantPath arrives (returning
// nil) or the deadline elapses. If an event for any path in forbidden arrives
// first, it fails the test immediately. Extracting this select/for loop keeps
// the individual fs-event tests below simple (and below CodeScene's complexity
// threshold) while giving them one consistent, race-free wait.
func waitForEvent(t *testing.T, w *Watcher, wantPath string, timeout time.Duration, forbidden ...string) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case event := <-w.Events():
			for _, bad := range forbidden {
				if event.Path == bad {
					t.Fatalf("unexpected event for forbidden path %q", bad)
				}
			}
			if event.Path == wantPath {
				return
			}
		case <-deadline:
			t.Fatalf("no event for %q within %s", wantPath, timeout)
		}
	}
}

// assertNoEvent drains w.Events for the grace window and fails if an event for
// any forbidden path arrives. Use it after a positive event to confirm a
// forbidden sibling event does not land shortly afterwards.
func assertNoEvent(t *testing.T, w *Watcher, grace time.Duration, forbidden ...string) {
	t.Helper()
	deadline := time.After(grace)
	for {
		select {
		case event := <-w.Events():
			for _, bad := range forbidden {
				if event.Path == bad {
					t.Fatalf("unexpected event for forbidden path %q", bad)
				}
			}
		case <-deadline:
			return
		}
	}
}

// TestAddDirectoryDottedRootIsWatched is the #413 regression: a recursive
// watcher whose registered ROOT directory name is dotted (e.g. ~/.dotfiles)
// must still be watched. filepath.Walk visits the root first, so an unconditional
// "skip hidden dirs" rule SkipDir'd the entire subtree, silently watching
// nothing and never firing an event for .env files written there.
func TestAddDirectoryDottedRootIsWatched(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fs event test in short mode")
	}

	parent := t.TempDir()
	// Leaf dir name starts with a dot, like ~/.dotfiles.
	root := filepath.Join(parent, ".dotfiles")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("Failed to create dotted root: %v", err)
	}

	w, err := New([]string{".env*"}, []string{}, true) // recursive
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	if err := w.AddDirectory(root); err != nil {
		t.Fatalf("Failed to add dotted directory: %v", err)
	}
	w.Start()

	// Writing a .env in the dotted root must fire an event; on the unfixed code
	// the root was SkipDir'd and no event ever arrives.
	envPath := filepath.Join(root, ".env.local")
	if err := os.WriteFile(envPath, []byte("X=1\n"), 0o644); err != nil {
		t.Fatalf("Failed to write .env in dotted root: %v", err)
	}

	// success: the dotted root is watched (#413: was SkipDir'd before the fix).
	waitForEvent(t, w, envPath, 3*time.Second)
}

// TestAddDirectorySkipsNestedHidden confirms the fix still skips hidden
// directories nested BELOW the registered root: a .env inside root/.git must not
// fire (we don't watch VCS internals), even though the dotted root itself is now
// watched.
func TestAddDirectorySkipsNestedHidden(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fs event test in short mode")
	}

	root := t.TempDir()
	hidden := filepath.Join(root, ".git")
	if err := os.Mkdir(hidden, 0o755); err != nil {
		t.Fatalf("Failed to create nested hidden dir: %v", err)
	}

	w, err := New([]string{".env*"}, []string{}, true) // recursive
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	if err := w.AddDirectory(root); err != nil {
		t.Fatalf("Failed to add directory: %v", err)
	}
	w.Start()

	// A .env written in root (not hidden) should fire...
	rootEnv := filepath.Join(root, ".env.local")
	if err := os.WriteFile(rootEnv, []byte("X=1\n"), 0o644); err != nil {
		t.Fatalf("write root .env: %v", err)
	}
	// ...while a .env in the nested hidden dir should NOT.
	hiddenEnv := filepath.Join(hidden, ".env.local")
	if err := os.WriteFile(hiddenEnv, []byte("Y=2\n"), 0o644); err != nil {
		t.Fatalf("write hidden .env: %v", err)
	}

	// The root .env must fire and the hidden one must never fire (even if it
	// arrives in the same batch, waitForEvent fails on it).
	waitForEvent(t, w, rootEnv, 2*time.Second, hiddenEnv)
	// Keep draining briefly: a hiddenEnv event can lag the rootEnv one, so a bare
	// "stop on first rootEnv" would miss a hidden-dir watch regression (#413).
	assertNoEvent(t, w, 300*time.Millisecond, hiddenEnv)
}

// TestStopClosesEvents is part of the #362 regression: after Stop, run() (the
// sole sender) must close w.events so consumers observe ok==false instead of
// blocking forever.
func TestStopClosesEvents(t *testing.T) {
	w, err := New([]string{".env*"}, []string{}, false)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	w.Start()
	w.Stop()

	select {
	case _, ok := <-w.Events():
		if ok {
			// A stray event is acceptable; drain until closed.
			select {
			case _, ok2 := <-w.Events():
				if ok2 {
					t.Fatal("events channel should be closed after Stop")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for events channel to close after Stop")
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: events channel not closed after Stop (#362)")
	}
}

// TestStopIsIdempotent ensures Stop can be called multiple times without a
// panic from double-closing w.done (#362 stopOnce guard).
func TestStopIsIdempotent(t *testing.T) {
	w, err := New([]string{".env*"}, []string{}, false)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	w.Start()
	w.Stop()
	w.Stop() // must not panic
}

// TestStopDrainsBlockedSend is the load-bearing #362 regression: if the events
// buffer is full and nobody drains it, run() must still observe Stop (via the
// select on w.done) and exit instead of wedging on the send.
func TestStopDrainsBlockedSend(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fs event test in short mode")
	}

	root := t.TempDir()
	w, err := New([]string{".env*"}, []string{}, false)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	if err := w.AddDirectory(root); err != nil {
		t.Fatalf("Failed to add directory: %v", err)
	}
	w.Start()

	// Fill the events buffer (cap 100) without ever reading from it by writing
	// many matching .env files. With no reader, an unguarded send in
	// handleEvent would eventually wedge run().
	for i := 0; i < 250; i++ {
		p := filepath.Join(root, ".env."+strconv.Itoa(i))
		if err := os.WriteFile(p, []byte("X=1\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	time.Sleep(300 * time.Millisecond) // let the watcher fill its buffer

	// Stop must return promptly and run() must exit. We detect run()'s exit by
	// the events channel closing (run defers closeEvents on the way out).
	w.Stop()

	closed := make(chan struct{})
	go func() {
		for range w.Events() { // drain until closed
		}
		close(closed)
	}()

	select {
	case <-closed:
		// run() exited and closed the channel: no leak/wedge.
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not exit after Stop with a full buffer (#362 wedge)")
	}
}
