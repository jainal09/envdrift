// Package guardian unit tests for the #494 checkIdleFiles/encryptIdleFile
// paths, driven directly with real fake subprocesses (see guardian_wedge_test
// for the fake-binary plumbing).
package guardian

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jainal09/envdrift-agent/internal/config"
	"github.com/jainal09/envdrift-agent/internal/project"
)

// idleCheckFixture wires a Guardian with one project watcher (not started; no
// fsnotify needed) whose tracked files checkIdleFiles will inspect, plus the
// fake envdrift/lsof binaries on PATH.
type idleCheckFixture struct {
	g          *Guardian
	pw         *ProjectWatcher
	projectDir string
	marker     string
}

// newIdleCheckFixture sets HOME, installs the fake binaries with the given
// envdrift mode ("ok" / "fail" / "hang"), and registers one project watcher
// with notifications off.
func newIdleCheckFixture(t *testing.T, envdriftMode string) *idleCheckFixture {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	marker := filepath.Join(t.TempDir(), "encrypt-started")
	installFakeBins(t, marker)
	t.Setenv("ENVDRIFT_AGENT_FAKE_ENVDRIFT", envdriftMode)

	projectDir := t.TempDir()
	cfg := project.DefaultGuardianConfig()
	cfg.Enabled = true
	cfg.Notify = false

	pw, err := NewProjectWatcher(projectDir, cfg)
	if err != nil {
		t.Fatalf("NewProjectWatcher: %v", err)
	}
	t.Cleanup(pw.Stop)

	g, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.projects[projectDir] = pw

	return &idleCheckFixture{g: g, pw: pw, projectDir: projectDir, marker: marker}
}

// trackIdle writes a file with the given content and tracks it as long idle.
func (f *idleCheckFixture) trackIdle(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(f.projectDir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f.pw.TrackFile(path, time.Now().Add(-time.Hour))
	return path
}

// tracked reports whether path is still in the watcher's tracking map.
func (f *idleCheckFixture) tracked(path string) bool {
	f.pw.mu.RLock()
	defer f.pw.mu.RUnlock()
	_, ok := f.pw.lastMod[path]
	return ok
}

// TestCheckIdleFiles_SuccessStopsTracking covers the happy path: an idle
// plaintext file is handed to `envdrift encrypt` (fake, exits 0) and dropped
// from tracking afterwards.
func TestCheckIdleFiles_SuccessStopsTracking(t *testing.T) {
	f := newIdleCheckFixture(t, "ok")
	path := f.trackIdle(t, ".env", "SECRET=plaintext\n")

	f.g.checkIdleFiles(context.Background())

	if _, err := os.Stat(f.marker); err != nil {
		t.Fatalf("fake envdrift encrypt was not invoked: %v", err)
	}
	if f.tracked(path) {
		t.Error("successfully encrypted file must be removed from tracking")
	}
}

// TestCheckIdleFiles_EncryptFailureKeepsTracking covers the error branch: a
// failing `envdrift encrypt` (fake, exits 1) is logged and the file stays
// tracked for a retry on a later check.
func TestCheckIdleFiles_EncryptFailureKeepsTracking(t *testing.T) {
	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	f := newIdleCheckFixture(t, "fail")
	path := f.trackIdle(t, ".env", "SECRET=plaintext\n")

	f.g.checkIdleFiles(context.Background())

	if !f.tracked(path) {
		t.Error("a file whose encryption failed must stay tracked for retry")
	}
}

// TestCheckIdleFiles_EncryptTimeoutIsBounded covers the per-subprocess
// timeout (#494): with a hung fake envdrift and a tiny encryptTimeout, the
// check returns promptly (child killed) and keeps the file tracked for retry.
func TestCheckIdleFiles_EncryptTimeoutIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping subprocess test in short mode")
	}

	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	f := newIdleCheckFixture(t, "hang")
	f.g.encryptTimeout = 200 * time.Millisecond
	path := f.trackIdle(t, ".env", "SECRET=plaintext\n")

	start := time.Now()
	f.g.checkIdleFiles(context.Background())
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("checkIdleFiles blocked %v on a hung subprocess; encryptTimeout must kill it (#494)", elapsed)
	}
	if !f.tracked(path) {
		t.Error("a timed-out file must stay tracked for retry")
	}
}

// TestCheckIdleFiles_MissingFileUntracked covers the stat branch: a tracked
// file that disappeared is dropped without invoking envdrift.
func TestCheckIdleFiles_MissingFileUntracked(t *testing.T) {
	f := newIdleCheckFixture(t, "ok")
	gone := filepath.Join(f.projectDir, ".env.gone")
	f.pw.TrackFile(gone, time.Now().Add(-time.Hour))

	f.g.checkIdleFiles(context.Background())

	if f.tracked(gone) {
		t.Error("a deleted file must be removed from tracking")
	}
	if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
		t.Errorf("envdrift must not be invoked for a missing file (marker err=%v)", err)
	}
}

// TestCheckIdleFiles_AlreadyEncryptedUntracked covers the IsEncrypted branch:
// a fully encrypted file is dropped from tracking without spawning envdrift.
func TestCheckIdleFiles_AlreadyEncryptedUntracked(t *testing.T) {
	f := newIdleCheckFixture(t, "ok")
	path := f.trackIdle(t, ".env", "SECRET=\"encrypted:abc123\"\n")

	f.g.checkIdleFiles(context.Background())

	if f.tracked(path) {
		t.Error("an already-encrypted file must be removed from tracking")
	}
	if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
		t.Errorf("envdrift must not be invoked for an encrypted file (marker err=%v)", err)
	}
}

// TestCheckIdleFiles_OpenFileSkipped covers the lockcheck branch: when lsof
// reports a foreign PID holding the file, encryption is skipped and the file
// stays tracked. Unix-only — Windows lock detection uses handle.exe/PowerShell
// rather than the injectable lsof on PATH.
func TestCheckIdleFiles_OpenFileSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lsof-based lock detection is not used on windows")
	}

	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	f := newIdleCheckFixture(t, "ok")
	t.Setenv("ENVDRIFT_AGENT_FAKE_LSOF", "open")
	path := f.trackIdle(t, ".env", "SECRET=plaintext\n")

	f.g.checkIdleFiles(context.Background())

	if !f.tracked(path) {
		t.Error("a file open in another process must stay tracked")
	}
	if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
		t.Errorf("envdrift must not be invoked for an open file (marker err=%v)", err)
	}
}

// TestCheckIdleFiles_CancelledContextReturnsEarly covers the shutdown
// short-circuit: with the context already cancelled, the check leaves files
// untouched and never spawns a subprocess.
func TestCheckIdleFiles_CancelledContextReturnsEarly(t *testing.T) {
	f := newIdleCheckFixture(t, "ok")
	path := f.trackIdle(t, ".env", "SECRET=plaintext\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.g.checkIdleFiles(ctx)

	if !f.tracked(path) {
		t.Error("shutdown must leave files tracked for the next run")
	}
	if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
		t.Errorf("envdrift must not be invoked after shutdown (marker err=%v)", err)
	}
}
