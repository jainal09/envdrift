// Package guardian regression tests for #494: a hung/slow `envdrift encrypt`
// subprocess must not wedge the guardian's Start() loop — shutdown
// (ctx.Done/SIGTERM) and file-event processing must stay responsive while an
// encryption subprocess is in flight.
package guardian

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jainal09/envdrift-agent/internal/config"
)

// TestMain doubles as a fake-binary entry point: when ENVDRIFT_AGENT_FAKE_BIN
// is set, the (copied) test binary behaves as a fake `envdrift` or `lsof`
// depending on its own basename, then exits — it never runs the test suite.
// This gives the wedge tests a REAL subprocess at the process boundary on
// every platform of the agent-ci matrix (linux/macos/windows) without shell
// scripts or .bat quoting quirks.
func TestMain(m *testing.M) {
	if os.Getenv("ENVDRIFT_AGENT_FAKE_BIN") == "1" {
		os.Exit(fakeBinMain())
	}
	os.Exit(m.Run())
}

// fakeBinMain implements the fake binaries used by the #494 tests:
//
//   - lsof: by default exits 1 (the "no process holds the file open"
//     contract) so the guardian proceeds to encrypt; with
//     ENVDRIFT_AGENT_FAKE_LSOF=open it prints a foreign PID and exits 0,
//     simulating a file held open by another process.
//   - envdrift encrypt <file>: writes a marker file (so the test knows the
//     subprocess started), then acts per ENVDRIFT_AGENT_FAKE_ENVDRIFT:
//     "ok" exits 0, "fail" exits 1, default ("hang") sleeps far longer than
//     any test deadline — the hung `envdrift` subprocess from #494.
func fakeBinMain() int {
	base := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	switch base {
	case "lsof":
		if os.Getenv("ENVDRIFT_AGENT_FAKE_LSOF") == "open" {
			fmt.Println(99999)
			return 0
		}
		return 1
	case "envdrift":
		if len(os.Args) > 1 && os.Args[1] == "encrypt" {
			if marker := os.Getenv("ENVDRIFT_AGENT_FAKE_MARKER"); marker != "" {
				_ = os.WriteFile(marker, []byte("encrypt started\n"), 0o644)
			}
			switch os.Getenv("ENVDRIFT_AGENT_FAKE_ENVDRIFT") {
			case "ok":
				return 0
			case "fail":
				return 1
			default:
				time.Sleep(30 * time.Second)
			}
		}
		return 0
	}
	return 0
}

// installFakeBins copies the running test binary into a fresh dir as `envdrift`
// (and `lsof` on Unix), prepends that dir to PATH, and arms the fake-bin env
// vars so the copies act as fakes (see TestMain/fakeBinMain).
func installFakeBins(t *testing.T, marker string) {
	t.Helper()

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read test binary: %v", err)
	}

	dir := t.TempDir()
	names := []string{"envdrift", "lsof"}
	if runtime.GOOS == "windows" {
		// lockcheck uses handle.exe/PowerShell on Windows, not lsof.
		names = []string{"envdrift.exe"}
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENVDRIFT_AGENT_FAKE_BIN", "1")
	t.Setenv("ENVDRIFT_AGENT_FAKE_MARKER", marker)
}

// slowEncryptGuardian stands up a guardian watching one real project whose
// plaintext .env is already idle, with a fake `envdrift` that hangs once
// encryption starts. It returns once the hung encrypt subprocess is running
// (marker observed), handing back the guardian, the project watcher, the
// project dir, cancel for the Start ctx, and the channel Start's result lands on.
func slowEncryptGuardian(t *testing.T) (g *Guardian, pw *ProjectWatcher, projectDir string, cancel context.CancelFunc, done chan error) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	marker := filepath.Join(t.TempDir(), "encrypt-started")
	installFakeBins(t, marker)

	// notify = false: a shutdown-killed fake encrypt must not pop a desktop
	// notification on developer/CI machines.
	projectDir = makeProjectWithToml(t, "[guardian]\nenabled = true\nnotify = false\n")

	// A plaintext .env, created before watching starts, already idle.
	envPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(envPath, []byte("SECRET=plaintext\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	writeRegistry(t, home, projectDir)

	cfg := config.DefaultConfig()
	cfg.Guardian.Enabled = true

	var err error
	g, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.checkTick = 50 * time.Millisecond

	ctx, cancelCtx := context.WithCancel(context.Background())
	cancel = cancelCtx
	done = make(chan error, 1)
	go func() { done <- g.Start(ctx) }()

	// Wait for the project watcher to come up.
	deadline := time.Now().Add(10 * time.Second)
	for {
		g.mu.RLock()
		pw = g.projects[projectDir]
		g.mu.RUnlock()
		if pw != nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("project watcher never started")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Make the file idle and wait until the fake encrypt subprocess is running.
	pw.TrackFile(envPath, time.Now().Add(-time.Hour))
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("fake envdrift encrypt was never invoked")
		}
		time.Sleep(10 * time.Millisecond)
	}

	return g, pw, projectDir, cancel, done
}

// TestGuardian_SlowEncryptShutdownStaysResponsive is the #494 wedge
// regression: with a hung `envdrift encrypt` subprocess in flight, cancelling
// the Start context (what the SIGINT/SIGTERM handler does) must still shut the
// guardian down promptly. Pre-fix, checkIdleFiles ran inline on the Start()
// select loop and EncryptSilent had no context, so ctx.Done() could not be
// observed until the child exited — SIGTERM appeared ignored and only SIGKILL
// ended the agent.
func TestGuardian_SlowEncryptShutdownStaysResponsive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping subprocess test in short mode")
	}

	_, _, _, cancel, done := slowEncryptGuardian(t)

	cancel() // the SIGTERM path

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not return within 5s of cancel: a hung encrypt subprocess wedges shutdown (#494)")
	}
}

// TestGuardian_SlowEncryptEventsStillProcessed is the second half of the #494
// wedge: while a hung `envdrift encrypt` subprocess is in flight, new file
// events must still be drained and tracked. Pre-fix the Start() select loop was
// blocked inside checkIdleFiles -> cmd.Run(), so no event was processed until
// the child exited.
func TestGuardian_SlowEncryptEventsStillProcessed(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping subprocess test in short mode")
	}

	// Silence the per-event logging noise.
	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	_, pw, projectDir, cancel, done := slowEncryptGuardian(t)

	// With the encrypt subprocess hanging, a new matching file event must still
	// be tracked by the Start loop.
	newFile := filepath.Join(projectDir, ".env.local")
	if err := os.WriteFile(newFile, []byte("OTHER=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	tracked := false
	for !tracked {
		pw.mu.RLock()
		_, tracked = pw.lastMod[newFile]
		pw.mu.RUnlock()
		if tracked {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Log("Start() also failed to shut down within 5s")
	}

	if !tracked {
		t.Fatal("file event was not processed while an encrypt subprocess was in flight (#494 wedge)")
	}
}
