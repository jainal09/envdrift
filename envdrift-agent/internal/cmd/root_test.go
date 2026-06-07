// Package cmd tests
package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jainal09/envdrift-agent/internal/daemon"
)

// captureStdout runs fn while capturing everything written to os.Stdout and
// returns it as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestRunStopMatchesBehavior is the #413 regression for the stop command.
//
// Previously runStop only printed status — when the agent was running it told
// the user to run "envdrift-agent uninstall" and returned nil (exit 0), so the
// help text "Stop the running agent" and docs were a lie. The fix actually stops
// the service (daemon.Stop) when running and is a clean no-op when not.
//
// This test exercises the deterministic not-running path (CI has no agent
// service loaded) and asserts:
//   - exit 0 with a "not running" message, and
//   - the old misleading "use 'envdrift-agent uninstall' to stop" guidance is gone.
func TestRunStopMatchesBehavior(t *testing.T) {
	if daemon.IsRunning() {
		t.Skip("an envdrift-agent service is actually running on this host; skipping not-running assertion")
	}

	out := captureStdout(t, func() {
		if err := runStop(stopCmd, nil); err != nil {
			t.Errorf("runStop returned error when not running: %v", err)
		}
	})

	if !strings.Contains(out, "not running") {
		t.Errorf("expected a 'not running' message, got:\n%s", out)
	}
	if strings.Contains(out, "uninstall") {
		t.Errorf("stop must not punt to 'uninstall'; behavior must match the help text. got:\n%s", out)
	}
}

// TestStopCmdHelpMatchesBehavior guards that the stop command's advertised short
// help still claims to stop the agent (now that behavior backs it up), keeping
// help, docs, and behavior in sync (#413).
func TestStopCmdHelpMatchesBehavior(t *testing.T) {
	if !strings.Contains(strings.ToLower(stopCmd.Short), "stop") {
		t.Errorf("stop command Short help should describe stopping the agent, got %q", stopCmd.Short)
	}
}
