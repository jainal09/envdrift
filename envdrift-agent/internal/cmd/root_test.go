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

// TestRunStopNotInstalledIsNoOp is the #413 regression for the stop command.
//
// Previously runStop only printed status — when the agent was running it told
// the user to run "envdrift-agent uninstall" and returned nil (exit 0), so the
// help text "Stop the running agent" and docs were a lie. The fix actually stops
// the service (daemon.Stop) and is a clean no-op (exit 0) only when nothing is
// installed.
//
// runStop now keys the no-op on IsInstalled() rather than IsRunning(): a status
// probe that *fails* must not be read as "not running" and used to skip the stop
// (which would falsely report success while the agent keeps running). We exercise
// the deterministic not-installed path (CI has no agent installed) and assert
// exit 0 with a "not installed" message that no longer punts to "uninstall".
func TestRunStopNotInstalledIsNoOp(t *testing.T) {
	if daemon.IsInstalled() {
		t.Skip("an envdrift-agent service is installed on this host; skipping not-installed assertion")
	}

	out := captureStdout(t, func() {
		if err := runStop(stopCmd, nil); err != nil {
			t.Errorf("runStop returned error when not installed: %v", err)
		}
	})

	if !strings.Contains(out, "not installed") {
		t.Errorf("expected a 'not installed' message, got:\n%s", out)
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
