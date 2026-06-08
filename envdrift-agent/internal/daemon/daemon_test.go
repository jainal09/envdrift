// Package daemon tests
package daemon

import (
	"encoding/xml"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLaunchAgentPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	path, err := launchAgentPath()
	if err != nil {
		t.Fatalf("launchAgentPath failed: %v", err)
	}
	if path == "" {
		t.Error("Launch agent path should not be empty")
	}

	if filepath.Ext(path) != ".plist" {
		t.Errorf("Expected .plist extension, got %s", filepath.Ext(path))
	}
}

func TestSystemdPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	path, err := systemdPath()
	if err != nil {
		t.Fatalf("systemdPath failed: %v", err)
	}
	if path == "" {
		t.Error("Systemd path should not be empty")
	}

	if !strings.HasSuffix(path, ".service") {
		t.Errorf("Expected .service suffix, got %s", path)
	}
}

func TestIsInstalled(t *testing.T) {
	// Just ensure this doesn't panic
	_ = IsInstalled()
}

func TestIsRunning(t *testing.T) {
	// Just ensure this doesn't panic
	_ = IsRunning()
}

// TestDispatchRoutesPerPlatform is the #413 regression for the `stop` command:
// the per-platform dispatch (which Stop/Install/Uninstall all route through)
// must invoke the handler for the current OS and surface an "unsupported
// platform" error on any other OS, rather than silently no-op'ing like the old
// runStop did. We exercise dispatch() with stub handlers instead of calling the
// real Stop(), so the unit test never runs a destructive service-control command
// (launchctl unload / systemctl --user stop / schtasks /end) against a live
// agent on the developer's or CI machine.
func TestDispatchRoutesPerPlatform(t *testing.T) {
	var called string
	mark := func(name string) func() error {
		return func() error { called = name; return nil }
	}

	err := dispatch(mark("darwin"), mark("linux"), mark("windows"))

	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		if err != nil {
			t.Fatalf("dispatch on supported OS %s returned error: %v", runtime.GOOS, err)
		}
		if called != runtime.GOOS {
			t.Errorf("dispatch invoked %q handler on %s; want the %s handler", called, runtime.GOOS, runtime.GOOS)
		}
	default:
		if err == nil || !strings.Contains(err.Error(), "unsupported platform") {
			t.Errorf("dispatch on %s should report unsupported platform, got %v", runtime.GOOS, err)
		}
		if called != "" {
			t.Errorf("dispatch invoked %q handler on unsupported OS %s; want none", called, runtime.GOOS)
		}
	}
}

// TestDispatchPropagatesHandlerError proves the chosen handler's error is
// returned unchanged — so a real stopMacOS/stopLinux/stopWindows failure is
// surfaced (and can then be wrapped as "failed to stop agent") rather than
// swallowed. We only assert this on a supported OS, where exactly one handler
// runs.
func TestDispatchPropagatesHandlerError(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
	default:
		t.Skipf("no platform handler runs on %s", runtime.GOOS)
	}

	sentinel := errors.New("boom")
	fail := func() error { return sentinel }
	if err := dispatch(fail, fail, fail); !errors.Is(err, sentinel) {
		t.Errorf("dispatch should return the handler error, got %v", err)
	}
}

// TestDispatchBoolRoutesPerPlatform mirrors TestDispatchRoutesPerPlatform for
// the bool-returning status probes (IsInstalled/IsRunning): the current OS's
// handler runs and an unsupported OS yields false without invoking any handler.
func TestDispatchBoolRoutesPerPlatform(t *testing.T) {
	var called string
	mark := func(name string) func() bool {
		return func() bool { called = name; return true }
	}

	got := dispatchBool(mark("darwin"), mark("linux"), mark("windows"))

	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		if !got {
			t.Errorf("dispatchBool on supported OS %s returned false", runtime.GOOS)
		}
		if called != runtime.GOOS {
			t.Errorf("dispatchBool invoked %q handler on %s; want the %s handler", called, runtime.GOOS, runtime.GOOS)
		}
	default:
		if got {
			t.Errorf("dispatchBool on unsupported OS %s returned true", runtime.GOOS)
		}
		if called != "" {
			t.Errorf("dispatchBool invoked %q handler on unsupported OS %s; want none", called, runtime.GOOS)
		}
	}
}

// TestSystemdUnitQuotesExecStart is the #348 G4 regression: a path containing
// spaces (or special characters) must be double-quoted in ExecStart so systemd
// treats it as a single argument.
func TestSystemdUnitQuotesExecStart(t *testing.T) {
	tests := []struct {
		name     string
		execPath string
		want     string // expected ExecStart line substring
	}{
		{
			name:     "path with spaces and ampersand",
			execPath: `/opt/My Apps/envdrift & co/agent`,
			want:     `ExecStart="/opt/My Apps/envdrift & co/agent" start`,
		},
		{
			name:     "simple path",
			execPath: `/usr/local/bin/agent`,
			want:     `ExecStart="/usr/local/bin/agent" start`,
		},
		{
			name:     "path with embedded double quote",
			execPath: `/opt/a"b/agent`,
			want:     `ExecStart="/opt/a\"b/agent" start`,
		},
		{
			name:     "path with backslash",
			execPath: `/opt/a\b/agent`,
			want:     `ExecStart="/opt/a\\b/agent" start`,
		},
		{
			// systemd would otherwise expand %h/%u etc. even inside quotes.
			name:     "path with percent specifier",
			execPath: `/opt/app%home/agent`,
			want:     `ExecStart="/opt/app%%home/agent" start`,
		},
		{
			// systemd would otherwise treat $FOO / ${FOO} as an env reference.
			name:     "path with dollar",
			execPath: `/opt/app$HOME/agent`,
			want:     `ExecStart="/opt/app$$HOME/agent" start`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := buildSystemdUnit(tt.execPath)
			if !strings.Contains(unit, tt.want) {
				t.Errorf("ExecStart not properly quoted.\nwant substring: %q\ngot unit:\n%s", tt.want, unit)
			}
		})
	}
}

// TestLaunchdPlistEscapesExecPath is the #348 G5 regression: XML-special
// characters in the exec path must be escaped so the plist is valid XML.
func TestLaunchdPlistEscapesExecPath(t *testing.T) {
	execPath := `/Users/me/My Apps/envdrift & co/<x>/agent`
	plist := buildLaunchdPlist(execPath)

	// The raw, unescaped path must not appear (it contains & < >).
	if strings.Contains(plist, execPath) {
		t.Errorf("raw special chars leaked into plist (must be escaped):\n%s", plist)
	}
	for _, want := range []string{"&amp;", "&lt;", "&gt;"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist missing escaped entity %q:\n%s", want, plist)
		}
	}

	// And the document must actually parse as XML.
	dec := xml.NewDecoder(strings.NewReader(plist))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("plist is not valid XML: %v", err)
		}
	}
}
