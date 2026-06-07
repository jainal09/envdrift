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

// TestStopDispatchesPerPlatform is the #413 regression for the `stop` command:
// daemon.Stop must actually attempt to stop the service per platform (launchctl
// unload / systemctl --user stop / schtasks /end) rather than being a no-op. We
// assert it never returns the "unsupported platform" sentinel on a supported OS,
// and that any error is the wrapped "failed to stop agent" form — proving Stop
// runs a real service-control command instead of silently succeeding like the
// old runStop did. (The success path on a *running* agent can't be reproduced in
// CI without installing a live service; see the PR note.)
func TestStopDispatchesPerPlatform(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		// supported
	default:
		err := Stop()
		if err == nil || !strings.Contains(err.Error(), "unsupported platform") {
			t.Errorf("Stop() on %s should report unsupported platform, got %v", runtime.GOOS, err)
		}
		return
	}

	err := Stop()
	if err == nil {
		// Service-control command ran and reported success (e.g. launchctl unload
		// of an absent agent on macOS exits 0). That's an acceptable no-op result.
		return
	}
	if strings.Contains(err.Error(), "unsupported platform") {
		t.Fatalf("Stop() returned unsupported-platform on supported OS %s: %v", runtime.GOOS, err)
	}
	if !strings.Contains(err.Error(), "failed to stop agent") {
		t.Errorf("Stop() error should be wrapped as 'failed to stop agent', got %v", err)
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
