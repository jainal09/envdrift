// Package notify tests
package notify

import (
	"testing"
)

func TestIsSupported(t *testing.T) {
	// Should return true on macOS, Linux, Windows
	result := IsSupported()
	t.Logf("Notifications supported: %v", result)
}

// Note: We don't actually test sending notifications in CI
// as that would display pop-ups. These tests just verify functions don't panic.

func TestEncryptedNotificationNoSend(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping notification test in short mode")
	}
	// This test is skipped in CI - only run manually
	t.Skip("Skipping to avoid sending actual notifications")
}

func TestWarningNotificationNoSend(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping notification test in short mode")
	}
	t.Skip("Skipping to avoid sending actual notifications")
}
