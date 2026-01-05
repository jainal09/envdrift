// Package notify provides desktop notification support.
package notify

import (
	"fmt"
	"runtime"

	"github.com/gen2brain/beeep"
)

const (
	appName = "EnvDrift Guardian"
)

// Encrypted sends a notification that a file was encrypted
func Encrypted(path string) error {
	title := "🔐 File Encrypted"
	message := fmt.Sprintf("Encrypted: %s", path)
	return send(title, message)
}

// Warning sends a warning notification
func Warning(message string) error {
	return send("⚠️ EnvDrift Warning", message)
}

// Error sends an error notification
func Error(message string) error {
	return send("❌ EnvDrift Error", message)
}

// Info sends an info notification
func Info(message string) error {
	return send("ℹ️ EnvDrift", message)
}

// send sends a desktop notification
func send(title, message string) error {
	// beeep handles cross-platform notifications
	return beeep.Notify(title, message, "")
}

// IsSupported returns true if notifications are supported on this platform
func IsSupported() bool {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return true
	default:
		return false
	}
}
