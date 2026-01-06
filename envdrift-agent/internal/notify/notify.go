// Package notify provides desktop notification support.
package notify

import (
	"fmt"
	"runtime"

	"github.com/gen2brain/beeep"
)

// Encrypted sends a desktop notification indicating that the specified file was encrypted.
// The notification title is "🔐 File Encrypted" and the message includes the provided path.
// It returns an error if the notification could not be dispatched.
func Encrypted(path string) error {
	title := "🔐 File Encrypted"
	message := fmt.Sprintf("Encrypted: %s", path)
	return send(title, message)
}

// Warning sends a warning desktop notification titled "⚠️ EnvDrift Warning" with the provided message.
// It returns an error if the notification cannot be delivered.
func Warning(message string) error {
	return send("⚠️ EnvDrift Warning", message)
}

// It returns any error encountered while attempting to display the notification.
func Error(message string) error {
	return send("❌ EnvDrift Error", message)
}

// Info sends an informational desktop notification with the provided message.
// It returns an error if the notification could not be delivered.
func Info(message string) error {
	return send("ℹ️ EnvDrift", message)
}

// send dispatches a desktop notification with the given title and message.
// It returns any error reported by the underlying notification backend.
func send(title, message string) error {
	// beeep handles cross-platform notifications
	return beeep.Notify(title, message, "")
}

// IsSupported reports whether desktop notifications are supported on the current operating system.
// It returns true for "darwin", "linux", and "windows", and false for other platforms.
func IsSupported() bool {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return true
	default:
		return false
	}
}