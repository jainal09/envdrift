// Package daemon handles system service installation.
package daemon

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Install installs the agent as a system service for the current operating system.
// It returns an error if installation fails or if the platform is unsupported.
func Install() error {
	switch runtime.GOOS {
	case "darwin":
		return installMacOS()
	case "linux":
		return installLinux()
	case "windows":
		return installWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Uninstall removes the EnvDrift Guardian agent from system services on the current platform.
// It delegates to the platform-specific uninstall implementation and returns an error if the operation fails or the platform is unsupported.
func Uninstall() error {
	switch runtime.GOOS {
	case "darwin":
		return uninstallMacOS()
	case "linux":
		return uninstallLinux()
	case "windows":
		return uninstallWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Stop stops the running agent service without removing its install unit, so a
// subsequent `install`/boot can start it again. It delegates to the
// platform-specific stop implementation and returns an error if the operation
// fails or the platform is unsupported.
func Stop() error {
	switch runtime.GOOS {
	case "darwin":
		return stopMacOS()
	case "linux":
		return stopLinux()
	case "windows":
		return stopWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// IsInstalled reports whether the agent is installed as a background service for the current user on the running platform.
// It returns `true` if the platform-specific service/unit/task is present, `false` otherwise.
func IsInstalled() bool {
	switch runtime.GOOS {
	case "darwin":
		return isInstalledMacOS()
	case "linux":
		return isInstalledLinux()
	case "windows":
		return isInstalledWindows()
	default:
		return false
	}
}

// IsRunning reports whether the agent service is currently running on the host.
// It returns true when the platform-specific runtime indicates the agent is active and false on unsupported platforms.
func IsRunning() bool {
	switch runtime.GOOS {
	case "darwin":
		return isRunningMacOS()
	case "linux":
		return isRunningLinux()
	case "windows":
		return isRunningWindows()
	default:
		return false
	}
}

// --- macOS LaunchAgent ---

const macOSPlistName = "com.envdrift.guardian.plist"

// launchAgentPath returns the filesystem path to the user's LaunchAgents plist for this daemon.
// It yields the full path to the plist file under the current user's Home directory (Library/LaunchAgents/com.envdrift.guardian.plist)
// or an error if the user's home directory cannot be determined.
func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", macOSPlistName), nil
}

// installMacOS creates a user LaunchAgent plist for the EnvDrift guardian and loads it with launchctl.
//
// The plist will run the current executable with the "start" argument, configure the agent to run at
// login and keep alive, and redirect stdout/stderr to /tmp. It returns an error if writing the plist,
// creating the target directory, obtaining the executable path, or loading the LaunchAgent fails.
func installMacOS() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	plist := buildLaunchdPlist(execPath)

	plistPath, err := launchAgentPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}

	// Load the agent
	return exec.Command("launchctl", "load", plistPath).Run()
}

// buildLaunchdPlist returns the launchd plist XML for the EnvDrift guardian,
// running execPath with the "start" argument. The exec path is XML-escaped so
// special characters (&, <, >) in the path produce valid XML (#348 G5).
func buildLaunchdPlist(execPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.envdrift.guardian</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/envdrift-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/envdrift-agent.err</string>
</dict>
</plist>`, xmlEscape(execPath))
}

// xmlEscape escapes s for safe inclusion in a plist <string> element (#348 G5).
func xmlEscape(s string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}

// uninstallMacOS removes the per-user LaunchAgent plist for com.envdrift.guardian and attempts to unload it from launchd.
// It returns any error encountered while resolving the plist path or removing the plist file; unload failures are ignored.
func uninstallMacOS() error {
	plistPath, err := launchAgentPath()
	if err != nil {
		return err
	}

	// Unload first
	_ = exec.Command("launchctl", "unload", plistPath).Run()

	return os.Remove(plistPath)
}

// stopMacOS unloads the EnvDrift Guardian LaunchAgent (so KeepAlive stops
// respawning it) without removing the plist, leaving the agent installed.
// It returns an error if the plist path cannot be resolved or launchctl fails.
func stopMacOS() error {
	plistPath, err := launchAgentPath()
	if err != nil {
		return err
	}
	if err := exec.Command("launchctl", "unload", plistPath).Run(); err != nil {
		return fmt.Errorf("failed to stop agent: %w", err)
	}
	return nil
}

// isInstalledMacOS reports whether the macOS LaunchAgent plist for EnvDrift Guardian exists.
// It returns `true` if the plist file exists at the user's ~/Library/LaunchAgents path, `false` if it does not or if the path cannot be determined.
func isInstalledMacOS() bool {
	path, err := launchAgentPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// isRunningMacOS reports whether the macOS LaunchAgent "com.envdrift.guardian" is currently loaded according to launchctl.
func isRunningMacOS() bool {
	cmd := exec.Command("launchctl", "list", "com.envdrift.guardian")
	return cmd.Run() == nil
}

// --- Linux systemd ---

const linuxServiceName = "envdrift-guardian.service"

// systemdPath returns the path to the per-user systemd unit file for the service.
// It yields the full file path under the current user's ~/.config/systemd/user directory, or an error if the user's home directory cannot be determined.
func systemdPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user", linuxServiceName), nil
}

// installLinux creates a user-level systemd service unit for EnvDrift Guardian, writes it to the user's systemd directory, reloads the user daemon, enables the service, and starts it.
// It returns an error if determining the executable path, resolving the target path, creating directories, writing the unit file, or starting the service fails.
func installLinux() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	service := buildSystemdUnit(execPath)

	servicePath, err := systemdPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(servicePath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(servicePath, []byte(service), 0644); err != nil {
		return err
	}

	// Reload and enable
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	_ = exec.Command("systemctl", "--user", "enable", linuxServiceName).Run()
	return exec.Command("systemctl", "--user", "start", linuxServiceName).Run()
}

// buildSystemdUnit returns the systemd user unit for the EnvDrift guardian,
// running execPath with the "start" argument. The exec path is double-quoted
// so a path containing spaces or special characters is not split by systemd
// into multiple arguments (#348 G4).
func buildSystemdUnit(execPath string) string {
	return fmt.Sprintf(`[Unit]
Description=EnvDrift Guardian - Auto-encrypt .env files
After=default.target

[Service]
ExecStart=%s start
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
`, systemdQuote(execPath))
}

// systemdQuote double-quotes a path for use in a systemd ExecStart line,
// escaping backslashes and double quotes per systemd's quoting rules (#348 G4).
func systemdQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// systemd expands `%` specifiers (%h, %u, …) and `$`/`${}` env refs even
	// inside a double-quoted ExecStart value; escape literal occurrences so a
	// path containing them isn't reinterpreted.
	s = strings.ReplaceAll(s, `%`, `%%`)
	s = strings.ReplaceAll(s, `$`, `$$`)
	return `"` + s + `"`
}

// uninstallLinux stops and disables the user systemd service and removes its unit file from the user's systemd directory.
// It returns an error if computing the unit file path or removing the file fails.
func uninstallLinux() error {
	_ = exec.Command("systemctl", "--user", "stop", linuxServiceName).Run()
	_ = exec.Command("systemctl", "--user", "disable", linuxServiceName).Run()
	path, err := systemdPath()
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// stopLinux stops the user systemd service without disabling or removing its
// unit, so it remains installed and can be started again. It returns an error if
// `systemctl --user stop` fails.
func stopLinux() error {
	if err := exec.Command("systemctl", "--user", "stop", linuxServiceName).Run(); err != nil {
		return fmt.Errorf("failed to stop agent: %w", err)
	}
	return nil
}

// isInstalledLinux reports whether the systemd user unit file for the daemon exists at the user's systemd configuration path.
// It returns `true` if the unit file exists and `false` otherwise.
func isInstalledLinux() bool {
	path, err := systemdPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// isRunningLinux reports whether the Linux user systemd service envdrift-guardian.service is active.
// It returns true if the service is active, false otherwise.
func isRunningLinux() bool {
	cmd := exec.Command("systemctl", "--user", "is-active", linuxServiceName)
	output, _ := cmd.Output()
	return strings.TrimSpace(string(output)) == "active"
}

// installWindows creates a Windows scheduled task named "EnvDriftGuardian" that runs the current executable with the "start" argument at user logon using limited privileges.
// It returns an error if the current executable path cannot be determined or if creating the scheduled task via `schtasks` fails.

func installWindows() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	// Create a scheduled task that runs at login
	cmd := exec.Command("schtasks", "/create",
		"/tn", "EnvDriftGuardian",
		"/tr", fmt.Sprintf(`"%s" start`, execPath),
		"/sc", "onlogon",
		"/rl", "limited",
		"/f")

	return cmd.Run()
}

// uninstallWindows removes the Windows scheduled task named "EnvDriftGuardian".
// It returns any error encountered while executing the schtasks delete command.
func uninstallWindows() error {
	return exec.Command("schtasks", "/delete", "/tn", "EnvDriftGuardian", "/f").Run()
}

// stopWindows ends the running EnvDriftGuardian scheduled task without deleting
// it, so the task remains registered and will run again at the next logon. It
// returns an error if `schtasks /end` fails.
func stopWindows() error {
	if err := exec.Command("schtasks", "/end", "/tn", "EnvDriftGuardian").Run(); err != nil {
		return fmt.Errorf("failed to stop agent: %w", err)
	}
	return nil
}

// isInstalledWindows reports whether the "EnvDriftGuardian" scheduled task exists on Windows.
// It returns true if the scheduled task query succeeds, false otherwise.
func isInstalledWindows() bool {
	cmd := exec.Command("schtasks", "/query", "/tn", "EnvDriftGuardian")
	return cmd.Run() == nil
}

// isRunningWindows reports whether the current executable is present in the Windows process list.
// It returns `true` if a process with the same executable name appears in tasklist output, `false` otherwise (including when the executable path cannot be determined).
func isRunningWindows() bool {
	// Get our actual executable name
	execPath, err := os.Executable()
	if err != nil {
		return false
	}
	execName := filepath.Base(execPath)

	// Check if our process is running
	cmd := exec.Command("tasklist", "/fi", fmt.Sprintf("imagename eq %s", execName))
	output, _ := cmd.Output()
	return strings.Contains(string(output), execName)
}
