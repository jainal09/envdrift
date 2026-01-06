// Package daemon handles system service installation.
package daemon

import (
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

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
</plist>`, execPath)

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

	service := fmt.Sprintf(`[Unit]
Description=EnvDrift Guardian - Auto-encrypt .env files
After=default.target

[Service]
ExecStart=%s start
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
`, execPath)

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