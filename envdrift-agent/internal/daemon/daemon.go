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

// Install installs the agent as a system service
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

// Uninstall removes the agent from system services
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

// IsInstalled checks if the agent is installed as a service
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

// IsRunning checks if the agent service is currently running
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

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", macOSPlistName)
}

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

	plistPath := launchAgentPath()
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}

	// Load the agent
	return exec.Command("launchctl", "load", plistPath).Run()
}

func uninstallMacOS() error {
	plistPath := launchAgentPath()

	// Unload first
	exec.Command("launchctl", "unload", plistPath).Run()

	return os.Remove(plistPath)
}

func isInstalledMacOS() bool {
	_, err := os.Stat(launchAgentPath())
	return err == nil
}

func isRunningMacOS() bool {
	cmd := exec.Command("launchctl", "list", "com.envdrift.guardian")
	return cmd.Run() == nil
}

// --- Linux systemd ---

const linuxServiceName = "envdrift-guardian.service"

func systemdPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", linuxServiceName)
}

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

	servicePath := systemdPath()
	if err := os.MkdirAll(filepath.Dir(servicePath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(servicePath, []byte(service), 0644); err != nil {
		return err
	}

	// Reload and enable
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	exec.Command("systemctl", "--user", "enable", linuxServiceName).Run()
	return exec.Command("systemctl", "--user", "start", linuxServiceName).Run()
}

func uninstallLinux() error {
	exec.Command("systemctl", "--user", "stop", linuxServiceName).Run()
	exec.Command("systemctl", "--user", "disable", linuxServiceName).Run()
	return os.Remove(systemdPath())
}

func isInstalledLinux() bool {
	_, err := os.Stat(systemdPath())
	return err == nil
}

func isRunningLinux() bool {
	cmd := exec.Command("systemctl", "--user", "is-active", linuxServiceName)
	output, _ := cmd.Output()
	return strings.TrimSpace(string(output)) == "active"
}

// --- Windows ---

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

func uninstallWindows() error {
	return exec.Command("schtasks", "/delete", "/tn", "EnvDriftGuardian", "/f").Run()
}

func isInstalledWindows() bool {
	cmd := exec.Command("schtasks", "/query", "/tn", "EnvDriftGuardian")
	return cmd.Run() == nil
}

func isRunningWindows() bool {
	// Check if our process is running
	cmd := exec.Command("tasklist", "/fi", "imagename eq envdrift-agent.exe")
	output, _ := cmd.Output()
	return strings.Contains(string(output), "envdrift-agent.exe")
}
