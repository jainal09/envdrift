// Package cmd provides the CLI commands for envdrift-agent.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jainal09/envdrift-agent/internal/config"
	"github.com/jainal09/envdrift-agent/internal/daemon"
	"github.com/jainal09/envdrift-agent/internal/encrypt"
	"github.com/jainal09/envdrift-agent/internal/guardian"
)

var (
	// Version is set at build time
	Version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "envdrift-agent",
	Short: "Auto-encrypt .env files when not in use",
	Long: `EnvDrift Guardian - A background agent that watches .env files
and automatically encrypts them when they're not being actively edited.

Install once with 'envdrift-agent install' and it runs automatically on startup.`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("envdrift-agent %s\n", Version)
	},
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install agent to run at system startup",
	Long:  `Installs the agent as a system service that starts automatically on boot.`,
	RunE:  runInstall,
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove agent from system startup",
	RunE:  runUninstall,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check if agent is running",
	RunE:  runStatus,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the agent in foreground (for debugging)",
	RunE:  runStart,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running agent",
	RunE:  runStop,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show or create config file",
	RunE:  runConfig,
}

// init registers all subcommands with rootCmd: version, install, uninstall, status, start, stop, and config.
func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(configCmd)
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

// runInstall installs the envdrift-agent as a system service and prints progress and status messages.
//
// It checks for dotenvx availability, ensures a configuration file exists (creating/saving a default if needed),
// reports the config path, and invokes daemon.Install. It returns any error encountered during loading or
// installing the agent; non-fatal failures to save the config are reported to stdout but do not stop installation.
func runInstall(cmd *cobra.Command, args []string) error {
	fmt.Println("Installing envdrift-agent...")

	// Check envdrift first
	if !encrypt.IsEnvdriftAvailable() {
		fmt.Println("⚠️  Warning: envdrift not found. Install it: pip install envdrift")
	}

	// Create default config if none exists
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := config.Save(cfg); err != nil {
		fmt.Printf("⚠️  Could not save config: %v\n", err)
	} else {
		fmt.Printf("📝 Config file: %s\n", config.ConfigPath())
	}

	if err := daemon.Install(); err != nil {
		return fmt.Errorf("failed to install: %w", err)
	}

	fmt.Println("✅ Agent installed and will start on system boot")
	return nil
}

// runUninstall removes the agent from system startup, printing progress messages.
//
// It performs the uninstallation and returns an error if the removal fails.
func runUninstall(cmd *cobra.Command, args []string) error {
	fmt.Println("Uninstalling envdrift-agent...")

	if err := daemon.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall: %w", err)
	}

	fmt.Println("✅ Agent removed from system startup")
	return nil
}

// runStatus reports whether the agent is installed and running and prints
// the configured paths for the config file and dotenvx.
//
// It writes four status lines to stdout: Installed, Running, Config, and dotenvx, and always returns nil.
func runStatus(cmd *cobra.Command, args []string) error {
	installed := daemon.IsInstalled()
	running := daemon.IsRunning()

	fmt.Printf("Installed: %v\n", installed)
	fmt.Printf("Running:   %v\n", running)
	fmt.Printf("Config:    %s\n", config.ConfigPath())
	fmt.Printf("envdrift:  %v\n", encrypt.IsEnvdriftAvailable())

	return nil
}

// runStart starts the agent in the foreground and runs the guardian until interrupted.
// It loads the configuration, creates and starts a guardian, and cancels execution when a SIGINT or SIGTERM is received; returns any error encountered while loading the config, creating the guardian, or starting it.
func runStart(cmd *cobra.Command, args []string) error {
	fmt.Println("Starting envdrift-agent in foreground...")
	fmt.Println("Press Ctrl+C to stop")

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	g, err := guardian.New(cfg)
	if err != nil {
		return err
	}

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	return g.Start(ctx)
}

// runStop reports whether the agent is currently running and prints guidance on how to stop it.
//
// It prints a stopping header and then either informs the user that the agent is running
// (suggesting the 'envdrift-agent uninstall' command to stop it) or that the agent is not running.
func runStop(cmd *cobra.Command, args []string) error {
	fmt.Println("Stopping envdrift-agent...")
	// For daemon mode, we'd need to signal the process
	// For now, just print status
	if daemon.IsRunning() {
		fmt.Println("Agent is running - use 'envdrift-agent uninstall' to stop")
	} else {
		fmt.Println("Agent is not running")
	}
	return nil
}

// runConfig displays the configuration file path, creates and saves a default
// configuration if the file is missing, and prints the current configuration
// settings to stdout. It returns an error if saving or loading the configuration fails.
func runConfig(cmd *cobra.Command, args []string) error {
	configPath := config.ConfigPath()

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg := config.DefaultConfig()
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Printf("Created config file: %s\n", configPath)
	} else {
		fmt.Printf("Config file: %s\n", configPath)
	}

	// Print current config
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	fmt.Printf("\nCurrent settings:\n")
	fmt.Printf("  Enabled:      %v\n", cfg.Guardian.Enabled)
	fmt.Printf("  Idle timeout: %v\n", cfg.Guardian.IdleTimeout)
	fmt.Printf("  Patterns:     %v\n", cfg.Guardian.Patterns)
	fmt.Printf("  Exclude:      %v\n", cfg.Guardian.Exclude)
	fmt.Printf("  Notify:       %v\n", cfg.Guardian.Notify)
	fmt.Printf("  Directories:  %v\n", cfg.Directories.Watch)

	return nil
}
