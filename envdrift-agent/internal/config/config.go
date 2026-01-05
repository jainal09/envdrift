// Package config handles configuration loading and defaults.
package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config holds the agent configuration
type Config struct {
	Guardian    GuardianConfig    `toml:"guardian"`
	Directories DirectoriesConfig `toml:"directories"`
}

// GuardianConfig holds encryption behavior settings
type GuardianConfig struct {
	Enabled     bool          `toml:"enabled"`
	IdleTimeout time.Duration `toml:"idle_timeout"`
	Patterns    []string      `toml:"patterns"`
	Exclude     []string      `toml:"exclude"`
	Notify      bool          `toml:"notify"`
}

// DirectoriesConfig holds directory watch settings
type DirectoriesConfig struct {
	Watch     []string `toml:"watch"`
	Recursive bool     `toml:"recursive"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	return &Config{
		Guardian: GuardianConfig{
			Enabled:     true,
			IdleTimeout: 5 * time.Minute,
			Patterns:    []string{".env*"},
			Exclude:     []string{".env.example", ".env.sample", ".env.keys"},
			Notify:      true,
		},
		Directories: DirectoriesConfig{
			Watch:     []string{filepath.Join(homeDir, "projects")},
			Recursive: true,
		},
	}
}

// ConfigPath returns the default config file path
func ConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".envdrift", "guardian.toml")
}

// Load reads config from disk or returns defaults
func Load() (*Config, error) {
	configPath := ConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	cfg := DefaultConfig()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes config to disk
func Save(cfg *Config) error {
	configPath := ConfigPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}
