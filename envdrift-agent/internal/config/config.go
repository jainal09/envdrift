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

// DefaultConfig returns a *Config populated with sensible defaults for the Guardian and Directories sections.
// 
// Defaults:
//   - Guardian: Enabled=true, IdleTimeout=5m, Patterns=[".env*"], Exclude=[".env.example", ".env.sample", ".env.keys"], Notify=true
//   - Directories: Watch=["$HOME/projects"], Recursive=true
//
// The default watch path is constructed from the current user's home directory; if the home directory cannot
// be determined the path will be "projects" (i.e., the home prefix will be empty).
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

// ConfigPath returns the path to the guardian configuration file under the user's home directory: "<home>/.envdrift/guardian.toml".
// If the user's home directory cannot be determined, the returned path is relative (".envdrift/guardian.toml").
func ConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".envdrift", "guardian.toml")
}

// Load reads the guardian configuration from the default config file and returns it.
// If the config file does not exist, Load returns the default configuration.
// If reading the file or unmarshalling TOML fails, Load returns a non-nil error.
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

// Save writes cfg to the default config file path as TOML.
// It ensures the parent directory exists, marshals cfg to TOML, and writes the file with permissions 0644.
// It returns an error if directory creation, marshaling, or writing fails.
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