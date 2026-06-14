// Package config handles configuration loading and defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/jainal09/envdrift-agent/internal/project"
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

// rawConfig mirrors Config for TOML decoding. idle_timeout is accepted as
// either the documented duration string ("5m") or the raw nanosecond integer
// that pre-#481 Save wrote; before this, the documented form crashed the agent
// at startup ("toml: cannot decode TOML string into struct field ... of type
// time.Duration"), which under launchd KeepAlive / systemd Restart=always
// became a perpetual crash-respawn loop. Absent fields stay nil/empty so
// defaults survive partial configs.
type rawConfig struct {
	Guardian    rawGuardianConfig    `toml:"guardian"`
	Directories rawDirectoriesConfig `toml:"directories"`
}

// Slice fields are pointers so an explicit empty array in the TOML
// (patterns = [], exclude = [], watch = []) is honored as "clear the default"
// rather than being indistinguishable from an absent key: a nil pointer means
// the key was absent (keep the default), a non-nil pointer to an empty slice
// means the user deliberately cleared it.
type rawGuardianConfig struct {
	Enabled     *bool     `toml:"enabled"`
	IdleTimeout any       `toml:"idle_timeout"`
	Patterns    *[]string `toml:"patterns"`
	Exclude     *[]string `toml:"exclude"`
	Notify      *bool     `toml:"notify"`
}

type rawDirectoriesConfig struct {
	Watch     *[]string `toml:"watch"`
	Recursive *bool     `toml:"recursive"`
}

// savedConfig is the shape Save serializes: idle_timeout goes out as the
// documented duration string, never as raw nanoseconds.
type savedConfig struct {
	Guardian    savedGuardianConfig `toml:"guardian"`
	Directories DirectoriesConfig   `toml:"directories"`
}

type savedGuardianConfig struct {
	Enabled     bool     `toml:"enabled"`
	IdleTimeout string   `toml:"idle_timeout"`
	Patterns    []string `toml:"patterns"`
	Exclude     []string `toml:"exclude"`
	Notify      bool     `toml:"notify"`
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
	var raw rawConfig
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	if err := mergeGuardian(&cfg.Guardian, &raw.Guardian, configPath); err != nil {
		return nil, err
	}
	mergeDirectories(&cfg.Directories, &raw.Directories)

	return cfg, nil
}

// mergeGuardian overlays the present fields of a decoded guardian section onto
// the defaults already in cfg. Only keys actually present in the file change a
// default; an explicit empty slice (patterns = []) clears it.
func mergeGuardian(cfg *GuardianConfig, raw *rawGuardianConfig, configPath string) error {
	if raw.Enabled != nil {
		cfg.Enabled = *raw.Enabled
	}
	if raw.IdleTimeout != nil {
		d, err := decodeIdleTimeout(raw.IdleTimeout)
		if err != nil {
			return fmt.Errorf("%s: guardian.idle_timeout: %w", configPath, err)
		}
		cfg.IdleTimeout = d
	}
	if raw.Patterns != nil {
		cfg.Patterns = *raw.Patterns
	}
	if raw.Exclude != nil {
		cfg.Exclude = *raw.Exclude
	}
	if raw.Notify != nil {
		cfg.Notify = *raw.Notify
	}
	return nil
}

// mergeDirectories overlays the present fields of a decoded directories section
// onto the defaults already in cfg (explicit watch = [] clears the default).
func mergeDirectories(cfg *DirectoriesConfig, raw *rawDirectoriesConfig) {
	if raw.Watch != nil {
		cfg.Watch = *raw.Watch
	}
	if raw.Recursive != nil {
		cfg.Recursive = *raw.Recursive
	}
}

// decodeIdleTimeout converts a TOML idle_timeout value into a time.Duration.
// The documented form is a duration string ("30s", "5m", "1h", "2d" — parsed
// by the same project.ParseIdleTimeout the per-project config uses); a bare
// integer is the legacy raw-nanosecond form pre-#481 Save wrote and stays
// loadable so existing config files don't start crashing the agent.
func decodeIdleTimeout(v any) (time.Duration, error) {
	switch tv := v.(type) {
	case string:
		return project.ParseIdleTimeout(tv)
	case int64:
		return time.Duration(tv), nil
	default:
		return 0, fmt.Errorf("unsupported value %v (type %T); use a duration string like \"5m\"", v, v)
	}
}

// FormatIdleTimeout renders a duration in the documented guardian.toml form: a
// compact single-unit duration string ("30s", "5m", "2h") when a whole unit
// fits, otherwise Go's default representation (which Load also accepts).
func FormatIdleTimeout(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", d/time.Second)
	default:
		return d.String()
	}
}

// Save writes cfg to the default config file path as TOML, serializing
// idle_timeout in the documented duration-string form ("5m") — pre-#481 it
// wrote time.Duration's raw nanoseconds (idle_timeout = 300000000000).
// It ensures the parent directory exists and writes the file with permissions 0644.
// It returns an error if directory creation, marshaling, or writing fails.
func Save(cfg *Config) error {
	configPath := ConfigPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	out := savedConfig{
		Guardian: savedGuardianConfig{
			Enabled:     cfg.Guardian.Enabled,
			IdleTimeout: FormatIdleTimeout(cfg.Guardian.IdleTimeout),
			Patterns:    cfg.Guardian.Patterns,
			Exclude:     cfg.Guardian.Exclude,
			Notify:      cfg.Guardian.Notify,
		},
		Directories: cfg.Directories,
	}

	data, err := toml.Marshal(out)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}
