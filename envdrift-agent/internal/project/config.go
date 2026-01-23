// Package project handles loading per-project configuration from envdrift.toml files.
package project

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Default values for guardian config
var (
	DefaultIdleTimeout = 5 * time.Minute
	DefaultPatterns    = []string{".env*"}
	DefaultExclude     = []string{".env.example", ".env.sample", ".env.keys"}
)

// idleTimeoutPattern matches duration strings like "5m", "30s", "1h", "2d"
var idleTimeoutPattern = regexp.MustCompile(`^(\d+)(s|m|h|d)$`)

// GuardianConfig holds the per-project guardian settings from envdrift.toml.
type GuardianConfig struct {
	Enabled     bool          `toml:"enabled"`
	IdleTimeout time.Duration `toml:"-"` // Parsed from string
	Patterns    []string      `toml:"patterns"`
	Exclude     []string      `toml:"exclude"`
	Notify      bool          `toml:"notify"`

	// Raw idle_timeout string for TOML parsing
	IdleTimeoutStr string `toml:"idle_timeout"`
}

// envdriftConfig represents the full envdrift.toml structure (we only need guardian section).
type envdriftConfig struct {
	Guardian guardianToml `toml:"guardian"`
}

// guardianToml is the raw TOML representation.
type guardianToml struct {
	Enabled     *bool    `toml:"enabled"`
	IdleTimeout string   `toml:"idle_timeout"`
	Patterns    []string `toml:"patterns"`
	Exclude     []string `toml:"exclude"`
	Notify      *bool    `toml:"notify"`
}

// LoadProjectConfig loads the guardian configuration from a project's envdrift.toml.
// If the file doesn't exist or has no guardian section, returns default config.
func LoadProjectConfig(projectPath string) (*GuardianConfig, error) {
	configPath := filepath.Join(projectPath, "envdrift.toml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultGuardianConfig(), nil
		}
		return nil, err
	}

	var cfg envdriftConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return parseGuardianConfig(&cfg.Guardian)
}

// DefaultGuardianConfig returns a GuardianConfig with default values.
func DefaultGuardianConfig() *GuardianConfig {
	return &GuardianConfig{
		Enabled:     false,
		IdleTimeout: DefaultIdleTimeout,
		Patterns:    DefaultPatterns,
		Exclude:     DefaultExclude,
		Notify:      true,
	}
}

// parseGuardianConfig converts the raw TOML config to GuardianConfig with defaults.
func parseGuardianConfig(raw *guardianToml) (*GuardianConfig, error) {
	cfg := DefaultGuardianConfig()

	// Apply values from TOML if present
	if raw.Enabled != nil {
		cfg.Enabled = *raw.Enabled
	}

	if raw.IdleTimeout != "" {
		duration, err := ParseIdleTimeout(raw.IdleTimeout)
		if err != nil {
			return nil, err
		}
		cfg.IdleTimeout = duration
		cfg.IdleTimeoutStr = raw.IdleTimeout
	}

	if len(raw.Patterns) > 0 {
		cfg.Patterns = raw.Patterns
	}

	if len(raw.Exclude) > 0 {
		cfg.Exclude = raw.Exclude
	}

	if raw.Notify != nil {
		cfg.Notify = *raw.Notify
	}

	return cfg, nil
}

// ParseIdleTimeout parses a duration string like "5m", "30s", "1h", "2d" into time.Duration.
func ParseIdleTimeout(s string) (time.Duration, error) {
	matches := idleTimeoutPattern.FindStringSubmatch(s)
	if matches == nil {
		// Try standard Go duration parsing as fallback
		return time.ParseDuration(s)
	}

	value, _ := strconv.Atoi(matches[1])
	unit := matches[2]

	switch unit {
	case "s":
		return time.Duration(value) * time.Second, nil
	case "m":
		return time.Duration(value) * time.Minute, nil
	case "h":
		return time.Duration(value) * time.Hour, nil
	case "d":
		return time.Duration(value) * 24 * time.Hour, nil
	default:
		return time.ParseDuration(s)
	}
}

// ProjectConfig holds a project path and its guardian configuration.
type ProjectConfig struct {
	Path     string
	Guardian *GuardianConfig
}

// LoadAllProjectConfigs loads guardian configs for all given project paths.
// Projects with guardian.enabled = false are excluded from the result.
func LoadAllProjectConfigs(projectPaths []string) ([]*ProjectConfig, error) {
	var configs []*ProjectConfig

	for _, path := range projectPaths {
		cfg, err := LoadProjectConfig(path)
		if err != nil {
			// Log but continue with other projects
			continue
		}

		// Only include enabled projects
		if cfg.Enabled {
			configs = append(configs, &ProjectConfig{
				Path:     path,
				Guardian: cfg,
			})
		}
	}

	return configs, nil
}
