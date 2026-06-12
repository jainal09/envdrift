// Package project handles loading per-project configuration from envdrift.toml files.
package project

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

// envdriftConfig represents the envdrift.toml structure used by the agent.
type envdriftConfig struct {
	Guardian guardianToml `toml:"guardian"`
	Vault    vaultToml    `toml:"vault"`
}

// guardianToml is the raw TOML representation.
type guardianToml struct {
	Enabled     *bool    `toml:"enabled"`
	IdleTimeout string   `toml:"idle_timeout"`
	Patterns    []string `toml:"patterns"`
	Exclude     []string `toml:"exclude"`
	Notify      *bool    `toml:"notify"`
}

type vaultToml struct {
	Sync vaultSyncToml `toml:"sync"`
}

type vaultSyncToml struct {
	Mappings []vaultSyncMappingToml `toml:"mappings"`
}

type vaultSyncMappingToml struct {
	EnvFile string `toml:"env_file"`
}

// pyprojectToml extracts the [tool.envdrift] table from a pyproject.toml. The
// pointer distinguishes "table present (even if empty)" from "absent", the
// same presence test the CLI's find_config applies.
type pyprojectToml struct {
	Tool struct {
		Envdrift *envdriftConfig `toml:"envdrift"`
	} `toml:"tool"`
}

// LoadProjectConfig loads the guardian configuration for a project using the
// same config-discovery contract as the Python CLI's find_config
// (src/envdrift/config.py): walk from the project directory toward the
// filesystem root; at each level an envdrift.toml wins, then a pyproject.toml
// with a [tool.envdrift] table. `envdrift agent register` blesses projects
// with that contract, so the agent must honor it too — pre-#481 it read only
// <path>/envdrift.toml and silently never watched projects registered via
// pyproject.toml or a parent-dir envdrift.toml.
// If no config is discovered, returns the default config.
func LoadProjectConfig(projectPath string) (*GuardianConfig, error) {
	cfg, found, err := discoverEnvdriftConfig(projectPath)
	if err != nil {
		return nil, err
	}
	if !found {
		return DefaultGuardianConfig(), nil
	}

	return parseGuardianConfig(&cfg.Guardian, cfg.Vault.Sync.Mappings)
}

// discoverEnvdriftConfig mirrors the CLI's find_config walk: starting at dir
// and moving up to (but not including) the filesystem root, return the first
// envdrift.toml, else the first pyproject.toml containing [tool.envdrift].
// A malformed pyproject.toml is skipped (like the CLI); a malformed
// envdrift.toml is an error (pre-existing behavior).
func discoverEnvdriftConfig(dir string) (*envdriftConfig, bool, error) {
	// Match Python's Path.resolve(): absolute with symlinks resolved, so the
	// walk sees the same ancestor chain the CLI saw at registration time.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	current, err := filepath.Abs(dir)
	if err != nil {
		return nil, false, err
	}

	for filepath.Dir(current) != current {
		data, err := os.ReadFile(filepath.Join(current, "envdrift.toml"))
		switch {
		case err == nil:
			var cfg envdriftConfig
			if err := toml.Unmarshal(data, &cfg); err != nil {
				return nil, false, err
			}
			return &cfg, true, nil
		case !os.IsNotExist(err):
			// An existing-but-unreadable envdrift.toml is an error, not a
			// silent skip (pre-existing behavior for the project's own file).
			return nil, false, err
		}

		if cfg, ok := readPyprojectEnvdrift(filepath.Join(current, "pyproject.toml")); ok {
			return cfg, true, nil
		}

		current = filepath.Dir(current)
	}

	return nil, false, nil
}

// readPyprojectEnvdrift returns the [tool.envdrift] config from a
// pyproject.toml, reporting ok=false when the file is missing, unreadable,
// malformed, or has no [tool.envdrift] table (all skipped silently, matching
// the CLI's find_config).
func readPyprojectEnvdrift(path string) (*envdriftConfig, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var py pyprojectToml
	if err := toml.Unmarshal(data, &py); err != nil {
		return nil, false
	}
	if py.Tool.Envdrift == nil {
		return nil, false
	}
	return py.Tool.Envdrift, true
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
func parseGuardianConfig(raw *guardianToml, vaultMappings []vaultSyncMappingToml) (*GuardianConfig, error) {
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

	cfg.Patterns = appendVaultEnvFilePatterns(cfg.Patterns, vaultMappings)

	return cfg, nil
}

func appendVaultEnvFilePatterns(patterns []string, mappings []vaultSyncMappingToml) []string {
	result := append([]string{}, patterns...)

	for _, mapping := range mappings {
		envFile := strings.TrimSpace(mapping.EnvFile)
		if envFile == "" || filepath.IsAbs(envFile) {
			continue
		}

		clean := filepath.Clean(envFile)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			continue
		}

		name := filepath.Base(clean)
		if name == "." || name == string(filepath.Separator) {
			continue
		}

		if patternListMatches(result, name) {
			continue
		}

		result = append(result, name)
	}

	return result
}

func patternListMatches(patterns []string, name string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, name)
		if err == nil && matched {
			return true
		}
		if pattern == name {
			return true
		}
	}
	return false
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
