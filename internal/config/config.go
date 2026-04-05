// Package config loads and exposes safesh configuration.
package config

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// DefaultPath returns the default config file path.
func DefaultPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, "safesh", "config.toml")
}

// Config holds all safesh configuration.
type Config struct {
	Defaults  DefaultsConfig  `toml:"defaults"`
	Findings  FindingsConfig  `toml:"findings"`
	History   HistoryConfig   `toml:"history"`
	StrictMode StrictModeConfig `toml:"strict_mode"`
	Environment EnvironmentConfig `toml:"environment"`
}

// DefaultsConfig holds top-level execution defaults.
type DefaultsConfig struct {
	Shell               string `toml:"shell"`
	StrictMode          bool   `toml:"strict_mode"`
	ConfirmOnFindings   bool   `toml:"confirm_on_findings"`
	EnvironmentIsolation bool  `toml:"environment_isolation"`
}

// FindingsConfig controls how finding categories are handled.
type FindingsConfig struct {
	Blocking []string `toml:"blocking"`
	WarnOnly []string `toml:"warn_only"`
	Ignore   []string `toml:"ignore"`
}

// HistoryConfig controls history retention.
type HistoryConfig struct {
	Enabled    bool `toml:"enabled"`
	MaxEntries int  `toml:"max_entries"`
	MaxAgeDays int  `toml:"max_age_days"`
}

// StrictModeConfig allows disabling strict mode per URL pattern.
type StrictModeConfig struct {
	DisabledFor []string `toml:"disabled_for"`
}

// EnvironmentConfig controls environment variable passthrough.
type EnvironmentConfig struct {
	Passthrough []string `toml:"passthrough"`
}

// Default returns a Config populated with safe defaults.
func Default() *Config {
	return &Config{
		Defaults: DefaultsConfig{
			Shell:                "bash",
			StrictMode:           true,
			ConfirmOnFindings:    true,
			EnvironmentIsolation: true,
		},
		Findings: FindingsConfig{
			Blocking: []string{"obfuscation", "execution-chain"},
			WarnOnly: []string{"network", "persistence"},
			Ignore:   []string{},
		},
		History: HistoryConfig{
			Enabled:    true,
			MaxEntries: 1000,
			MaxAgeDays: 90,
		},
		StrictMode:  StrictModeConfig{DisabledFor: []string{}},
		Environment: EnvironmentConfig{Passthrough: []string{}},
	}
}

// Load reads config from path, falling back to defaults for any unset fields.
// If the file does not exist, defaults are returned without error.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, err
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadDefault loads from the default config path.
func LoadDefault() (*Config, error) {
	return Load(DefaultPath())
}
