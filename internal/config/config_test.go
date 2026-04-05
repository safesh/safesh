package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	assert.Equal(t, "bash", cfg.Defaults.Shell)
	assert.True(t, cfg.Defaults.StrictMode)
	assert.True(t, cfg.Defaults.ConfirmOnFindings)
	assert.True(t, cfg.Defaults.EnvironmentIsolation)
	assert.True(t, cfg.History.Enabled)
	assert.Equal(t, []string{"obfuscation", "execution-chain"}, cfg.Findings.Blocking)
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.toml")
	require.NoError(t, err)
	assert.Equal(t, Default(), cfg)
}

func TestLoadValidTOML(t *testing.T) {
	content := `
[defaults]
shell = "zsh"
strict_mode = false

[history]
enabled = false
max_entries = 50
`
	f := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(f, []byte(content), 0o600))

	cfg, err := Load(f)
	require.NoError(t, err)
	assert.Equal(t, "zsh", cfg.Defaults.Shell)
	assert.False(t, cfg.Defaults.StrictMode)
	assert.False(t, cfg.History.Enabled)
	assert.Equal(t, 50, cfg.History.MaxEntries)
	// Unset fields should retain defaults
	assert.True(t, cfg.Defaults.ConfirmOnFindings)
}

func TestLoadInvalidTOML(t *testing.T) {
	f := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(f, []byte("not valid toml :::"), 0o600))

	_, err := Load(f)
	assert.Error(t, err)
}
