package executor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildScript_StrictMode(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	out := buildScript(src, true)
	assert.Contains(t, string(out), "#!/bin/bash\n")
	assert.Contains(t, string(out), "set -euo pipefail\n")
	// preamble should come after shebang
	shebangEnd := 12 // len("#!/bin/bash\n")
	rest := string(out[shebangEnd:])
	assert.True(t, len(rest) > 0)
	assert.Contains(t, rest, "set -euo pipefail")
}

func TestBuildScript_NoShebang(t *testing.T) {
	src := []byte("echo hello\n")
	out := buildScript(src, true)
	assert.Contains(t, string(out), "set -euo pipefail\necho hello\n")
}

func TestBuildScript_NoStrictMode(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	out := buildScript(src, false)
	assert.Equal(t, src, out)
}

func TestShellFromShebang(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{"#!/bin/bash\necho hi\n", "bash"},
		{"#!/usr/bin/env bash\necho hi\n", "bash"},
		{"#!/bin/sh\necho hi\n", "sh"},
		{"#!/usr/bin/env zsh\necho hi\n", "zsh"},
		{"echo hi\n", ""},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, ShellFromShebang([]byte(tt.src)), "src: %q", tt.src)
	}
}

func TestResolveShell_Bash(t *testing.T) {
	path, err := ResolveShell("bash")
	require.NoError(t, err)
	assert.NotEmpty(t, path)
}

func TestResolveShell_NotFound(t *testing.T) {
	_, err := ResolveShell("__nonexistent_shell_xyz__")
	assert.Error(t, err)
}

func TestBuildEnv_Isolated(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "hunter2")
	t.Setenv("PATH", "/usr/bin:/bin")

	env := buildEnv(true, nil)

	envMap := map[string]string{}
	for _, kv := range env {
		k, v := splitKV(kv)
		envMap[k] = v
	}

	assert.Contains(t, envMap, "PATH")
	assert.NotContains(t, envMap, "SECRET_TOKEN")
}

func TestBuildEnv_WithPassthrough(t *testing.T) {
	t.Setenv("MY_TOKEN", "abc123")

	env := buildEnv(true, []string{"MY_TOKEN"})

	envMap := map[string]string{}
	for _, kv := range env {
		k, v := splitKV(kv)
		envMap[k] = v
	}
	assert.Equal(t, "abc123", envMap["MY_TOKEN"])
}

func TestBuildEnv_NotIsolated(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "hunter2")
	env := buildEnv(false, nil)
	// Should include everything
	found := false
	for _, kv := range env {
		if kv == "SECRET_TOKEN=hunter2" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestRun_DryRun(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	result, err := Run(src, Options{DryRun: true})
	require.NoError(t, err)
	assert.True(t, result.Skipped)
}

func TestRun_SimpleScript(t *testing.T) {
	shell, err := ResolveShell("bash")
	require.NoError(t, err)

	src := []byte("echo hello")
	result, err := Run(src, Options{
		Shell:      shell,
		StrictMode: true,
		IsolateEnv: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.False(t, result.Skipped)
}

func TestRun_FailingScript(t *testing.T) {
	shell, err := ResolveShell("bash")
	require.NoError(t, err)

	src := []byte("exit 42")
	result, err := Run(src, Options{Shell: shell, IsolateEnv: true})
	require.NoError(t, err)
	assert.Equal(t, 42, result.ExitCode)
}

func splitKV(kv string) (string, string) {
	for i, c := range kv {
		if c == '=' {
			return kv[:i], kv[i+1:]
		}
	}
	return kv, ""
}
