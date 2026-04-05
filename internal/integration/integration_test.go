//go:build integration

// Package integration contains end-to-end tests for safesh.
// Run with: go test -tags=integration ./internal/integration/
package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binaryPath returns the path to the safesh binary, building it if needed.
func binaryPath(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "safesh")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/adeshmukh/safesh/cmd/safesh")
	cmd.Dir = projectRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "building safesh: %s", out)
	return bin
}

// projectRoot finds the repo root by looking for go.mod.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(file)
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find project root")
	return ""
}

// testdataScript reads a testdata script.
func testdataScript(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(projectRoot(t), "testdata", "scripts", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading %s", path)
	return data
}

// runSafesh runs safesh with the given stdin and args.
// Returns stdout, stderr, and the exit code.
func runSafesh(t *testing.T, bin string, stdin []byte, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	return stdout.String(), stderr.String(), code
}

// ── Pipe mode ─────────────────────────────────────────────────────────────────

func TestPipeMode_CleanScript(t *testing.T) {
	bin := binaryPath(t)
	script := testdataScript(t, "clean.sh")

	_, stderr, code := runSafesh(t, bin, script, "--no-confirm")
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr, "no findings")
}

func TestPipeMode_WithFindings(t *testing.T) {
	bin := binaryPath(t)
	script := testdataScript(t, "with_findings.sh")

	_, stderr, _ := runSafesh(t, bin, script, "--dry-run", "--no-confirm")
	// Should report findings
	assert.Contains(t, stderr, "[privilege]")
	assert.Contains(t, stderr, "[network]")
	assert.Contains(t, stderr, "[persistence]")
}

func TestPipeMode_DryRun(t *testing.T) {
	bin := binaryPath(t)
	// A script that would fail if actually executed
	script := []byte("#!/bin/bash\nset -euo pipefail\nexit 99\n")

	_, _, code := runSafesh(t, bin, script, "--dry-run", "--no-confirm")
	// dry-run should not execute the script, so exit code should not be 99
	assert.NotEqual(t, 99, code)
}

func TestPipeMode_StrictModeInjected(t *testing.T) {
	bin := binaryPath(t)
	// A script that accesses an unset variable — should fail with strict mode
	script := []byte("echo $DEFINITELY_UNSET_VAR_XYZ\n")

	_, _, code := runSafesh(t, bin, script, "--no-confirm")
	// With set -u, accessing unset var should cause non-zero exit
	assert.NotEqual(t, 0, code)
}

func TestPipeMode_NoStrictSkipsInjection(t *testing.T) {
	bin := binaryPath(t)
	// Without strict mode, an unset var echoes empty string (exit 0)
	script := []byte("echo ${DEFINITELY_UNSET_VAR_XYZ:-}\n")

	_, _, code := runSafesh(t, bin, script, "--no-strict", "--no-confirm")
	assert.Equal(t, 0, code)
}

func TestPipeMode_ShellOverride(t *testing.T) {
	bin := binaryPath(t)
	script := []byte("echo hello\n")

	_, _, code := runSafesh(t, bin, script, "bash", "--no-confirm")
	assert.Equal(t, 0, code)
}

func TestPipeMode_UnknownShell(t *testing.T) {
	bin := binaryPath(t)
	script := []byte("echo hello\n")

	_, stderr, code := runSafesh(t, bin, script, "notashell")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "notashell")
}

func TestPipeMode_EmptyStdin(t *testing.T) {
	bin := binaryPath(t)
	_, _, code := runSafesh(t, bin, []byte{})
	assert.NotEqual(t, 0, code)
}

// ── URL mode ──────────────────────────────────────────────────────────────────

func TestURLMode_Success(t *testing.T) {
	bin := binaryPath(t)
	script := []byte("#!/bin/bash\nset -euo pipefail\necho hello from url\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(script)
	}))
	defer srv.Close()

	stdout, _, code := runSafesh(t, bin, nil, "--no-confirm", srv.URL+"/install.sh")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "hello from url")
}

func TestURLMode_WithChecksum(t *testing.T) {
	bin := binaryPath(t)
	script := []byte("#!/bin/bash\nset -euo pipefail\necho verified\n")
	h := sha256.Sum256(script)
	hash := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/install.sh":
			_, _ = w.Write(script)
		case "/install.sh.sha256":
			_, _ = fmt.Fprintf(w, "%s  install.sh\n", hash)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, stderr, code := runSafesh(t, bin, nil, "--no-confirm", srv.URL+"/install.sh")
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr, "integrity verified")
}

func TestURLMode_WrongChecksum(t *testing.T) {
	bin := binaryPath(t)

	_, _, code := runSafesh(t, bin, nil, "--sha256", "deadbeef00", "--no-confirm", "https://example.com/fake")
	assert.NotEqual(t, 0, code)
}

// ── History subcommand ────────────────────────────────────────────────────────

func TestHistoryList_AfterRun(t *testing.T) {
	bin := binaryPath(t)

	// Override history dir via XDG_DATA_HOME
	tmpHome := t.TempDir()
	env := append(os.Environ(), "XDG_DATA_HOME="+tmpHome)

	script := []byte("#!/bin/bash\nset -euo pipefail\necho hi\n")
	cmd := exec.Command(bin, "--no-confirm")
	cmd.Stdin = bytes.NewReader(script)
	cmd.Env = env
	require.NoError(t, cmd.Run())

	// Now list history
	listCmd := exec.Command(bin, "history")
	listCmd.Env = env
	var out bytes.Buffer
	listCmd.Stdout = &out
	require.NoError(t, listCmd.Run())
	assert.Contains(t, out.String(), "stdin")
}

// ── Findings categories ───────────────────────────────────────────────────────

func TestFindings_ObfuscatedScript(t *testing.T) {
	bin := binaryPath(t)
	script := testdataScript(t, "obfuscated.sh")

	_, stderr, _ := runSafesh(t, bin, script, "--dry-run", "--no-confirm")
	assert.Contains(t, stderr, "[obfuscation]")
	assert.Contains(t, stderr, "[execution-chain]")
}

// ── Environment isolation ─────────────────────────────────────────────────────

func TestEnvIsolation_StripsSensitiveVars(t *testing.T) {
	bin := binaryPath(t)

	// Script that tries to echo a secret env var
	script := []byte("#!/bin/bash\necho \"SECRET=${MY_SECRET_TOKEN:-not-set}\"\n")
	t.Setenv("MY_SECRET_TOKEN", "hunter2")

	stdout, _, code := runSafesh(t, bin, script, "--no-confirm")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "not-set") // var should be stripped
	assert.NotContains(t, stdout, "hunter2")
}

func TestEnvPassthrough(t *testing.T) {
	bin := binaryPath(t)
	script := []byte("#!/bin/bash\necho \"TOKEN=${MY_TOKEN:-not-set}\"\n")
	t.Setenv("MY_TOKEN", "myvalue")

	stdout, _, code := runSafesh(t, bin, script, "--env", "MY_TOKEN", "--no-confirm")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "myvalue")
}

// ── Explain flag ──────────────────────────────────────────────────────────────

func TestExplain(t *testing.T) {
	bin := binaryPath(t)
	stdout, _, code := runSafesh(t, bin, nil, "--explain", "privilege")
	assert.Equal(t, 0, code)
	assert.True(t, strings.Contains(stdout, "sudo") || strings.Contains(stdout, "privilege"))
}
