// Package executor runs scripts via the system shell.
package executor

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/safesh/safesh/internal/sandbox"
)

// safeEnvVars is the set of environment variable names passed through by default.
var safeEnvVars = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true,
	"SHELL": true, "TERM": true, "LANG": true, "LC_ALL": true,
	"TMPDIR": true,
}

// Options controls executor behaviour.
type Options struct {
	Shell               string         // resolved shell binary path
	StrictMode          bool           // prepend set -euo pipefail
	IsolateEnv          bool           // strip env to safe baseline
	ExtraEnvPassthrough []string       // additional vars to pass through
	DryRun              bool           // skip execution (analysis only)
	Sandbox             sandbox.Config // sandbox configuration
}

// Result holds execution outcome.
type Result struct {
	ExitCode   int
	Duration   time.Duration
	Skipped    bool // true if DryRun was set
}

// Run executes the script src using the configured options.
// The script is written to a temp file before execution.
func Run(src []byte, opts Options) (Result, error) {
	if opts.DryRun {
		return Result{Skipped: true}, nil
	}

	content := buildScript(src, opts.StrictMode)

	tmpFile, err := writeTempScript(content)
	if err != nil {
		return Result{}, fmt.Errorf("creating temp script: %w", err)
	}
	defer os.Remove(tmpFile)

	env := buildEnv(opts.IsolateEnv, opts.ExtraEnvPassthrough)

	// Resolve the command to run, wrapping with a sandbox backend if requested.
	bin, cmdArgs, err := sandbox.WrapCommand(opts.Shell, tmpFile, opts.Sandbox)
	if err != nil {
		return Result{}, fmt.Errorf("sandbox: %w", err)
	}

	start := time.Now()
	cmd := exec.Command(bin, cmdArgs...) //nolint:gosec
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return Result{}, fmt.Errorf("running script: %w", runErr)
		}
	}

	return Result{ExitCode: exitCode, Duration: duration}, nil
}

// ResolveShell looks up the shell by name in PATH and returns its absolute path.
// Returns an error if the shell cannot be found.
func ResolveShell(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("shell %q not found in PATH: %w", name, err)
	}
	return path, nil
}

// ShellFromShebang extracts the shell name from a shebang line.
// Returns "" if no shebang is present or it doesn't match a known shell.
func ShellFromShebang(src []byte) string {
	if !bytes.HasPrefix(src, []byte("#!")) {
		return ""
	}
	end := bytes.IndexByte(src, '\n')
	if end < 0 {
		end = len(src)
	}
	shebang := string(src[2:end])
	shebang = strings.TrimSpace(shebang)

	// Handle #!/usr/bin/env bash (or #!/usr/bin/env -S bash ...)
	parts := strings.Fields(shebang)
	for i, p := range parts {
		if filepath.Base(p) == "env" && i+1 < len(parts) {
			// Skip env flags (e.g. -S)
			for j := i + 1; j < len(parts); j++ {
				if !strings.HasPrefix(parts[j], "-") {
					return filepath.Base(parts[j])
				}
			}
		}
	}

	return filepath.Base(parts[0])
}

// buildScript prepends the strict-mode preamble after the shebang (if present).
func buildScript(src []byte, strictMode bool) []byte {
	if !strictMode {
		return src
	}

	preamble := []byte("set -euo pipefail\n")

	// If script starts with a shebang, insert preamble after the first line.
	if bytes.HasPrefix(src, []byte("#!")) {
		nl := bytes.IndexByte(src, '\n')
		if nl >= 0 {
			var buf bytes.Buffer
			buf.Write(src[:nl+1])
			buf.Write(preamble)
			buf.Write(src[nl+1:])
			return buf.Bytes()
		}
	}

	var buf bytes.Buffer
	buf.Write(preamble)
	buf.Write(src)
	return buf.Bytes()
}

// writeTempScript writes content to a secure temp file and returns its path.
func writeTempScript(content []byte) (string, error) {
	dir, err := os.MkdirTemp("", "safesh-*")
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}

// buildEnv constructs the environment for the child process.
func buildEnv(isolate bool, extra []string) []string {
	if !isolate {
		return os.Environ()
	}

	// Start with safe baseline from current environment
	var env []string
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := kv[:eq]
		if safeEnvVars[key] {
			env = append(env, kv)
		}
	}

	// Add explicitly requested passthrough vars
	for _, key := range extra {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}

	return env
}
