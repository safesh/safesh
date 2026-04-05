// Package observer runs a shell script under strace and records what it
// actually does at the syscall level (files touched, network connections,
// processes spawned).  This is a Linux-only feature.
package observer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// EventKind classifies a dynamic observation event.
type EventKind string

const (
	// EventFile covers openat / creat / mkdir / unlink family.
	EventFile EventKind = "file"
	// EventNetwork covers connect() syscalls.
	EventNetwork EventKind = "network"
	// EventProcess covers execve() syscalls.
	EventProcess EventKind = "process"
)

// Event is a single observed syscall-level happening.
type Event struct {
	Kind      EventKind `json:"kind"`
	Syscall   string    `json:"syscall"`
	Detail    string    `json:"detail"`    // path, address, or command
	PID       int       `json:"pid"`
	Timestamp time.Time `json:"timestamp"`
}

// Observation is the result of a --observe run.
type Observation struct {
	Shell    string        `json:"shell"`
	Duration time.Duration `json:"duration_ms"` // stored as ms
	ExitCode int           `json:"exit_code"`
	Events   []Event       `json:"events"`
}

// Options controls how the observer runs the script.
type Options struct {
	Shell      string   // resolved shell path
	StrictMode bool     // prepend set -euo pipefail
	IsolateEnv bool
	ExtraEnvPassthrough []string
}

// Run executes src under strace and returns structured observations.
// It returns an error if strace is not found in PATH or if the strace
// process itself cannot be started (script exit codes are captured in
// Observation.ExitCode, not returned as errors).
func Run(src []byte, opts Options) (*Observation, error) {
	stracePath, err := exec.LookPath("strace")
	if err != nil {
		return nil, fmt.Errorf("strace not found in PATH: install strace to use --observe")
	}

	content := buildScript(src, opts.StrictMode)

	tmpDir, err := os.MkdirTemp("", "safesh-observe-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	scriptPath := filepath.Join(tmpDir, "script.sh")
	if err := os.WriteFile(scriptPath, content, 0o600); err != nil {
		return nil, fmt.Errorf("writing temp script: %w", err)
	}

	straceLog := filepath.Join(tmpDir, "strace.log")

	// -f   follow forks
	// -tt  timestamps (microsecond precision) – gives us per-event time
	// -e   only trace the syscalls we care about
	// -o   write to file (avoids interleaving with script stdout/stderr)
	straceArgs := []string{
		"-f",
		"-tt",
		"-e", "trace=openat,open,creat,unlink,unlinkat,mkdir,mkdirat,connect,execve",
		"-o", straceLog,
		opts.Shell,
		scriptPath,
	}

	cmd := exec.Command(stracePath, straceArgs...) //nolint:gosec
	cmd.Env = buildEnv(opts.IsolateEnv, opts.ExtraEnvPassthrough)
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("running strace: %w", runErr)
		}
	}

	// Parse strace output
	logData, err := os.ReadFile(straceLog)
	if err != nil {
		return nil, fmt.Errorf("reading strace log: %w", err)
	}

	events := ParseStraceLog(logData, scriptPath)

	return &Observation{
		Shell:    opts.Shell,
		Duration: duration,
		ExitCode: exitCode,
		Events:   events,
	}, nil
}

// HasStrace reports whether strace is available in PATH.
func HasStrace() bool {
	_, err := exec.LookPath("strace")
	return err == nil
}
