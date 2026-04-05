//go:build linux

package sandbox

import (
	"fmt"
	"os/exec"
)

// bwrapReadOnlyDirs are the host directories bind-mounted read-only inside the
// sandbox.  Only directories that actually exist on the host are included at
// runtime (see buildBwrapArgs).
var bwrapReadOnlyDirs = []string{
	"/usr", "/lib", "/lib64", "/bin", "/sbin",
}

// Detect returns the best available backend on this system.
// When cfg.Enabled is false it always returns BackendNone without error.
func Detect(cfg Config) (Backend, error) {
	if !cfg.Enabled {
		return BackendNone, nil
	}

	if path, err := exec.LookPath("bwrap"); err == nil && path != "" {
		return BackendBwrap, nil
	}

	return BackendNone, &NotAvailableError{
		Reason: "bubblewrap (bwrap) not found in PATH; install it or remove --sandbox",
	}
}

// WrapCommand prepends the bwrap invocation to the given shell + script args.
// scriptPath must be an absolute path to the temp script file.
// Returns an error if cfg.Enabled is true but no backend is available.
func WrapCommand(shell, scriptPath string, cfg Config) (bin string, args []string, err error) {
	backend, err := Detect(cfg)
	if err != nil {
		return "", nil, err
	}

	if backend == BackendNone {
		// No sandboxing — return the original command unchanged.
		return shell, []string{scriptPath}, nil
	}

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return "", nil, fmt.Errorf("bwrap disappeared from PATH: %w", err)
	}

	bwrapArgs := buildBwrapArgs(shell, scriptPath, cfg)
	return bwrapPath, bwrapArgs, nil
}

// buildBwrapArgs constructs the argument list for bwrap.
func buildBwrapArgs(shell, scriptPath string, cfg Config) []string {
	args := []string{}

	// Read-only bind mounts for system directories.
	for _, dir := range bwrapReadOnlyDirs {
		args = append(args, "--ro-bind-try", dir, dir)
	}

	// /dev — needed for basic I/O (stdin/stdout/stderr pass-through).
	args = append(args, "--dev", "/dev")

	// Proc filesystem — many scripts rely on /proc.
	args = append(args, "--proc", "/proc")

	// Tmpfs on /tmp so the script has somewhere to write temporarily.
	args = append(args, "--tmpfs", "/tmp")

	// Bind the temp script file read-only so the shell can read it.
	// We bind the whole parent directory so the shell can resolve the path.
	args = append(args, "--ro-bind", scriptPath, scriptPath)

	// Block network access unless explicitly allowed.
	if !cfg.AllowNet {
		args = append(args, "--unshare-net")
	}

	// Unshare IPC, UTS, and PID namespaces for better isolation.
	args = append(args, "--unshare-ipc")
	args = append(args, "--unshare-uts")
	args = append(args, "--unshare-pid")

	// Die on parent death so the sandbox does not outlive safesh.
	args = append(args, "--die-with-parent")

	// Finally: the actual command to run inside the sandbox.
	args = append(args, "--", shell, scriptPath)

	return args
}
