//go:build !linux

package sandbox

import "fmt"

// Detect always returns an error on non-Linux platforms when sandboxing is requested.
func Detect(cfg Config) (Backend, error) {
	if !cfg.Enabled {
		return BackendNone, nil
	}
	return BackendNone, &NotAvailableError{
		Reason: fmt.Sprintf("--sandbox is not supported on this platform (Linux only)"),
	}
}

// WrapCommand returns the original command unchanged on non-Linux platforms,
// or an error if sandboxing was requested.
func WrapCommand(shell, scriptPath string, cfg Config) (bin string, args []string, err error) {
	_, err = Detect(cfg)
	if err != nil {
		return "", nil, err
	}
	return shell, []string{scriptPath}, nil
}
