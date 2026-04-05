// Package sandbox detects available sandboxing backends and builds
// the appropriate wrapper command for sandboxed script execution.
package sandbox

// Config holds the sandbox configuration requested by the caller.
type Config struct {
	// Enabled is true when --sandbox was passed.
	Enabled bool
	// AllowNet when true disables network isolation (i.e. does NOT pass
	// --unshare-net to bwrap).  Default is false → network is blocked.
	AllowNet bool
}

// Backend identifies the sandboxing mechanism that will be used.
type Backend string

const (
	// BackendNone means no sandboxing is active.
	BackendNone Backend = "none"
	// BackendBwrap uses bubblewrap (bwrap) for sandboxing.
	BackendBwrap Backend = "bwrap"
)

// NotAvailableError is returned when --sandbox is requested but no
// supported backend can be found.
type NotAvailableError struct {
	Reason string
}

func (e *NotAvailableError) Error() string {
	return "sandbox not available: " + e.Reason
}
