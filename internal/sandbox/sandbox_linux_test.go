//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBwrapArgs_NetworkBlocked(t *testing.T) {
	args := buildBwrapArgs("/bin/bash", "/tmp/script.sh", Config{Enabled: true, AllowNet: false})

	// Network should be blocked
	assert.Contains(t, args, "--unshare-net")

	// Script must be bound
	assertContainsSequence(t, args, "--ro-bind", "/tmp/script.sh", "/tmp/script.sh")

	// Tmpfs on /tmp
	assertContainsSequence(t, args, "--tmpfs", "/tmp")

	// Command separator and actual command at the end
	cmdStart := indexOfStr(args, "--")
	require.NotEqual(t, -1, cmdStart, "expected -- separator in bwrap args")
	assert.Equal(t, "/bin/bash", args[cmdStart+1])
	assert.Equal(t, "/tmp/script.sh", args[cmdStart+2])
}

func TestBuildBwrapArgs_NetworkAllowed(t *testing.T) {
	args := buildBwrapArgs("/bin/bash", "/tmp/script.sh", Config{Enabled: true, AllowNet: true})
	assert.NotContains(t, args, "--unshare-net")
}

func TestBuildBwrapArgs_Shell(t *testing.T) {
	args := buildBwrapArgs("/usr/bin/zsh", "/tmp/myscript.sh", Config{Enabled: true})
	cmdStart := indexOfStr(args, "--")
	require.NotEqual(t, -1, cmdStart)
	assert.Equal(t, "/usr/bin/zsh", args[cmdStart+1])
	assert.Equal(t, "/tmp/myscript.sh", args[cmdStart+2])
}

func TestDetect_Enabled_BwrapAvailable(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available on this machine")
	}

	backend, err := Detect(Config{Enabled: true})
	assert.NoError(t, err)
	assert.Equal(t, BackendBwrap, backend)
}

func TestDetect_Enabled_BwrapUnavailable(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err == nil {
		t.Skip("bwrap IS available; cannot test unavailable path")
	}

	backend, err := Detect(Config{Enabled: true})
	assert.Error(t, err)
	assert.Equal(t, BackendNone, backend)

	var notAvail *NotAvailableError
	assert.ErrorAs(t, err, &notAvail)
}

func TestWrapCommand_Disabled(t *testing.T) {
	bin, args, err := WrapCommand("/bin/bash", "/tmp/script.sh", Config{Enabled: false})
	require.NoError(t, err)
	assert.Equal(t, "/bin/bash", bin)
	assert.Equal(t, []string{"/tmp/script.sh"}, args)
}

func TestWrapCommand_Enabled_BwrapAvailable(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available on this machine")
	}

	// Create a temporary script file so the bind path is real-ish
	f, err := os.CreateTemp("", "safesh-test-*.sh")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	require.NoError(t, f.Close())

	bin, args, err := WrapCommand("/bin/bash", f.Name(), Config{Enabled: true})
	require.NoError(t, err)
	assert.Contains(t, bin, "bwrap")
	assert.Contains(t, args, "--unshare-net")
}

// assertContainsSequence checks that needle appears as a contiguous subsequence of haystack.
func assertContainsSequence(t *testing.T, haystack []string, needle ...string) {
	t.Helper()
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j, n := range needle {
			if haystack[i+j] != n {
				match = false
				break
			}
		}
		if match {
			return
		}
	}
	t.Errorf("sequence %v not found in %v", needle, haystack)
}

// indexOfStr returns the index of the first occurrence of s in ss, or -1.
func indexOfStr(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}
