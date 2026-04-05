package observer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStraceLine_Openat(t *testing.T) {
	line := `1234   12:34:56.000001 openat(AT_FDCWD, "/tmp/foo.txt", O_WRONLY|O_CREAT, 0666) = 3`
	ev, ok := parseStraceLineWithScript(line, "/safe/script.sh")
	require.True(t, ok)
	assert.Equal(t, EventFile, ev.Kind)
	assert.Equal(t, "openat", ev.Syscall)
	assert.Equal(t, "/tmp/foo.txt", ev.Detail)
	assert.Equal(t, 1234, ev.PID)
}

func TestParseStraceLine_Execve(t *testing.T) {
	line := `5678   09:00:00.000001 execve("/usr/bin/curl", ["/usr/bin/curl", "-s", "https://example.com"], [/* env */]) = 0`
	ev, ok := parseStraceLineWithScript(line, "/safe/script.sh")
	require.True(t, ok)
	assert.Equal(t, EventProcess, ev.Kind)
	assert.Equal(t, "execve", ev.Syscall)
	assert.Equal(t, "/usr/bin/curl", ev.Detail)
}

func TestParseStraceLine_Connect_IPv4(t *testing.T) {
	line := `1234   12:34:56.000002 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0`
	ev, ok := parseStraceLineWithScript(line, "/safe/script.sh")
	require.True(t, ok)
	assert.Equal(t, EventNetwork, ev.Kind)
	assert.Equal(t, "connect", ev.Syscall)
	assert.Contains(t, ev.Detail, "93.184.216.34")
	assert.Contains(t, ev.Detail, "443")
}

func TestParseStraceLine_Unlink(t *testing.T) {
	line := `1234   12:34:56.000003 unlink("/tmp/something.txt") = 0`
	ev, ok := parseStraceLineWithScript(line, "/safe/script.sh")
	require.True(t, ok)
	assert.Equal(t, EventFile, ev.Kind)
	assert.Equal(t, "unlink", ev.Syscall)
	assert.Equal(t, "/tmp/something.txt", ev.Detail)
}

func TestParseStraceLine_SkipsScriptPath(t *testing.T) {
	scriptPath := "/tmp/safesh-observe-abc/script.sh"
	line := `1234   12:34:56.000001 openat(AT_FDCWD, "` + scriptPath + `", O_RDONLY) = 3`
	_, ok := parseStraceLineWithScript(line, scriptPath)
	assert.False(t, ok, "should skip the script's own path")
}

func TestParseStraceLine_SkipsNoisyPaths(t *testing.T) {
	line := `1234   12:34:56.000001 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY) = 3`
	_, ok := parseStraceLineWithScript(line, "/script.sh")
	assert.False(t, ok, "should skip libc and similar paths")
}

func TestParseStraceLine_UnfinishedSkipped(t *testing.T) {
	line := `1234   12:34:56.000001 openat(AT_FDCWD, "/tmp/foo" <unfinished ...>`
	_, ok := parseStraceLineWithScript(line, "/script.sh")
	assert.False(t, ok)
}

func TestParseStraceLine_InvalidLine(t *testing.T) {
	_, ok := parseStraceLineWithScript("", "/script.sh")
	assert.False(t, ok)

	_, ok = parseStraceLineWithScript("--- SIGTERM {si_signo=SIGTERM} ---", "/script.sh")
	assert.False(t, ok)
}

func TestParseStraceLog(t *testing.T) {
	log := []byte(`1234   12:34:56.000001 execve("/bin/bash", ["/bin/bash", "/tmp/script.sh"], [/* 3 vars */]) = 0
1234   12:34:56.000002 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
1234   12:34:56.000003 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY) = 3
1234   12:34:56.000004 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
1234   12:34:56.000005 unlink("/tmp/tempfile.txt") = 0
`)
	events := ParseStraceLog(log, "/tmp/script.sh")

	// Should have: execve(/bin/bash), openat(/etc/passwd), connect, unlink
	// Should NOT have: openat(/lib/... - noisy)
	assert.Len(t, events, 4)

	kinds := make(map[EventKind]int)
	for _, e := range events {
		kinds[e.Kind]++
	}
	assert.Equal(t, 2, kinds[EventFile])   // /etc/passwd + unlink
	assert.Equal(t, 1, kinds[EventNetwork])
	assert.Equal(t, 1, kinds[EventProcess])
}

func TestExtractFirstStringArg(t *testing.T) {
	tests := []struct {
		expr string
		want string
	}{
		{`openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3`, "/etc/passwd"},
		{`execve("/bin/bash", [...]) = 0`, "/bin/bash"},
		{`connect(4, {sa_family=AF_UNIX, sun_path="/run/systemd/private/io.systemd.sysext"}, 34) = -1`, "/run/systemd/private/io.systemd.sysext"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, extractFirstStringArg(tt.expr), "expr: %s", tt.expr)
	}
}

func TestExtractConnectAddr_IPv4(t *testing.T) {
	expr := `connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0`
	assert.Equal(t, "93.184.216.34:443", extractConnectAddr(expr))
}

func TestExtractConnectAddr_UnixSocket(t *testing.T) {
	expr := `connect(3, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 30) = 0`
	assert.Equal(t, "unix:/run/dbus/system_bus_socket", extractConnectAddr(expr))
}

func TestHasStrace(t *testing.T) {
	// On a Linux CI environment strace should be present; we just assert no panic
	_ = HasStrace()
}
