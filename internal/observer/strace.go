package observer

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"time"
)

// ParseStraceLog parses the output of strace -f -tt -o <file> and returns
// typed events.  scriptPath is filtered out of file-open events so we don't
// report the script reading itself as a suspicious finding.
//
// strace -tt line format:
//
//	<pid>  HH:MM:SS.ffffff syscall(args...) = retval
//
// Example lines:
//
//	1234   12:34:56.000001 execve("/bin/bash", ["/bin/bash", "/tmp/safesh-observe-xyz/script.sh"], [...]) = 0
//	1234   12:34:56.000002 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
//	1234   12:34:56.000003 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
func ParseStraceLog(data []byte, scriptPath string) []Event {
	var events []Event

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		ev, ok := parseStraceLineWithScript(line, scriptPath)
		if ok {
			events = append(events, ev)
		}
	}

	return events
}

// parseStraceLineWithScript parses one strace log line and returns an Event if
// it is a syscall of interest.
func parseStraceLineWithScript(line, scriptPath string) (Event, bool) {
	// Trim leading whitespace / continuation markers
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
		return Event{}, false
	}

	// Parse: pid  timestamp syscall(...)  = retval
	// pid field
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return Event{}, false
	}

	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return Event{}, false
	}

	// timestamp field (HH:MM:SS.ffffff)
	tsStr := fields[1]
	ts := parseTimestamp(tsStr)

	// rest is the syscall expression
	rest := strings.Join(fields[2:], " ")

	// find syscall name (everything before the first '(')
	parenIdx := strings.IndexByte(rest, '(')
	if parenIdx < 0 {
		return Event{}, false
	}
	syscallName := strings.TrimSpace(rest[:parenIdx])

	// Strip trailing " <unfinished ...>" or "<... syscall resumed>" markers
	if strings.Contains(rest, "<unfinished") || strings.HasPrefix(rest, "<...") {
		return Event{}, false
	}

	// Check return value — skip failed calls (retval == -1 or negative)
	// We still want to record them for visibility, so we don't skip them.

	switch {
	case isFileOpen(syscallName):
		detail := extractFirstStringArg(rest)
		if detail == "" || detail == scriptPath {
			return Event{}, false
		}
		// Skip internal kernel / linker paths that are noise
		if isNoisyPath(detail) {
			return Event{}, false
		}
		return Event{
			Kind:      EventFile,
			Syscall:   syscallName,
			Detail:    detail,
			PID:       pid,
			Timestamp: ts,
		}, true

	case isFileDestructive(syscallName):
		detail := extractFirstStringArg(rest)
		if detail == "" {
			return Event{}, false
		}
		return Event{
			Kind:      EventFile,
			Syscall:   syscallName,
			Detail:    detail,
			PID:       pid,
			Timestamp: ts,
		}, true

	case syscallName == "connect":
		detail := extractConnectAddr(rest)
		if detail == "" {
			return Event{}, false
		}
		return Event{
			Kind:      EventNetwork,
			Syscall:   "connect",
			Detail:    detail,
			PID:       pid,
			Timestamp: ts,
		}, true

	case syscallName == "execve":
		detail := extractFirstStringArg(rest)
		if detail == "" {
			return Event{}, false
		}
		return Event{
			Kind:      EventProcess,
			Syscall:   "execve",
			Detail:    detail,
			PID:       pid,
			Timestamp: ts,
		}, true
	}

	return Event{}, false
}

// isFileOpen returns true for syscalls that open / create files or directories.
func isFileOpen(name string) bool {
	switch name {
	case "open", "openat", "creat", "mkdir", "mkdirat":
		return true
	}
	return false
}

// isFileDestructive returns true for syscalls that delete files.
func isFileDestructive(name string) bool {
	switch name {
	case "unlink", "unlinkat":
		return true
	}
	return false
}

// isNoisyPath returns true for paths that are kernel / linker internals and
// would produce noise in the output.
func isNoisyPath(p string) bool {
	noisy := []string{
		"/proc/", "/sys/", "/dev/",
		"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
		"/usr/share/locale/",
		"/etc/ld.so", "/etc/nsswitch.conf", "/etc/resolv.conf",
		"/etc/hosts",
	}
	for _, prefix := range noisy {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// extractFirstStringArg extracts the first double-quoted string argument from
// a strace syscall expression like:  openat(AT_FDCWD, "/etc/passwd", O_RDONLY)
func extractFirstStringArg(expr string) string {
	start := strings.IndexByte(expr, '"')
	if start < 0 {
		return ""
	}
	// find closing quote — handle \" escapes
	for i := start + 1; i < len(expr); i++ {
		if expr[i] == '\\' {
			i++ // skip escaped char
			continue
		}
		if expr[i] == '"' {
			raw := expr[start+1 : i]
			return unescapeStrace(raw)
		}
	}
	return ""
}

// extractConnectAddr extracts a human-readable address string from a strace
// connect() line.  It looks for:
//   - sin_addr=inet_addr("...") for IPv4
//   - sin6_addr=inet_pton(..., "...") for IPv6
//   - sun_path="..." for Unix domain sockets
func extractConnectAddr(expr string) string {
	// Unix socket — sa_family=AF_UNIX
	if strings.Contains(expr, "AF_UNIX") || strings.Contains(expr, "AF_LOCAL") {
		if p := extractNamedField(expr, "sun_path"); p != "" {
			return "unix:" + p
		}
		return ""
	}

	// IPv4
	if strings.Contains(expr, "AF_INET,") || strings.Contains(expr, "AF_INET}") ||
		strings.Contains(expr, "sin_addr") {
		addr := extractNamedField(expr, "sin_addr=inet_addr")
		port := extractPortHtons(expr)
		if addr != "" {
			if port != "" {
				return addr + ":" + port
			}
			return addr
		}
	}

	// IPv6
	if strings.Contains(expr, "AF_INET6") {
		addr := extractNamedField(expr, "sin6_addr=inet_pton")
		if addr == "" {
			addr = extractNamedField(expr, "sin6_addr")
		}
		port := extractPortHtons(expr)
		if addr != "" {
			if port != "" {
				return "[" + addr + "]:" + port
			}
			return addr
		}
	}

	return ""
}

// extractNamedField extracts the quoted string value immediately after
// `name(` or `name="`.  For example:
//
//	sin_addr=inet_addr("1.2.3.4")  →  "1.2.3.4"
//	sun_path="/tmp/foo"             →  "/tmp/foo"
func extractNamedField(expr, name string) string {
	idx := strings.Index(expr, name)
	if idx < 0 {
		return ""
	}
	rest := expr[idx+len(name):]
	// skip '(' or '='
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '(' || rest[0] == '=' {
		rest = rest[1:]
	}
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := strings.IndexByte(rest[1:], '"')
	if end < 0 {
		return ""
	}
	return rest[1 : end+1]
}

// extractPortHtons extracts the port number from sin_port=htons(NNN).
func extractPortHtons(expr string) string {
	const marker = "sin_port=htons("
	idx := strings.Index(expr, marker)
	if idx < 0 {
		return ""
	}
	rest := expr[idx+len(marker):]
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// unescapeStrace turns common strace string escape sequences back to their
// printable form.  It only handles the common cases (\n, \t, \\, \").
func unescapeStrace(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	return s
}

// parseTimestamp parses the HH:MM:SS.ffffff timestamp from strace -tt output.
// Returns zero time on failure.
func parseTimestamp(s string) time.Time {
	t, err := time.Parse("15:04:05.000000", s)
	if err != nil {
		return time.Time{}
	}
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(),
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.Local)
}
