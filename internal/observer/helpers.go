package observer

import (
	"bytes"
	"os"
	"strings"
)

// safeEnvVars mirrors executor.safeEnvVars: the baseline for isolated execution.
var safeEnvVars = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true,
	"SHELL": true, "TERM": true, "LANG": true, "LC_ALL": true,
	"TMPDIR": true,
}

// buildScript mirrors executor.buildScript: prepend strict-mode preamble.
func buildScript(src []byte, strictMode bool) []byte {
	if !strictMode {
		return src
	}

	preamble := []byte("set -euo pipefail\n")

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

// buildEnv mirrors executor.buildEnv.
func buildEnv(isolate bool, extra []string) []string {
	if !isolate {
		return os.Environ()
	}

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

	for _, key := range extra {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}

	return env
}
