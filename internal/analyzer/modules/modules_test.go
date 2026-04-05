package modules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safesh/safesh/internal/finding"
)

func findingsOfCategory(findings []finding.Finding, cat finding.Category) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if f.Category == cat {
			out = append(out, f)
		}
	}
	return out
}

// ── ExecutionIntegrity ────────────────────────────────────────────────────────

func TestExecutionIntegrity_MissingAll(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	findings := ExecutionIntegrity{}.Analyze(src)
	assert.Len(t, findings, 3, "should flag missing set -e, -u, pipefail")
}

func TestExecutionIntegrity_HasAll(t *testing.T) {
	src := []byte("#!/bin/bash\nset -euo pipefail\necho hello\n")
	findings := ExecutionIntegrity{}.Analyze(src)
	assert.Empty(t, findings)
}

func TestExecutionIntegrity_HasSome(t *testing.T) {
	src := []byte("#!/bin/bash\nset -e\nset -o pipefail\necho hello\n")
	findings := ExecutionIntegrity{}.Analyze(src)
	// Should still flag missing -u
	cats := make(map[string]int)
	for _, f := range findings {
		cats[f.Description]++
	}
	assert.Equal(t, 1, cats["missing set -u"])
}

func TestExecutionIntegrity_SetInsideFunction(t *testing.T) {
	// set -euo pipefail inside a function body must NOT suppress the finding;
	// the flags must appear at the top level to be effective for the whole script.
	src := []byte("#!/bin/bash\nmy_func() {\n  set -euo pipefail\n  echo inside\n}\necho hello\n")
	findings := ExecutionIntegrity{}.Analyze(src)
	assert.Len(t, findings, 3, "flags inside a function body should not count as top-level")
}

func TestExecutionIntegrity_SetInsideIf(t *testing.T) {
	// set -euo pipefail inside an if-clause must NOT suppress the finding.
	src := []byte("#!/bin/bash\nif true; then\n  set -euo pipefail\nfi\necho hello\n")
	findings := ExecutionIntegrity{}.Analyze(src)
	assert.Len(t, findings, 3, "flags inside an if-clause should not count as top-level")
}

func TestExecutionIntegrity_SetTopLevelAfterFunction(t *testing.T) {
	// set -euo pipefail at the top level is fine even when a function is also present.
	src := []byte("#!/bin/bash\nset -euo pipefail\nmy_func() {\n  echo inside\n}\necho hello\n")
	findings := ExecutionIntegrity{}.Analyze(src)
	assert.Empty(t, findings, "top-level set should suppress all findings")
}

// ── Destructive ───────────────────────────────────────────────────────────────

func TestDestructive_RmRf(t *testing.T) {
	src := []byte("#!/bin/bash\nrm -rf /tmp/mydir\n")
	findings := Destructive{}.Analyze(src)
	require.Len(t, findings, 1)
	assert.Equal(t, finding.CategoryDestructive, findings[0].Category)
	assert.Contains(t, findings[0].Description, "rm")
}

func TestDestructive_SafeRm(t *testing.T) {
	src := []byte("#!/bin/bash\nrm /tmp/file.txt\n")
	findings := Destructive{}.Analyze(src)
	assert.Empty(t, findings)
}

func TestDestructive_DD(t *testing.T) {
	src := []byte("#!/bin/bash\ndd if=/dev/zero of=/dev/sda bs=4M\n")
	findings := Destructive{}.Analyze(src)
	require.Len(t, findings, 1)
	assert.Equal(t, finding.CategoryDestructive, findings[0].Category)
}

func TestDestructive_Mkfs(t *testing.T) {
	src := []byte("#!/bin/bash\nmkfs.ext4 /dev/sdb1\n")
	findings := Destructive{}.Analyze(src)
	require.Len(t, findings, 1)
}

// ── Privilege ─────────────────────────────────────────────────────────────────

func TestPrivilege_Sudo(t *testing.T) {
	src := []byte("#!/bin/bash\nsudo apt-get install -y curl\n")
	findings := Privilege{}.Analyze(src)
	require.Len(t, findings, 1)
	assert.Equal(t, finding.CategoryPrivilege, findings[0].Category)
	assert.Equal(t, 2, findings[0].Line)
}

func TestPrivilege_None(t *testing.T) {
	src := []byte("#!/bin/bash\napt-get install -y curl\n")
	findings := Privilege{}.Analyze(src)
	assert.Empty(t, findings)
}

func TestPrivilege_Multiple(t *testing.T) {
	src := []byte("#!/bin/bash\nsudo foo\nsu -c bar\npkexec baz\n")
	findings := Privilege{}.Analyze(src)
	assert.Len(t, findings, 3)
}

// ── Persistence ───────────────────────────────────────────────────────────────

func TestPersistence_Bashrc(t *testing.T) {
	src := []byte("#!/bin/bash\necho 'export PATH=$PATH:/opt/tool' >> ~/.bashrc\n")
	findings := Persistence{}.Analyze(src)
	require.NotEmpty(t, findings)
	assert.Equal(t, finding.CategoryPersistence, findings[0].Category)
}

func TestPersistence_Crontab(t *testing.T) {
	src := []byte("#!/bin/bash\ncrontab -e\n")
	findings := Persistence{}.Analyze(src)
	require.NotEmpty(t, findings)
}

func TestPersistence_SystemctlEnable(t *testing.T) {
	src := []byte("#!/bin/bash\nsystemctl enable myservice\n")
	findings := Persistence{}.Analyze(src)
	require.NotEmpty(t, findings)
}

// ── Network ───────────────────────────────────────────────────────────────────

func TestNetwork_CurlWithURL(t *testing.T) {
	src := []byte("#!/bin/bash\ncurl -fsSL https://releases.example.com/tool.tar.gz -o tool.tar.gz\n")
	findings := Network{}.Analyze(src)
	require.Len(t, findings, 1)
	assert.Equal(t, finding.CategoryNetwork, findings[0].Category)
	assert.Contains(t, findings[0].Description, "releases.example.com")
}

func TestNetwork_CurlDynamic(t *testing.T) {
	src := []byte("#!/bin/bash\ncurl -fsSL \"$DOWNLOAD_URL\" -o file\n")
	findings := Network{}.Analyze(src)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "unresolvable")
}

func TestNetwork_NoNetwork(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\ntar xzf archive.tar.gz\n")
	findings := Network{}.Analyze(src)
	assert.Empty(t, findings)
}

// ── Obfuscation ───────────────────────────────────────────────────────────────

func TestObfuscation_Eval(t *testing.T) {
	src := []byte("#!/bin/bash\neval \"$(some_command)\"\n")
	findings := Obfuscation{}.Analyze(src)
	require.NotEmpty(t, findings)
	assert.Equal(t, finding.CategoryObfuscation, findings[0].Category)
}

func TestObfuscation_Base64Decode(t *testing.T) {
	src := []byte("#!/bin/bash\necho dGVzdA== | base64 -d | bash\n")
	findings := Obfuscation{}.Analyze(src)
	require.NotEmpty(t, findings)
	cats := findingsOfCategory(findings, finding.CategoryObfuscation)
	assert.NotEmpty(t, cats)
}

func TestObfuscation_Clean(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\ntar xzf foo.tar.gz\n")
	findings := Obfuscation{}.Analyze(src)
	assert.Empty(t, findings)
}

// ── ExecutionChain ────────────────────────────────────────────────────────────

func TestExecutionChain_CurlBash(t *testing.T) {
	src := []byte("#!/bin/bash\ncurl -fsSL https://example.com/setup.sh | bash\n")
	findings := ExecutionChain{}.Analyze(src)
	require.NotEmpty(t, findings)
	assert.Equal(t, finding.CategoryExecutionChain, findings[0].Category)
}

func TestExecutionChain_WgetSh(t *testing.T) {
	src := []byte("#!/bin/bash\nwget -qO- https://example.com/setup.sh | sh\n")
	findings := ExecutionChain{}.Analyze(src)
	require.NotEmpty(t, findings)
}

func TestExecutionChain_None(t *testing.T) {
	src := []byte("#!/bin/bash\ncurl -fsSL https://example.com/file -o /tmp/file\n")
	findings := ExecutionChain{}.Analyze(src)
	assert.Empty(t, findings)
}
