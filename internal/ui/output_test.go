package ui

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safesh/safesh/internal/finding"
	"github.com/safesh/safesh/internal/integrity"
)

func TestPrintFindings_Empty(t *testing.T) {
	var buf bytes.Buffer
	PrintFindings(&buf, nil, false)
	assert.Contains(t, buf.String(), "no findings")
}

func TestPrintFindings_WithFindings(t *testing.T) {
	findings := []finding.Finding{
		{Category: finding.CategoryPrivilege, Line: 5, Description: "invokes sudo", Snippet: "sudo apt-get install -y curl"},
		{Category: finding.CategoryNetwork, Line: 12, Description: "invokes curl → example.com"},
	}
	var buf bytes.Buffer
	PrintFindings(&buf, findings, false)
	out := buf.String()
	assert.Contains(t, out, "2 findings")
	assert.Contains(t, out, "privilege")
	assert.Contains(t, out, "invokes sudo")
	assert.Contains(t, out, "sudo apt-get install -y curl")
	assert.Contains(t, out, "network")
	assert.Contains(t, out, "example.com")
	assert.NotContains(t, out, "[privilege]")
	assert.NotContains(t, out, "[network]")
}

func TestPrintFindings_LineZero(t *testing.T) {
	findings := []finding.Finding{
		{Category: finding.CategoryExecutionIntegrity, Line: 0, Description: "missing set -e"},
	}
	var buf bytes.Buffer
	PrintFindings(&buf, findings, false)
	assert.Contains(t, buf.String(), "missing set -e")
}

func TestPrintFetchBanner_NoIntegrity(t *testing.T) {
	var buf bytes.Buffer
	PrintFetchBanner(&buf, 2457, nil, false)
	assert.Contains(t, buf.String(), "safesh fetched 2.4 KB")
	assert.NotContains(t, buf.String(), "sha256")
}

func TestPrintFetchBanner_Verified(t *testing.T) {
	var buf bytes.Buffer
	ir := &integrity.Result{Checked: true, Verified: true, ChecksumSource: "sidecar"}
	PrintFetchBanner(&buf, 1024, ir, false)
	out := buf.String()
	assert.Contains(t, out, "1.0 KB")
	assert.Contains(t, out, "sha256 verified")
}

func TestPrintFetchBanner_Failed(t *testing.T) {
	var buf bytes.Buffer
	ir := &integrity.Result{Checked: true, Verified: false, ExpectedHash: "abc", ActualHash: "xyz"}
	PrintFetchBanner(&buf, 512, ir, false)
	assert.Contains(t, buf.String(), "sha256 FAILED")
}

func TestPrintSuccess_Normal(t *testing.T) {
	var buf bytes.Buffer
	PrintSuccess(&buf, 0, false, "/home/user/.local/share/safesh/history", false)
	out := buf.String()
	assert.Contains(t, out, "exited 0")
	assert.Contains(t, out, "history saved to")
}

func TestPrintSuccess_DryRun(t *testing.T) {
	var buf bytes.Buffer
	PrintSuccess(&buf, 0, true, "/home/user/.local/share/safesh/history", false)
	out := buf.String()
	assert.Contains(t, out, "dry-run complete")
	assert.Contains(t, out, "history saved to")
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hel...", truncate("hello world", 6))
}
