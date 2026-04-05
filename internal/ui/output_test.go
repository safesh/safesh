package ui

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safesh/safesh/internal/finding"
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
	assert.Contains(t, out, "[privilege]")
	assert.Contains(t, out, "invokes sudo")
	assert.Contains(t, out, "sudo apt-get install -y curl")
	assert.Contains(t, out, "[network]")
	assert.Contains(t, out, "example.com")
}

func TestPrintFindings_LineZero(t *testing.T) {
	findings := []finding.Finding{
		{Category: finding.CategoryExecutionIntegrity, Line: 0, Description: "missing set -e"},
	}
	var buf bytes.Buffer
	PrintFindings(&buf, findings, false)
	assert.Contains(t, buf.String(), "missing set -e")
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hel...", truncate("hello world", 6))
}
