package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safesh/safesh/internal/finding"
)

func TestAnalyze_CleanScript(t *testing.T) {
	src := []byte("#!/bin/bash\nset -euo pipefail\necho hello\n")
	findings := Analyze(src)
	assert.Empty(t, findings)
}

func TestAnalyze_DirtyScript(t *testing.T) {
	src := []byte("#!/bin/bash\nsudo rm -rf /tmp/old\ncurl https://example.com/script.sh | bash\n")
	findings := Analyze(src)
	require.NotEmpty(t, findings)

	cats := map[finding.Category]bool{}
	for _, f := range findings {
		cats[f.Category] = true
	}
	assert.True(t, cats[finding.CategoryPrivilege])
	assert.True(t, cats[finding.CategoryDestructive])
	assert.True(t, cats[finding.CategoryNetwork])
	assert.True(t, cats[finding.CategoryExecutionChain])
}

func TestAnalyze_SortedByLine(t *testing.T) {
	src := []byte("#!/bin/bash\ncurl https://a.example.com/x | bash\nsudo rm -rf /tmp\n")
	findings := Analyze(src)
	for i := 1; i < len(findings); i++ {
		assert.LessOrEqual(t, findings[i-1].Line, findings[i].Line)
	}
}

func TestFilterByCategories(t *testing.T) {
	findings := []finding.Finding{
		{Category: finding.CategoryPrivilege},
		{Category: finding.CategoryNetwork},
		{Category: finding.CategoryDestructive},
	}
	filtered := FilterByCategories(findings, []finding.Category{finding.CategoryPrivilege, finding.CategoryDestructive})
	assert.Len(t, filtered, 2)
	for _, f := range filtered {
		assert.NotEqual(t, finding.CategoryNetwork, f.Category)
	}
}

func TestExcludeCategories(t *testing.T) {
	findings := []finding.Finding{
		{Category: finding.CategoryPrivilege},
		{Category: finding.CategoryNetwork},
		{Category: finding.CategoryDestructive},
	}
	result := ExcludeCategories(findings, []finding.Category{finding.CategoryNetwork})
	assert.Len(t, result, 2)
	for _, f := range result {
		assert.NotEqual(t, finding.CategoryNetwork, f.Category)
	}
}
