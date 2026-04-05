package analyzer

import (
	"sort"
	"sync"

	"github.com/safesh/safesh/internal/analyzer/modules"
	"github.com/safesh/safesh/internal/finding"
)

// defaultModules is the set of modules run on every script.
var defaultModules = []finding.Module{
	modules.ExecutionIntegrity{},
	modules.Destructive{},
	modules.Privilege{},
	modules.Persistence{},
	modules.Network{},
	modules.Obfuscation{},
	modules.ExecutionChain{},
}

// Analyze runs all modules against src and returns sorted findings.
func Analyze(src []byte) []finding.Finding {
	return AnalyzeWith(src, defaultModules)
}

// AnalyzeWith runs the provided modules against src (used for testing).
func AnalyzeWith(src []byte, mods []finding.Module) []finding.Finding {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		combined []finding.Finding
	)

	for _, mod := range mods {
		wg.Add(1)
		go func(m finding.Module) {
			defer wg.Done()
			results := m.Analyze(src)
			if len(results) > 0 {
				mu.Lock()
				combined = append(combined, results...)
				mu.Unlock()
			}
		}(mod)
	}

	wg.Wait()

	sort.Slice(combined, func(i, j int) bool {
		if combined[i].Line != combined[j].Line {
			return combined[i].Line < combined[j].Line
		}
		return combined[i].Category < combined[j].Category
	})

	return combined
}

// FilterByCategories returns only findings whose category is in the keep set.
func FilterByCategories(findings []finding.Finding, keep []finding.Category) []finding.Finding {
	if len(keep) == 0 {
		return nil
	}
	set := make(map[finding.Category]bool, len(keep))
	for _, c := range keep {
		set[c] = true
	}
	var out []finding.Finding
	for _, f := range findings {
		if set[f.Category] {
			out = append(out, f)
		}
	}
	return out
}

// ExcludeCategories returns findings not in the exclude set.
func ExcludeCategories(findings []finding.Finding, exclude []finding.Category) []finding.Finding {
	if len(exclude) == 0 {
		return findings
	}
	set := make(map[finding.Category]bool, len(exclude))
	for _, c := range exclude {
		set[c] = true
	}
	var out []finding.Finding
	for _, f := range findings {
		if !set[f.Category] {
			out = append(out, f)
		}
	}
	return out
}
