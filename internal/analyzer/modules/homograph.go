package modules

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"

	"github.com/safesh/safesh/internal/finding"
)

// Homograph flags Unicode hazards that hide what a script does:
//   - bidi override / isolate controls (RLO, LRO, PDF, FSI…)
//   - zero-width characters (ZWSP, ZWJ, ZWNJ, BOM, WJ)
//   - non-ASCII or mixed-script URL hostnames (IDN homograph)
//
// The check is intentionally conservative: legitimate shell scripts targeting
// curl|bash installs are virtually always pure ASCII, so any non-ASCII content
// in a URL host or any bidi/zero-width control is treated as a finding.
type Homograph struct{}

// bidiControls are formatting characters that can reorder rendered text.
// Code that contains these may render very differently from how it executes.
// Numeric rune constants are used so this file itself stays pure ASCII —
// embedding the literal characters would trip the same check we are running.
var bidiControls = map[rune]string{
	0x202A: "LRE (left-to-right embedding)",
	0x202B: "RLE (right-to-left embedding)",
	0x202C: "PDF (pop directional formatting)",
	0x202D: "LRO (left-to-right override)",
	0x202E: "RLO (right-to-left override)",
	0x2066: "LRI (left-to-right isolate)",
	0x2067: "RLI (right-to-left isolate)",
	0x2068: "FSI (first strong isolate)",
	0x2069: "PDI (pop directional isolate)",
}

// zeroWidthControls are invisible characters that can hide content or splice
// identifiers (e.g. `cu<ZWJ>rl` to bypass naive string matches).
var zeroWidthControls = map[rune]string{
	0x200B: "ZWSP (zero-width space)",
	0x200C: "ZWNJ (zero-width non-joiner)",
	0x200D: "ZWJ (zero-width joiner)",
	0x2060: "WJ (word joiner)",
	0xFEFF: "BOM/ZWNBSP",
}

// Analyze reports Unicode hazards found in src.
func (Homograph) Analyze(src []byte) []finding.Finding {
	var findings []finding.Finding

	findings = append(findings, scanInvisible(src)...)

	f, err := parse(src)
	if err != nil {
		return findings
	}

	syntax.Walk(f, func(node syntax.Node) bool {
		word, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		s := wordLiteral(word)
		if s == "" {
			return true
		}
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			return true
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return true
		}
		if hf := analyzeHost(u.Host, word.Pos(), src); hf != nil {
			findings = append(findings, *hf)
		}
		return true
	})

	return findings
}

// scanInvisible walks src byte-by-byte and reports every bidi or zero-width
// control character. Each occurrence is its own finding because position
// matters — the same character on different lines can be doing different jobs.
func scanInvisible(src []byte) []finding.Finding {
	var findings []finding.Finding
	line := 1
	col := 1
	for i := 0; i < len(src); {
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			col++
			continue
		}
		if r == '\n' {
			line++
			col = 1
			i += size
			continue
		}
		if name, ok := bidiControls[r]; ok {
			findings = append(findings, finding.Finding{
				Category:    finding.CategoryHomograph,
				Line:        line,
				Col:         col,
				Description: fmt.Sprintf("bidi control character U+%04X %s — rendered text may not match executed text", r, name),
				Snippet:     lineSnippet(src, line),
			})
		} else if name, ok := zeroWidthControls[r]; ok {
			findings = append(findings, finding.Finding{
				Category:    finding.CategoryHomograph,
				Line:        line,
				Col:         col,
				Description: fmt.Sprintf("zero-width character U+%04X %s — invisible content", r, name),
				Snippet:     lineSnippet(src, line),
			})
		}
		i += size
		col++
	}
	return findings
}

// analyzeHost flags URL hosts containing non-ASCII characters (potential IDN
// homograph) or mixing scripts within a single label.
func analyzeHost(host string, pos syntax.Pos, src []byte) *finding.Finding {
	hostname := host
	if i := strings.LastIndex(hostname, ":"); i >= 0 {
		hostname = hostname[:i]
	}
	if hostname == "" || isASCII(hostname) {
		return nil
	}

	mixed := mixedScriptLabel(hostname)
	desc := fmt.Sprintf("URL host %q contains non-ASCII characters — possible IDN homograph", hostname)
	if mixed != "" {
		desc = fmt.Sprintf("URL host %q mixes scripts in label %q — likely IDN homograph", hostname, mixed)
	}
	return &finding.Finding{
		Category:    finding.CategoryHomograph,
		Line:        int(pos.Line()),
		Col:         int(pos.Col()),
		Description: desc,
		Snippet:     lineSnippet(src, int(pos.Line())),
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// mixedScriptLabel returns the first dot-separated label that contains
// characters from more than one Unicode script (e.g. Latin + Cyrillic).
// Returns "" if no label mixes scripts.
//
// Common digits, hyphens and U+00B7 are ignored for the script test.
func mixedScriptLabel(host string) string {
	for _, label := range strings.Split(host, ".") {
		if labelHasMixedScripts(label) {
			return label
		}
	}
	return ""
}

func labelHasMixedScripts(label string) bool {
	scripts := map[string]bool{}
	for _, r := range label {
		s := scriptOf(r)
		if s == "" {
			continue
		}
		scripts[s] = true
		if len(scripts) > 1 {
			return true
		}
	}
	return false
}

// scriptOf returns a coarse script bucket for r, or "" for runes that don't
// participate in the mixed-script test (digits, punctuation, etc.).
func scriptOf(r rune) string {
	switch {
	case r < 0x80:
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return "Latin"
		}
		return ""
	case unicode.Is(unicode.Latin, r):
		return "Latin"
	case unicode.Is(unicode.Cyrillic, r):
		return "Cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "Greek"
	case unicode.Is(unicode.Han, r):
		return "Han"
	case unicode.Is(unicode.Hangul, r):
		return "Hangul"
	case unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r):
		return "Japanese"
	case unicode.Is(unicode.Arabic, r):
		return "Arabic"
	case unicode.Is(unicode.Hebrew, r):
		return "Hebrew"
	}
	return ""
}
