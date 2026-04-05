package modules

import (
	"net/url"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/safesh/safesh/internal/finding"
)

// Network flags outbound network calls and extracts destination domains.
type Network struct{}

var networkCommands = map[string]bool{
	"curl":  true,
	"wget":  true,
	"fetch": true,
	"http":  true,
	"httpie": true,
}

func (Network) Analyze(src []byte) []finding.Finding {
	f, err := parse(src)
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	syntax.Walk(f, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		cmd := wordLiteral(call.Args[0])
		if !networkCommands[cmd] {
			return true
		}

		pos := call.Args[0].Pos()
		args := call.Args[1:]

		// Try to find URL arguments
		domains := extractDomains(args)
		desc := "invokes " + cmd
		if len(domains) > 0 {
			desc += " → " + strings.Join(domains, ", ")
		} else {
			desc += " (destination unresolvable — uses dynamic URL)"
		}

		findings = append(findings, finding.Finding{
			Category:    finding.CategoryNetwork,
			Line:        int(pos.Line()),
			Col:         int(pos.Col()),
			Description: desc,
			Snippet:     lineSnippet(src, int(pos.Line())),
		})
		return true
	})

	return findings
}

func extractDomains(words []*syntax.Word) []string {
	seen := map[string]bool{}
	var domains []string
	for _, w := range words {
		s := wordLiteral(w)
		if s == "" {
			continue
		}
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			continue
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			continue
		}
		if !seen[u.Host] {
			seen[u.Host] = true
			domains = append(domains, u.Host)
		}
	}
	return domains
}
