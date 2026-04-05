package modules

import (
	"mvdan.cc/sh/v3/syntax"

	"github.com/safesh/safesh/internal/finding"
)

// Privilege flags privilege escalation commands.
type Privilege struct{}

var privilegeCommands = map[string]bool{
	"sudo":    true,
	"su":      true,
	"pkexec":  true,
	"doas":    true,
	"runuser": true,
}

// Analyze reports privilege escalation commands found in src.
func (Privilege) Analyze(src []byte) []finding.Finding {
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
		if !privilegeCommands[cmd] {
			return true
		}
		pos := call.Args[0].Pos()
		findings = append(findings, finding.Finding{
			Category:    finding.CategoryPrivilege,
			Line:        int(pos.Line()),
			Col:         int(pos.Col()),
			Description: "invokes " + cmd,
			Snippet:     lineSnippet(src, int(pos.Line())),
		})
		return true
	})

	return findings
}
