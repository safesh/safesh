package modules

import (
	"mvdan.cc/sh/v3/syntax"

	"github.com/safesh/safesh/internal/finding"
)

// ExecutionChain flags nested pipe-to-shell patterns inside the script.
type ExecutionChain struct{}

// Analyze reports nested pipe-to-shell patterns found in src.
func (ExecutionChain) Analyze(src []byte) []finding.Finding {
	f, err := parse(src)
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	syntax.Walk(f, func(node syntax.Node) bool {
		bin, ok := node.(*syntax.BinaryCmd)
		if !ok || bin.Op != syntax.Pipe {
			return true
		}

		rightShell := pipeRightShell(bin)
		if rightShell == "" {
			return true
		}

		leftCmd := stmtCmdName(bin.X)
		pos := bin.Pos()

		desc := "pipes to " + rightShell + " internally"
		if leftCmd != "" {
			desc = leftCmd + " | " + rightShell + " (nested pipe-to-shell)"
		}

		findings = append(findings, finding.Finding{
			Category:    finding.CategoryExecutionChain,
			Line:        int(pos.Line()),
			Col:         int(pos.Col()),
			Description: desc,
			Snippet:     lineSnippet(src, int(pos.Line())),
		})
		return true
	})

	return findings
}

// pipeRightShell returns the shell name if the right side of a pipe is a known shell.
func pipeRightShell(bin *syntax.BinaryCmd) string {
	cmd := stmtCmdName(bin.Y)
	if knownShells[cmd] {
		return cmd
	}
	return ""
}
