package modules

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/adeshmukh/safesh/internal/finding"
)

// Obfuscation flags patterns that hide what the script does.
type Obfuscation struct{}

func (Obfuscation) Analyze(src []byte) []finding.Finding {
	f, err := parse(src)
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	syntax.Walk(f, func(node syntax.Node) bool {
		switch v := node.(type) {
		case *syntax.CallExpr:
			if len(v.Args) == 0 {
				return true
			}
			cmd := wordLiteral(v.Args[0])

			// Direct eval invocation
			if cmd == "eval" {
				pos := v.Args[0].Pos()
				findings = append(findings, finding.Finding{
					Category:    finding.CategoryObfuscation,
					Line:        int(pos.Line()),
					Col:         int(pos.Col()),
					Description: "uses eval",
					Snippet:     lineSnippet(src, int(pos.Line())),
				})
			}

			// base64 decode piped to a shell (handled via pipe detection below)
			if cmd == "base64" {
				args := callArgs(v)
				for _, a := range args[1:] {
					if a == "-d" || a == "--decode" || a == "-D" {
						pos := v.Args[0].Pos()
						findings = append(findings, finding.Finding{
							Category:    finding.CategoryObfuscation,
							Line:        int(pos.Line()),
							Col:         int(pos.Col()),
							Description: "decodes base64 (check if result is executed)",
							Snippet:     lineSnippet(src, int(pos.Line())),
						})
						break
					}
				}
			}

		case *syntax.BinaryCmd:
			// Detect base64 -d | bash pattern
			if v.Op != syntax.Pipe {
				return true
			}
			leftCmd := stmtCmdName(v.X)
			rightCmd := stmtCmdName(v.Y)
			if strings.HasPrefix(leftCmd, "base64") && knownShells[rightCmd] {
				pos := v.Pos()
				findings = append(findings, finding.Finding{
					Category:    finding.CategoryObfuscation,
					Line:        int(pos.Line()),
					Col:         int(pos.Col()),
					Description: "pipes base64-decoded content to " + rightCmd,
					Snippet:     lineSnippet(src, int(pos.Line())),
				})
			}
		}
		return true
	})

	return findings
}
