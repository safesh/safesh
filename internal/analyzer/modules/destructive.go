package modules

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/safesh/safesh/internal/finding"
)

// Destructive flags irreversible filesystem operations.
type Destructive struct{}

// destructivePatterns maps commands to the flag patterns that make them dangerous.
var destructivePatterns = map[string][]string{
	"rm":       {"-r", "-f", "-rf", "-fr", "-Rf", "-fR"},
	"dd":       {},   // any dd invocation is flagged
	"mkfs":     {},   // any mkfs or mkfs.* invocation
	"shred":    {},
	"truncate": {"-s 0", "--size=0", "--size 0"},
}

// Analyze reports irreversible filesystem operations found in src.
func (Destructive) Analyze(src []byte) []finding.Finding {
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
		if cmd == "" {
			return true
		}

		allArgs := callArgs(call)

		// Skip past privilege-escalation wrappers (sudo, doas, etc.) to find the real command.
		offset := 0
		if privilegeCommands[cmd] && len(allArgs) > 1 {
			offset = 1
			// Skip flags like sudo -n, sudo -u user
			for offset < len(allArgs) && strings.HasPrefix(allArgs[offset], "-") {
				offset++
				if offset < len(allArgs) && !strings.HasPrefix(allArgs[offset], "-") {
					// consume option argument (e.g. -u <user>)
					if allArgs[offset-1] == "-u" || allArgs[offset-1] == "--user" {
						offset++
					}
				}
			}
			if offset >= len(allArgs) {
				return true
			}
			cmd = allArgs[offset]
			offset++ // advance past the real command
		}

		// Handle mkfs.ext4 etc.
		basecmd := cmd
		if idx := strings.Index(cmd, "."); idx > 0 {
			basecmd = cmd[:idx]
		}

		flagPatterns, known := destructivePatterns[basecmd]
		if !known {
			return true
		}

		args := allArgs[offset:]
		argStr := strings.Join(args, " ")

		// dd and mkfs are always flagged
		if basecmd == "dd" || basecmd == "mkfs" || basecmd == "shred" {
			pos := call.Args[0].Pos()
			findings = append(findings, finding.Finding{
				Category:    finding.CategoryDestructive,
				Line:        int(pos.Line()),
				Col:         int(pos.Col()),
				Description: "invokes " + cmd,
				Snippet:     lineSnippet(src, int(pos.Line())),
			})
			return true
		}

		// For rm and truncate, only flag if dangerous flags are present
		for _, pattern := range flagPatterns {
			if strings.Contains(argStr, pattern) {
				pos := call.Args[0].Pos()
				findings = append(findings, finding.Finding{
					Category:    finding.CategoryDestructive,
					Line:        int(pos.Line()),
					Col:         int(pos.Col()),
					Description: "invokes " + cmd + " " + pattern,
					Snippet:     lineSnippet(src, int(pos.Line())),
				})
				return true
			}
		}
		return true
	})

	return findings
}
