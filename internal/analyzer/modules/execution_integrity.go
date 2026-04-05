// Package modules contains individual analysis modules for safesh.
package modules

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/adeshmukh/safesh/internal/finding"
)

// ExecutionIntegrity checks for missing strict-mode flags.
type ExecutionIntegrity struct{}

func (ExecutionIntegrity) Analyze(src []byte) []finding.Finding {
	f, err := parse(src)
	if err != nil {
		return nil
	}

	hasE, hasU, hasPipefail := false, false, false

	syntax.Walk(f, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		args := callArgs(call)
		if len(args) == 0 || args[0] != "set" {
			return true
		}
		e, u, p := parseSetFlags(args[1:])
		if e {
			hasE = true
		}
		if u {
			hasU = true
		}
		if p {
			hasPipefail = true
		}
		return true
	})

	var findings []finding.Finding
	if !hasE {
		findings = append(findings, finding.Finding{
			Category:    finding.CategoryExecutionIntegrity,
			Description: "missing set -e",
		})
	}
	if !hasU {
		findings = append(findings, finding.Finding{
			Category:    finding.CategoryExecutionIntegrity,
			Description: "missing set -u",
		})
	}
	if !hasPipefail {
		findings = append(findings, finding.Finding{
			Category:    finding.CategoryExecutionIntegrity,
			Description: "missing set -o pipefail",
		})
	}
	return findings
}

// parseSetFlags returns which safety flags are present in the arguments of a `set` call.
// args should be the arguments after "set" itself.
func parseSetFlags(args []string) (hasE, hasU, hasPipefail bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-o" {
			if i+1 < len(args) && args[i+1] == "pipefail" {
				hasPipefail = true
				i++
			}
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		flags := arg[1:]
		for j, c := range flags {
			switch c {
			case 'e':
				hasE = true
			case 'u':
				hasU = true
			case 'o':
				// -o takes the next token as value, either as next arg or rest of this arg
				rest := flags[j+1:]
				if rest == "pipefail" {
					hasPipefail = true
				} else if rest == "" && i+1 < len(args) && args[i+1] == "pipefail" {
					hasPipefail = true
					i++
				}
				goto nextArg
			}
		}
	nextArg:
	}
	return
}
