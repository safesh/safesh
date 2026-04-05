package modules

import (
	"bytes"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// parse parses shell source into an AST file.
func parse(src []byte) (*syntax.File, error) {
	parser := syntax.NewParser(syntax.KeepComments(false))
	return parser.Parse(bytes.NewReader(src), "")
}

// callArgs extracts the string arguments of a CallExpr.
// Non-literal arguments are included as empty strings to preserve index positions.
func callArgs(call *syntax.CallExpr) []string {
	var args []string
	for _, word := range call.Args {
		if s := wordLiteral(word); s != "" {
			args = append(args, s)
		} else {
			args = append(args, "")
		}
	}
	return args
}

// wordLiteral returns the string value of a word if it consists entirely of literals.
func wordLiteral(word *syntax.Word) string {
	var b strings.Builder
	for _, part := range word.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return ""
		}
		b.WriteString(lit.Value)
	}
	return b.String()
}

// wordString returns a best-effort string representation of a word,
// rendering non-literal parts as "<expr>".
func wordString(word *syntax.Word) string {
	var b strings.Builder
	for _, part := range word.Parts {
		switch v := part.(type) {
		case *syntax.Lit:
			b.WriteString(v.Value)
		default:
			b.WriteString("<expr>")
		}
	}
	return b.String()
}

// lineSnippet returns up to maxLen characters of the source line at the given 1-based line number.
func lineSnippet(src []byte, line int) string {
	const maxLen = 100
	lines := bytes.Split(src, []byte("\n"))
	if line < 1 || line > len(lines) {
		return ""
	}
	s := strings.TrimSpace(string(lines[line-1]))
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return s
}

// stmtCmdName returns the command name of the first CallExpr in a *Stmt, best-effort.
func stmtCmdName(stmt *syntax.Stmt) string {
	if stmt == nil {
		return ""
	}
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
		return wordLiteral(call.Args[0])
	}
	return ""
}

// knownShells is the set of shell binary names safesh recognises.
var knownShells = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"fish": true, "ksh": true, "mksh": true,
}
