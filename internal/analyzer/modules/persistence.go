package modules

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/adeshmukh/safesh/internal/finding"
)

// Persistence flags modifications that survive the current session.
type Persistence struct{}

// persistenceTargets are path fragments that indicate persistence.
var persistenceTargets = []string{
	".bashrc", ".zshrc", ".bash_profile", ".zprofile", ".profile",
	".bash_login", ".zlogin", ".config/fish/config.fish",
	"/etc/profile", "/etc/profile.d/", "/etc/environment",
	"/etc/bash.bashrc", "/etc/zsh/",
	"crontab", "/etc/cron", "/var/spool/cron",
	"systemctl enable", ".config/systemd", "/etc/systemd",
	".xinitrc", ".xprofile", ".config/autostart",
}

func (Persistence) Analyze(src []byte) []finding.Finding {
	f, err := parse(src)
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	syntax.Walk(f, func(node syntax.Node) bool {
		// Check redirects (>> ~/.bashrc)
		if redir, ok := node.(*syntax.Redirect); ok {
			if redir.Word != nil {
				target := wordString(redir.Word)
				if desc, matched := matchesPersistenceTarget(target); matched {
					pos := redir.Word.Pos()
					findings = append(findings, finding.Finding{
						Category:    finding.CategoryPersistence,
						Line:        int(pos.Line()),
						Col:         int(pos.Col()),
						Description: "writes to " + desc,
						Snippet:     lineSnippet(src, int(pos.Line())),
					})
				}
			}
			return true
		}

		// Check crontab invocations and systemctl enable
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		cmd := wordLiteral(call.Args[0])
		args := callArgs(call)
		argStr := strings.Join(args, " ")

		if cmd == "crontab" {
			pos := call.Args[0].Pos()
			findings = append(findings, finding.Finding{
				Category:    finding.CategoryPersistence,
				Line:        int(pos.Line()),
				Col:         int(pos.Col()),
				Description: "invokes crontab (may install cron job)",
				Snippet:     lineSnippet(src, int(pos.Line())),
			})
		}

		if cmd == "systemctl" && strings.Contains(argStr, "enable") {
			pos := call.Args[0].Pos()
			findings = append(findings, finding.Finding{
				Category:    finding.CategoryPersistence,
				Line:        int(pos.Line()),
				Col:         int(pos.Col()),
				Description: "enables systemd service (persists across reboots)",
				Snippet:     lineSnippet(src, int(pos.Line())),
			})
		}

		return true
	})

	return findings
}

func matchesPersistenceTarget(path string) (string, bool) {
	for _, target := range persistenceTargets {
		if strings.Contains(path, target) {
			return target, true
		}
	}
	return "", false
}
