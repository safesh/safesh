// Package ui handles user-facing output and interactive prompts.
package ui

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/safesh/safesh/internal/finding"
	"github.com/safesh/safesh/internal/history"
	"github.com/safesh/safesh/internal/integrity"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// PrintFindings writes the findings report to w.
func PrintFindings(w io.Writer, findings []finding.Finding, useColor bool) {
	if len(findings) == 0 {
		fmt.Fprintln(w, tag(colorGreen, "✓", useColor)+" no findings")
		return
	}

	fmt.Fprintf(w, "\n%ssafesh findings:%s\n", bold(useColor), colorReset)

	// Group by category
	byCategory := make(map[finding.Category][]finding.Finding)
	for _, f := range findings {
		byCategory[f.Category] = append(byCategory[f.Category], f)
	}

	for _, cat := range finding.AllCategories {
		fs, ok := byCategory[cat]
		if !ok {
			continue
		}
		catLabel := fmt.Sprintf("[%s]", cat)
		for _, f := range fs {
			line := ""
			if f.Line > 0 {
				line = fmt.Sprintf("  line %-4d", f.Line)
			} else {
				line = "            "
			}
			fmt.Fprintf(w, "  %s%s  %s\n",
				tag(colorYellow, catLabel, useColor),
				line,
				f.Description,
			)
			if f.Snippet != "" {
				fmt.Fprintf(w, "              %s%s%s\n",
					dim(useColor), f.Snippet, colorReset)
			}
		}
	}
	fmt.Fprintln(w)
}

// PrintUnsuspiciousNotice writes the "unsuspicious ≠ safe" reminder.
func PrintUnsuspiciousNotice(w io.Writer, useColor bool) {
	fmt.Fprintf(w, "%snote:%s a script with no findings is unsuspicious, not safe\n",
		dim(useColor), colorReset)
}

// PrintIntegrityResult prints the integrity check result.
// r may be nil (no check was performed).
func PrintIntegrityResult(w io.Writer, r *integrity.Result, useColor bool) {
	if r == nil || !r.Checked {
		return
	}
	if r.Verified {
		label := tag(colorGreen, "✓ verified", useColor)
		src := ""
		if r.ChecksumSource != "" {
			src = fmt.Sprintf(" (source: %s)", r.ChecksumSource)
		}
		fmt.Fprintf(w, "Integrity: %s %s%s\n", label, r.ActualHash[:16]+"…", src)
	} else {
		label := tag(colorRed, "✗ FAILED", useColor)
		fmt.Fprintf(w, "Integrity: %s expected=%s got=%s\n", label, r.ExpectedHash, r.ActualHash)
	}
}

// PrintEntry prints a full history entry to w.
func PrintEntry(w io.Writer, e *history.Entry, useColor bool) {
	m := e.Meta
	sep := strings.Repeat("─", 60)

	fmt.Fprintf(w, "%sEntry:%s  %s\n", bold(useColor), colorReset, m.ID)
	fmt.Fprintf(w, "Date:    %s\n", m.Timestamp.Local().Format(time.DateTime))
	fmt.Fprintf(w, "Source:  %s\n", m.Source)
	fmt.Fprintf(w, "Shell:   %s\n", m.Shell)

	switch {
	case m.DryRun:
		fmt.Fprintf(w, "Mode:    %s\n", tag(colorCyan, "dry-run", useColor))
	case m.Aborted:
		fmt.Fprintf(w, "Mode:    %s\n", tag(colorYellow, "aborted", useColor))
	case e.Exit != nil:
		exitStr := fmt.Sprintf("exit %d", e.Exit.ExitCode)
		dur := fmt.Sprintf("%.1fs", float64(e.Exit.DurationMS)/1000)
		if e.Exit.ExitCode == 0 {
			fmt.Fprintf(w, "Exit:    %s (%s)\n", tag(colorGreen, exitStr, useColor), dur)
		} else {
			fmt.Fprintf(w, "Exit:    %s (%s)\n", tag(colorRed, exitStr, useColor), dur)
		}
	}

	PrintIntegrityResult(w, m.Checksum, useColor)

	if len(e.Findings) == 0 {
		fmt.Fprintf(w, "\nFindings: %s\n", tag(colorGreen, "none", useColor))
	} else {
		fmt.Fprintln(w, "\nFindings:")
		PrintFindings(w, e.Findings, useColor)
	}

	fmt.Fprintf(w, "\nScript:\n%s\n%s\n%s\n", sep, string(e.Script), sep)
}

// PrintEntryList prints a list of history entry metadata.
func PrintEntryList(w io.Writer, metas []history.Meta, useColor bool) {
	if len(metas) == 0 {
		fmt.Fprintln(w, "no history entries")
		return
	}
	for _, m := range metas {
		status := ""
		if m.DryRun {
			status = " " + tag(colorCyan, "[dry-run]", useColor)
		} else if m.Aborted {
			status = " " + tag(colorYellow, "[aborted]", useColor)
		}
		fmt.Fprintf(w, "%s  %s  %s%s\n",
			m.ID,
			m.Timestamp.Local().Format("2006-01-02 15:04"),
			truncate(m.Source, 60),
			status,
		)
	}
}

func tag(color, text string, useColor bool) string {
	if !useColor {
		return text
	}
	return color + text + colorReset
}

func bold(useColor bool) string {
	if !useColor {
		return ""
	}
	return colorBold
}

func dim(useColor bool) string {
	if !useColor {
		return ""
	}
	return colorDim
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
