package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/safesh/safesh/internal/analyzer"
	"github.com/safesh/safesh/internal/config"
	"github.com/safesh/safesh/internal/executor"
	"github.com/safesh/safesh/internal/fetcher"
	"github.com/safesh/safesh/internal/finding"
	"github.com/safesh/safesh/internal/history"
	"github.com/safesh/safesh/internal/integrity"
	"github.com/safesh/safesh/internal/observer"
	"github.com/safesh/safesh/internal/sandbox"
	"github.com/safesh/safesh/internal/ui"
)

// Build-time variables set by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "safesh: %v\n", err)
		os.Exit(1)
	}
}

// flags holds CLI flag values.
type flags struct {
	dryRun          bool
	observe         bool
	sha256          string
	envVars         []string
	noStrict        bool
	noConfirm       bool
	ci              bool
	configPath      string
	explain         string
	sandbox         bool
	sandboxAllowNet bool
}

func newRootCmd() *cobra.Command {
	f := &flags{}

	root := &cobra.Command{
		Use:   "safesh [shell] [flags]",
		Short: "A safer replacement for 'curl | bash'",
		Long: `safesh is a drop-in replacement for bash in the 'curl | bash' pattern.

Usage:
  curl -fsSL https://example.com/install.sh | safesh
  curl -fsSL https://example.com/install.sh | safesh bash
  safesh https://example.com/install.sh
  safesh --dry-run https://example.com/install.sh`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMain(cmd, args, f)
		},
	}

	root.PersistentFlags().BoolVar(&f.dryRun, "dry-run", false, "analyse without executing")
	root.PersistentFlags().BoolVar(&f.observe, "observe", false, "run script under strace and report observed behaviour (Linux only, requires strace)")
	root.PersistentFlags().StringVar(&f.sha256, "sha256", "", "expected SHA-256 hash (URL mode only)")
	root.PersistentFlags().StringArrayVar(&f.envVars, "env", nil, "pass through environment variable (repeatable)")
	root.PersistentFlags().BoolVar(&f.noStrict, "no-strict", false, "do not inject set -euo pipefail")
	root.PersistentFlags().BoolVar(&f.noConfirm, "no-confirm", false, "skip confirmation prompt")
	root.PersistentFlags().BoolVar(&f.ci, "ci", false, "CI mode: skip prompt, print findings as warnings, exit non-zero only on execution failure")
	root.PersistentFlags().StringVar(&f.configPath, "config", "", "config file path")
	root.PersistentFlags().StringVar(&f.explain, "explain", "", "print explanation for a finding category")
	root.PersistentFlags().BoolVar(&f.sandbox, "sandbox", false, "run script inside a bubblewrap sandbox (Linux only, requires bwrap)")
	root.PersistentFlags().BoolVar(&f.sandboxAllowNet, "sandbox-allow-net", false, "allow network access inside the sandbox (default: network is blocked)")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newHistoryCmd(f))

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("safesh %s (commit %s, built %s)\n", version, commit, date)
		},
	}
}

func runMain(_ *cobra.Command, args []string, f *flags) error {
	// Handle --explain flag
	if f.explain != "" {
		printExplanation(f.explain)
		return nil
	}

	// --observe is Linux-only
	if f.observe && runtime.GOOS != "linux" {
		return fmt.Errorf("--observe is only supported on Linux (current OS: %s)", runtime.GOOS)
	}
	if f.observe && !observer.HasStrace() {
		return fmt.Errorf("--observe requires strace; install it (e.g. apt install strace) and retry")
	}

	cfg, err := loadConfig(f.configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine invocation mode and optional shell override
	shellOverride := ""
	urlArg := ""

	knownShells := map[string]bool{
		"bash": true, "sh": true, "zsh": true, "dash": true,
		"fish": true, "ksh": true, "mksh": true,
	}

	if len(args) == 1 {
		arg := args[0]
		switch {
		case fetcher.IsURL(arg):
			urlArg = arg
		case knownShells[arg]:
			shellOverride = arg
		default:
			return fmt.Errorf("unknown argument %q: expected a URL or shell name (bash, zsh, sh, …)", arg)
		}
	}

	// Fetch script
	var fetch *fetcher.Result
	if urlArg != "" {
		fetch, err = fetcher.FromURL(urlArg)
	} else {
		fetch, err = fetcher.FromStdin()
	}
	if err != nil {
		return err
	}

	useColor := ui.IsInteractive()
	histWriter := history.NewDefaultWriter()
	entryID := history.NewID()

	// Integrity check (URL mode only)
	var integrityResult *integrity.Result
	if urlArg != "" || f.sha256 != "" {
		ir := integrity.Check(fetch.Content, fetch.Source, f.sha256)
		integrityResult = &ir
	}

	ui.PrintFetchBanner(os.Stderr, len(fetch.Content), integrityResult, useColor)

	if integrityResult != nil && integrityResult.Checked && !integrityResult.Verified {
		return fmt.Errorf("integrity check failed: expected %s got %s",
			integrityResult.ExpectedHash, integrityResult.ActualHash)
	}

	// Analyse
	findings := analyzer.Analyze(fetch.Content)

	// Apply ignored categories from config
	ignoreCats := stringsToCategories(cfg.Findings.Ignore)
	if len(ignoreCats) > 0 {
		findings = analyzer.ExcludeCategories(findings, ignoreCats)
	}

	// Print findings
	PrintFindingsToStderr(findings, useColor)

	// Determine if confirmation is needed.
	// --observe mode skips confirmation — it is a safe sandbox run.
	blockingCats := stringsToCategories(cfg.Findings.Blocking)
	blockingFindings := analyzer.FilterByCategories(findings, blockingCats)

	aborted := false
	if f.ci {
		// CI mode: print findings as warnings but never block on them.
		// Findings are already printed above; emit a notice if any were found.
		if len(findings) > 0 {
			fmt.Fprintf(os.Stderr, "warning: safesh --ci: %d finding(s) reported above; proceeding with execution\n", len(findings))
		}
	} else if !f.observe && len(findings) > 0 && !f.noConfirm && cfg.Defaults.ConfirmOnFindings {
		isInteractive := ui.IsInteractive()
		if len(blockingFindings) > 0 || isInteractive {
			confirmed := ui.Confirm(!isInteractive, ui.DefaultConfirmOptions())
			if !confirmed {
				aborted = true
			}
		}
	}

	// Resolve shell
	shellName := resolveShellName(fetch.Content, shellOverride, cfg.Defaults.Shell)
	shellPath, err := executor.ResolveShell(shellName)
	if err != nil {
		return err
	}

	// Build history entry
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}

	meta := history.Meta{
		ID:             entryID,
		Timestamp:      time.Now().UTC(),
		Source:         fetch.Source,
		Mode:           invocationMode(urlArg),
		Shell:          shellPath,
		ShellRequested: shellOverride,
		SafeshVersion:  version,
		Hostname:       hostname,
		User:           user,
		DryRun:         f.dryRun,
		Observe:        f.observe,
		Aborted:        aborted,
		CIMode:         f.ci,
		StrictMode:     !f.noStrict && cfg.Defaults.StrictMode,
		Checksum:       integrityResult,
	}

	entry := &history.Entry{
		Meta:     meta,
		Findings: findings,
		Script:   fetch.Content,
	}

	if aborted {
		_ = histWriter.Write(entry)
		return fmt.Errorf("execution aborted by user")
	}

	// --observe: run under strace and report; do not execute normally.
	if f.observe {
		obsOpts := observer.Options{
			Shell:               shellPath,
			StrictMode:          !f.noStrict && cfg.Defaults.StrictMode,
			IsolateEnv:          cfg.Defaults.EnvironmentIsolation,
			ExtraEnvPassthrough: append(cfg.Environment.Passthrough, f.envVars...),
		}
		obs, obsErr := observer.Run(fetch.Content, obsOpts)
		if obsErr != nil {
			_ = histWriter.Write(entry)
			return fmt.Errorf("observe: %w", obsErr)
		}
		entry.Exit = &history.ExitInfo{
			ExitCode:   obs.ExitCode,
			DurationMS: obs.Duration.Milliseconds(),
		}
		_ = histWriter.Write(entry)

		ui.PrintObservation(os.Stderr, obs, useColor)

		if obs.ExitCode != 0 {
			os.Exit(obs.ExitCode)
		}
		return nil
	}

	// Normal execute
	opts := executor.Options{
		Shell:               shellPath,
		StrictMode:          !f.noStrict && cfg.Defaults.StrictMode,
		IsolateEnv:          cfg.Defaults.EnvironmentIsolation,
		ExtraEnvPassthrough: append(cfg.Environment.Passthrough, f.envVars...),
		DryRun:              f.dryRun,
		Sandbox: sandbox.Config{
			Enabled:  f.sandbox,
			AllowNet: f.sandboxAllowNet,
		},
	}

	result, execErr := executor.Run(fetch.Content, opts)
	if !result.Skipped {
		entry.Exit = &history.ExitInfo{
			ExitCode:   result.ExitCode,
			DurationMS: result.Duration.Milliseconds(),
		}
	}

	_ = histWriter.Write(entry)

	if execErr != nil {
		return execErr
	}
	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}
	ui.PrintSuccess(os.Stderr, result.ExitCode, result.Skipped, history.DefaultDir(), useColor)
	return nil
}

// ── History subcommand ────────────────────────────────────────────────────────

func newHistoryCmd(_ *flags) *cobra.Command {
	histCmd := &cobra.Command{
		Use:   "history",
		Short: "Inspect execution history",
		RunE: func(_ *cobra.Command, _ []string) error {
			dir := history.DefaultDir()
			metas, err := history.List(dir)
			if err != nil {
				return err
			}
			ui.PrintEntryList(os.Stdout, metas, ui.IsInteractive())
			return nil
		},
	}

	var showLast bool
	showCmd := &cobra.Command{
		Use:   "show [id]",
		Short: "Show a history entry",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dir := history.DefaultDir()
			var id string
			if showLast || len(args) == 0 {
				metas, err := history.List(dir)
				if err != nil {
					return err
				}
				if len(metas) == 0 {
					return fmt.Errorf("no history entries")
				}
				id = metas[0].ID
			} else {
				id = args[0]
			}

			entry, err := history.Load(dir, id)
			if err != nil {
				return fmt.Errorf("loading entry %q: %w", id, err)
			}
			ui.PrintEntry(os.Stdout, entry, ui.IsInteractive())
			return nil
		},
	}
	showCmd.Flags().BoolVar(&showLast, "last", false, "show most recent entry")

	histCmd.AddCommand(showCmd)
	return histCmd
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func loadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	return config.LoadDefault()
}

func stringsToCategories(ss []string) []finding.Category {
	cats := make([]finding.Category, len(ss))
	for i, s := range ss {
		cats[i] = finding.Category(s)
	}
	return cats
}

func resolveShellName(src []byte, override, defaultShell string) string {
	if override != "" {
		return override
	}
	if shebang := executor.ShellFromShebang(src); shebang != "" {
		return shebang
	}
	return defaultShell
}

func invocationMode(urlArg string) string {
	if urlArg != "" {
		return "url"
	}
	return "pipe"
}



// PrintFindingsToStderr writes findings to stderr.
func PrintFindingsToStderr(findings []finding.Finding, useColor bool) {
	ui.PrintFindings(os.Stderr, findings, useColor)
	if len(findings) == 0 {
		ui.PrintUnsuspiciousNotice(os.Stderr, useColor)
	}
}

func printExplanation(category string) {
	explanations := map[string]string{
		"execution-integrity": "Checks for missing strict-mode flags (set -e, set -u, set -o pipefail). Without these, a script continues on errors and may behave unpredictably with unset variables.",
		"destructive":         "Flags irreversible filesystem operations: rm -rf, dd, mkfs, shred. These can permanently delete data.",
		"privilege":           "Flags privilege escalation: sudo, su, pkexec. These run commands as root or another user.",
		"persistence":         "Flags modifications that survive the session: cron jobs, shell profile changes, systemd services.",
		"network":             "Lists outbound network calls (curl, wget) and the domains contacted.",
		"obfuscation":         "Flags eval and base64-decode-then-execute chains that hide what the script does.",
		"execution-chain":     "Flags nested curl|bash patterns inside the script — the same risk you're already guarding against.",
	}

	if desc, ok := explanations[category]; ok {
		fmt.Printf("[%s]\n%s\n", category, desc)
	} else {
		fmt.Printf("unknown category %q\n", category)
		fmt.Printf("known categories: execution-integrity, destructive, privilege, persistence, network, obfuscation, execution-chain\n")
	}
}
