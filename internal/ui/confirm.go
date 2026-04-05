package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// IsInteractive reports whether both stdin and stderr are connected to a terminal.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// ConfirmOptions controls the confirmation prompt behaviour.
type ConfirmOptions struct {
	In       io.Reader
	Out      io.Writer
	UseColor bool
}

// DefaultConfirmOptions returns options using os.Stdin and os.Stderr.
func DefaultConfirmOptions() ConfirmOptions {
	return ConfirmOptions{
		In:       os.Stdin,
		Out:      os.Stderr,
		UseColor: IsInteractive(),
	}
}

// Confirm prompts the user and returns true if they confirm execution.
// If nonInteractive is true, prints a notice and returns false without prompting.
func Confirm(nonInteractive bool, opts ConfirmOptions) bool {
	if nonInteractive {
		fmt.Fprintf(opts.Out, "%swarning:%s non-interactive mode — skipping confirmation, execution blocked\n",
			tag(colorYellow, "", opts.UseColor), colorReset)
		return false
	}

	fmt.Fprintf(opts.Out, "Proceed with execution? [y/N] ")

	scanner := bufio.NewScanner(opts.In)
	if !scanner.Scan() {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes"
}
