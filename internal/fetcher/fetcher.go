// Package fetcher reads shell scripts from stdin or HTTPS URLs.
package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maxScriptSize = 10 * 1024 * 1024 // 10 MiB
	httpTimeout   = 30 * time.Second
)

// Result holds the fetched script and its source description.
type Result struct {
	Source  string // URL or "stdin"
	Content []byte
}

// FromStdin reads the complete script from os.Stdin.
func FromStdin() (*Result, error) {
	content, err := io.ReadAll(io.LimitReader(os.Stdin, maxScriptSize))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("no script received on stdin")
	}
	return &Result{Source: "stdin", Content: content}, nil
}

// FromURL fetches the script at the given HTTPS URL.
func FromURL(rawURL string) (*Result, error) {
	if err := validateURL(rawURL); err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(rawURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", rawURL, resp.StatusCode)
	}

	content, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptSize))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", rawURL, err)
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("empty response from %s", rawURL)
	}

	return &Result{Source: rawURL, Content: content}, nil
}

// IsURL reports whether s looks like an HTTP/HTTPS URL.
func IsURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("unsupported scheme %q: only http/https allowed", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid URL %q: missing host", rawURL)
	}
	return nil
}
