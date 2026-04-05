// Package integrity verifies script checksums against published hash files.
package integrity

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

const httpTimeout = 15 * time.Second

// Result holds the outcome of an integrity check.
type Result struct {
	Checked       bool   // whether a checksum was found and verified
	Verified      bool   // whether the checksum matched
	Algorithm     string // e.g. "sha256"
	ExpectedHash  string
	ActualHash    string
	ChecksumSource string // URL of the checksum file found
	Err           error
}

// Check attempts to verify src against a known hash or by auto-discovering
// a checksum file adjacent to scriptURL.
//
// If expectedHash is non-empty, it is used directly (no network fetch).
// If scriptURL is non-empty, common sibling checksum URLs are probed.
// If neither is available, the result has Checked=false.
func Check(src []byte, scriptURL, expectedHash string) Result {
	actual := sha256sum(src)

	if expectedHash != "" {
		match := strings.EqualFold(actual, strings.TrimSpace(expectedHash))
		return Result{
			Checked:      true,
			Verified:     match,
			Algorithm:    "sha256",
			ExpectedHash: expectedHash,
			ActualHash:   actual,
		}
	}

	if scriptURL == "" || scriptURL == "stdin" {
		return Result{Checked: false}
	}

	expected, source, err := fetchExpectedHash(scriptURL, path.Base(scriptURL))
	if err != nil || expected == "" {
		return Result{Checked: false}
	}

	match := strings.EqualFold(actual, expected)
	return Result{
		Checked:        true,
		Verified:       match,
		Algorithm:      "sha256",
		ExpectedHash:   expected,
		ActualHash:     actual,
		ChecksumSource: source,
	}
}

// sha256sum returns the lowercase hex SHA-256 of data.
func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// candidateURLs returns URLs to probe for a checksum file adjacent to scriptURL.
func candidateURLs(scriptURL string) []string {
	return []string{
		scriptURL + ".sha256",
		scriptURL + ".sha256sum",
		baseURL(scriptURL) + "checksums.txt",
		baseURL(scriptURL) + "SHA256SUMS",
		baseURL(scriptURL) + "CHECKSUMS",
	}
}

// baseURL returns the directory component of a URL (with trailing slash).
func baseURL(u string) string {
	idx := strings.LastIndex(u, "/")
	if idx < 0 {
		return u + "/"
	}
	return u[:idx+1]
}

// fetchExpectedHash tries candidate checksum URLs and returns the expected hash
// for the script filename and the URL it was found at.
func fetchExpectedHash(scriptURL, filename string) (hash, source string, err error) {
	client := &http.Client{Timeout: httpTimeout}

	for _, url := range candidateURLs(scriptURL) {
		resp, err := client.Get(url) //nolint:noctx
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		h, parseErr := parseChecksumFile(resp.Body, filename)
		resp.Body.Close()
		if parseErr != nil || h == "" {
			continue
		}
		return h, url, nil
	}
	return "", "", fmt.Errorf("no checksum file found for %s", scriptURL)
}

// parseChecksumFile parses common checksum file formats and returns
// the hash for the given filename.
//
// Supported formats:
//   - "<hash>  <filename>" (sha256sum output)
//   - "<hash>  <path/to/filename>"
//   - A single bare hash (when the file contains only one hash)
func parseChecksumFile(r io.Reader, filename string) (string, error) {
	var firstHash string
	var lineCount int

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lineCount++

		fields := strings.Fields(line)
		if len(fields) == 1 {
			// Bare hash line
			if firstHash == "" {
				firstHash = fields[0]
			}
			continue
		}
		if len(fields) >= 2 {
			fileField := strings.TrimPrefix(fields[1], "*") // strip binary mode marker
			if path.Base(fileField) == filename || fileField == filename {
				return fields[0], nil
			}
		}
	}

	// If there's exactly one hash and no filename matched, return the single hash.
	if lineCount == 1 && firstHash != "" {
		return firstHash, nil
	}

	return "", scanner.Err()
}
