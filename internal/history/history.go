// Package history persists safesh execution records to disk.
package history

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/safesh/safesh/internal/finding"
	"github.com/safesh/safesh/internal/integrity"
)

// DefaultDir returns the default history directory.
func DefaultDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	// Use XDG data dir convention
	dataDir := os.Getenv("XDG_DATA_HOME")
	if dataDir == "" {
		dataDir = filepath.Join(os.Getenv("HOME"), ".local", "share")
	}
	_ = base
	return filepath.Join(dataDir, "safesh", "history")
}

// Meta holds execution metadata for a history entry.
type Meta struct {
	ID              string              `json:"id"`
	Timestamp       time.Time           `json:"timestamp"`
	Source          string              `json:"source"`
	Mode            string              `json:"mode"`
	Shell           string              `json:"shell"`
	ShellRequested  string              `json:"shell_requested,omitempty"`
	SafeshVersion   string              `json:"safesh_version"`
	Hostname        string              `json:"hostname"`
	User            string              `json:"user"`
	DryRun          bool                `json:"dry_run"`
	Aborted         bool                `json:"aborted"`
	CIMode          bool                `json:"ci_mode,omitempty"`
	StrictMode      bool                `json:"strict_mode"`
	Checksum        *integrity.Result   `json:"checksum,omitempty"`
}

// ExitInfo holds execution result information.
type ExitInfo struct {
	ExitCode   int   `json:"exit_code"`
	DurationMS int64 `json:"duration_ms"`
}

// FindingsRecord wraps findings for JSON serialization.
type FindingsRecord struct {
	Findings []finding.Finding `json:"findings"`
}

// Entry is a fully loaded history entry (in memory).
type Entry struct {
	Meta     Meta
	Findings []finding.Finding
	Script   []byte
	Exit     *ExitInfo // nil for dry-run or aborted entries
}

// Writer writes a history entry to disk.
type Writer struct {
	dir string
}

// NewWriter returns a Writer using the given directory.
func NewWriter(dir string) *Writer {
	return &Writer{dir: dir}
}

// NewDefaultWriter returns a Writer using the default history directory.
func NewDefaultWriter() *Writer {
	return NewWriter(DefaultDir())
}

// Write persists an entry to the history directory.
func (w *Writer) Write(e *Entry) error {
	entryDir := filepath.Join(w.dir, e.Meta.ID)
	if err := os.MkdirAll(entryDir, 0o700); err != nil {
		return fmt.Errorf("creating history entry dir: %w", err)
	}

	if err := writeJSON(filepath.Join(entryDir, "meta.json"), e.Meta); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(entryDir, "findings.json"), FindingsRecord{Findings: e.Findings}); err != nil {
		return err
	}
	if len(e.Script) > 0 {
		if err := os.WriteFile(filepath.Join(entryDir, "script.sh"), e.Script, 0o600); err != nil {
			return fmt.Errorf("writing script.sh: %w", err)
		}
	}
	if e.Exit != nil {
		if err := writeJSON(filepath.Join(entryDir, "exit.json"), e.Exit); err != nil {
			return err
		}
	}
	return nil
}

// List returns history entry metadata sorted by timestamp descending (newest first).
func List(dir string) ([]Meta, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var metas []Meta
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		metaPath := filepath.Join(dir, de.Name(), "meta.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var m Meta
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		metas = append(metas, m)
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Timestamp.After(metas[j].Timestamp)
	})
	return metas, nil
}

// Load reads a full history entry by ID.
func Load(dir, id string) (*Entry, error) {
	entryDir := filepath.Join(dir, id)

	metaData, err := os.ReadFile(filepath.Join(entryDir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("reading meta.json: %w", err)
	}
	var meta Meta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, err
	}

	findData, err := os.ReadFile(filepath.Join(entryDir, "findings.json"))
	if err != nil {
		return nil, fmt.Errorf("reading findings.json: %w", err)
	}
	var fr FindingsRecord
	if err := json.Unmarshal(findData, &fr); err != nil {
		return nil, err
	}

	script, _ := os.ReadFile(filepath.Join(entryDir, "script.sh"))

	e := &Entry{Meta: meta, Findings: fr.Findings, Script: script}

	exitData, err := os.ReadFile(filepath.Join(entryDir, "exit.json"))
	if err == nil {
		var exit ExitInfo
		if json.Unmarshal(exitData, &exit) == nil {
			e.Exit = &exit
		}
	}

	return e, nil
}

// NewID generates a collision-resistant entry ID based on current UTC time.
func NewID() string {
	t := time.Now().UTC()
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%sZ-%s",
		t.Format("20060102T150405"),
		hex.EncodeToString(b),
	)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
