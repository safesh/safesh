package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safesh/safesh/internal/finding"
)

func TestNewID(t *testing.T) {
	id1 := NewID()
	id2 := NewID()
	assert.NotEqual(t, id1, id2)
	// Format: 20060102T150405Z-xxxxxx
	// "20060102" (8) + "T" (1) + "150405" (6) + "Z-" (2) + 6 hex = 23 chars
	assert.Len(t, id1, 23)
	assert.Regexp(t, `^\d{8}T\d{6}Z-[0-9a-f]{6}$`, id1)
}

func TestWriteAndLoad(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	entry := &Entry{
		Meta: Meta{
			ID:        "20260405T143022Z-a3f9b2",
			Timestamp: time.Date(2026, 4, 5, 14, 30, 22, 0, time.UTC),
			Source:    "https://example.com/install.sh",
			Mode:      "url",
			Shell:     "/usr/bin/bash",
			DryRun:    false,
			Aborted:   false,
		},
		Findings: []finding.Finding{
			{Category: finding.CategoryPrivilege, Line: 5, Description: "invokes sudo"},
		},
		Script: []byte("#!/bin/bash\nsudo echo hi\n"),
		Exit:   &ExitInfo{ExitCode: 0, DurationMS: 1234},
	}

	require.NoError(t, w.Write(entry))

	// Verify files exist
	entryDir := filepath.Join(dir, entry.Meta.ID)
	for _, f := range []string{"meta.json", "findings.json", "script.sh", "exit.json"} {
		assert.FileExists(t, filepath.Join(entryDir, f))
	}

	// Load back
	loaded, err := Load(dir, entry.Meta.ID)
	require.NoError(t, err)
	assert.Equal(t, entry.Meta.ID, loaded.Meta.ID)
	assert.Equal(t, entry.Meta.Source, loaded.Meta.Source)
	assert.Equal(t, entry.Script, loaded.Script)
	require.Len(t, loaded.Findings, 1)
	assert.Equal(t, finding.CategoryPrivilege, loaded.Findings[0].Category)
	require.NotNil(t, loaded.Exit)
	assert.Equal(t, 0, loaded.Exit.ExitCode)
}

func TestWriteAndLoad_NilExit(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	entry := &Entry{
		Meta:     Meta{ID: "20260405T143022Z-abc123", Timestamp: time.Now()},
		Findings: nil,
		Script:   []byte("echo hi"),
		Exit:     nil, // dry run — no exit.json
	}

	require.NoError(t, w.Write(entry))
	loaded, err := Load(dir, entry.Meta.ID)
	require.NoError(t, err)
	assert.Nil(t, loaded.Exit)
}

func TestList_Empty(t *testing.T) {
	dir := t.TempDir()
	metas, err := List(dir)
	require.NoError(t, err)
	assert.Empty(t, metas)
}

func TestList_Sorted(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	times := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	ids := []string{"aaa", "bbb", "ccc"}

	for i, ts := range times {
		require.NoError(t, w.Write(&Entry{
			Meta:   Meta{ID: ids[i], Timestamp: ts},
			Script: []byte("echo"),
		}))
	}

	metas, err := List(dir)
	require.NoError(t, err)
	require.Len(t, metas, 3)
	// Newest first
	assert.True(t, metas[0].Timestamp.After(metas[1].Timestamp))
	assert.True(t, metas[1].Timestamp.After(metas[2].Timestamp))
}

func TestList_NonexistentDir(t *testing.T) {
	metas, err := List("/nonexistent/history/dir")
	require.NoError(t, err)
	assert.Empty(t, metas)
}
