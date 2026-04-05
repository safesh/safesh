package integrity

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSHA256Sum(t *testing.T) {
	data := []byte("hello world\n")
	got := sha256sum(data)
	assert.Len(t, got, 64)
	assert.Equal(t, "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447", got)
}

func TestCheckWithExpectedHash(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	hash := sha256sum(src)

	r := Check(src, "", hash)
	assert.True(t, r.Checked)
	assert.True(t, r.Verified)
	assert.Equal(t, "sha256", r.Algorithm)
}

func TestCheckWithWrongHash(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	r := Check(src, "", "deadbeef")
	assert.True(t, r.Checked)
	assert.False(t, r.Verified)
}

func TestCheckNoURLNoHash(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	r := Check(src, "", "")
	assert.False(t, r.Checked)
}

func TestCheckAutoDiscovery(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")
	hash := sha256sum(src)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/install.sh":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(src)
		case "/install.sh.sha256":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "%s  install.sh\n", hash)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := Check(src, srv.URL+"/install.sh", "")
	assert.True(t, r.Checked)
	assert.True(t, r.Verified)
	assert.Contains(t, r.ChecksumSource, "install.sh.sha256")
}

func TestCheckAutoDiscovery_NoChecksumFile(t *testing.T) {
	src := []byte("#!/bin/bash\necho hello\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := Check(src, srv.URL+"/install.sh", "")
	assert.False(t, r.Checked)
}

func TestParseChecksumFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		filename string
		want     string
	}{
		{
			name:     "sha256sum format",
			content:  "abc123  install.sh\n",
			filename: "install.sh",
			want:     "abc123",
		},
		{
			name:     "binary mode marker",
			content:  "abc123 *install.sh\n",
			filename: "install.sh",
			want:     "abc123",
		},
		{
			name:     "with path prefix",
			content:  "abc123  dist/install.sh\n",
			filename: "install.sh",
			want:     "abc123",
		},
		{
			name:     "multiple entries",
			content:  "aaa111  other.sh\nabc123  install.sh\n",
			filename: "install.sh",
			want:     "abc123",
		},
		{
			name:     "bare single hash",
			content:  "abc123\n",
			filename: "anything",
			want:     "abc123",
		},
		{
			name:     "no match",
			content:  "aaa111  other.sh\n",
			filename: "install.sh",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseChecksumFile(strings.NewReader(tt.content), tt.filename)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
