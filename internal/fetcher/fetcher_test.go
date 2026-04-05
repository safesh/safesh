package fetcher

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsURL(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://example.com/install.sh", true},
		{"http://example.com/install.sh", true},
		{"bash", false},
		{"zsh", false},
		{"./script.sh", false},
		{"", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, IsURL(tt.in), "IsURL(%q)", tt.in)
	}
}

func TestFromURL_Success(t *testing.T) {
	script := "#!/bin/bash\necho hello\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(script))
	}))
	defer srv.Close()

	result, err := FromURL(srv.URL + "/install.sh")
	require.NoError(t, err)
	assert.Equal(t, script, string(result.Content))
	assert.Contains(t, result.Source, srv.URL)
}

func TestFromURL_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := FromURL(srv.URL + "/missing.sh")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
}

func TestFromURL_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := FromURL(srv.URL + "/empty.sh")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty response")
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://example.com/script.sh", false},
		{"http://example.com/script.sh", false},
		{"ftp://example.com/script.sh", true},
		{"not-a-url", true},
		{"https:///no-host", true},
	}
	for _, tt := range tests {
		err := validateURL(tt.url)
		if tt.wantErr {
			assert.Error(t, err, "validateURL(%q)", tt.url)
		} else {
			assert.NoError(t, err, "validateURL(%q)", tt.url)
		}
	}
}
