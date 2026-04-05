package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{}
	assert.False(t, cfg.Enabled)
	assert.False(t, cfg.AllowNet)
}

func TestNotAvailableError(t *testing.T) {
	err := &NotAvailableError{Reason: "bwrap not found"}
	assert.Contains(t, err.Error(), "bwrap not found")
	assert.Contains(t, err.Error(), "sandbox not available")
}

func TestDetect_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	backend, err := Detect(cfg)
	assert.NoError(t, err)
	assert.Equal(t, BackendNone, backend)
}
