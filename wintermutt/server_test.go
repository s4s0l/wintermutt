package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestMergeSecrets(t *testing.T) {
	common := map[string]string{
		"SECRET1": "common1",
		"SECRET2": "common2",
	}
	shared := map[string]string{
		"SECRET1": "shared1",
		"SECRET3": "shared3",
	}

	merged := mergeSecrets(common, shared)

	assert.Equal(t, "common1", merged["SECRET1"])
	assert.Equal(t, "common2", merged["SECRET2"])
	assert.Equal(t, "shared3", merged["SECRET3"])
}

func TestFormatSecrets(t *testing.T) {
	secrets := map[string]string{
		"SECRET1": "val1",
		"SECRET2": "val2",
	}

	formatted := formatSecrets(secrets)

	// Since maps are unordered, we check for presence
	assert.Contains(t, formatted, "export SECRET1=\"val1\"\n")
	assert.Contains(t, formatted, "export SECRET2=\"val2\"\n")
}

func TestParseExecCommand(t *testing.T) {
	payload := ssh.Marshal(struct {
		Command string
	}{Command: "get-binary"})

	cmd, err := parseExecCommand(payload)
	assert.NoError(t, err)
	assert.Equal(t, "get-binary", cmd)
}

func TestHandleExecRejectsUnsupportedCommand(t *testing.T) {
	srv := &Server{cfg: &Config{ServerConfig: ServerConfig{EnableBinaryDownload: true}}}

	err := srv.handleExec(nil, "unknown")
	assert.EqualError(t, err, "unsupported command: unknown")
}

func TestHandleExecRejectsWhenDisabled(t *testing.T) {
	srv := &Server{cfg: &Config{ServerConfig: ServerConfig{EnableBinaryDownload: false}}}

	err := srv.handleExec(nil, "get-binary")
	assert.EqualError(t, err, "binary download is disabled; enable with -enable-binary-download")
}
