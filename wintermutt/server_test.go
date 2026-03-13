package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
