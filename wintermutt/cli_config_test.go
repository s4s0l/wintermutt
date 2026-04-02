package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadCLIUsesConfigFileDefaults(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "wintermutt.yml"))
	require.NoError(t, os.WriteFile(os.Getenv("WINTERMUTT_CONFIG_FILE"), []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
  common_prefix: secrets/data/wintermutt
  allowed_keys_path: secrets/data/wintermutt/allowed-keys
`), 0o600))

	cfg, err := LoadCLI(&CommonConfig{}, []string{"set", "-path", "secrets/data/custom", "-name", "api_key"})
	require.NoError(t, err)

	assert.Equal(t, "http://127.0.0.1:8200", cfg.VaultAddress)
	assert.Equal(t, "secrets/data/wintermutt", cfg.CommonPrefix)
	assert.Equal(t, "secrets/data/wintermutt/allowed-keys", cfg.AllowedKeysPath)
}

func TestLoadCLIArgOverridesConfigFile(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "wintermutt.yml"))
	require.NoError(t, os.WriteFile(os.Getenv("WINTERMUTT_CONFIG_FILE"), []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
`), 0o600))

	cfg, err := LoadCLI(&CommonConfig{}, []string{"set", "-vault-address", "http://192.168.1.10:8200", "-path", "secrets/data/custom", "-name", "api_key"})
	require.NoError(t, err)

	assert.Equal(t, "http://192.168.1.10:8200", cfg.VaultAddress)
}

func TestLoadCLIMissingRequiredSettingReportsError(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "wintermutt.yml"))
	require.NoError(t, os.WriteFile(os.Getenv("WINTERMUTT_CONFIG_FILE"), []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
`), 0o600))

	_, err := LoadCLI(&CommonConfig{}, []string{"list-allowed"})
	require.Error(t, err)
	assert.EqualError(t, err, "-allowed-keys-path is required for list-allowed operation")
}

func TestLoadCLIDefaultConfigPathFromHome(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, ".config", "wintermutt", "wintermutt.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(configPath), 0o755))
	require.NoError(t, os.WriteFile(configPath, []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
`), 0o600))

	t.Setenv("HOME", home)
	t.Setenv("WINTERMUTT_CONFIG_FILE", "")

	cfg, err := LoadCLI(&CommonConfig{}, []string{"set", "-path", "secrets/data/custom", "-name", "api_key"})
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8200", cfg.VaultAddress)
}

func TestLoadCLIMissingConfigFileIsNonFatal(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yml"))

	cfg, err := LoadCLI(&CommonConfig{}, []string{"set", "-vault-address", "http://127.0.0.1:8200", "-path", "secrets/data/custom", "-name", "api_key"})
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8200", cfg.VaultAddress)
}
