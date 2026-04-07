package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withExplicitTokenFile(args []string) []string {
	return append(args, "-vault-token-file", "/tmp/test-vault-token")
}

func TestLoadCLIUsesConfigFileDefaults(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "wintermutt.yml"))
	require.NoError(t, os.WriteFile(os.Getenv("WINTERMUTT_CONFIG_FILE"), []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
  common_prefix: secrets/data/wintermutt
  allowed_keys_path: secrets/data/wintermutt/allowed-keys
`), 0o600))

	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set", "-path", "secrets/data/custom", "-name", "api_key"}))
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

	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set", "-vault-address", "http://192.168.1.10:8200", "-path", "secrets/data/custom", "-name", "api_key"}))
	require.NoError(t, err)

	assert.Equal(t, "http://192.168.1.10:8200", cfg.VaultAddress)
}

func TestLoadCLIMissingRequiredSettingReportsError(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "wintermutt.yml"))
	require.NoError(t, os.WriteFile(os.Getenv("WINTERMUTT_CONFIG_FILE"), []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
`), 0o600))

	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list-allowed"}))
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

	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set", "-path", "secrets/data/custom", "-name", "api_key"}))
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8200", cfg.VaultAddress)
}

func TestLoadCLIMissingConfigFileIsNonFatal(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yml"))

	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set", "-vault-address", "http://127.0.0.1:8200", "-path", "secrets/data/custom", "-name", "api_key"}))
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8200", cfg.VaultAddress)
}

func TestLoadCLISharedPathFromConfigFile(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "wintermutt.yml"))
	require.NoError(t, os.WriteFile(os.Getenv("WINTERMUTT_CONFIG_FILE"), []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
  shared_path: secrets/data/wintermutt/shared
`), 0o600))

	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set-shared", "-name", "api_key"}))
	require.NoError(t, err)
	assert.Equal(t, "secrets/data/wintermutt/shared", cfg.CliSharedPath)
}

func TestLoadCLISharedPathArgOverridesConfigFile(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "wintermutt.yml"))
	require.NoError(t, os.WriteFile(os.Getenv("WINTERMUTT_CONFIG_FILE"), []byte(`wintermutt:
  vault_address: http://127.0.0.1:8200
  shared_path: secrets/data/from-config
`), 0o600))

	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set-shared", "-name", "api_key", "-shared-path", "secrets/data/from-arg"}))
	require.NoError(t, err)
	assert.Equal(t, "secrets/data/from-arg", cfg.CliSharedPath)
}

func TestLoadCLISharedOpsRequireSharedPath(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yml"))

	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set-shared", "-vault-address", "http://127.0.0.1:8200", "-name", "api_key"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-shared-path is required for set-shared operation")
}

func TestLoadCLISharedOpsRejectPublicKey(t *testing.T) {
	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"rm-shared", "-vault-address", "http://127.0.0.1:8200", "-name", "api_key", "-shared-path", "secrets/data/wintermutt/shared", "-public-key", "id.pub"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-public-key is not allowed for rm-shared operation")
}

func TestLoadCLISharedOpsRejectPath(t *testing.T) {
	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"set-shared", "-vault-address", "http://127.0.0.1:8200", "-name", "api_key", "-shared-path", "secrets/data/wintermutt/shared", "-path", "secrets/data/custom"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-path is not allowed for set-shared operation")
}

func TestLoadCLIListWithPathSkipsPublicKey(t *testing.T) {
	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list", "-vault-address", "http://127.0.0.1:8200", "-path", "secrets/data/custom"}))
	require.NoError(t, err)
	assert.Equal(t, "secrets/data/custom", cfg.SecretPath)
}

func TestLoadCLIListWithPublicKeyAndCommonPrefix(t *testing.T) {
	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list", "-vault-address", "http://127.0.0.1:8200", "-public-key", "id.pub", "-common-prefix", "secrets/data/wintermutt"}))
	require.NoError(t, err)
	assert.Equal(t, "id.pub", cfg.PublicKeyFile)
	assert.Equal(t, "secrets/data/wintermutt", cfg.CommonPrefix)
}

func TestLoadCLIListRequiresPublicKeyOrPath(t *testing.T) {
	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list", "-vault-address", "http://127.0.0.1:8200", "-common-prefix", "secrets/data/wintermutt"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-public-key is required for CLI mode (unless -path is provided)")
}

func TestLoadCLIListRejectsName(t *testing.T) {
	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list", "-vault-address", "http://127.0.0.1:8200", "-path", "secrets/data/custom", "-name", "api_key"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-name is not allowed for list operation")
}

func TestLoadCLIListSharedAcceptsSharedPath(t *testing.T) {
	cfg, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list-shared", "-vault-address", "http://127.0.0.1:8200", "-shared-path", "secrets/data/wintermutt/shared"}))
	require.NoError(t, err)
	assert.Equal(t, "secrets/data/wintermutt/shared", cfg.CliSharedPath)
}

func TestLoadCLIListSharedRequiresSharedPath(t *testing.T) {
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yml"))

	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list-shared", "-vault-address", "http://127.0.0.1:8200"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-shared-path is required for list-shared operation")
}

func TestLoadCLIListSharedRejectsPublicKey(t *testing.T) {
	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list-shared", "-vault-address", "http://127.0.0.1:8200", "-shared-path", "secrets/data/wintermutt/shared", "-public-key", "id.pub"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-public-key is not allowed for list-shared operation")
}

func TestLoadCLIListSharedRejectsPath(t *testing.T) {
	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list-shared", "-vault-address", "http://127.0.0.1:8200", "-shared-path", "secrets/data/wintermutt/shared", "-path", "secrets/data/custom"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-path is not allowed for list-shared operation")
}

func TestLoadCLIListSharedRejectsName(t *testing.T) {
	_, err := LoadCLI(&CommonConfig{}, withExplicitTokenFile([]string{"list-shared", "-vault-address", "http://127.0.0.1:8200", "-shared-path", "secrets/data/wintermutt/shared", "-name", "api_key"}))
	require.Error(t, err)
	assert.EqualError(t, err, "-name is not allowed for list-shared operation")
}

func TestLoadCLIUsesDefaultHomeVaultTokenWhenFlagMissing(t *testing.T) {
	home := t.TempDir()
	defaultTokenPath := filepath.Join(home, ".vault-token")
	require.NoError(t, os.WriteFile(defaultTokenPath, []byte("token"), 0o600))

	t.Setenv("HOME", home)
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yml"))

	cfg, err := LoadCLI(&CommonConfig{}, []string{"set", "-vault-address", "http://127.0.0.1:8200", "-path", "secrets/data/custom", "-name", "api_key"})
	require.NoError(t, err)
	assert.Equal(t, defaultTokenPath, cfg.VaultTokenFile)
}

func TestLoadCLIExplicitVaultTokenFileOverridesDefault(t *testing.T) {
	home := t.TempDir()
	defaultTokenPath := filepath.Join(home, ".vault-token")
	require.NoError(t, os.WriteFile(defaultTokenPath, []byte("default-token"), 0o600))

	explicitTokenPath := filepath.Join(home, "custom-token")

	t.Setenv("HOME", home)
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yml"))

	cfg, err := LoadCLI(&CommonConfig{}, []string{"set", "-vault-address", "http://127.0.0.1:8200", "-vault-token-file", explicitTokenPath, "-path", "secrets/data/custom", "-name", "api_key"})
	require.NoError(t, err)
	assert.Equal(t, explicitTokenPath, cfg.VaultTokenFile)
}

func TestLoadCLIMissingVaultTokenFileReportsRequiredError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("WINTERMUTT_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yml"))

	_, err := LoadCLI(&CommonConfig{}, []string{"set", "-vault-address", "http://127.0.0.1:8200", "-path", "secrets/data/custom", "-name", "api_key"})
	require.Error(t, err)
	assert.EqualError(t, err, "-vault-token-file is required")
}
