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

	err := srv.handleExec(nil, "unknown", true, false)
	assert.EqualError(t, err, "unsupported command: unknown")
}

func TestHandleExecRejectsWhenDisabled(t *testing.T) {
	srv := &Server{cfg: &Config{ServerConfig: ServerConfig{EnableBinaryDownload: false}}}

	err := srv.handleExec(nil, "get-binary", true, false)
	assert.EqualError(t, err, "binary download is disabled; enable with -enable-binary-download")
}

func TestHandleExecRejectsDownloadForDisallowedKeyWhenConfigured(t *testing.T) {
	srv := &Server{cfg: &Config{ServerConfig: ServerConfig{EnableBinaryDownload: true, DisallowDownloadByAnybody: true}}}

	err := srv.handleExec(nil, "get-binary", false, true)
	assert.EqualError(t, err, "public key not authorized")
}

func TestIsDownloadAuthorized(t *testing.T) {
	assert.True(t, isDownloadAuthorized(&Config{ServerConfig: ServerConfig{DisallowDownloadByAnybody: false}}, false, true))
	assert.True(t, isDownloadAuthorized(&Config{ServerConfig: ServerConfig{DisallowDownloadByAnybody: true}}, true, true))
	assert.False(t, isDownloadAuthorized(&Config{ServerConfig: ServerConfig{DisallowDownloadByAnybody: true}}, false, true))
	assert.True(t, isDownloadAuthorized(&Config{ServerConfig: ServerConfig{DisallowDownloadByAnybody: true}}, false, false))
}

func TestRenderCLIInstallScriptIncludesServerSettings(t *testing.T) {
	cfg := &Config{CommonConfig: CommonConfig{
		VaultAddress:    "http://127.0.0.1:8200",
		CommonPrefix:    "secrets/data/wintermutt",
		AllowedKeysPath: "secrets/data/wintermutt/allowed-keys",
	}, ServerConfig: ServerConfig{SharedPath: "secrets/data/wintermutt/shared", ExternalHost: "ssh.example.com", ExternalPort: "2222"}}

	script, err := renderCLIInstallScript(cfg)
	assert.NoError(t, err)
	assert.Contains(t, script, "vault_address: http://127.0.0.1:8200")
	assert.Contains(t, script, "common_prefix: secrets/data/wintermutt")
	assert.Contains(t, script, "shared_path: secrets/data/wintermutt/shared")
	assert.Contains(t, script, "allowed_keys_path: secrets/data/wintermutt/allowed-keys")
	assert.Contains(t, script, "SSH_HOST=\"ssh.example.com\"")
	assert.Contains(t, script, "ssh.example.com")
	assert.Contains(t, script, "SSH_PORT=\"2222\"")
	assert.Contains(t, script, "2222")
	assert.Contains(t, script, "SSH_TARGET=\"wintermutt@$SSH_HOST\"")
	assert.Contains(t, script, "WINTERMUTT_CONFIG_FILE")
	assert.Contains(t, script, "WINTERMUTT_INSTALL_BIN_FILE")
	assert.Contains(t, script, "WINTERMUTT_INSTALL_IDENTITY_FILE")
	assert.Contains(t, script, "get-binary")
}

func TestParseAllowedKeysMissingKeysField(t *testing.T) {
	_, err := parseAllowedKeys(map[string]interface{}{})
	assert.EqualError(t, err, "invalid format for allowed keys: 'keys' field missing or not a list")
}

func TestParseAllowedKeysParsesJSONList(t *testing.T) {
	keys, err := parseAllowedKeys(map[string]interface{}{"keys": `["ssh-ed25519 AAAA test@example"]`})
	assert.NoError(t, err)
	assert.Equal(t, []string{"ssh-ed25519 AAAA test@example"}, keys)
}

func TestParseAllowedKeysInvalidJSON(t *testing.T) {
	_, err := parseAllowedKeys(map[string]interface{}{"keys": `not-json`})
	assert.EqualError(t, err, "failed to parse JSON keys: invalid character 'o' in literal null (expecting 'u')")
}
