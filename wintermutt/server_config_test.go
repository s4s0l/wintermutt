package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadServerRequiresExternalVaultAddress(t *testing.T) {
	serverCfg = ServerConfig{
		AppRoleID:    "role-id",
		SecretIDFile: "secret-id-file",
		ExternalHost: "ssh.example.com",
		ExternalPort: "2222",
	}

	cfg, err := LoadServer(&CommonConfig{
		VaultAddress: "http://127.0.0.1:8200",
		CommonPrefix: "secrets/data/wintermutt",
	})

	assert.Nil(t, cfg)
	assert.EqualError(t, err, "-external-vault-address is required")
}
