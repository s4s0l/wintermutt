package main

import (
	"flag"
	"fmt"
)

type Config struct {
	ListenAddr   string
	VaultAddress string
	AppRoleID    string
	SecretIDFile string
	CommonPrefix string
	SharedPath   string
	StoragePath  string
	AllowedKeysPath string
}

func Load() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen-address", ":2222", "Address for the SSH server to listen on")
	flag.StringVar(&cfg.VaultAddress, "vault-address", "", "Address of the HashiCorp Vault server")
	flag.StringVar(&cfg.AppRoleID, "app-role-id", "", "AppRole Role ID for Vault authentication")
	flag.StringVar(&cfg.SecretIDFile, "secret-id-file", "", "Path to a file containing the AppRole Secret ID")
	flag.StringVar(&cfg.CommonPrefix, "common-prefix", "", "Common prefix for secrets in Vault (e.g., secrets/data/wintermutt)")
	flag.StringVar(&cfg.SharedPath, "shared-path", "", "Optional: A path in Vault to read shared secrets from")
	flag.StringVar(&cfg.StoragePath, "storage", ".", "Directory to store the server host key")
	flag.StringVar(&cfg.AllowedKeysPath, "allowed-keys-path", "", "Optional: Path to Vault secret containing JSON list of allowed keys")

	flag.Parse()

	if cfg.VaultAddress == "" {
		return nil, fmt.Errorf("-vault-address is required")
	}
	if cfg.AppRoleID == "" {
		return nil, fmt.Errorf("-app-role-id is required")
	}
	if cfg.SecretIDFile == "" {
		return nil, fmt.Errorf("-secret-id-file is required")
	}
	if cfg.CommonPrefix == "" {
		return nil, fmt.Errorf("-common-prefix is required")
	}

	return cfg, nil
}
