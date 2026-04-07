package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type ServerConfig struct {
	ListenAddr                string
	AppRoleID                 string
	AppRoleIDFile             string
	SecretIDFile              string
	SharedPath                string
	StoragePath               string
	EnableBinaryDownload      bool
	DisallowDownloadByAnybody bool
	ExternalHost              string
	ExternalPort              string
	ExternalVaultAddress      string
}

var serverCfg ServerConfig

func init() {
	flag.StringVar(&serverCfg.ListenAddr, "listen-address", ":2222", "Address for the SSH server to listen on")
	flag.StringVar(&serverCfg.AppRoleID, "app-role-id", "", "AppRole Role ID for Vault authentication - exclusive with -app-role-id-file")
	flag.StringVar(&serverCfg.AppRoleIDFile, "app-role-id-file", "", "Path to a file containing the AppRole Role ID for Vault authentication - exclusive with -app-role-id")
	flag.StringVar(&serverCfg.SecretIDFile, "secret-id-file", "", "Path to a file containing the AppRole Secret ID")
	flag.StringVar(&serverCfg.SharedPath, "shared-path", "", "A path in Vault to read shared secrets from")
	flag.StringVar(&serverCfg.StoragePath, "storage", ".", "Directory to store the server host key")
	flag.BoolVar(&serverCfg.EnableBinaryDownload, "enable-binary-download", false, "Allow authenticated SSH clients to use 'get-binary' and 'cli-install'")
	flag.BoolVar(&serverCfg.DisallowDownloadByAnybody, "disallow-download-by-anybody", false, "Require download commands to use an allowed key when -allowed-keys-path is configured")
	flag.StringVar(&serverCfg.ExternalHost, "external-host", "", "Public SSH host used by generated cli-install script")
	flag.StringVar(&serverCfg.ExternalPort, "external-port", "", "Public SSH port used by generated cli-install script")
	flag.StringVar(&serverCfg.ExternalVaultAddress, "external-vault-address", "", "Vault address written to generated cli-install config")
}

func LoadServer(common *CommonConfig) (*Config, error) {
	cfg := &Config{
		CommonConfig: *common,
		ServerConfig: serverCfg,
	}

	if cfg.VaultAddress == "" {
		return nil, fmt.Errorf("-vault-address is required")
	}
	if cfg.AppRoleID != "" && cfg.AppRoleIDFile != "" {
		return nil, fmt.Errorf("only one of -app-role-id or -app-role-id-file may be set")
	}
	if cfg.AppRoleID == "" && cfg.AppRoleIDFile == "" {
		return nil, fmt.Errorf("one of -app-role-id or -app-role-id-file is required")
	}
	if cfg.AppRoleIDFile != "" {
		data, err := os.ReadFile(cfg.AppRoleIDFile)
		if err != nil {
			return nil, fmt.Errorf("reading -app-role-id-file: %w", err)
		}
		cfg.AppRoleID = strings.TrimSpace(string(data))
		if cfg.AppRoleID == "" {
			return nil, fmt.Errorf("-app-role-id-file %q is empty", cfg.AppRoleIDFile)
		}
	}
	if cfg.SecretIDFile == "" {
		return nil, fmt.Errorf("-secret-id-file is required")
	}
	if cfg.CommonPrefix == "" {
		return nil, fmt.Errorf("-common-prefix is required")
	}
	if cfg.ExternalHost == "" {
		return nil, fmt.Errorf("-external-host is required")
	}
	if cfg.ExternalPort == "" {
		return nil, fmt.Errorf("-external-port is required")
	}
	if cfg.ExternalVaultAddress == "" {
		return nil, fmt.Errorf("-external-vault-address is required")
	}
	if cfg.DisallowDownloadByAnybody && cfg.AllowedKeysPath == "" {
		return nil, fmt.Errorf("-allowed-keys-path is required when -disallow-download-by-anybody is set")
	}

	return cfg, nil
}

func ServerHelp() string {
	return `Usage: wintermutt serve [options]

Options:
  -listen-address string   Address for the SSH server to listen on (default: :2222)
  -vault-address string    Address of the HashiCorp Vault server (required)
  -app-role-id string      AppRole Role ID for Vault authentication (required if --app-role-id-file not set)
  -app-role-id-file string Path to a file containing the AppRole Role ID (required if --app-role-id not set)
  -secret-id-file string   Path to a file containing the AppRole Secret ID (required)
  -common-prefix string    Common prefix for secrets in Vault (required)
  -shared-path string      A path in Vault to read shared secrets from
  -storage string          Directory to store the server host key (default: .)
  -enable-binary-download  Allow authenticated SSH clients to use 'get-binary' and 'cli-install'
  -disallow-download-by-anybody Require download commands to use an allowed key when -allowed-keys-path is configured
	-external-host string    Public SSH host used by generated cli-install script (required)
	-external-port string    Public SSH port used by generated cli-install script (required)
	-external-vault-address string Vault address written to generated cli-install config (required)
	-allowed-keys-path string Path to Vault secret containing JSON list of allowed keys

Common Options (also available in cli mode):
  -log-level string        Log level: debug, info, warn, error (default: info)
  -log-format string      Log format: text, json (default: text)
`
}
