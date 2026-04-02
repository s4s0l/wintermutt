package main

import (
	"flag"
	"fmt"
)

type ServerConfig struct {
	ListenAddr           string
	AppRoleID            string
	SecretIDFile         string
	SharedPath           string
	StoragePath          string
	EnableBinaryDownload bool
	ExternalHost         string
	ExternalPort         string
}

var serverCfg ServerConfig

func init() {
	flag.StringVar(&serverCfg.ListenAddr, "listen-address", ":2222", "Address for the SSH server to listen on")
	flag.StringVar(&serverCfg.AppRoleID, "app-role-id", "", "AppRole Role ID for Vault authentication")
	flag.StringVar(&serverCfg.SecretIDFile, "secret-id-file", "", "Path to a file containing the AppRole Secret ID")
	flag.StringVar(&serverCfg.SharedPath, "shared-path", "", "A path in Vault to read shared secrets from")
	flag.StringVar(&serverCfg.StoragePath, "storage", ".", "Directory to store the server host key")
	flag.BoolVar(&serverCfg.EnableBinaryDownload, "enable-binary-download", false, "Allow authenticated SSH clients to use 'get-binary' and 'cli-install'")
	flag.StringVar(&serverCfg.ExternalHost, "external-host", "", "Public SSH host used by generated cli-install script")
	flag.StringVar(&serverCfg.ExternalPort, "external-port", "", "Public SSH port used by generated cli-install script")
}

func LoadServer(common *CommonConfig) (*Config, error) {
	cfg := &Config{
		CommonConfig: *common,
		ServerConfig: serverCfg,
	}

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
	if cfg.ExternalHost == "" {
		return nil, fmt.Errorf("-external-host is required")
	}
	if cfg.ExternalPort == "" {
		return nil, fmt.Errorf("-external-port is required")
	}

	return cfg, nil
}

func ServerHelp() string {
	return `Usage: wintermutt serve [options]

Options:
  -listen-address string   Address for the SSH server to listen on (default: :2222)
  -vault-address string    Address of the HashiCorp Vault server (required)
  -app-role-id string      AppRole Role ID for Vault authentication (required)
  -secret-id-file string   Path to a file containing the AppRole Secret ID (required)
  -common-prefix string    Common prefix for secrets in Vault (required)
  -shared-path string      A path in Vault to read shared secrets from
  -storage string          Directory to store the server host key (default: .)
  -enable-binary-download  Allow authenticated SSH clients to use 'get-binary' and 'cli-install'
  -external-host string    Public SSH host used by generated cli-install script (required)
  -external-port string    Public SSH port used by generated cli-install script (required)
  -allowed-keys-path string Path to Vault secret containing JSON list of allowed keys

Common Options (also available in cli mode):
  -log-level string        Log level: debug, info, warn, error (default: info)
  -log-format string      Log format: text, json (default: text)
`
}
