package main

import (
	"flag"
	"fmt"
	"strings"
)

type CliConfig struct {
	VaultTokenFile string
	PublicKeyFile  string
	Operation      string
	SecretName     string
	SecretPath     string
}

var cliCfg CliConfig

func init() {
	flag.StringVar(&cliCfg.VaultTokenFile, "vault-token-file", "", "Path to file containing Vault token")
	flag.StringVar(&cliCfg.PublicKeyFile, "public-key", "", "Path to public key file")
	flag.StringVar(&cliCfg.Operation, "op", "", "CLI operation: 'set', 'rm', 'allow', 'revoke', 'list-allowed'")
	flag.StringVar(&cliCfg.SecretName, "name", "", "Name of the secret (for set/rm)")
	flag.StringVar(&cliCfg.SecretPath, "path", "", "Override the secret path in Vault (skips fingerprint derivation)")
}

func parseCLIArgs(args []string) ([]string, error) {
	var positionalArgs []string

	i := 0
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				err := flag.CommandLine.Parse([]string{arg, args[i+1]})
				if err != nil {
					return nil, fmt.Errorf("failed to parse flag %s: %w", arg, err)
				}
				i += 2
			} else {
				err := flag.CommandLine.Parse([]string{arg})
				if err != nil {
					return nil, fmt.Errorf("failed to parse flag %s: %w", arg, err)
				}
				i++
			}
		} else {
			positionalArgs = append(positionalArgs, arg)
			i++
		}
	}

	if i < len(args) {
		err := flag.CommandLine.Parse(args[i:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse remaining flags: %w", err)
		}
	}

	positionalArgs = append(positionalArgs, flag.Args()...)
	return positionalArgs, nil
}

func LoadCLI(common *CommonConfig, args []string) (*Config, error) {
	positionalArgs, err := parseCLIArgs(args)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		CommonConfig: *common,
		CliConfig:    cliCfg,
	}

	if len(positionalArgs) >= 1 {
		cfg.Operation = positionalArgs[0]
	}

	if cfg.VaultAddress == "" {
		return nil, fmt.Errorf("-vault-address is required")
	}
	if cfg.Operation == "" {
		return nil, fmt.Errorf("CLI operation required: set, rm, allow, revoke, or list-allowed")
	}
	if !isCLIOperation(cfg.Operation) {
		return nil, fmt.Errorf("invalid CLI operation: %s (must be set, rm, allow, revoke, or list-allowed)", cfg.Operation)
	}
	if cfg.Operation != "list-allowed" {
		if cfg.PublicKeyFile == "" && cfg.SecretPath == "" {
			return nil, fmt.Errorf("-public-key is required for CLI mode (unless -path is provided)")
		}
	}
	if cfg.Operation == "set" || cfg.Operation == "rm" {
		if cfg.SecretName == "" {
			return nil, fmt.Errorf("-name is required for %s operation", cfg.Operation)
		}
		if cfg.CommonPrefix == "" && cfg.SecretPath == "" {
			return nil, fmt.Errorf("-common-prefix or -path is required")
		}
	}
	if cfg.Operation == "allow" || cfg.Operation == "revoke" {
		if cfg.AllowedKeysPath == "" {
			return nil, fmt.Errorf("-allowed-keys-path is required for %s operation", cfg.Operation)
		}
		if cfg.CommonPrefix == "" {
			return nil, fmt.Errorf("-common-prefix is required")
		}
	}
	if cfg.Operation == "list-allowed" {
		if cfg.AllowedKeysPath == "" {
			return nil, fmt.Errorf("-allowed-keys-path is required for list-allowed operation")
		}
	}

	return cfg, nil
}

func CLIHelp() string {
	return `Usage: wintermutt cli [options] <operation>

CLI Operations:
  set          Set a secret for a public key
  rm           Delete a secret for a public key
  allow        Add a public key to the allowed list
  revoke       Remove a public key from the allowed list
  list-allowed List all allowed public keys

Options:
  -vault-address string    Address of the HashiCorp Vault server (required)
  -common-prefix string    Common prefix for secrets in Vault (required for set/rm/allow/revoke)
  -allowed-keys-path string Path to Vault secret containing JSON list of allowed keys (required for allow/revoke/list-allowed)
  -vault-token-file string Path to file containing Vault token
  -public-key string      Path to public key file
  -op string              CLI operation (set, rm, allow, revoke, list-allowed)
  -name string            Name of the secret (for set/rm)
  -path string            Override the secret path in Vault

Common Options (also available in serve mode):
  -log-level string       Log level: debug, info, warn, error (default: info)
  -log-format string     Log format: text, json (default: text)
`
}
