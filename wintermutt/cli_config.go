package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type CliConfig struct {
	VaultTokenFile string
	PublicKeyFile  string
	Operation      string
	SecretName     string
	SecretPath     string
	CliSharedPath  string
}

var cliCfg CliConfig

func init() {
	flag.StringVar(&cliCfg.VaultTokenFile, "vault-token-file", "", "Path to file containing Vault token")
	flag.StringVar(&cliCfg.PublicKeyFile, "public-key", "", "Path to public key file")
	flag.StringVar(&cliCfg.Operation, "op", "", "CLI operation: 'set', 'rm', 'set-shared', 'rm-shared', 'allow', 'revoke', 'list-allowed'")
	flag.StringVar(&cliCfg.SecretName, "name", "", "Name of the secret (for set/rm/set-shared/rm-shared)")
	flag.StringVar(&cliCfg.SecretPath, "path", "", "Override the secret path in Vault (skips fingerprint derivation)")
}

type cliFileConfig struct {
	Wintermutt *struct {
		VaultAddress    string `yaml:"vault_address"`
		CommonPrefix    string `yaml:"common_prefix"`
		AllowedKeysPath string `yaml:"allowed_keys_path"`
		SharedPath      string `yaml:"shared_path"`
	} `yaml:"wintermutt"`
}

func parseCLIArgs(commonDefaults *CommonConfig, args []string) (*Config, map[string]bool, []string, error) {
	common := *commonDefaults
	cli := cliCfg

	fs := flag.NewFlagSet("cli", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&common.VaultAddress, "vault-address", common.VaultAddress, "Address of the HashiCorp Vault server")
	fs.StringVar(&common.CommonPrefix, "common-prefix", common.CommonPrefix, "Common prefix for secrets in Vault")
	fs.StringVar(&common.AllowedKeysPath, "allowed-keys-path", common.AllowedKeysPath, "Path to Vault secret containing JSON list of allowed keys")
	fs.StringVar(&cli.VaultTokenFile, "vault-token-file", cli.VaultTokenFile, "Path to file containing Vault token")
	fs.StringVar(&cli.PublicKeyFile, "public-key", cli.PublicKeyFile, "Path to public key file")
	fs.StringVar(&cli.Operation, "op", cli.Operation, "CLI operation: 'set', 'rm', 'set-shared', 'rm-shared', 'allow', 'revoke', 'list-allowed'")
	fs.StringVar(&cli.SecretName, "name", cli.SecretName, "Name of the secret (for set/rm/set-shared/rm-shared)")
	fs.StringVar(&cli.SecretPath, "path", cli.SecretPath, "Override the secret path in Vault (skips fingerprint derivation)")
	fs.StringVar(&cli.CliSharedPath, "shared-path", cli.CliSharedPath, "Path in Vault for shared secrets (used by set-shared/rm-shared)")
	fs.StringVar(&logLevel, "log-level", logLevel, "Log level: debug, info, warn, error")
	fs.StringVar(&logFormat, "log-format", logFormat, "Log format: text, json")

	var positionalArgs []string

	i := 0
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") {
				err := fs.Parse([]string{arg})
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to parse flag %s: %w", arg, err)
				}
				i++
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				err := fs.Parse([]string{arg, args[i+1]})
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to parse flag %s: %w", arg, err)
				}
				i += 2
			} else {
				err := fs.Parse([]string{arg})
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to parse flag %s: %w", arg, err)
				}
				i++
			}
		} else {
			positionalArgs = append(positionalArgs, arg)
			i++
		}
	}

	flagsSet := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		flagsSet[f.Name] = true
	})

	cfg := &Config{
		CommonConfig: common,
		CliConfig:    cli,
	}

	return cfg, flagsSet, positionalArgs, nil
}

func configFilePath() (string, error) {
	if custom := strings.TrimSpace(os.Getenv("WINTERMUTT_CONFIG_FILE")); custom != "" {
		return custom, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home directory: %w", err)
	}

	return filepath.Join(home, ".config", "wintermutt", "wintermutt.yml"), nil
}

func applyCLIConfigFileDefaults(cfg *Config, flagsSet map[string]bool) error {
	path, err := configFilePath()
	if err != nil {
		return err
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var fileCfg cliFileConfig
	if err := yaml.Unmarshal(contents, &fileCfg); err != nil {
		return fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	if fileCfg.Wintermutt == nil {
		return fmt.Errorf("config file %s must contain root key 'wintermutt'", path)
	}

	if !flagsSet["vault-address"] && cfg.VaultAddress == "" {
		cfg.VaultAddress = strings.TrimSpace(fileCfg.Wintermutt.VaultAddress)
	}
	if !flagsSet["common-prefix"] && cfg.CommonPrefix == "" {
		cfg.CommonPrefix = strings.TrimSpace(fileCfg.Wintermutt.CommonPrefix)
	}
	if !flagsSet["allowed-keys-path"] && cfg.AllowedKeysPath == "" {
		cfg.AllowedKeysPath = strings.TrimSpace(fileCfg.Wintermutt.AllowedKeysPath)
	}
	if !flagsSet["shared-path"] && cfg.CliSharedPath == "" {
		cfg.CliSharedPath = strings.TrimSpace(fileCfg.Wintermutt.SharedPath)
	}

	return nil
}

func LoadCLI(common *CommonConfig, args []string) (*Config, error) {
	cfg, flagsSet, positionalArgs, err := parseCLIArgs(common, args)
	if err != nil {
		return nil, err
	}

	if err := applyCLIConfigFileDefaults(cfg, flagsSet); err != nil {
		return nil, err
	}

	if len(positionalArgs) >= 1 {
		cfg.Operation = positionalArgs[0]
	}

	if cfg.VaultAddress == "" {
		return nil, fmt.Errorf("-vault-address is required")
	}
	if cfg.Operation == "" {
		return nil, fmt.Errorf("CLI operation required: set, rm, set-shared, rm-shared, allow, revoke, or list-allowed")
	}
	if !isCLIOperation(cfg.Operation) {
		return nil, fmt.Errorf("invalid CLI operation: %s (must be set, rm, set-shared, rm-shared, allow, revoke, or list-allowed)", cfg.Operation)
	}
	if cfg.Operation != "list-allowed" && cfg.Operation != "set-shared" && cfg.Operation != "rm-shared" {
		if cfg.PublicKeyFile == "" && cfg.SecretPath == "" {
			return nil, fmt.Errorf("-public-key is required for CLI mode (unless -path is provided)")
		}
	}
	if cfg.Operation == "set" || cfg.Operation == "rm" || cfg.Operation == "set-shared" || cfg.Operation == "rm-shared" {
		if cfg.SecretName == "" {
			return nil, fmt.Errorf("-name is required for %s operation", cfg.Operation)
		}
	}
	if cfg.Operation == "set" || cfg.Operation == "rm" {
		if cfg.CommonPrefix == "" && cfg.SecretPath == "" {
			return nil, fmt.Errorf("-common-prefix or -path is required")
		}
	}
	if cfg.Operation == "set-shared" || cfg.Operation == "rm-shared" {
		if cfg.CliSharedPath == "" {
			return nil, fmt.Errorf("-shared-path is required for %s operation", cfg.Operation)
		}
		if cfg.PublicKeyFile != "" {
			return nil, fmt.Errorf("-public-key is not allowed for %s operation", cfg.Operation)
		}
		if cfg.SecretPath != "" {
			return nil, fmt.Errorf("-path is not allowed for %s operation", cfg.Operation)
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
  set-shared   Set a secret at shared path
  rm-shared    Delete a secret at shared path
  allow        Add a public key to the allowed list
  revoke       Remove a public key from the allowed list
  list-allowed List all allowed public keys

Options:
  -vault-address string    Address of the HashiCorp Vault server (required)
  -common-prefix string    Common prefix for secrets in Vault (required for set/rm/allow/revoke)
  -allowed-keys-path string Path to Vault secret containing JSON list of allowed keys (required for allow/revoke/list-allowed)
  -vault-token-file string Path to file containing Vault token
  -public-key string      Path to public key file
  -op string              CLI operation (set, rm, set-shared, rm-shared, allow, revoke, list-allowed)
  -name string            Name of the secret (for set/rm/set-shared/rm-shared)
  -path string            Override the secret path in Vault
  -shared-path string     Path in Vault for shared secrets (used by set-shared/rm-shared)

Config file defaults (cli mode):
  - uses WINTERMUTT_CONFIG_FILE when set
  - otherwise uses ~/.config/wintermutt/wintermutt.yml when present
  - expected YAML format:
      wintermutt:
        vault_address: http://127.0.0.1:8200
        common_prefix: secrets/data/wintermutt
        allowed_keys_path: secrets/data/wintermutt/allowed-keys
        shared_path: secrets/data/wintermutt/shared

Common Options (also available in serve mode):
  -log-level string       Log level: debug, info, warn, error (default: info)
  -log-format string     Log format: text, json (default: text)
`
}
