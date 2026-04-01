package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"log/slog"
)

var (
	logger    *slog.Logger
	logLevel  string
	logFormat string
)

func init() {
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.StringVar(&logFormat, "log-format", "text", "Log format: text, json")
}

func InitLogger() error {
	level := &slog.LevelVar{}
	switch logLevel {
	case "debug":
		level.Set(slog.LevelDebug)
	case "info":
		level.Set(slog.LevelInfo)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		return fmt.Errorf("invalid log level: %s", logLevel)
	}

	var handler slog.Handler
	switch logFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	case "text":
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	default:
		return fmt.Errorf("invalid log format: %s", logFormat)
	}

	logger = slog.New(handler)
	return nil
}

type Config struct {
	ListenAddr      string
	VaultAddress    string
	AppRoleID       string
	SecretIDFile    string
	CommonPrefix    string
	SharedPath      string
	StoragePath     string
	AllowedKeysPath string
	Mode            string
	Operation       string
	SecretName      string
	VaultTokenFile  string
	PublicKeyFile   string
}

func Load() (*Config, error) {
	cfg := &Config{}

	// Define all flags first
	flag.StringVar(&cfg.ListenAddr, "listen-address", ":2222", "Address for the SSH server to listen on")
	flag.StringVar(&cfg.VaultAddress, "vault-address", "", "Address of the HashiCorp Vault server")
	flag.StringVar(&cfg.AppRoleID, "app-role-id", "", "AppRole Role ID for Vault authentication")
	flag.StringVar(&cfg.SecretIDFile, "secret-id-file", "", "Path to a file containing the AppRole Secret ID")
	flag.StringVar(&cfg.CommonPrefix, "common-prefix", "", "Common prefix for secrets in Vault (e.g., secrets/data/wintermutt)")
	flag.StringVar(&cfg.SharedPath, "shared-path", "", "Optional: A path in Vault to read shared secrets from")
	flag.StringVar(&cfg.StoragePath, "storage", ".", "Directory to store the server host key")
	flag.StringVar(&cfg.AllowedKeysPath, "allowed-keys-path", "", "Optional: Path to Vault secret containing JSON list of allowed keys")
	flag.StringVar(&cfg.VaultTokenFile, "vault-token-file", "", "Path to file containing Vault token (CLI mode)")
	flag.StringVar(&cfg.PublicKeyFile, "public-key", "", "Path to public key file (CLI mode)")
	flag.StringVar(&cfg.Operation, "op", "", "CLI operation: 'set', 'rm', 'allow', 'revoke'")
	flag.StringVar(&cfg.SecretName, "name", "", "Name of the secret (for set/rm)")

	// Parse flags manually to handle positional args before flags
	args := os.Args[1:]
	var positionalArgs []string

	i := 0
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			// Handle flag with value
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
			// Positional arg
			positionalArgs = append(positionalArgs, arg)
			i++
		}
	}

	// Parse any remaining flags
	if i < len(args) {
		err := flag.CommandLine.Parse(args[i:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse remaining flags: %w", err)
		}
	}

	// Collect remaining positional args
	positionalArgs = append(positionalArgs, flag.Args()...)

	if cfg.VaultTokenFile != "" {
		cfg.Mode = "cli"
		if len(positionalArgs) >= 1 {
			cfg.Operation = positionalArgs[0]
		}
	}

	if cfg.Mode == "cli" {
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
			if cfg.PublicKeyFile == "" {
				return nil, fmt.Errorf("-public-key is required for CLI mode")
			}
		}
		if cfg.Operation == "set" || cfg.Operation == "rm" {
			if cfg.SecretName == "" {
				return nil, fmt.Errorf("-name is required for %s operation", cfg.Operation)
			}
			if cfg.CommonPrefix == "" {
				return nil, fmt.Errorf("-common-prefix is required")
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
	} else {
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
	}

	return cfg, nil
}

func isCLIOperation(op string) bool {
	return op == "set" || op == "rm" || op == "allow" || op == "revoke" || op == "list-allowed"
}
