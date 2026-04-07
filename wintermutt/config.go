package main

import (
	"flag"
	"fmt"
	"os"

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

type CommonConfig struct {
	VaultAddress    string
	CommonPrefix    string
	AllowedKeysPath string
}

var commonCfg CommonConfig

func init() {
	flag.StringVar(&commonCfg.VaultAddress, "vault-address", "", "Address of the HashiCorp Vault server")
	flag.StringVar(&commonCfg.CommonPrefix, "common-prefix", "", "Common prefix for secrets in Vault")
	flag.StringVar(&commonCfg.AllowedKeysPath, "allowed-keys-path", "", "Path to Vault secret containing JSON list of allowed keys")
}

type Config struct {
	CommonConfig
	CliConfig
	ServerConfig
}

func LoadCommon() *CommonConfig {
	return &commonCfg
}

func ParseFlags(args []string) error {
	return flag.CommandLine.Parse(args)
}

func isCLIOperation(op string) bool {
	return op == "set" || op == "rm" || op == "list" || op == "set-shared" || op == "rm-shared" || op == "list-shared" || op == "allow" || op == "revoke" || op == "list-allowed"
}

func CommonHelp() string {
	return `Common Options:
  -vault-address string      Address of the HashiCorp Vault server
  -common-prefix string      Common prefix for secrets in Vault
  -allowed-keys-path string  Path to Vault secret containing JSON list of allowed keys
  -log-level string          Log level: debug, info, warn, error (default: info)
  -log-format string        Log format: text, json (default: text)
`
}
