package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := InitLogger(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	cfg, err := Load()
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	if cfg.Mode == "cli" {
		if err := runCLI(cfg); err != nil {
			logger.Error("CLI error", "error", err)
			os.Exit(1)
		}
		return
	}

	vaultClient, err := NewClient(cfg.VaultAddress, cfg.AppRoleID, cfg.SecretIDFile)
	if err != nil {
		logger.Error("Failed to initialize Vault client", "error", err)
		os.Exit(1)
	}

	srv, err := New(cfg, vaultClient)
	if err != nil {
		logger.Error("Failed to create server", "error", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Shutting down...")
		srv.Stop()
	}()

	logger.Info("SSH server listening", "address", cfg.ListenAddr)
	if err := srv.Start(); err != nil {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}

	fmt.Println("Server stopped")
}

func runCLI(cfg *Config) error {
	vaultClient, err := NewClientWithTokenFile(cfg.VaultAddress, cfg.VaultTokenFile)
	if err != nil {
		return fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	if cfg.Operation != "list-allowed" {
		publicKey, err := readPublicKeyFile(cfg.PublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}

		switch cfg.Operation {
		case "set":
			return cliSet(cfg, vaultClient, publicKey)
		case "rm":
			return cliRm(cfg, vaultClient, publicKey)
		case "allow":
			return cliAllow(cfg, vaultClient, publicKey)
		case "revoke":
			return cliRevoke(cfg, vaultClient, publicKey)
		default:
			return fmt.Errorf("unknown operation: %s", cfg.Operation)
		}
	} else {
		return cliListAllowed(cfg, vaultClient)
	}
}
