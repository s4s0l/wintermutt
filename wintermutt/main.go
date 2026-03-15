package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Mode == "cli" {
		if err := runCLI(cfg); err != nil {
			log.Fatalf("CLI error: %v", err)
		}
		return
	}

	vaultClient, err := NewClient(cfg.VaultAddress, cfg.AppRoleID, cfg.SecretIDFile)
	if err != nil {
		log.Fatalf("Failed to initialize Vault client: %v", err)
	}

	srv, err := New(cfg, vaultClient)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		srv.Stop()
	}()

	log.Printf("SSH server listening on %s", cfg.ListenAddr)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
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
