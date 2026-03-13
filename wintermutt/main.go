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
