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

	args := os.Args[1:]
	if len(args) == 0 {
		printHelp("")
		os.Exit(1)
	}

	mode := args[0]
	args = args[1:]

	common := LoadCommon()

	switch mode {
	case "serve":
		if err := ParseFlags(args); err != nil {
			logger.Error("Failed to parse flags", "error", err)
			os.Exit(1)
		}

		cfg, err := LoadServer(common)
		if err != nil {
			logger.Error("Failed to load server config", "error", err)
			fmt.Fprintln(os.Stderr, "Error:", err)
			fmt.Fprint(os.Stderr, ServerHelp())
			os.Exit(1)
		}

		vaultClient, err := NewClient(cfg.VaultAddress, cfg.AppRoleID, cfg.SecretIDFile)
		if err != nil {
			logger.Error("Failed to initialize Vault client", "error", err)
			os.Exit(1)
		}
		defer vaultClient.Close()

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

	case "cli":
		cfg, err := LoadCLI(common, args)
		if err != nil {
			logger.Error("Failed to load CLI config", "error", err)
			fmt.Fprintln(os.Stderr, "Error:", err)
			fmt.Fprint(os.Stderr, CLIHelp())
			os.Exit(1)
		}

		if err := runCLI(cfg); err != nil {
			logger.Error("CLI error", "error", err)
			os.Exit(1)
		}

	case "help":
		if len(args) > 0 {
			printHelp(args[0])
		} else {
			printHelp("")
		}
		os.Exit(0)

	default:
		printHelp("")
		os.Exit(1)
	}
}

func printHelp(mode string) {
	fmt.Println("wintermutt - SSH server that exposes secrets from Vault")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  wintermutt serve [options]    Run the SSH server")
	fmt.Println("  wintermutt cli [options]     Run CLI operations")
	fmt.Println("  wintermutt help [serve|cli]  Show help for a specific mode")
	fmt.Println("")

	if mode == "serve" {
		fmt.Print(ServerHelp())
	} else if mode == "cli" {
		fmt.Print(CLIHelp())
	} else {
		fmt.Print("Run 'wintermutt help serve' or 'wintermutt help cli' for more details.\n")
	}
}

func runCLI(cfg *Config) error {
	vaultClient, err := NewClientWithTokenFile(cfg.VaultAddress, cfg.VaultTokenFile)
	if err != nil {
		return fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	if cfg.Operation != "list-allowed" {
		publicKey := ""
		if cfg.Operation != "set-shared" && cfg.Operation != "rm-shared" && cfg.Operation != "list-shared" && cfg.SecretPath == "" {
			publicKey, err = readPublicKeyFile(cfg.PublicKeyFile)
			if err != nil {
				return fmt.Errorf("failed to read public key: %w", err)
			}
		}

		switch cfg.Operation {
		case "set":
			return cliSet(cfg, vaultClient, publicKey)
		case "rm":
			return cliRm(cfg, vaultClient, publicKey)
		case "list":
			return cliList(cfg, vaultClient, publicKey)
		case "set-shared":
			return cliSetShared(cfg, vaultClient)
		case "rm-shared":
			return cliRmShared(cfg, vaultClient)
		case "list-shared":
			return cliListShared(cfg, vaultClient)
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
