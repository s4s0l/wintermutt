package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
)

func readPublicKeyFile(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read public key file %s: %w", path, err)
	}

	keyStr := strings.TrimSpace(string(bytes))
	_, _, _, _, err = ssh.ParseAuthorizedKey([]byte(keyStr))
	if err != nil {
		return "", fmt.Errorf("invalid public key in %s: %w", path, err)
	}

	return keyStr, nil
}

func deriveFingerprint(publicKey string) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	keyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	stripped, err := _StripIdPubKey(keyStr)
	if err != nil {
		return "", fmt.Errorf("failed to strip key: %w", err)
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*stripped))
	if err != nil {
		return "", fmt.Errorf("failed to re-parse key: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(parsedKey)
	return fingerprint[7:], nil
}

func readSecretValue() (string, error) {
	if !isTerminal(os.Stdin) {
		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read from stdin: %w", err)
		}
		return strings.TrimSpace(string(bytes)), nil
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter secret value: ")
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read value: %w", err)
	}
	return strings.TrimSpace(value), nil
}

func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func cliSet(cfg *Config, vault *Client, publicKey string) error {
	fingerprint, err := deriveFingerprint(publicKey)
	if err != nil {
		return fmt.Errorf("failed to derive fingerprint: %w", err)
	}

	secretPath := path.Join(cfg.CommonPrefix, fingerprint)
	value, err := readSecretValue()
	if err != nil {
		return err
	}

	err = vault.SetSecret(secretPath, cfg.SecretName, value)
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	fmt.Printf("Secret %s set successfully\n", cfg.SecretName)
	return nil
}

func cliRm(cfg *Config, vault *Client, publicKey string) error {
	fingerprint, err := deriveFingerprint(publicKey)
	if err != nil {
		return fmt.Errorf("failed to derive fingerprint: %w", err)
	}

	secretPath := path.Join(cfg.CommonPrefix, fingerprint)
	err = vault.DeleteSecret(secretPath, cfg.SecretName)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("Secret %s deleted successfully\n", cfg.SecretName)
	return nil
}

func cliAllow(cfg *Config, vault *Client, publicKey string) error {
	err := vault.UpdateAllowedKeys(cfg.AllowedKeysPath, publicKey, true)
	if err != nil {
		return fmt.Errorf("failed to add key to allowed list: %w", err)
	}

	fmt.Println("Key added to allowed list")
	return nil
}

func cliRevoke(cfg *Config, vault *Client, publicKey string) error {
	err := vault.UpdateAllowedKeys(cfg.AllowedKeysPath, publicKey, false)
	if err != nil {
		return fmt.Errorf("failed to remove key from allowed list: %w", err)
	}

	fmt.Println("Key removed from allowed list")
	return nil
}

func cliListAllowed(cfg *Config, vault *Client) error {
	data, err := vault.GetRawSecret(cfg.AllowedKeysPath)
	if err != nil {
		return fmt.Errorf("failed to read allowed keys: %w", err)
	}

	if data == nil {
		fmt.Println("No allowed keys configured")
		return nil
	}

	keysStr, ok := data["keys"].(string)
	if !ok {
		return fmt.Errorf("allowed keys not in expected format")
	}

	var keys []string
	err = json.Unmarshal([]byte(keysStr), &keys)
	if err != nil {
		return fmt.Errorf("failed to parse allowed keys: %w", err)
	}

	if len(keys) == 0 {
		fmt.Println("No allowed keys configured")
		return nil
	}

	fmt.Println("Allowed public keys:")
	for i, key := range keys {
		fmt.Printf("%d. %s\n", i+1, key)
	}

	return nil
}
