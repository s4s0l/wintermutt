package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func getHostKey(storagePath string) (*rsa.PrivateKey, error) {
	keyPath := filepath.Join(storagePath, "host_key")

	// Try to read existing key
	data, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	// Generate new key if not found
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Save the new key
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyFile.Close()

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		return nil, fmt.Errorf("failed to encode key to PEM: %w", err)
	}

	return key, nil
}
